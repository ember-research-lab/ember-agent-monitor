//! Enforcing egress gate — in-band hold-and-resume approval for outfacing actions.
//!
//! `ember-agent-monitor` already intercepts the agent⇄LLM channel in-band (the
//! `net::proxy`) and can `Observe` / `Warn` / `Block` ([`InterventionMode`]). The
//! egress gate is the next step past `Block`: instead of merely *refusing* a
//! dangerous action, it **holds** an *outfacing* action (one that reaches an
//! external system — HTTP, email, payment, spawned process) pending an explicit
//! human decision, then **resumes** (executes) or **cancels** it on that decision.
//! It is the single chokepoint that makes "anything outfacing requires approval"
//! true by construction rather than by remembering to wire per-call checks.
//!
//! ## Multi-consumer by design
//!
//! This is a **neutral** capability consumed by outward-facing products (the SMB
//! agent platform and Whale Signal to start, and future products). It speaks in
//! neutral terms — a `principal` performs an action within a `namespace` — and
//! makes no assumption about what those map to (an "agent" + "tenant", a "bot" +
//! "account", …). Each consumer adapts its own gate trait onto this API.
//!
//! ## What's here vs. integration seams
//!
//! [`EgressGate`] is the in-memory **state machine**: submit → held →
//! resolve(approve|deny) → execute|cancel, plus the pending queue the approval
//! surfaces render. Two of the original integration seams now have implementations
//! in this module:
//! - **Durable held state** ([`PersistentEgressGate`], seam #2): a write-through
//!   [`journal`] so held actions survive a restart (an approval can arrive hours
//!   after `submit`), recovered by [`PendingId`].
//! - **Bypass detection** ([`bypass`], seam #4): reconciles egress observed on the
//!   wire (by `ember-network`) against the gate's approval record and emits a HIGH
//!   `Finding` for egress that never went through the gate.
//!
//! Still a seam: the *suspension* of the real outbound call (the proxy holding a
//! connection, or a dispatcher awaiting) — `net::proxy` / consumer dispatcher.
//!
//! [`InterventionMode`]: crate::types::InterventionMode

pub mod bypass;
pub mod journal;

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Mutex;

use journal::EgressJournal;

/// The class of outfacing action. Every side-effecting egress kind routes through
/// the gate; `Other` carries connector/tool-specific kinds neutrally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressKind {
    Http,
    Smtp,
    Payment,
    Subprocess,
    Other(String),
}

impl EgressKind {
    /// Stable token for the durable journal. `Other(x)` is `other:x` so it can
    /// never collide with a builtin token (and round-trips through [`from_token`]).
    ///
    /// [`from_token`]: EgressKind::from_token
    pub fn token(&self) -> String {
        match self {
            EgressKind::Http => "http".into(),
            EgressKind::Smtp => "smtp".into(),
            EgressKind::Payment => "payment".into(),
            EgressKind::Subprocess => "subprocess".into(),
            EgressKind::Other(s) => format!("other:{s}"),
        }
    }

    /// Inverse of [`token`](EgressKind::token). An unknown builtin token is treated
    /// as `Other` (forward-compatible: a token this version doesn't know is carried
    /// neutrally rather than dropped).
    pub fn from_token(t: &str) -> Self {
        match t {
            "http" => EgressKind::Http,
            "smtp" => EgressKind::Smtp,
            "payment" => EgressKind::Payment,
            "subprocess" => EgressKind::Subprocess,
            other => EgressKind::Other(other.strip_prefix("other:").unwrap_or(other).to_string()),
        }
    }
}

/// An outfacing action submitted to the gate. `principal`/`namespace` are neutral
/// identifiers the consumer assigns (e.g. agent id / tenant id). `summary` is what
/// a human sees on the approval surface; `payload_ref` points at the full action.
#[derive(Clone, Debug)]
pub struct OutfacingAction {
    pub principal: String,
    pub namespace: String,
    pub kind: EgressKind,
    pub summary: String,
    pub payload_ref: String,
}

/// Opaque handle to a held action awaiting a decision. **Process-local + monotonic**
/// as minted here (`egress-<n>`). Durable identity across restart is the integrator's
/// job (seam 3b): persist held state under this id and mint it with a boot nonce /
/// disk-backed counter so ids do not collide after a restart.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PendingId(pub String);

/// A human decision on a held action. `approver` is the neutral identity the
/// integrator has already authenticated + authorized for the namespace.
#[derive(Clone, Debug)]
pub enum Decision {
    Approve { approver: String },
    Deny { approver: String, reason: String },
}

/// The outcome of resolving a held action. On approve, the integrator must
/// **resume/execute** the returned action exactly once; on deny it is dropped,
/// carrying the deny `reason` through for the audit record (don't lose it).
#[derive(Clone, Debug)]
pub enum Resolution {
    Execute(OutfacingAction),
    Cancelled { reason: String },
}

/// A currently-held action, for rendering on approval surfaces.
#[derive(Clone, Debug)]
pub struct HeldAction {
    pub id: PendingId,
    pub action: OutfacingAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateError {
    UnknownPending,
}

/// The enforcing egress gate.
///
/// **Contract:** an action passed to [`submit`](EgressGate::submit) is `Held` and
/// produces **no side effect**; it executes only when [`resolve`](EgressGate::resolve)
/// returns [`Resolution::Execute`] for it (i.e. an explicit `Approve`). The
/// integrator (the proxy/dispatcher) is responsible for *not* performing the real
/// egress until then, for resuming it exactly once on approve, and for auditing
/// every submit/resolve to the action ledger.
/// Internal state behind a **single** lock — one mutex, one invariant: the queue
/// and the id counter move together (no cross-lock gap).
#[derive(Default)]
struct GateState {
    queue: VecDeque<HeldAction>,
    counter: u64,
}

#[derive(Default)]
pub struct EgressGate {
    state: Mutex<GateState>,
}

impl EgressGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Route an outfacing action through the gate. It is held pending approval and
    /// returns its `PendingId`. (Auto-approval is a consumer-side policy decision:
    /// a consumer that wishes to auto-approve simply calls `resolve` immediately
    /// with an authorized approver — the gate stays the single enforcement point.)
    pub fn submit(&self, action: OutfacingAction) -> PendingId {
        let mut st = self.state.lock().unwrap();
        st.counter += 1;
        let id = PendingId(format!("egress-{}", st.counter));
        st.queue.push_back(HeldAction {
            id: id.clone(),
            action,
        });
        id
    }

    /// Resolve a held action. `Approve` returns the action to resume/execute;
    /// `Deny` cancels it. Resolving an unknown/already-resolved id is an error.
    pub fn resolve(&self, id: &PendingId, decision: Decision) -> Result<Resolution, GateError> {
        let mut st = self.state.lock().unwrap();
        let pos = st
            .queue
            .iter()
            .position(|h| &h.id == id)
            .ok_or(GateError::UnknownPending)?;
        let entry = st.queue.remove(pos).expect("position just found");
        match decision {
            Decision::Approve { .. } => Ok(Resolution::Execute(entry.action)),
            Decision::Deny { reason, .. } => Ok(Resolution::Cancelled { reason }),
        }
    }

    /// Held actions for a namespace — the approval queue a surface renders.
    pub fn pending(&self, namespace: &str) -> Vec<HeldAction> {
        self.state
            .lock()
            .unwrap()
            .queue
            .iter()
            .filter(|h| h.action.namespace == namespace)
            .cloned()
            .collect()
    }

    /// Count of all held actions (across namespaces).
    pub fn pending_count(&self) -> usize {
        self.state.lock().unwrap().queue.len()
    }

    /// Reconstruct a gate from durably-recovered held actions plus the high-water id
    /// counter, so freshly-minted ids continue **past** the pre-restart ones (no
    /// collision after a restart). Used by [`PersistentEgressGate::recover`]; not the
    /// hot path.
    pub fn from_recovered(held: Vec<HeldAction>, counter: u64) -> Self {
        Self {
            state: Mutex::new(GateState {
                queue: held.into(),
                counter,
            }),
        }
    }

    /// Remove a held action **without** resolving it (no `Execute`/`Cancelled`,
    /// hence no side effect). Exists so the persistence layer can roll an in-memory
    /// hold back when its durable journal write fails — keeping memory and the
    /// journal consistent. Returns whether the id was present. Not for consumer use;
    /// the approval path is [`resolve`](EgressGate::resolve).
    pub fn discard(&self, id: &PendingId) -> bool {
        let mut st = self.state.lock().unwrap();
        if let Some(pos) = st.queue.iter().position(|h| &h.id == id) {
            st.queue.remove(pos);
            true
        } else {
            false
        }
    }
}

/// Failure of a durable gate operation: the gate state machine rejected it, or the
/// durable journal write failed. Kept distinct from [`GateError`] so the in-memory
/// gate's API stays unchanged for its existing consumers.
#[derive(Debug)]
pub enum PersistError {
    Gate(GateError),
    Journal(String),
}

impl From<GateError> for PersistError {
    fn from(e: GateError) -> Self {
        PersistError::Gate(e)
    }
}

/// **Durable egress gate** (integration seam #2): the in-memory [`EgressGate`] state
/// machine plus a write-through [`EgressJournal`], so held actions survive a restart
/// — an approval can arrive hours after the `submit`.
///
/// Crash-safety (why no window double-executes or loses an action):
/// - [`submit`](Self::submit) queues in memory, then journals `held`. If the journal
///   write fails it **rolls the hold back** and returns the error — a hold that isn't
///   durable is never reported as held.
/// - [`resolve`](Self::resolve) removes from memory (the single-use guard) **then**
///   journals `resolved` before the caller can act on `Execute`. If the journal write
///   fails after the in-memory removal, the caller gets an error and must NOT execute;
///   on the next restart the action recovers as still-held and can be re-approved —
///   exactly once. The reverse order (journal-then-remove) could let a crash between
///   the two re-offer an already-executed action, so the order is deliberate.
///
/// The journal is *not* the audit ledger (seam #3, hash-chained, consumer-side); it
/// carries only what held-state recovery needs.
pub struct PersistentEgressGate {
    inner: EgressGate,
    journal: Mutex<EgressJournal>,
}

impl PersistentEgressGate {
    /// Open the gate, **recovering** any prior held state from the journal at `path`
    /// (a missing journal opens an empty gate). Freshly-minted ids continue past the
    /// recovered high-water mark so they cannot collide with pre-restart ids.
    pub fn recover(path: &Path) -> Result<Self, String> {
        let recovered = journal::recover(path)?;
        let inner = EgressGate::from_recovered(recovered.held, recovered.counter);
        let journal = EgressJournal::open(path)?;
        Ok(Self {
            inner,
            journal: Mutex::new(journal),
        })
    }

    /// Submit an action durably. Held in memory and journaled before returning; on a
    /// journal-write failure the hold is rolled back and the error returned.
    pub fn submit(&self, action: OutfacingAction) -> Result<PendingId, String> {
        let mut j = self.journal.lock().unwrap();
        let id = self.inner.submit(action.clone());
        if let Err(e) = j.append_held(&id, &action) {
            self.inner.discard(&id); // keep memory consistent with the failed journal
            return Err(e);
        }
        Ok(id)
    }

    /// Resolve an action durably (write-ahead on the resolution — see the type docs).
    pub fn resolve(&self, id: &PendingId, decision: Decision) -> Result<Resolution, PersistError> {
        let mut j = self.journal.lock().unwrap();
        // Remove in memory first: validates the id and enforces single-use.
        let resolution = self.inner.resolve(id, decision.clone())?;
        // Then make the resolution durable BEFORE the caller can act on `Execute`.
        j.append_resolved(id, &decision)
            .map_err(PersistError::Journal)?;
        Ok(resolution)
    }

    /// Held actions for a namespace (the approval queue) — delegates to the gate.
    pub fn pending(&self, namespace: &str) -> Vec<HeldAction> {
        self.inner.pending(namespace)
    }

    /// Count of all held actions across namespaces.
    pub fn pending_count(&self) -> usize {
        self.inner.pending_count()
    }

    /// Assemble from an explicit gate + journal — lets tests inject a journal whose
    /// sink fails, to exercise the crash-safety branches.
    #[cfg(test)]
    fn from_parts(inner: EgressGate, journal: EgressJournal) -> Self {
        Self {
            inner,
            journal: Mutex::new(journal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(principal: &str, namespace: &str) -> OutfacingAction {
        OutfacingAction {
            principal: principal.into(),
            namespace: namespace.into(),
            kind: EgressKind::Smtp,
            summary: "send email to customer".into(),
            payload_ref: "draft-1".into(),
        }
    }

    #[test]
    fn submit_holds_then_approve_executes() {
        let gate = EgressGate::new();
        let id = gate.submit(action("a1", "tenant-1"));
        // Held: nothing executed, it's on the queue.
        assert_eq!(gate.pending("tenant-1").len(), 1);
        let res = gate
            .resolve(
                &id,
                Decision::Approve {
                    approver: "owner".into(),
                },
            )
            .unwrap();
        match res {
            Resolution::Execute(a) => assert_eq!(a.principal, "a1"),
            Resolution::Cancelled { .. } => panic!("approve must execute"),
        }
        assert_eq!(gate.pending("tenant-1").len(), 0);
    }

    #[test]
    fn deny_cancels_and_drains() {
        let gate = EgressGate::new();
        let id = gate.submit(action("a1", "tenant-1"));
        let res = gate
            .resolve(
                &id,
                Decision::Deny {
                    approver: "owner".into(),
                    reason: "no".into(),
                },
            )
            .unwrap();
        // Cancelled carries the deny reason through for the audit record.
        match res {
            Resolution::Cancelled { reason } => assert_eq!(reason, "no"),
            Resolution::Execute(_) => panic!("deny must cancel"),
        }
        assert_eq!(gate.pending("tenant-1").len(), 0);
    }

    #[test]
    fn unknown_pending_is_error_and_resolve_is_single_use() {
        let gate = EgressGate::new();
        let id = gate.submit(action("a1", "tenant-1"));
        gate.resolve(
            &id,
            Decision::Approve {
                approver: "owner".into(),
            },
        )
        .unwrap();
        // second resolve of the same id fails — no double-execute.
        assert!(matches!(
            gate.resolve(
                &id,
                Decision::Approve {
                    approver: "owner".into()
                }
            ),
            Err(GateError::UnknownPending)
        ));
    }

    #[test]
    fn pending_is_namespace_scoped() {
        let gate = EgressGate::new();
        gate.submit(action("a1", "tenant-1"));
        gate.submit(action("a2", "tenant-2"));
        assert_eq!(gate.pending("tenant-1").len(), 1);
        assert_eq!(gate.pending("tenant-2").len(), 1);
        assert_eq!(gate.pending_count(), 2);
    }

    fn journal_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "eam-egress-persist-{}-{name}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn held_state_survives_a_restart() {
        let path = journal_path("restart");
        let _ = std::fs::remove_file(&path);

        // First "process": submit two, resolve one.
        let id_keep = {
            let gate = PersistentEgressGate::recover(&path).unwrap();
            let id1 = gate.submit(action("a1", "tenant-1")).unwrap();
            let _id2 = gate.submit(action("a2", "tenant-1")).unwrap();
            gate.resolve(
                &id1,
                Decision::Approve {
                    approver: "owner".into(),
                },
            )
            .unwrap();
            assert_eq!(gate.pending("tenant-1").len(), 1);
            _id2
        };

        // "Restart": a fresh gate recovers from the same journal. The unresolved
        // hold is still there; the resolved one is gone.
        let gate2 = PersistentEgressGate::recover(&path).unwrap();
        let still = gate2.pending("tenant-1");
        assert_eq!(still.len(), 1, "the unresolved hold survived the restart");
        assert_eq!(still[0].id, id_keep);

        // And it is still approvable after the restart -> executes exactly once.
        let res = gate2
            .resolve(
                &id_keep,
                Decision::Approve {
                    approver: "owner".into(),
                },
            )
            .unwrap();
        assert!(matches!(res, Resolution::Execute(_)));
        assert_eq!(gate2.pending_count(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn recovered_ids_do_not_collide_after_restart() {
        let path = journal_path("nocollide");
        let _ = std::fs::remove_file(&path);
        {
            // First "process": mint egress-1 and egress-2, then drop the gate.
            let gate = PersistentEgressGate::recover(&path).unwrap();
            gate.submit(action("a1", "t1")).unwrap();
            gate.submit(action("a2", "t1")).unwrap();
        }
        // Restart: the next minted id must be egress-3, not egress-1 (no collision
        // with the recovered holds).
        let gate2 = PersistentEgressGate::recover(&path).unwrap();
        let id3 = gate2.submit(action("a3", "t1")).unwrap();
        assert_eq!(id3.0, "egress-3");
        assert_eq!(gate2.pending_count(), 3);
        let _ = std::fs::remove_file(&path);
    }

    /// A `Write` sink that succeeds for `ok_writes` records, then fails — to drive
    /// the gate's crash-safety branches a real file won't trigger on demand.
    struct FlakySink {
        ok_writes: std::cell::Cell<u32>,
    }
    impl std::io::Write for FlakySink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.ok_writes.get() == 0 {
                return Err(std::io::Error::other("injected journal write failure"));
            }
            self.ok_writes.set(self.ok_writes.get() - 1);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // `Cell<u32>` is `Send` (just not `Sync`), so `FlakySink` is `Send` automatically
    // — no `unsafe impl` needed (the crate forbids unsafe).

    fn flaky_gate(ok_writes: u32) -> PersistentEgressGate {
        let journal = journal::EgressJournal::from_sink(Box::new(FlakySink {
            ok_writes: std::cell::Cell::new(ok_writes),
        }));
        PersistentEgressGate::from_parts(EgressGate::new(), journal)
    }

    #[test]
    fn submit_rolls_back_when_the_durable_write_fails() {
        // 0 successful writes -> the `held` journal write fails.
        let gate = flaky_gate(0);
        let res = gate.submit(action("a1", "t1"));
        assert!(
            res.is_err(),
            "a non-durable hold must NOT be reported as held"
        );
        // and it is rolled back out of memory, so it can't be resolved/executed.
        assert_eq!(
            gate.pending_count(),
            0,
            "the hold is discarded to stay consistent with the failed journal"
        );
    }

    #[test]
    fn resolve_errs_without_executing_when_the_durable_write_fails() {
        // 1 successful write (the `held`), then the `resolved` write fails.
        let gate = flaky_gate(1);
        let id = gate
            .submit(action("a1", "t1"))
            .expect("held write succeeds");
        let res = gate.resolve(
            &id,
            Decision::Approve {
                approver: "owner".into(),
            },
        );
        // The caller gets an error and therefore must NOT execute the action — the
        // double-execute-prevention guarantee on a crash between remove and journal.
        assert!(
            matches!(res, Err(PersistError::Journal(_))),
            "a resolve whose durable record fails must return an error, never Execute"
        );
    }
}
