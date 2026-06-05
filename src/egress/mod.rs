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
//! This module is the **state machine**: submit → held → resolve(approve|deny) →
//! execute|cancel, plus the pending queue the approval surfaces render. The
//! *suspension* of the real outbound call (the proxy holding a connection, or a
//! dispatcher awaiting) and **durable** persistence of held state across restart
//! are integration seams in `net::proxy` / `store`. The gate keeps held state in
//! memory here; the proxy is expected to persist it for resume-after-restart.
//!
//! [`InterventionMode`]: crate::types::InterventionMode

use std::collections::VecDeque;
use std::sync::Mutex;

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
}
