//! Durable held-state journal for the egress gate (integration seam #2).
//!
//! The [`EgressGate`](super::EgressGate) keeps held actions in memory; that does
//! not survive a restart, but an approval can arrive **hours** after a `submit`.
//! This append-only JSONL journal records every `held` and `resolved` transition
//! so the live held set — and the id high-water mark — can be **recovered** after
//! a restart, keyed by [`PendingId`](super::PendingId).
//!
//! Same on-disk posture as [`crate::store::log`]: one `write_all` + `flush` per
//! record (an interrupted process leaves a complete or empty trailing line, never a
//! half-record), zero deps, every record serialized through [`crate::json`] — never
//! `format!`. The journal is *not* the audit ledger (seam #3, hash-chained, in the
//! consumer): it carries only what held-state recovery needs.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use super::{Decision, EgressKind, HeldAction, OutfacingAction, PendingId};
use crate::json::{parse, to_json_string, JsonValue};

/// The recovered state: the actions still held (in submit order), the highest id
/// counter seen (so new ids continue past it), and the **approved correlation
/// tokens** — the `payload_ref`s of actions that were resolved with `Approve`. The
/// last feeds the egress-bypass detector ([`super::bypass`]): a wire egress whose
/// token is absent from this set was never approved through the gate.
#[derive(Debug, Default)]
pub struct Recovered {
    pub held: Vec<HeldAction>,
    pub counter: u64,
    pub approved: Vec<String>,
}

impl Recovered {
    /// The approved correlation tokens as a set — the exact input the egress-bypass detector
    /// reconciles wire egress against ([`super::bypass::reconcile`]).
    pub fn approved_set(&self) -> std::collections::HashSet<String> {
        self.approved.iter().cloned().collect()
    }
}

/// Append-only journal writer.
pub struct EgressJournal {
    /// The append target. Boxed `dyn Write` (not a bare `File`) so the durable write
    /// path is the same in production and under test — a test can inject a sink that
    /// fails, exercising the crash-safety branches (`submit` rollback, `resolve`
    /// error-without-execute) that a real file never triggers on demand.
    sink: Box<dyn Write + Send>,
}

impl EgressJournal {
    /// Open (creating + parents as needed) for append.
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("open {path:?}: {e}"))?;
        Ok(Self {
            sink: Box::new(file),
        })
    }

    /// Build a journal over an arbitrary sink — used by tests to inject write
    /// failures and verify the gate's crash-safety handling.
    #[cfg(test)]
    pub fn from_sink(sink: Box<dyn Write + Send>) -> Self {
        Self { sink }
    }

    /// Record that `action` is now held under `id`.
    pub fn append_held(&mut self, id: &PendingId, action: &OutfacingAction) -> Result<(), String> {
        let rec = JsonValue::Object(vec![
            ("event".into(), JsonValue::Str("held".into())),
            ("id".into(), JsonValue::Str(id.0.clone())),
            ("principal".into(), JsonValue::Str(action.principal.clone())),
            ("namespace".into(), JsonValue::Str(action.namespace.clone())),
            ("kind".into(), JsonValue::Str(action.kind.token())),
            ("summary".into(), JsonValue::Str(action.summary.clone())),
            (
                "payload_ref".into(),
                JsonValue::Str(action.payload_ref.clone()),
            ),
        ]);
        self.write_line(&rec)
    }

    /// Record that the action under `id` was resolved (no longer held).
    pub fn append_resolved(&mut self, id: &PendingId, decision: &Decision) -> Result<(), String> {
        let mut fields = vec![
            ("event".into(), JsonValue::Str("resolved".into())),
            ("id".into(), JsonValue::Str(id.0.clone())),
        ];
        match decision {
            Decision::Approve { approver } => {
                fields.push(("decision".into(), JsonValue::Str("approve".into())));
                fields.push(("approver".into(), JsonValue::Str(approver.clone())));
            }
            Decision::Deny { approver, reason } => {
                fields.push(("decision".into(), JsonValue::Str("deny".into())));
                fields.push(("approver".into(), JsonValue::Str(approver.clone())));
                fields.push(("reason".into(), JsonValue::Str(reason.clone())));
            }
        }
        self.write_line(&JsonValue::Object(fields))
    }

    fn write_line(&mut self, rec: &JsonValue) -> Result<(), String> {
        let mut line = to_json_string(rec);
        line.push('\n');
        self.sink
            .write_all(line.as_bytes())
            .map_err(|e| format!("write egress journal: {e}"))?;
        self.sink
            .flush()
            .map_err(|e| format!("flush egress journal: {e}"))
    }
}

/// Replay the journal at `path` and reconstruct the live held set + id high-water
/// mark. A missing file is an empty (fresh) journal. A malformed line is an error
/// (fail loud — a corrupt durable record must not silently drop held actions).
pub fn recover(path: &Path) -> Result<Recovered, String> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Recovered::default()),
        Err(e) => return Err(format!("open {path:?}: {e}")),
    };

    // Preserve submit order; remove on resolve. Linear scan keeps it dependency-free
    // and the held set is small (the human approval queue).
    let mut held: Vec<HeldAction> = Vec::new();
    let mut counter: u64 = 0;
    let mut approved: Vec<String> = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("read egress journal line {i}: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let v = parse(&line).map_err(|e| format!("parse egress journal line {i}: {e:?}"))?;
        let event = field(&v, "event").ok_or_else(|| format!("line {i}: missing `event`"))?;
        let id = field(&v, "id").ok_or_else(|| format!("line {i}: missing `id`"))?;
        counter = counter.max(id_counter(id));
        match event {
            "held" => {
                let action = OutfacingAction {
                    principal: field(&v, "principal").unwrap_or("").to_string(),
                    namespace: field(&v, "namespace").unwrap_or("").to_string(),
                    kind: EgressKind::from_token(field(&v, "kind").unwrap_or("")),
                    summary: field(&v, "summary").unwrap_or("").to_string(),
                    payload_ref: field(&v, "payload_ref").unwrap_or("").to_string(),
                };
                held.push(HeldAction {
                    id: PendingId(id.to_string()),
                    action,
                });
            }
            "resolved" => {
                // On approve, the action's correlation token (its payload_ref, read
                // from the matching `held` record still in scope) joins the approved
                // set — what the bypass detector reconciles wire egress against.
                if field(&v, "decision") == Some("approve") {
                    if let Some(h) = held.iter().find(|h| h.id.0 == id) {
                        approved.push(h.action.payload_ref.clone());
                    }
                }
                held.retain(|h| h.id.0 != id);
            }
            other => return Err(format!("line {i}: unknown event `{other}`")),
        }
    }
    Ok(Recovered {
        held,
        counter,
        approved,
    })
}

fn field<'a>(v: &'a JsonValue, key: &str) -> Option<&'a str> {
    v.get(key).and_then(JsonValue::as_str)
}

/// Extract the numeric high-water value from an `egress-<n>` id; 0 if it doesn't
/// match (a custom id scheme just won't advance the builtin counter).
fn id_counter(id: &str) -> u64 {
    id.rsplit_once('-')
        .and_then(|(_, n)| n.parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "eam-egress-journal-{}-{name}.jsonl",
            std::process::id()
        ))
    }

    fn action(principal: &str, namespace: &str, kind: EgressKind) -> OutfacingAction {
        OutfacingAction {
            principal: principal.into(),
            namespace: namespace.into(),
            kind,
            summary: "send the quote".into(),
            payload_ref: "draft-1".into(),
        }
    }

    #[test]
    fn recover_replays_held_minus_resolved() {
        let path = tmp("replay");
        let _ = std::fs::remove_file(&path);
        {
            let mut j = EgressJournal::open(&path).unwrap();
            j.append_held(
                &PendingId("egress-1".into()),
                &action("a1", "t1", EgressKind::Smtp),
            )
            .unwrap();
            j.append_held(
                &PendingId("egress-2".into()),
                &action("a2", "t1", EgressKind::Other("instagram.post".into())),
            )
            .unwrap();
            // resolve the first -> only egress-2 remains held.
            j.append_resolved(
                &PendingId("egress-1".into()),
                &Decision::Approve {
                    approver: "owner".into(),
                },
            )
            .unwrap();
        }
        let r = recover(&path).unwrap();
        assert_eq!(r.held.len(), 1, "held minus resolved");
        assert_eq!(r.held[0].id.0, "egress-2");
        // Other(..) kind round-trips through the token.
        assert_eq!(
            r.held[0].action.kind,
            EgressKind::Other("instagram.post".into())
        );
        // counter is the high-water mark so new ids continue past egress-2.
        assert_eq!(r.counter, 2);
        // egress-1 was APPROVED -> its correlation token (payload_ref) is in the
        // approved set the bypass detector reconciles against.
        assert_eq!(r.approved, vec!["draft-1".to_string()]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_journal_is_empty_not_an_error() {
        let path = tmp("absent");
        let _ = std::fs::remove_file(&path);
        let r = recover(&path).unwrap();
        assert!(r.held.is_empty());
        assert_eq!(r.counter, 0);
    }

    #[test]
    fn malformed_line_is_an_error() {
        let path = tmp("corrupt");
        std::fs::write(&path, "{not json}\n").unwrap();
        assert!(recover(&path).is_err(), "a corrupt record must fail loud");
        let _ = std::fs::remove_file(&path);
    }
}
