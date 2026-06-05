//! Egress-bypass detection (integration seam #4).
//!
//! Reconciles egress **observed on the wire** (what `ember-network`, the passive
//! wire observer, reports) against the gate's **approval record**. An outbound that
//! reached an external system whose correlation token was never approved through the
//! gate **bypassed the moat** — a HIGH `egress_bypass` [`Finding`].
//!
//! Scope (per `agent-monitor-spec.md` §1/§7, and this repo's CLAUDE.md): this crate
//! owns the gate's approval state and the `Finding`; the wire observation is an
//! INPUT produced by `ember-network` — this tool is *not* a network tool and does
//! not itself watch the wire. The reconciliation and the verdict live here; the
//! observation source does not.

use std::collections::HashSet;

use super::EgressKind;
use crate::detect::{Finding, FindingScope};
use crate::types::Severity;

/// A side-effecting egress observed crossing the wire — the input `ember-network`
/// provides. `correlation` is the token the consumer stamps on the real outbound so
/// a wire observation can be matched to a gate approval (the approved action's
/// `payload_ref`).
#[derive(Clone, Debug)]
pub struct ObservedEgress {
    pub principal: String,
    pub namespace: String,
    pub kind: EgressKind,
    pub destination: String,
    pub correlation: String,
}

/// Reconcile an observed wire egress against the gate's `approved` correlation-token
/// set (e.g. [`journal::recover`](super::journal::recover)`(..).approved` collected
/// into a set). Returns a HIGH `egress_bypass` [`Finding`] when the egress was **not**
/// approved through the gate — its token is absent — and `None` when it was approved
/// (legitimate egress).
pub fn detect_bypass(
    observed: &ObservedEgress,
    approved: &HashSet<String>,
    session_id: &str,
) -> Option<Finding> {
    if approved.contains(&observed.correlation) {
        return None; // approved through the gate — legitimate egress
    }
    let rationale = format!(
        "outfacing {} egress to {} reached the wire with no prior gate approval \
         (correlation {:?}, principal {:?}, namespace {:?}) — moat bypass",
        observed.kind.token(),
        observed.destination,
        observed.correlation,
        observed.principal,
        observed.namespace,
    );
    Some(Finding {
        finding_type: "egress_bypass".into(),
        scope: FindingScope::Dynamic,
        severity: Severity::High,
        session_id: session_id.to_string(),
        event_id: None,
        tool: Some(observed.kind.token()),
        argument: Some(observed.destination.clone()),
        matched_value: Some(observed.correlation.clone()),
        pattern: None,
        trust_zone: None,
        rationale,
        score: 0.9,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(correlation: &str) -> ObservedEgress {
        ObservedEgress {
            principal: "a1".into(),
            namespace: "tenant-1".into(),
            kind: EgressKind::Smtp,
            destination: "smtp://mail.example.test".into(),
            correlation: correlation.into(),
        }
    }

    #[test]
    fn unapproved_egress_is_a_high_bypass_finding() {
        let approved: HashSet<String> = ["draft-approved".into()].into_iter().collect();
        // Observed token wasn't approved -> bypass.
        let f = detect_bypass(&observed("draft-smuggled"), &approved, "sess-1")
            .expect("an unapproved egress must produce a finding");
        assert_eq!(f.finding_type, "egress_bypass");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.scope, FindingScope::Dynamic);
        assert_eq!(f.matched_value.as_deref(), Some("draft-smuggled"));
        assert_eq!(f.session_id, "sess-1");
    }

    #[test]
    fn approved_egress_produces_no_finding() {
        let approved: HashSet<String> = ["draft-approved".into()].into_iter().collect();
        assert!(
            detect_bypass(&observed("draft-approved"), &approved, "sess-1").is_none(),
            "egress that matches a gate approval is legitimate — no finding"
        );
    }

    #[test]
    fn empty_approval_set_flags_any_egress() {
        // Nothing approved (or the gate journal is empty) -> every observed egress
        // is a bypass. The safe default: unrecognized egress is suspicious.
        let approved = HashSet::new();
        assert!(detect_bypass(&observed("anything"), &approved, "s").is_some());
    }

    #[test]
    fn finding_serializes_through_the_json_writer() {
        let approved = HashSet::new();
        let f = detect_bypass(&observed("tok"), &approved, "s").unwrap();
        let line = f.to_jsonl();
        assert!(line.contains("\"type\":\"egress_bypass\""));
        assert!(line.contains("\"severity\":\"high\""));
        assert!(line.ends_with('\n'));
    }
}
