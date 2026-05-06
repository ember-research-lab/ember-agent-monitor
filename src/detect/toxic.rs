//! Toxic capability combinations.
//!
//! Spec §3 ("Capability composition"): operates on the lattice (the union
//! of capabilities across all registered tools), *not* on server topology.
//! Repackaging tools across MCP servers cannot evade these checks.

use crate::types::{Capability, Severity};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct ToxicCombination {
    pub name: &'static str,
    pub required: &'static [Capability],
    pub rationale: &'static str,
    pub severity: Severity,
}

pub fn known_combinations() -> &'static [ToxicCombination] {
    use Capability::*;
    use Severity::*;
    &[
        ToxicCombination {
            name: "git_init + filesystem_write = arbitrary_code_execution",
            required: &[RepoInit, FileWrite],
            rationale:
                "git init in arbitrary path + write to .git/config = shell exec via git filters \
                 (Cyata 2026 RCE chain)",
            severity: High,
        },
        ToxicCombination {
            name: "credential_access + network_out = exfil_primitive",
            required: &[CredentialAccess, NetworkOut],
            rationale:
                "Tool can both read credentials and make outbound network calls — \
                 single-step exfiltration is reachable",
            severity: High,
        },
        ToxicCombination {
            name: "file_read_sensitive + network_out = exfil_via_sensitive_zone",
            required: &[FileRead, NetworkOut],
            rationale:
                "Network egress in a session that can also read sensitive paths → \
                 credential exfiltration primitive (gated by sensitive_zone_access)",
            severity: Severity::Medium,
        },
    ]
}

pub fn check(caps: &BTreeSet<Capability>) -> Vec<&'static ToxicCombination> {
    let mut out = Vec::new();
    for tc in known_combinations() {
        if tc.required.iter().all(|c| caps.contains(c)) {
            out.push(tc);
        }
    }
    out
}
