//! Integration with sibling tools — read-only consumers per spec §6.
//!
//! Loose-coupling discipline: each tool has its own data model and
//! substrate. We read their published artifacts (file paths under
//! ~/.ember/<tool>/) but never link to their crates and never share state.

use crate::json::{parse, JsonValue};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// vetpkg findings (`~/.ember/vetpkg/findings.jsonl`). Each line is one
/// install-time finding. Sessions whose declared dependencies overlap with
/// flagged packages get elevated detection sensitivity.
#[derive(Debug, Clone, Default)]
pub struct VetpkgFindings {
    pub by_package: HashMap<String, Vec<VetpkgFinding>>,
    /// Lines that were not a JSON object with a `package` (counted, not
    /// skipped silently).
    pub unreadable_lines: usize,
}

#[derive(Debug, Clone)]
pub struct VetpkgFinding {
    pub package: String,
    pub ecosystem: String,
    pub severity: String,
    pub reason: String,
    pub version: String,
}

impl VetpkgFinding {
    /// Verdict::Warn is written as "medium", Block as "high": WARN-or-higher
    /// is medium and up.
    pub fn is_warn_or_higher(&self) -> bool {
        matches!(self.severity.as_str(), "medium" | "high" | "critical")
    }
}

impl VetpkgFindings {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn load(home: &Path) -> Self {
        let path = home.join(".ember/vetpkg/findings.jsonl");
        Self::load_from(&path)
    }

    pub fn load_from(path: &PathBuf) -> Self {
        let mut out = Self::default();
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return out, // no vetpkg findings yet — fine
        };
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let v = match parse(line) {
                Ok(v) => v,
                Err(_) => {
                    out.unreadable_lines += 1;
                    continue;
                }
            };
            let obj = match v {
                JsonValue::Object(o) => o,
                _ => {
                    out.unreadable_lines += 1;
                    continue;
                }
            };
            let pkg = string_field(&obj, "package").unwrap_or_default();
            let eco = string_field(&obj, "ecosystem").unwrap_or_default();
            let sev = string_field(&obj, "severity").unwrap_or_default();
            let reason = string_field(&obj, "reason").unwrap_or_default();
            if pkg.is_empty() {
                out.unreadable_lines += 1;
                continue;
            }
            out.by_package
                .entry(pkg.clone())
                .or_default()
                .push(VetpkgFinding {
                    package: pkg,
                    ecosystem: eco,
                    severity: sev,
                    reason,
                    version: string_field(&obj, "version").unwrap_or_default(),
                });
        }
        out
    }

    pub fn has_high_risk_for(&self, pkg: &str) -> bool {
        self.by_package
            .get(pkg)
            .map(|v| {
                v.iter()
                    .any(|f| matches!(f.severity.as_str(), "high" | "critical"))
            })
            .unwrap_or(false)
    }
}

/// Schema version of ember-persistent `findings.jsonl` this reader understands.
pub const PERSISTENT_FINDINGS_SCHEMA: u64 = 2;

/// One ember-persistent finding (schema v2: `schema_version, type, severity,
/// workspace, session_id, source_session, unit_hash, agent_id, event_id,
/// rationale, ts_ms`). Only the fields posture needs are kept.
#[derive(Debug, Clone)]
pub struct PersistentFinding {
    pub finding_type: String,
    pub severity: String,
    pub workspace: String,
    pub session_id: String,
    pub rationale: String,
}

/// `~/.ember/persistent/findings.jsonl`, advisory only. Lines with a missing
/// or unknown `schema_version` are refused (counted in `refused_schema`, with
/// the offending versions) rather than guessed at; other unparseable lines
/// are counted in `unreadable_lines`.
#[derive(Debug, Clone, Default)]
pub struct PersistentFindings {
    pub findings: Vec<PersistentFinding>,
    pub unreadable_lines: usize,
    pub refused_schema: usize,
    /// Distinct refused versions, as written ("missing" when absent).
    pub refused_versions: Vec<String>,
}

impl PersistentFindings {
    pub fn load_from(path: &Path) -> Self {
        let mut out = Self::default();
        let Ok(content) = std::fs::read_to_string(path) else {
            return out;
        };
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(JsonValue::Object(obj)) = parse(line) else {
                out.unreadable_lines += 1;
                continue;
            };
            let version = match obj.iter().find(|(k, _)| k == "schema_version") {
                Some((_, JsonValue::Number(n))) => Some(*n),
                _ => None,
            };
            if version != Some(PERSISTENT_FINDINGS_SCHEMA as f64) {
                out.refused_schema += 1;
                let shown = version
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "missing".into());
                if !out.refused_versions.contains(&shown) {
                    out.refused_versions.push(shown);
                }
                continue;
            }
            let (Some(t), Some(sev), Some(ws)) = (
                string_field(&obj, "type"),
                string_field(&obj, "severity"),
                string_field(&obj, "workspace"),
            ) else {
                out.unreadable_lines += 1;
                continue;
            };
            out.findings.push(PersistentFinding {
                finding_type: t,
                severity: sev,
                workspace: ws,
                session_id: string_field(&obj, "session_id").unwrap_or_default(),
                rationale: string_field(&obj, "rationale").unwrap_or_default(),
            });
        }
        out
    }
}

/// One ember-network finding. Its `findings.jsonl` uses the monitor's own
/// finding shape (`type, scope, severity, session_id, ..., rationale, score`,
/// ember-network `docs/wire-contract.md`); `session_id` is `""` when the
/// connection could not be attributed to a session.
#[derive(Debug, Clone)]
pub struct NetworkFinding {
    pub finding_type: String,
    pub severity: String,
    pub session_id: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkFindings {
    pub findings: Vec<NetworkFinding>,
    pub unreadable_lines: usize,
}

impl NetworkFindings {
    pub fn load_from(path: &Path) -> Self {
        let mut out = Self::default();
        let Ok(content) = std::fs::read_to_string(path) else {
            return out;
        };
        for line in content.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(JsonValue::Object(obj)) = parse(line) else {
                out.unreadable_lines += 1;
                continue;
            };
            let (Some(t), Some(sev), Some(sid)) = (
                string_field(&obj, "type"),
                string_field(&obj, "severity"),
                string_field(&obj, "session_id"),
            ) else {
                out.unreadable_lines += 1;
                continue;
            };
            out.findings.push(NetworkFinding {
                finding_type: t,
                severity: sev,
                session_id: sid,
                rationale: string_field(&obj, "rationale").unwrap_or_default(),
            });
        }
        out
    }
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    obj.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        })
}
