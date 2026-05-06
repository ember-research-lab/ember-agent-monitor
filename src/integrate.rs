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
}

#[derive(Debug, Clone)]
pub struct VetpkgFinding {
    pub package: String,
    pub ecosystem: String,
    pub severity: String,
    pub reason: String,
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
                Err(_) => continue,
            };
            let obj = match v {
                JsonValue::Object(o) => o,
                _ => continue,
            };
            let pkg = string_field(&obj, "package").unwrap_or_default();
            let eco = string_field(&obj, "ecosystem").unwrap_or_default();
            let sev = string_field(&obj, "severity").unwrap_or_default();
            let reason = string_field(&obj, "reason").unwrap_or_default();
            if pkg.is_empty() {
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

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    obj.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        })
}
