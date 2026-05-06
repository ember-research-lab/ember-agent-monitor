//! Session summary writer — produces `<sid>.summary.json`.
//!
//! Contract: see `docs/session-graph-contract.md`. v1 schema, written
//! exactly once at session end via tempfile + atomic rename.

use crate::detect::Finding;
use crate::graph::SessionGraph;
use crate::json::{to_json_string, JsonValue};
use crate::types::{EventKind, FidelityStatus};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const SUMMARY_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub session_id: String,
    pub started_ms: u64,
    pub ended_ms: u64,
    pub model: Option<String>,
    pub cwd: Option<String>,
    pub git_branch: Option<String>,
    pub fidelity_status: FidelityStatus,
    pub event_log_path: PathBuf,
    pub event_count: usize,
    pub kind_counts: BTreeMap<String, usize>,
    pub capability_set: Vec<String>,
    pub mcp_servers: Vec<String>,
    pub skills_loaded: Vec<String>,
    pub hooks_registered_count: usize,
    pub plugins_installed: Vec<String>,
    pub findings_count: usize,
    pub findings_by_type: BTreeMap<String, usize>,
    pub findings_by_severity: BTreeMap<String, usize>,
    pub highest_severity: Option<String>,
    pub spectral_summary: Option<SpectralSummary>,
    pub vetpkg_packages_seen: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SpectralSummary {
    pub n_nodes: usize,
    pub fiedler_value: f64,
    pub spectral_dimension: Option<f64>,
    pub anomaly_score: f64,
    pub motif_matches: Vec<String>,
}

impl SessionSummary {
    pub fn build(
        session_id: &str,
        graph: &SessionGraph,
        findings: &[Finding],
        fidelity: FidelityStatus,
        event_log_path: &Path,
    ) -> Self {
        let mut kind_counts: BTreeMap<String, usize> = BTreeMap::new();
        let started_ms = graph
            .dynamic_graph
            .events
            .first()
            .map(|e| e.timestamp_ms)
            .unwrap_or(0);
        let ended_ms = graph
            .dynamic_graph
            .events
            .last()
            .map(|e| e.timestamp_ms)
            .unwrap_or(started_ms);
        for ev in &graph.dynamic_graph.events {
            *kind_counts.entry(ev.kind.as_str().into()).or_insert(0) += 1;
        }

        let mut findings_by_type: BTreeMap<String, usize> = BTreeMap::new();
        let mut findings_by_severity: BTreeMap<String, usize> = BTreeMap::new();
        let mut highest_severity = None;
        for f in findings {
            *findings_by_type.entry(f.finding_type.clone()).or_insert(0) += 1;
            *findings_by_severity
                .entry(f.severity.as_str().into())
                .or_insert(0) += 1;
            highest_severity = match highest_severity {
                None => Some(f.severity),
                Some(prev) if f.severity > prev => Some(f.severity),
                other => other,
            };
        }

        // Lift session_start metadata if present.
        let mut model: Option<String> = None;
        let mut cwd: Option<String> = None;
        let mut git_branch: Option<String> = None;
        if let Some(ev) = graph
            .dynamic_graph
            .events
            .iter()
            .find(|e| e.kind == EventKind::SessionStart)
        {
            model = string_body(ev, "model");
            cwd = string_body(ev, "cwd");
            git_branch = string_body(ev, "git_branch");
        }

        Self {
            session_id: session_id.to_string(),
            started_ms,
            ended_ms,
            model,
            cwd,
            git_branch,
            fidelity_status: fidelity,
            event_log_path: event_log_path.to_path_buf(),
            event_count: graph.dynamic_graph.events.len(),
            kind_counts,
            capability_set: graph.static_graph.capabilities.iter().cloned().collect(),
            mcp_servers: graph.static_graph.mcp_servers.keys().cloned().collect(),
            skills_loaded: graph.static_graph.skills.iter().cloned().collect(),
            hooks_registered_count: graph.static_graph.hooks.values().map(|v| v.len()).sum(),
            plugins_installed: graph.static_graph.plugins.iter().cloned().collect(),
            findings_count: findings.len(),
            findings_by_type,
            findings_by_severity,
            highest_severity: highest_severity.map(|s| s.as_str().into()),
            spectral_summary: None,
            vetpkg_packages_seen: Vec::new(),
        }
    }

    pub fn with_spectral(mut self, summary: SpectralSummary) -> Self {
        self.spectral_summary = Some(summary);
        self
    }

    pub fn with_vetpkg_packages(mut self, packages: Vec<String>) -> Self {
        self.vetpkg_packages_seen = packages;
        self
    }

    pub fn to_json(&self) -> JsonValue {
        let mut o: Vec<(String, JsonValue)> = Vec::new();
        o.push((
            "schema_version".into(),
            JsonValue::Number(SUMMARY_SCHEMA_VERSION as f64),
        ));
        o.push(("session_id".into(), JsonValue::Str(self.session_id.clone())));
        o.push((
            "started_ms".into(),
            JsonValue::Number(self.started_ms as f64),
        ));
        o.push(("ended_ms".into(), JsonValue::Number(self.ended_ms as f64)));
        if let Some(m) = &self.model {
            o.push(("model".into(), JsonValue::Str(m.clone())));
        }
        if let Some(c) = &self.cwd {
            o.push(("cwd".into(), JsonValue::Str(c.clone())));
        }
        if let Some(g) = &self.git_branch {
            o.push(("git_branch".into(), JsonValue::Str(g.clone())));
        }
        o.push((
            "fidelity_status".into(),
            JsonValue::Str(self.fidelity_status.as_str().into()),
        ));
        o.push((
            "event_log_path".into(),
            JsonValue::Str(self.event_log_path.display().to_string()),
        ));
        o.push((
            "event_count".into(),
            JsonValue::Number(self.event_count as f64),
        ));
        o.push((
            "kind_counts".into(),
            JsonValue::Object(
                self.kind_counts
                    .iter()
                    .map(|(k, v)| (k.clone(), JsonValue::Number(*v as f64)))
                    .collect(),
            ),
        ));
        o.push((
            "capability_set".into(),
            JsonValue::Array(
                self.capability_set
                    .iter()
                    .map(|s| JsonValue::Str(s.clone()))
                    .collect(),
            ),
        ));
        o.push((
            "mcp_servers".into(),
            JsonValue::Array(
                self.mcp_servers
                    .iter()
                    .map(|s| JsonValue::Str(s.clone()))
                    .collect(),
            ),
        ));
        o.push((
            "skills_loaded".into(),
            JsonValue::Array(
                self.skills_loaded
                    .iter()
                    .map(|s| JsonValue::Str(s.clone()))
                    .collect(),
            ),
        ));
        o.push((
            "hooks_registered_count".into(),
            JsonValue::Number(self.hooks_registered_count as f64),
        ));
        o.push((
            "plugins_installed".into(),
            JsonValue::Array(
                self.plugins_installed
                    .iter()
                    .map(|s| JsonValue::Str(s.clone()))
                    .collect(),
            ),
        ));
        o.push((
            "findings_count".into(),
            JsonValue::Number(self.findings_count as f64),
        ));
        o.push((
            "findings_by_type".into(),
            JsonValue::Object(
                self.findings_by_type
                    .iter()
                    .map(|(k, v)| (k.clone(), JsonValue::Number(*v as f64)))
                    .collect(),
            ),
        ));
        o.push((
            "findings_by_severity".into(),
            JsonValue::Object(
                self.findings_by_severity
                    .iter()
                    .map(|(k, v)| (k.clone(), JsonValue::Number(*v as f64)))
                    .collect(),
            ),
        ));
        if let Some(h) = &self.highest_severity {
            o.push(("highest_severity".into(), JsonValue::Str(h.clone())));
        }
        if let Some(s) = &self.spectral_summary {
            let mut sp: Vec<(String, JsonValue)> = Vec::new();
            sp.push(("n_nodes".into(), JsonValue::Number(s.n_nodes as f64)));
            sp.push(("fiedler_value".into(), JsonValue::Number(s.fiedler_value)));
            if let Some(d) = s.spectral_dimension {
                sp.push(("spectral_dimension".into(), JsonValue::Number(d)));
            }
            sp.push(("anomaly_score".into(), JsonValue::Number(s.anomaly_score)));
            sp.push((
                "motif_matches".into(),
                JsonValue::Array(
                    s.motif_matches
                        .iter()
                        .map(|m| JsonValue::Str(m.clone()))
                        .collect(),
                ),
            ));
            o.push(("spectral_summary".into(), JsonValue::Object(sp)));
        }
        if !self.vetpkg_packages_seen.is_empty() {
            o.push((
                "vetpkg_packages_seen".into(),
                JsonValue::Array(
                    self.vetpkg_packages_seen
                        .iter()
                        .map(|s| JsonValue::Str(s.clone()))
                        .collect(),
                ),
            ));
        }
        JsonValue::Object(o)
    }

    /// Atomic write: tempfile + rename.
    pub fn save(&self, dest: &Path) -> Result<(), String> {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
        }
        let tmp = dest.with_extension("json.tmp");
        std::fs::write(&tmp, to_json_string(&self.to_json()))
            .map_err(|e| format!("write tmp: {e}"))?;
        std::fs::rename(&tmp, dest).map_err(|e| format!("rename: {e}"))?;
        Ok(())
    }
}

fn string_body(ev: &crate::event::Event, key: &str) -> Option<String> {
    ev.body.get(key).and_then(|v| match v {
        JsonValue::Str(s) => Some(s.clone()),
        _ => None,
    })
}
