//! Rule-based detection layer (v0.5).
//!
//! Maps directly to design/agent-monitor-spec.md §4. Each detection rule
//! evaluates a `SessionGraph` (or a single new event in dynamic mode) and
//! emits zero or more findings.
//!
//! Detection score (spec §4): `pattern × source_trust_inverse × severity`.
//! A `you MUST` in a workspace doc is low-signal; the same in fetched
//! webpage content is high-signal. Trust-zone context is *required*, not
//! optional.

pub mod finding;
pub mod patterns;
pub mod rules;
pub mod toxic;

use crate::event::Event;
use crate::graph::SessionGraph;
use crate::trust::sensitive::SensitiveSet;
pub use finding::{Finding, FindingScope};

/// Configuration loaded once at daemon startup, governs which rules fire
/// and at what threshold. User-extensible patterns are merged from
/// `~/.ember/agent-monitor/state/user/{sensitive.txt,patterns.txt}`.
#[derive(Debug, Clone)]
pub struct DetectionConfig {
    pub sensitive: SensitiveSet,
    pub workspace_root: Option<std::path::PathBuf>,
    /// Score threshold below which findings are suppressed.
    pub min_score: f64,
    /// Spectral baseline used by `spectral_anomaly`. None disables the rule.
    pub spectral_baseline: Option<crate::spectral::Baseline>,
    /// Run spectral analysis at most every N events (cost control).
    pub spectral_cadence: usize,
    /// Anomaly score above which `spectral_anomaly` fires.
    pub spectral_threshold: f64,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            sensitive: SensitiveSet::default_set(),
            workspace_root: None,
            min_score: 0.30,
            spectral_baseline: Some(crate::spectral::Baseline::default_baseline()),
            spectral_cadence: 5,
            spectral_threshold: 0.5,
        }
    }
}

/// Run static detections that fire once at session start (or when the static
/// graph changes — e.g. an MCP server is registered mid-session).
pub fn run_static(graph: &SessionGraph, cfg: &DetectionConfig) -> Vec<Finding> {
    let mut out = Vec::new();
    rules::toxic_capability_composition(graph, &mut out);
    rules::lethal_trifecta_reachability(graph, &mut out);
    rules::high_risk_plugin_composition(graph, &mut out);
    let _ = cfg; // reserved for future static rules
    out
}

/// Run the v2 spectral analysis. Cost-bounded: only invoked when
/// `event_count % spectral_cadence == 0`. Returns spectral_anomaly +
/// motif_match findings.
pub fn run_spectral(graph: &SessionGraph, cfg: &DetectionConfig) -> Vec<Finding> {
    let mut out = Vec::new();
    rules::spectral_anomaly(graph, cfg, &mut out);
    rules::spectral_motif_match(graph, cfg, &mut out);
    out
}

/// Run dynamic detections against a single new event in the context of the
/// running session graph.
pub fn run_dynamic(event: &Event, graph: &SessionGraph, cfg: &DetectionConfig) -> Vec<Finding> {
    let mut out = Vec::new();
    rules::sensitive_zone_access(event, cfg, &mut out);
    rules::argument_injection_pattern(event, &mut out);
    rules::instruction_shape_in_tool_result(event, &mut out);
    rules::instruction_shape_in_mcp_description(event, &mut out);
    rules::trigger_cause_violation(event, graph, &mut out);
    rules::classifier_disagreement(event, graph, &mut out);
    rules::webhook_destination_arg(event, &mut out);
    rules::multimodal_in_tool_result(event, &mut out);
    rules::subagent_via_injection(event, graph, &mut out);
    out.retain(|f| f.score >= cfg.min_score);
    out
}

/// Convenience: run all detections over a complete event log. Used by the
/// `replay` command and the regression-test harness.
pub fn run_all(events: &[Event], cfg: &DetectionConfig) -> Vec<Finding> {
    let mut graph = SessionGraph::default();
    let mut findings = Vec::new();
    for ev in events {
        graph.ingest(ev.clone());
    }
    findings.extend(run_static(&graph, cfg));
    let mut running = SessionGraph::default();
    for ev in events {
        running.ingest(ev.clone());
        findings.extend(run_dynamic(ev, &running, cfg));
    }
    // Spectral runs once over the final graph in offline mode. Online mode
    // would call run_spectral periodically; see proxy.rs.
    findings.extend(run_spectral(&graph, cfg));
    findings
}
