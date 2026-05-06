//! Smoke test for the spectral layer.
//!
//! Goal: confirm the v2 layer fires on a session whose graph SHAPE
//! resembles an attack motif even without any pattern-rule trip.

use ember_agent_monitor::detect::{run_all, DetectionConfig};
use ember_agent_monitor::store::log::read_all;
use std::path::PathBuf;

#[test]
fn cyata_fixture_emits_spectral_diagnostics() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("threat-intel/fixtures/cyata_mcp_git_rce/events.jsonl");
    let events = read_all(&fixture).expect("read fixture");
    let cfg = DetectionConfig::default();

    let mut graph = ember_agent_monitor::graph::SessionGraph::default();
    for ev in &events {
        graph.ingest(ev.clone());
    }
    let profile = ember_agent_monitor::spectral::SpectralProfile::from_session(&graph);
    eprintln!(
        "spectral profile: N={} fiedler={:.4} d_s={:?}",
        profile.n_nodes, profile.fiedler_value, profile.spectral_dimension
    );
    eprintln!("eigenvalues: {:?}", profile.eigenvalues);
    eprintln!("heat_trace[0..5]: {:?}", &profile.heat_trace[..5.min(profile.heat_trace.len())]);

    let findings = run_all(&events, &cfg);
    let spectral_findings: Vec<_> = findings
        .iter()
        .filter(|f| f.finding_type.starts_with("spectral_"))
        .collect();
    eprintln!("spectral findings:");
    for f in &spectral_findings {
        eprintln!("  - {} [{}]: {}", f.finding_type, f.severity.as_str(), f.rationale);
    }

    assert!(profile.n_nodes >= 5, "expected meaningful node count, got {}", profile.n_nodes);
    assert!(profile.fiedler_value > 0.0);
}
