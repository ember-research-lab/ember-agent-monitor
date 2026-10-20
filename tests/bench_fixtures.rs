//! bench_fixtures — offline check of the benchmark converters' committed
//! 3-case fixtures (#42). Verifies shape and the event build; detection
//! quality is measured by the ignored `bench_full` test, not asserted here.

mod bench_support;

use bench_support::{build_events, is_design, parse_cases};
use ember_agent_monitor::types::{EventKind, TrustZone};
use std::path::PathBuf;

const BENCHES: &[&str] = &["injecagent", "agentdojo", "bipia", "opi", "asb", "llmail"];

#[test]
fn every_fixture_has_three_cases_and_builds_the_expected_events() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bench/fixtures");
    for b in BENCHES {
        let p = dir.join(format!("{b}.cases.jsonl"));
        let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        let cases = bench_support::parse_cases(&text).unwrap_or_else(|e| panic!("{b}: {e}"));
        assert_eq!(cases.len(), 3, "{b}: fixture must hold exactly 3 cases");
        assert!(cases.iter().any(|c| c.attack), "{b}: no attack case");
        for c in &cases {
            assert_eq!(c.bench, *b);
            assert!(!c.content.is_empty(), "{b}/{}: empty content", c.id);
            let evs = build_events(c, true);
            assert_eq!(evs.len(), 3 + c.attacker_tools.len());
            assert_eq!(evs[2].kind, EventKind::ToolResult);
            assert_eq!(evs[2].trust_zone, TrustZone::UntrustedToolOutput);
        }
    }
}

#[test]
fn split_is_deterministic_and_roughly_seventy_thirty() {
    assert_eq!(is_design("some group"), is_design("some group"));
    let n = (0..2000).filter(|i| is_design(&format!("g{i}"))).count();
    assert!((1300..=1500).contains(&n), "design share {n}/2000");
    assert!(parse_cases("").unwrap().is_empty());
}
