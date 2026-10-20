//! benign_budget — per-rule benign false-positive budget (#45 class guard).
//!
//! Replays `~/.claude/projects/**` (real driver transcripts, the benign
//! proxy) plus the repo's benign fixtures through the dynamic detectors and
//! prints each rule's benign FP per 1000 events. The pinned budgets below
//! fail the test when exceeded: a rule may not ship HIGH with a benign rate
//! above its budget.
//!
//! `#[ignore]`d (reads the maintainer's home directory):
//!
//! ```text
//! cargo test --release --test benign_budget -- --ignored --nocapture
//! ```

mod bench_support;

use bench_support::benign_replay;
use ember_agent_monitor::detect::DetectionConfig;
use std::collections::BTreeMap;

/// Pinned benign FP ceiling per rule, findings per 1000 events (all
/// severities), measured 2026-10-20 on ~133k events with ~10% headroom for
/// corpus drift (the corpus grows every session). A rule absent from this
/// table gets `DEFAULT_BUDGET`, so a new rule cannot ship noisy by omission.
/// Lower a number when a rule improves; raising one needs a justification in
/// the PR and a tracking issue.
///
/// Known debt, pinned at the measured level (not a target): `sensitive_zone_access`
/// (the `.claude` path component covers the driver's own config home) and
/// `multimodal_in_tool_result`.
const BUDGETS: &[(&str, f64)] = &[
    ("argument_injection_pattern", 10.0), // RCA bar <= 10/1000; measured 8.82
    ("sensitive_zone_access", 51.0),      // measured 46.27, debt
    ("multimodal_in_tool_result", 9.3),   // measured 8.38, debt
    ("instruction_directive_in_tool_result", 5.0),
    ("invisible_unicode_in_tool_result", 1.7),
    ("instruction_shape_in_tool_result", 1.5),
    ("memory_write_by_subagent", 0.35),
    ("sandbox_escape_pattern", 0.35),
    ("agent_as_intermediary_clickfix", 0.1),
    ("api_base_url_redirect", 0.1),
    ("webhook_destination_arg", 0.05),
];
const DEFAULT_BUDGET: f64 = 1.0;

/// `argument_injection_pattern` shapes that must be zero on the benign
/// corpus (#45): shell chain / `$(..)` in a shell tool, and backtick spans in
/// prose tools. Matched against the `type | sev | tool | pattern` detail key.
fn must_be_zero(key: &str) -> bool {
    let f: Vec<&str> = key.split(" | ").collect();
    if f.len() != 4 || f[0] != "argument_injection_pattern" {
        return false;
    }
    let shape = f[3].contains("command chain") || f[3].contains("command substitution");
    let shell = matches!(f[2].to_ascii_lowercase().as_str(), "bash")
        || f[2].to_ascii_lowercase().contains("shell");
    let prose = matches!(
        f[2].to_ascii_lowercase().as_str(),
        "agent" | "sendmessage" | "subagenthandback" | "artifact" | "task"
    );
    (shell && shape) || (prose && f[3].contains("backtick"))
}

#[test]
#[ignore = "reads ~/.claude/projects; run with --ignored"]
fn benign_fp_per_rule() {
    let cfg = DetectionConfig::default();
    let split = benign_replay(&cfg);
    let events: usize = split.iter().map(|t| t.events).sum();
    let mut by_rule: BTreeMap<String, usize> = BTreeMap::new();
    let mut high: BTreeMap<String, usize> = BTreeMap::new();
    let mut detail: BTreeMap<String, usize> = BTreeMap::new();
    for t in &split {
        for (k, v) in &t.by_type {
            *by_rule.entry(k.clone()).or_insert(0) += v;
        }
        for (k, v) in &t.by_detail {
            *detail.entry(k.clone()).or_insert(0) += v;
            let mut it = k.split(" | ");
            let (rule, sev) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
            if sev == "high" || sev == "critical" {
                *high.entry(rule.to_string()).or_insert(0) += v;
            }
        }
    }
    assert!(events > 0, "empty benign corpus");
    let per1000 = |n: usize| 1000.0 * n as f64 / events as f64;
    println!("benign events: {events}");
    for (k, v) in &by_rule {
        println!(
            "rule {k}: {v} total {:.2}/1000, high+ {} = {:.2}/1000",
            per1000(*v),
            high.get(k).copied().unwrap_or(0),
            per1000(high.get(k).copied().unwrap_or(0))
        );
    }
    for (k, v) in &detail {
        println!("DETAIL {v}: {k}");
    }

    let mut over = Vec::new();
    for (k, v) in &by_rule {
        let budget = BUDGETS
            .iter()
            .find(|(r, _)| r == k)
            .map_or(DEFAULT_BUDGET, |(_, b)| *b);
        if per1000(*v) > budget {
            over.push(format!("{k}: {:.2}/1000 > budget {budget}", per1000(*v)));
        }
    }
    for (k, v) in &detail {
        if must_be_zero(k) {
            over.push(format!("{v} x {k} (must be 0, #45)"));
        }
    }
    assert!(
        over.is_empty(),
        "benign FP budget exceeded:\n{}",
        over.join("\n")
    );
}
