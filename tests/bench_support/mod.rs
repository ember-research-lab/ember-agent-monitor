//! bench_support — shared case loader, seeded split and scorer for the public
//! prompt-injection benchmark tests (#42).
//!
//! Cases are the JSONL produced by `tests/bench/convert.py`. Everything here
//! is test-side: no monitor code depends on it.

#![allow(dead_code)]

use ember_agent_monitor::crypto::sha256::sha256;
use ember_agent_monitor::detect::{run_dynamic, DetectionConfig};
use ember_agent_monitor::event::Event;
use ember_agent_monitor::graph::SessionGraph;
use ember_agent_monitor::json::{parse, JsonValue};
use ember_agent_monitor::types::{EventKind, TrustZone};
use std::collections::HashMap;

/// Split seed. Pre-registered in the RCA report; never changed after results.
pub const SEED: &str = "rca-2026-10-20";

#[derive(Debug)]
pub enum BenchError {
    Json(String),
    Field(&'static str),
}

impl std::fmt::Display for BenchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BenchError::Json(e) => write!(f, "case json: {e}"),
            BenchError::Field(k) => write!(f, "case missing field {k}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Case {
    pub id: String,
    pub bench: String,
    pub group: String,
    pub attack: bool,
    pub category: String,
    pub user_prompt: String,
    pub tool: String,
    pub tool_input: String,
    pub content: String,
    pub attacker_tools: Vec<String>,
}

fn s(o: &[(String, JsonValue)], k: &'static str) -> Result<String, BenchError> {
    o.iter()
        .find(|(n, _)| n == k)
        .and_then(|(_, v)| v.as_str().map(String::from))
        .ok_or(BenchError::Field(k))
}

pub fn parse_cases(text: &str) -> Result<Vec<Case>, BenchError> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v = parse(line).map_err(|e| BenchError::Json(format!("{e:?}")))?;
        let JsonValue::Object(o) = v else {
            return Err(BenchError::Json("not an object".into()));
        };
        let attacker_tools = match o.iter().find(|(n, _)| n == "attacker_tools") {
            Some((_, JsonValue::Array(a))) => a
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            _ => Vec::new(),
        };
        out.push(Case {
            id: s(&o, "id")?,
            bench: s(&o, "bench")?,
            group: s(&o, "group")?,
            attack: s(&o, "label")? == "attack",
            category: s(&o, "category")?,
            user_prompt: s(&o, "user_prompt")?,
            tool: s(&o, "tool")?,
            tool_input: s(&o, "tool_input")?,
            content: s(&o, "content")?,
            attacker_tools,
        });
    }
    Ok(out)
}

/// True when `key` belongs to the 70% design side of the seeded split.
pub fn is_design(key: &str) -> bool {
    let h = sha256(format!("{SEED}|{key}").as_bytes());
    let mut v = 0u64;
    for b in &h[..8] {
        v = (v << 8) | u64::from(*b);
    }
    v % 100 < 70
}

fn body(pairs: Vec<(&str, JsonValue)>) -> HashMap<String, JsonValue> {
    pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
}

/// The 3-event trajectory (user prompt, tool call, untrusted tool result),
/// optionally followed by one tool_call per attacker tool ("trajectory
/// mode": what the benchmark defines as the attack succeeding).
pub fn build_events(c: &Case, trajectory: bool) -> Vec<Event> {
    let sid = format!("bench-{}", c.id);
    let st = |x: &str| JsonValue::Str(x.to_string());
    let mut v = vec![
        Event::new(
            sid.clone(),
            EventKind::UserPrompt,
            TrustZone::UserInput,
            body(vec![("text", st(&c.user_prompt))]),
        ),
        Event::new(
            sid.clone(),
            EventKind::ToolCall,
            TrustZone::WorkspaceLocal,
            body(vec![
                ("tool_name", st(&c.tool)),
                ("tool_use_id", st("t1")),
                (
                    "input",
                    JsonValue::Object(vec![("q".into(), st(&c.tool_input))]),
                ),
            ]),
        ),
        Event::new(
            sid.clone(),
            EventKind::ToolResult,
            TrustZone::UntrustedToolOutput,
            body(vec![
                ("tool_use_id", st("t1")),
                ("content", st(&c.content)),
                ("is_error", JsonValue::Bool(false)),
            ]),
        ),
    ];
    if trajectory {
        for (i, t) in c.attacker_tools.iter().enumerate() {
            v.push(Event::new(
                sid.clone(),
                EventKind::ToolCall,
                TrustZone::WorkspaceLocal,
                body(vec![
                    ("tool_name", st(t)),
                    ("tool_use_id", st(&format!("a{i}"))),
                    ("input", JsonValue::Object(Vec::new())),
                ]),
            ));
        }
    }
    v
}

/// Finding types fired per event, in order.
pub fn run_events(events: &[Event], cfg: &DetectionConfig) -> Vec<(usize, String)> {
    let mut g = SessionGraph::default();
    let mut out = Vec::new();
    for (i, ev) in events.iter().enumerate() {
        g.ingest(ev.clone());
        for f in run_dynamic(ev, &g, cfg) {
            out.push((i, f.finding_type));
        }
    }
    out
}

/// Types fired by a case at the tool_result (index 2) or, in trajectory
/// mode, anywhere.
pub fn case_types(c: &Case, trajectory: bool, cfg: &DetectionConfig) -> Vec<String> {
    run_events(&build_events(c, trajectory), cfg)
        .into_iter()
        .filter(|(i, _)| trajectory || *i <= 2)
        .map(|(_, t)| t)
        .collect()
}

pub fn pct(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        100.0 * n as f64 / d as f64
    }
}
