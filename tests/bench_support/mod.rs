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
use ember_agent_monitor::watcher::{interpret_line, LineOutcome};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

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

/// Benign-traffic replay shared by bench_full and benign_budget (#45).
pub fn walk(d: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|x| x.to_str()) == Some("jsonl") {
                out.push(p);
            }
        }
    }
}

#[derive(Default)]
pub struct Tally {
    pub events: usize,
    pub results: usize,
    pub by_type: BTreeMap<String, usize>,
    /// Diagnostics for the directive rule: cue combination and tool, counts only.
    pub by_cue: BTreeMap<String, usize>,
    pub by_tool: BTreeMap<String, usize>,
    /// `type | severity | tool | pattern` -> count, every rule (#45 class guard).
    pub by_detail: BTreeMap<String, usize>,
}

pub fn replay_events(
    sid: &str,
    events: impl Iterator<Item = Event>,
    cfg: &DetectionConfig,
    split: &mut [Tally; 2],
) {
    let side = usize::from(!is_design(sid));
    let mut g = SessionGraph::default();
    for ev in events {
        split[side].events += 1;
        if ev.kind == EventKind::ToolResult {
            split[side].results += 1;
        }
        g.ingest(ev.clone());
        for f in run_dynamic(&ev, &g, cfg) {
            if f.finding_type == "instruction_directive_in_tool_result" {
                *split[side]
                    .by_cue
                    .entry(f.pattern.clone().unwrap_or_default())
                    .or_insert(0) += 1;
                *split[side]
                    .by_tool
                    .entry(format!(
                        "{} :: {}",
                        f.tool.clone().unwrap_or_default(),
                        f.pattern.clone().unwrap_or_default()
                    ))
                    .or_insert(0) += 1;
            }
            *split[side]
                .by_detail
                .entry(format!(
                    "{} | {} | {} | {}",
                    f.finding_type,
                    f.severity.as_str(),
                    f.tool.clone().unwrap_or_default(),
                    f.pattern.clone().unwrap_or_default()
                ))
                .or_insert(0) += 1;
            *split[side].by_type.entry(f.finding_type).or_insert(0) += 1;
        }
    }
}

/// Benign corpus: Aaron's real transcripts + the repo's benign fixtures.
pub fn benign_replay(cfg: &DetectionConfig) -> [Tally; 2] {
    let mut split = [Tally::default(), Tally::default()];
    let root = PathBuf::from(std::env::var("HOME").expect("HOME")).join(".claude/projects");
    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();
    assert!(
        !files.is_empty(),
        "no transcripts under {root:?}: refusing to report an empty benign corpus"
    );
    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        let sid = f
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string();
        let mut seen = std::collections::HashSet::new();
        let evs = text
            .lines()
            .flat_map(|l| match interpret_line(l, &mut seen) {
                LineOutcome::Events(e) => e,
                _ => Vec::new(),
            });
        replay_events(&sid, evs, cfg, &mut split);
    }
    let fx = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("threat-intel");
    for name in [
        "fixtures/benign_shell_session",
        "fixtures/spectral_clean_pipeline",
        "fixtures/unicode_tag_flag_emoji_benign",
        "fixtures/presence_agent_clean_heartbeat",
        "calibration/clean_corpus",
    ] {
        let p = fx.join(name);
        let mut files = Vec::new();
        walk(&p, &mut files);
        for f in files.iter().filter(|f| f.extension().is_some()) {
            if f.file_name().and_then(|n| n.to_str()) == Some("expected.json") {
                continue;
            }
            if let Ok(evs) = ember_agent_monitor::store::log::read_all(f) {
                let sid = format!("fixture:{}", f.display());
                replay_events(&sid, evs.into_iter(), cfg, &mut split);
            }
        }
    }
    split
}
