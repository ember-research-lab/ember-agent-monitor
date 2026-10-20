//! bench_full — full public-benchmark run plus benign-traffic replay (#42).
//!
//! `#[ignore]`d: needs the pinned benchmark cache (see tests/bench/README.md)
//! and reads `~/.claude/projects/**` (read-only; field names only are printed).
//!
//! ```text
//! cargo test --release --test bench_full -- --ignored --nocapture
//! ```
//!
//! Held-out discipline: by default only the DESIGN split is printed (and its
//! miss inventory, which is what rules are designed against). Set
//! `BENCH_REPORT_HELDOUT=1` to print the held-out split; do that once, after the
//! rules are frozen.

mod bench_support;

use bench_support::{case_types, is_design, parse_cases, pct, Case};
use ember_agent_monitor::detect::{run_dynamic, DetectionConfig};
use ember_agent_monitor::event::Event;
use ember_agent_monitor::graph::SessionGraph;
use ember_agent_monitor::types::EventKind;
use ember_agent_monitor::watcher::{interpret_line, LineOutcome};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const BENCHES: &[&str] = &["injecagent", "agentdojo", "bipia", "opi", "asb", "llmail"];

/// Injection-class stack before this work (the pre-registered FP gate counts
/// exactly this set plus each new detector).
const BASE: &[&str] = &[
    "instruction_shape_in_tool_result",
    "agent_as_intermediary_clickfix",
    "invisible_unicode_in_tool_result",
];
const D1: &str = "instruction_directive_in_tool_result";
const D2: &str = "tainted_argument_provenance";
const D3: &str = "sink_after_untrusted_source";

fn configs() -> Vec<(&'static str, Vec<&'static str>)> {
    let with = |extra: &[&'static str]| {
        let mut v: Vec<&'static str> = BASE.to_vec();
        v.extend_from_slice(extra);
        v
    };
    vec![
        ("baseline", with(&[])),
        ("+D1 directive", with(&[D1])),
        ("+D2 taint", with(&[D2])),
        ("+D3 sink", with(&[D3])),
        ("combined", with(&[D1, D2, D3])),
    ]
}

fn cache_dir() -> PathBuf {
    match std::env::var("BENCH_CACHE") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from(std::env::var("HOME").expect("HOME"))
            .join("ember-review/_lit-cache/agent-injection-benchmarks-2026-10"),
    }
}

fn convert(bench: &str, cache: &Path) -> Vec<Case> {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("bench");
    std::fs::create_dir_all(&out).expect("tmp dir");
    let dst = out.join(format!("{bench}.cases.jsonl"));
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/bench/convert.py");
    // `-I` and a cwd outside the data dir: nothing in the corpus can be imported.
    let st = Command::new("python3")
        .current_dir(&out)
        .arg("-I")
        .arg(&script)
        .args([bench, "--cache"])
        .arg(cache)
        .arg("--out")
        .arg(&dst)
        .status()
        .expect("run python3");
    assert!(
        st.success(),
        "converter failed for {bench} (cache {cache:?})"
    );
    parse_cases(&std::fs::read_to_string(&dst).expect("read cases")).expect("parse cases")
}

fn walk(d: &Path, out: &mut Vec<PathBuf>) {
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
struct Tally {
    events: usize,
    results: usize,
    by_type: BTreeMap<String, usize>,
    /// Diagnostics for the directive rule: cue combination and tool, counts only.
    by_cue: BTreeMap<String, usize>,
    by_tool: BTreeMap<String, usize>,
}

fn replay_events(
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
            if f.finding_type == D1 {
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
            *split[side].by_type.entry(f.finding_type).or_insert(0) += 1;
        }
    }
}

/// Benign corpus: Aaron's real transcripts + the repo's benign fixtures.
fn benign_replay(cfg: &DetectionConfig) -> [Tally; 2] {
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

fn count(types: &BTreeMap<String, usize>, set: &[&str]) -> usize {
    types
        .iter()
        .filter(|(k, _)| set.contains(&k.as_str()))
        .map(|(_, v)| *v)
        .sum()
}

#[test]
#[ignore = "needs the pinned benchmark cache and ~/.claude/projects; run with --ignored"]
fn benchmarks_and_benign_replay() {
    let heldout = std::env::var("BENCH_REPORT_HELDOUT").as_deref() == Ok("1");
    let cfg = DetectionConfig::default();
    let cache = cache_dir();
    let cfgs = configs();
    let sides: &[(&str, bool)] = if heldout {
        &[("design", true), ("heldout", false)]
    } else {
        &[("design", true)]
    };

    let only = std::env::var("BENCH_ONLY").unwrap_or_default();
    for b in BENCHES
        .iter()
        .filter(|b| only.is_empty() || only.split(',').any(|o| o == **b))
    {
        let cases = convert(b, &cache);
        // Results per case: types at the tool_result, and over the trajectory.
        let res: Vec<(Vec<String>, Vec<String>)> = cases
            .iter()
            .map(|c| (case_types(c, false, &cfg), case_types(c, true, &cfg)))
            .collect();
        println!(
            "== {b}: {} cases, {} attack, {} benign, {} groups",
            cases.len(),
            cases.iter().filter(|c| c.attack).count(),
            cases.iter().filter(|c| !c.attack).count(),
            cases
                .iter()
                .map(|c| c.group.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        for (cname, set) in &cfgs {
            for (side, want_design) in sides {
                for (mode, idx) in [("result", 0usize), ("trajectory", 1usize)] {
                    let fired = |i: usize| {
                        let t = if idx == 0 { &res[i].0 } else { &res[i].1 };
                        t.iter().any(|x| set.contains(&x.as_str()))
                    };
                    // primary split: by group; secondary (leaky): by case id.
                    let (mut ad, mut an, mut bd, mut bn, mut cd, mut cn) = (0, 0, 0, 0, 0, 0);
                    for (i, c) in cases.iter().enumerate() {
                        if c.attack {
                            if is_design(&c.group) == *want_design {
                                an += 1;
                                ad += usize::from(fired(i));
                            }
                            if is_design(&c.id) == *want_design {
                                cn += 1;
                                cd += usize::from(fired(i));
                            }
                        } else if is_design(&c.group) == *want_design {
                            bn += 1;
                            bd += usize::from(fired(i));
                        }
                    }
                    println!(
                        "  {cname:<14} {side:<7} {mode:<10} attack(group split) {ad}/{an} = {:.1}%  attack(case-id split) {cd}/{cn} = {:.1}%  benign-cases fired {bd}/{bn}",
                        pct(ad, an),
                        pct(cd, cn)
                    );
                }
            }
        }
        // Per-category hit counts, design split only, result mode (all types).
        let mut cat: BTreeMap<(String, String), (usize, usize)> = BTreeMap::new();
        for (i, c) in cases
            .iter()
            .enumerate()
            .filter(|(_, c)| c.attack && is_design(&c.group))
        {
            let e = cat.entry((c.category.clone(), String::new())).or_default();
            e.0 += 1;
            e.1 += usize::from(res[i].0.iter().any(|t| cfgs[4].1.contains(&t.as_str())));
        }
        for ((k, _), (n, h)) in &cat {
            println!("    category {k}: combined hits {h}/{n}");
        }
        // Design-split misses (rule-design input), one per group; never the held-out split.
        let mut shown = std::collections::BTreeSet::new();
        for (i, c) in cases.iter().enumerate() {
            if c.attack
                && is_design(&c.group)
                && !res[i].0.iter().any(|t| cfgs[4].1.contains(&t.as_str()))
                && shown.len() < 40
                && shown.insert(c.group.clone())
            {
                let tail: String = c
                    .content
                    .chars()
                    .rev()
                    .take(150)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect();
                println!(
                    "    DESIGN-MISS {} [{}] :: {}",
                    c.id,
                    c.tool,
                    tail.replace('\n', "\\n")
                );
            }
        }
    }

    if std::env::var("BENCH_NO_BENIGN").is_ok() {
        return;
    }
    let split = benign_replay(&cfg);
    println!("== benign replay (real transcripts + repo benign fixtures)");
    let mut all: BTreeMap<String, usize> = BTreeMap::new();
    for t in &split {
        for (k, v) in &t.by_type {
            *all.entry(k.clone()).or_insert(0) += v;
        }
    }
    let whole_ev = split[0].events + split[1].events;
    println!(
        "  events: design {} heldout {} whole {whole_ev} (tool_results {})",
        split[0].events,
        split[1].events,
        split[0].results + split[1].results
    );
    for (name, set) in &cfgs {
        let d = count(&split[0].by_type, set);
        let h = count(&split[1].by_type, set);
        let line = format!(
            "  stack {name:<14} FP/1000 events: design {:.2}  whole {:.2}",
            1000.0 * d as f64 / split[0].events as f64,
            1000.0 * (d + h) as f64 / whole_ev as f64
        );
        if heldout {
            println!(
                "{line}  heldout {:.2}",
                1000.0 * h as f64 / split[1].events as f64
            );
        } else {
            println!("{line}");
        }
    }
    if std::env::var("BENCH_DIAG").is_ok() {
        let mut cues: Vec<_> = split[0].by_cue.iter().collect();
        cues.sort_by(|a, b| b.1.cmp(a.1));
        for (k, v) in cues.iter().take(25) {
            println!("  DIAG design cue-combo {v}: {k}");
        }
        let mut tools: Vec<_> = split[0].by_tool.iter().collect();
        tools.sort_by(|a, b| b.1.cmp(a.1));
        for (k, v) in tools.iter().take(30) {
            println!("  DIAG design tool {v}: {k}");
        }
    }
    for (k, v) in &all {
        println!(
            "  rule {k}: {v} total, {:.2}/1000 events",
            1000.0 * *v as f64 / whole_ev as f64
        );
    }
}
