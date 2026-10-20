//! Cost accounting (#63): hand-computed totals on a fixture transcript tree, UNPRICED rows,
//! `--strict` exit code, staleness warning, and the pinned price table itself.
//!
//! Fixture (tests/fixtures/cost/projects/projA), list prices from prices.toml:
//!   msg_a opus-5-5 (twice in the file, first line is a partial output=5: counted once at the final 500) 1000 in, 500 out, 2000 read, 1000 w5m, 3000 w1h
//!        = 0.004 + 0.010 + 0.0004 + 0.005 + 0.024 = 0.0434
//!   msg_b sonnet-5-5, 2026-10-19: 100000 in, 10000 out = 0.2 + 0.1 = 0.3
//!   msg_c haiku-4-5-20251001, subagent: 200000 in, 100000 out, 1000000 read = 0.2 + 0.5 + 0.1 = 0.8
//!   msg_d mystery-9, subagent: 10 in, 20 out = UNPRICED
//!   msg_e <synthetic> all-zero usage: skipped

use ember_agent_monitor::cost::{aggregate, normalize_model, scan, GroupBy, Prices, ScanOptions};
use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cost/projects")
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() < 1e-9
}

#[test]
fn fixture_totals_match_hand_computation() {
    let prices = Prices::builtin().unwrap();
    let (recs, stats) = scan(&root(), &ScanOptions::default()).unwrap();
    assert_eq!(stats.messages, 4);
    assert_eq!(stats.duplicates_skipped, 1);
    assert_eq!(stats.synthetic_skipped, 1);
    let rep = aggregate(&recs, GroupBy::Model, &prices);
    let row = |k: &str| rep.rows.iter().find(|r| r.key == k).unwrap();
    assert!(close(row("claude-opus-5-5").cost_usd, 0.0434));
    assert_eq!(row("claude-opus-5-5").cache_write_1h, 3000);
    assert!(close(row("claude-sonnet-5-5").cost_usd, 0.3));
    assert!(close(row("claude-haiku-4-5").cost_usd, 0.8)); // dated id normalised
    assert_eq!(row("mystery-9").unpriced_messages, 1);
    assert_eq!(row("mystery-9").input + row("mystery-9").output, 30);
    assert!(close(rep.total.cost_usd, 1.1434));
    assert_eq!(rep.total.unpriced_messages, 1);
}

#[test]
fn since_filters_by_event_date_and_actor_splits_subagents() {
    let prices = Prices::builtin().unwrap();
    let opts = ScanOptions {
        since: Some("2026-10-20".into()),
        session: None,
    };
    let (recs, _) = scan(&root(), &opts).unwrap();
    let rep = aggregate(&recs, GroupBy::Actor, &prices);
    let row = |k: &str| rep.rows.iter().find(|r| r.key == k).unwrap();
    assert!(close(row("driver").cost_usd, 0.0434));
    assert!(close(row("subagent").cost_usd, 0.8));
    assert_eq!(row("subagent").unpriced_messages, 1);
    assert!(close(rep.total.cost_usd, 0.8434));
}

#[test]
fn unpriced_is_never_zero_and_strict_exits_nonzero() {
    let bin = env!("CARGO_BIN_EXE_ember-agent");
    let run = |extra: &[&str]| {
        Command::new(bin)
            .args(["cost", "--root", root().to_str().unwrap(), "--by", "model"])
            .args(extra)
            .output()
            .unwrap()
    };
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.starts_with("mystery-9")).unwrap();
    assert!(line.ends_with("UNPRICED"), "{line}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("UNPRICED: 1 message(s)"));
    assert!(text.contains("valid_from 2026-10-20"));
    assert_eq!(run(&["--strict"]).status.code(), Some(3));
    let j = run(&["--json"]);
    assert!(String::from_utf8_lossy(&j.stdout).contains("\"cost_usd\":null"));
}

#[test]
fn staleness_warning_when_message_newer_than_reviewed_until() {
    let table = std::env::temp_dir().join(format!("ember-cost-prices-{}.toml", std::process::id()));
    let text =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("prices.toml"))
            .unwrap()
            .replace("valid_from = \"2026-10-20\"", "valid_from = \"2026-10-19\"")
            .replace(
                "reviewed_until = \"2026-10-20\"",
                "reviewed_until = \"2026-10-19\"",
            );
    std::fs::write(&table, text).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ember-agent"))
        .args([
            "cost",
            "--root",
            root().to_str().unwrap(),
            "--prices",
            table.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&table);
    assert!(String::from_utf8_lossy(&out.stderr).contains("STALE PRICES"));
}

#[test]
fn pinned_table_is_dated_and_malformed_tables_fail_loud() {
    let p = Prices::builtin().unwrap();
    assert_eq!(p.valid_from, "2026-10-20");
    assert_eq!(p.reviewed_until, "2026-10-20");
    assert!(p.lookup("claude-opus-5-5[1m]").is_some());
    assert!(p.lookup("opus").is_none()); // aliases are not guessed
    assert_eq!(
        normalize_model("claude-haiku-4-5-20251001"),
        "claude-haiku-4-5"
    );
    assert!(Prices::parse("[meta]\nvalid_from = \"2026-10-20\"\n").is_err());
    assert!(Prices::parse("[[model]]\nid = \"x\"\nbogus line\n").is_err());
}

#[test]
fn rollup_is_written_atomically_to_the_data_dir() {
    let data = std::env::temp_dir().join(format!("ember-cost-rollup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    ember_agent_monitor::cost::write_rollup(&root(), &data).unwrap();
    let text = std::fs::read_to_string(data.join("cost-rollup.json")).unwrap();
    assert!(text.contains("\"by_day\"") && text.contains("\"by_model\""));
    assert!(!data.join("cost-rollup.json.tmp").exists());
    let _ = std::fs::remove_dir_all(&data);
}
