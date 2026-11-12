//! #80: `finalize-idle` obeys the same spectral node cap as the live proxy.

use ember_agent_monitor::json::{self, JsonValue};
use std::process::Command;
use std::time::{Duration, Instant};

fn session_log(n: usize) -> String {
    let mut s = String::new();
    for i in 0..n {
        let (kind, zone) = if i % 2 == 0 {
            ("user_prompt", "user_input")
        } else {
            ("model_text", "workspace_local")
        };
        let parent = if i == 0 {
            "null".to_string()
        } else {
            format!("\"e{}\"", i - 1)
        };
        s.push_str(&format!(
            "{{\"event_id\":\"e{i}\",\"session_id\":\"s\",\"timestamp_ms\":{},\"parent_event_id\":{parent},\"trust_zone\":\"{zone}\",\"content_hash\":\"h{i}\",\"kind\":\"{kind}\",\"body\":{{\"text\":\"step {i}\"}}}}\n",
            1746086402000u64 + i as u64 * 1000
        ));
    }
    s
}

fn finalize(tag: &str, n: usize) -> (std::path::PathBuf, String, Duration) {
    let dir = std::env::temp_dir().join(format!("ember-fin-cap-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sessions")).unwrap();
    std::fs::write(dir.join("sessions/s.jsonl"), session_log(n)).unwrap();
    let t = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_ember-agent"))
        .args(["finalize-idle", "--idle-secs", "0", "--data-dir"])
        .arg(&dir)
        .output()
        .unwrap();
    let took = t.elapsed();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let summary = std::fs::read_to_string(dir.join("sessions/s.summary.json")).unwrap();
    (dir, summary, took)
}

/// Well above the cap: finalizes fast, and the summary says it was capped.
#[test]
fn session_above_cap_finalizes_fast_and_records_the_cap() {
    let (dir, summary, took) = finalize("big", 3000);
    assert!(took < Duration::from_secs(10), "took {took:?}");
    assert!(
        summary.contains(r#""spectral_capped":{"n_nodes":3000,"cap":256}"#),
        "{summary}"
    );
    assert!(
        summary.contains(r#""spectral_skipped":1"#),
        "skip finding missing: {summary}"
    );
    assert!(!summary.contains("spectral_summary"), "{summary}");
    let _ = std::fs::remove_dir_all(dir);
}

/// Structural compare: same key set and order, same strings/ints/bools exactly;
/// only non-integer numbers get a relative tolerance. The eigen-solve's last
/// digits differ across platforms (macOS CI: spectral_dimension
/// 1.0976590935600512 vs 1.0976590935600514 on Linux, rel diff ~2e-16), so
/// byte equality of floats is not portable; 1e-9 leaves 7 orders of headroom.
fn assert_same(path: &str, got: &JsonValue, want: &JsonValue) {
    match (got, want) {
        (JsonValue::Number(g), JsonValue::Number(w)) if w.fract() != 0.0 => {
            let rel = (g - w).abs() / w.abs().max(f64::MIN_POSITIVE);
            assert!(rel <= 1e-9, "{path}: {g} vs {w} (rel {rel:e})");
        }
        (JsonValue::Number(g), JsonValue::Number(w)) => assert_eq!(g, w, "{path}"),
        (JsonValue::Str(g), JsonValue::Str(w)) => assert_eq!(g, w, "{path}"),
        (JsonValue::Bool(g), JsonValue::Bool(w)) => assert_eq!(g, w, "{path}"),
        (JsonValue::Null, JsonValue::Null) => {}
        (JsonValue::Array(g), JsonValue::Array(w)) => {
            assert_eq!(g.len(), w.len(), "{path}: array length");
            for (i, (a, b)) in g.iter().zip(w).enumerate() {
                assert_same(&format!("{path}[{i}]"), a, b);
            }
        }
        (JsonValue::Object(g), JsonValue::Object(w)) => {
            let gk: Vec<_> = g.iter().map(|(k, _)| k).collect();
            let wk: Vec<_> = w.iter().map(|(k, _)| k).collect();
            assert_eq!(gk, wk, "{path}: keys/order");
            for ((k, a), (_, b)) in g.iter().zip(w) {
                assert_same(&format!("{path}.{k}"), a, b);
            }
        }
        _ => panic!("{path}: type mismatch {got:?} vs {want:?}"),
    }
}

/// At or below the cap the summary matches what main produced before #80
/// (golden captured from origin/main 89ff8e2): identical structure and
/// non-float values, floats within 1e-9 relative.
#[test]
fn session_below_cap_matches_pre_change_golden() {
    let (dir, summary, _) = finalize("small", 100);
    let golden = include_str!("fixtures/finalize_cap_golden_100.summary.json");
    let got = summary.replace(dir.to_str().unwrap(), "@DIR@");
    assert_same(
        "$",
        &json::parse(&got).unwrap(),
        &json::parse(golden).unwrap(),
    );
    let _ = std::fs::remove_dir_all(dir);
}
