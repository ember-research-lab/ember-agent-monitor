//! #80: `finalize-idle` obeys the same spectral node cap as the live proxy.

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

/// At or below the cap the summary is byte-identical to what main produced
/// before #80 (golden captured from origin/main 89ff8e2).
#[test]
fn session_below_cap_is_byte_identical_to_pre_change() {
    let (dir, summary, _) = finalize("small", 100);
    let golden = include_str!("fixtures/finalize_cap_golden_100.summary.json");
    let got = summary.replace(dir.to_str().unwrap(), "@DIR@");
    assert_eq!(got, golden.trim_end());
    let _ = std::fs::remove_dir_all(dir);
}
