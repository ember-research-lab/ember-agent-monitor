//! `ember-agent finalize-idle`: hands never-ended (watched) sessions to ember-persistent.

use std::process::Command;

const EV: &str = r#"{"event_id":"e1","session_id":"a","timestamp_ms":1746086402000,"parent_event_id":null,"trust_zone":"user_input","content_hash":"x","kind":"user_prompt","body":{"text":"hello"}}"#;

fn run(dir: &std::path::Path, idle: &str) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ember-agent"))
        .args(["finalize-idle", "--idle-secs", idle, "--data-dir"])
        .arg(dir)
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn finalizes_quiet_sessions_once_and_skips_recent_ones() {
    let dir = std::env::temp_dir().join(format!("ember-fin-idle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sessions")).unwrap();
    std::fs::write(dir.join("sessions/a.jsonl"), format!("{EV}\n")).unwrap();

    let (ok, out) = run(&dir, "100000"); // not idle long enough
    assert!(ok && out.contains("0 finalized"), "{out}");
    assert!(!dir.join("sessions/a.summary.json").exists());

    let (ok, out) = run(&dir, "0");
    assert!(ok && out.contains("1 finalized"), "{out}");
    assert!(dir.join("sessions/a.summary.json").exists());

    let (ok, out) = run(&dir, "0"); // summary now newer than the log
    assert!(ok && out.contains("0 finalized"), "{out}");
}

#[test]
fn unreadable_session_fails_loud() {
    let dir = std::env::temp_dir().join(format!("ember-fin-bad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sessions")).unwrap();
    std::fs::write(dir.join("sessions/bad.jsonl"), "not json\n").unwrap();
    let (ok, out) = run(&dir, "0");
    assert!(!ok, "malformed log must make the command fail: {out}");
}
