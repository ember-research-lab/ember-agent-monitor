//! Watcher on the real Claude Code layout: `<project>/<session>.jsonl`,
//! tail-from-EOF for pre-existing files, complete lines only, and transcript
//! records converted with the tool_result != user_prompt invariant intact.

use ember_agent_monitor::types::{DaemonConfig, EventKind};
use ember_agent_monitor::watcher::{interpret_line, LineOutcome, WatcherState};
use std::io::Write;

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("ember-watch-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn cfg(root: &std::path::Path) -> DaemonConfig {
    DaemonConfig {
        watch_dir: root.to_path_buf(),
        ..Default::default()
    }
}

const USER: &str =
    r#"{"type":"user","sessionId":"s1","message":{"role":"user","content":"hi there"}}"#;
const TOOL_USE: &str = r#"{"type":"assistant","sessionId":"s1","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/etc/passwd"}}]}}"#;
const TOOL_RESULT: &str = r#"{"type":"user","sessionId":"s1","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"root:x:0:0"}]}}"#;

#[test]
fn real_layout_tail_from_eof_then_new_lines_and_partial_line() {
    let root = scratch("layout");
    let proj = root.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let f = proj.join("s1.jsonl");
    std::fs::write(&f, format!("{USER}\n")).unwrap(); // history: must be skipped
    let c = cfg(&root);
    let mut st = WatcherState::new();
    assert!(st.poll(&c).unwrap().is_empty(), "history is not replayed");

    let mut h = std::fs::OpenOptions::new().append(true).open(&f).unwrap();
    write!(h, "{TOOL_USE}\n{}", &TOOL_RESULT[..20]).unwrap(); // trailing partial line
    let up = st.poll(&c).unwrap();
    assert_eq!(up.len(), 1);
    assert_eq!(up[0].1, vec![TOOL_USE.to_string()], "partial line withheld");

    writeln!(h, "{}", &TOOL_RESULT[20..]).unwrap();
    let up = st.poll(&c).unwrap();
    assert_eq!(
        up[0].1,
        vec![TOOL_RESULT.to_string()],
        "completed line delivered whole"
    );

    // A file created after the first poll is read from byte 0.
    std::fs::write(proj.join("s2.jsonl"), format!("{USER}\n")).unwrap();
    assert_eq!(st.poll(&c).unwrap().len(), 1);
}

#[test]
fn subagent_layout_watched() {
    let root = scratch("subagents");
    let sub = root.join("proj").join("sid1").join("subagents");
    std::fs::create_dir_all(&sub).unwrap();
    let c = cfg(&root);
    let mut st = WatcherState::new();
    st.poll(&c).unwrap();
    std::fs::write(sub.join("agent-x.jsonl"), format!("{USER}\n")).unwrap();
    assert_eq!(st.poll(&c).unwrap().len(), 1);
}

#[test]
fn spec_layout_still_watched() {
    let root = scratch("speclayout");
    let sess = root.join("proj").join("sessions");
    std::fs::create_dir_all(&sess).unwrap();
    let c = cfg(&root);
    let mut st = WatcherState::new();
    st.poll(&c).unwrap();
    std::fs::write(sess.join("a.jsonl"), format!("{USER}\n")).unwrap();
    assert_eq!(st.poll(&c).unwrap().len(), 1);
}

#[test]
fn transcript_records_keep_tool_result_distinct_from_user_prompt() {
    let mut seen = std::collections::HashSet::new();
    seen.insert("s1".to_string());
    let mut kinds = |l: &str| match interpret_line(l, &mut seen) {
        LineOutcome::Events(e) => e.iter().map(|x| x.kind).collect::<Vec<_>>(),
        _ => panic!("expected events for {l}"),
    };
    assert_eq!(kinds(USER), vec![EventKind::UserPrompt]);
    assert_eq!(kinds(TOOL_USE), vec![EventKind::ToolCall]);
    assert_eq!(kinds(TOOL_RESULT), vec![EventKind::ToolResult]);
}

#[test]
fn non_conversation_is_ignored_and_garbage_is_loud() {
    let mut seen = std::collections::HashSet::new();
    assert!(matches!(
        interpret_line(
            r#"{"type":"system","subtype":"x","sessionId":"s1"}"#,
            &mut seen
        ),
        LineOutcome::NotConversation
    ));
    assert!(matches!(
        interpret_line("not json", &mut seen),
        LineOutcome::Malformed(_)
    ));
    assert!(matches!(
        interpret_line(
            r#"{"type":"user","message":{"role":"user","content":"x"}}"#,
            &mut seen
        ),
        LineOutcome::Malformed(_)
    ));
}

#[test]
fn first_record_of_a_session_yields_session_start_with_cwd() {
    let mut seen = std::collections::HashSet::new();
    let line = r#"{"type":"user","sessionId":"s9","cwd":"/work/x","gitBranch":"main","message":{"role":"user","content":"hi"}}"#;
    let evs = match interpret_line(line, &mut seen) {
        LineOutcome::Events(e) => e,
        _ => panic!("events"),
    };
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[0].kind, EventKind::SessionStart);
    let again = match interpret_line(line, &mut seen) {
        LineOutcome::Events(e) => e,
        _ => panic!("events"),
    };
    assert_eq!(again.len(), 1, "session_start only once per session");
}

#[test]
fn agent_attribution_fields_are_carried_into_every_event_body() {
    use ember_agent_monitor::json::JsonValue;
    let mut seen = std::collections::HashSet::new();
    let line = r#"{"type":"assistant","sessionId":"s7","agentId":"a1b2","isSidechain":true,"uuid":"u-1","message":{"role":"assistant","content":[{"type":"tool_use","id":"t9","name":"Write","input":{"file_path":"/x"}}]}}"#;
    let evs = match interpret_line(line, &mut seen) {
        LineOutcome::Events(e) => e,
        _ => panic!("events"),
    };
    assert_eq!(evs.len(), 2); // session_start + tool_call
    for ev in &evs {
        assert_eq!(
            ev.body.get("agent_id"),
            Some(&JsonValue::Str("a1b2".into()))
        );
        assert_eq!(ev.body.get("is_sidechain"), Some(&JsonValue::Bool(true)));
        assert_eq!(ev.body.get("uuid"), Some(&JsonValue::Str("u-1".into())));
    }
    // A main-agent record carries no agent_id.
    let main = r#"{"type":"user","sessionId":"s7","isSidechain":false,"uuid":"u-2","message":{"role":"user","content":"hi"}}"#;
    let evs = match interpret_line(main, &mut seen) {
        LineOutcome::Events(e) => e,
        _ => panic!("events"),
    };
    assert!(!evs[0].body.contains_key("agent_id"));
    assert_eq!(
        evs[0].body.get("is_sidechain"),
        Some(&JsonValue::Bool(false))
    );
}

#[test]
fn every_transcript_field_is_carried_or_explicitly_dropped() {
    use ember_agent_monitor::json::{parse, JsonValue};
    use ember_agent_monitor::watcher::{FieldDisposition, TRANSCRIPT_FIELDS};
    // A full real-shape Claude Code record. A new upstream field must be
    // added here AND to TRANSCRIPT_FIELDS (carried or dropped on purpose).
    let rec = r#"{"parentUuid":"p","isSidechain":true,"userType":"external","cwd":"/w","sessionId":"s8","version":"2.1","gitBranch":"main","agentId":"ag","type":"user","message":{"role":"user","content":"x"},"uuid":"u","timestamp":"2026-10-20T00:00:00Z","requestId":"r","toolUseResult":{},"isMeta":false,"slug":"s","permissionMode":"default","promptId":"pid","entrypoint":"cli","sourceToolAssistantUUID":"z"}"#;
    let JsonValue::Object(o) = parse(rec).unwrap() else {
        panic!("object")
    };
    for (k, _) in &o {
        assert!(
            TRANSCRIPT_FIELDS.iter().any(|(n, _)| n == k),
            "transcript field {k} has no disposition"
        );
    }
    let mut seen = std::collections::HashSet::new();
    let evs = match interpret_line(rec, &mut seen) {
        LineOutcome::Events(e) => e,
        _ => panic!("events"),
    };
    for (name, disp) in TRANSCRIPT_FIELDS {
        match disp {
            FieldDisposition::Carried(dst) => {
                assert!(
                    evs[0].body.contains_key(*dst),
                    "{name} not carried as {dst}"
                )
            }
            FieldDisposition::Dropped => {
                assert!(!evs[0].body.contains_key(*name), "{name} leaked unrenamed")
            }
            FieldDisposition::Consumed => {}
        }
    }
}
