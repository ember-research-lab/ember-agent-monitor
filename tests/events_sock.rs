//! The daemon's context must expose `<data_dir>/events.sock` and stream
//! recorded tool_calls to a subscriber (spec §6 — ember-network's input).

use ember_agent_monitor::event::Event;
use ember_agent_monitor::json::JsonValue;
use ember_agent_monitor::net::proxy::ProxyContext;
use ember_agent_monitor::net::socket::Source;
use ember_agent_monitor::types::{DaemonConfig, EventKind, TrustZone};
use ember_agent_monitor::watcher::{interpret_line, LineOutcome};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;

#[test]
fn tool_calls_reach_a_subscriber_and_user_prompts_do_not() {
    // unix socket paths are capped near 108 bytes: keep this short.
    let dir = std::path::PathBuf::from(format!("/tmp/ems-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = DaemonConfig {
        data_dir: dir.clone(),
        ..Default::default()
    };
    let ctx = ProxyContext::new(cfg).unwrap();
    assert!(ctx.events_sock.is_some(), "events.sock must bind");
    let sub = UnixStream::connect(dir.join("events.sock")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200)); // accept loop registers it

    let mut body = HashMap::new();
    body.insert("text".to_string(), JsonValue::Str("hi".into()));
    ctx.record(&Event::new(
        "s",
        EventKind::UserPrompt,
        TrustZone::UserInput,
        body,
    ));
    let mut body = HashMap::new();
    body.insert("tool_name".to_string(), JsonValue::Str("WebFetch".into()));
    ctx.record(&Event::new(
        "s",
        EventKind::ToolCall,
        TrustZone::WorkspaceLocal,
        body,
    ));

    sub.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    let mut line = String::new();
    BufReader::new(sub).read_line(&mut line).unwrap();
    assert!(line.contains("\"kind\":\"tool_call\""), "{line}");
    let _ = std::fs::remove_dir_all(&dir);
}

const TOOL_USE: &str = r#"{"type":"assistant","sessionId":"s1","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"curl https://example.com"}}]}}"#;

fn ctx_and_sub(tag: &str) -> (ProxyContext, UnixStream, std::path::PathBuf) {
    let dir = std::path::PathBuf::from(format!("/tmp/ems-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cfg = DaemonConfig {
        data_dir: dir.clone(),
        ..Default::default()
    };
    let ctx = ProxyContext::new(cfg).unwrap();
    let sub = UnixStream::connect(dir.join("events.sock")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    sub.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();
    (ctx, sub, dir)
}

fn watched_events() -> Vec<Event> {
    let mut seen = std::collections::HashSet::new();
    match interpret_line(TOOL_USE, &mut seen) {
        LineOutcome::Events(e) => e,
        _ => panic!("transcript line must convert"),
    }
}

#[test]
fn watcher_fed_transcript_tool_call_is_broadcast_with_contract_shape() {
    let (ctx, sub, dir) = ctx_and_sub("w");
    for ev in watched_events() {
        ctx.record_from(&ev, Source::Watcher);
    }
    let mut r = BufReader::new(sub);
    let mut line = String::new();
    r.read_line(&mut line).unwrap();
    // session_start is not a tool_call: first line on the wire is the tool_call.
    let v = ember_agent_monitor::json::parse(line.trim_end()).unwrap();
    let JsonValue::Object(o) = v else { panic!() };
    let get = |k: &str| o.iter().find(|(n, _)| n == k).map(|(_, x)| x.clone());
    assert_eq!(
        get("kind"),
        Some(JsonValue::Str("tool_call".into())),
        "{line}"
    );
    assert_eq!(get("session_id"), Some(JsonValue::Str("s1".into())));
    assert_eq!(get("source"), Some(JsonValue::Str("watcher".into())));
    assert!(matches!(get("event_id"), Some(JsonValue::Str(_))));
    assert!(matches!(get("timestamp_ms"), Some(JsonValue::Number(_))));
    let Some(JsonValue::Object(b)) = get("body") else {
        panic!()
    };
    let bget = |k: &str| b.iter().find(|(n, _)| n == k).map(|(_, x)| x.clone());
    assert_eq!(bget("tool_use_id"), Some(JsonValue::Str("toolu_1".into())));
    assert_eq!(bget("tool_name"), Some(JsonValue::Str("Bash".into())));
    assert!(matches!(bget("input"), Some(JsonValue::Object(_))));
    let _ = std::fs::remove_dir_all(dir.as_path());
}

#[test]
fn same_tool_use_id_from_proxy_and_watcher_is_broadcast_once() {
    let (ctx, sub, dir) = ctx_and_sub("d");
    let evs = watched_events();
    for ev in &evs {
        ctx.record_from(ev, Source::Proxy);
    }
    for ev in &evs {
        ctx.record_from(ev, Source::Watcher); // duplicate
    }
    let mut other = HashMap::new();
    other.insert("tool_use_id".to_string(), JsonValue::Str("toolu_2".into()));
    other.insert("tool_name".to_string(), JsonValue::Str("Read".into()));
    ctx.record(&Event::new(
        "s1",
        EventKind::ToolCall,
        TrustZone::WorkspaceLocal,
        other,
    ));
    let mut r = BufReader::new(sub);
    let (mut a, mut b) = (String::new(), String::new());
    r.read_line(&mut a).unwrap();
    r.read_line(&mut b).unwrap();
    assert!(
        a.contains("toolu_1") && a.contains("\"source\":\"proxy\""),
        "{a}"
    );
    assert!(
        b.contains("toolu_2"),
        "duplicate must not be re-broadcast: {b}"
    );
    let _ = std::fs::remove_dir_all(dir.as_path());
}
