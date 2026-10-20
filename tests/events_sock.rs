//! The daemon's context must expose `<data_dir>/events.sock` and stream
//! recorded tool_calls to a subscriber (spec §6 — ember-network's input).

use ember_agent_monitor::event::Event;
use ember_agent_monitor::json::JsonValue;
use ember_agent_monitor::net::proxy::ProxyContext;
use ember_agent_monitor::types::{DaemonConfig, EventKind, TrustZone};
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
