//! End-to-end test of the OpenAI-compatible protocol path.
//!
//! Verifies:
//!   1. A POST to /openai/v1/chat/completions parses, records events, and
//!      forwards upstream with the local /openai prefix stripped.
//!   2. A request whose body shape disagrees with the path emits a
//!      `protocol_mismatch_attempt` finding.
//!   3. Tool-result content arriving as `role: tool` lands in the events
//!      with TrustZone::UntrustedToolOutput (the schema-discipline
//!      invariant, vendor-independent).

use ember_agent_monitor::net::proxy::{serve, ProxyContext};
use ember_agent_monitor::types::{DaemonConfig, InterventionMode};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[test]
fn openai_path_forwards_with_prefix_stripped() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("upstream bind");
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_url = format!("http://127.0.0.1:{}", upstream_addr.port());

    let received_paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let received_paths_clone = Arc::clone(&received_paths);
    let upstream_stop = Arc::new(AtomicBool::new(false));
    let upstream_stop_clone = Arc::clone(&upstream_stop);
    upstream_listener
        .set_nonblocking(true)
        .expect("nonblocking");

    let _upstream_thread = thread::spawn(move || loop {
        if upstream_stop_clone.load(Ordering::Relaxed) {
            return;
        }
        match upstream_listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                reader.read_line(&mut request_line).ok();
                received_paths_clone
                    .lock()
                    .unwrap()
                    .push(request_line.trim().to_string());
                // Drain headers + body
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if let Some(rest) = line.strip_prefix("Content-Length:") {
                        content_length = rest.trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                if content_length > 0 {
                    let mut buf = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut buf);
                }
                let resp_body = br#"{"choices":[{"message":{"role":"assistant","content":"ok"}}]}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp_body.len()
                );
                stream.write_all(resp.as_bytes()).ok();
                stream.write_all(resp_body).ok();
                stream.flush().ok();
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    });

    let data_dir = std::env::temp_dir().join(format!("eam-openai-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let port = pick_free_port();
    let cfg = DaemonConfig {
        proxy_port: port,
        mode: InterventionMode::Observe,
        data_dir: data_dir.clone(),
        upstream_openai: upstream_url,
        ..DaemonConfig::default()
    };

    let ctx = Arc::new(ProxyContext::new(cfg.clone()).expect("ctx"));
    let stop = Arc::new(AtomicBool::new(false));
    let ctx_clone = Arc::clone(&ctx);
    let stop_clone = Arc::clone(&stop);
    let _proxy_thread = thread::spawn(move || {
        let _ = serve(ctx_clone, stop_clone);
    });
    thread::sleep(Duration::from_millis(200));

    let request_body = r#"{"model":"gpt-4o","messages":[
      {"role":"user","content":"hello"},
      {"role":"assistant","tool_calls":[{"id":"t1","type":"function",
        "function":{"name":"read","arguments":"{\"path\":\"/tmp/x\"}"}}]},
      {"role":"tool","tool_call_id":"t1","content":"file contents"}
    ]}"#;
    let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).expect("client");
    let req = format!(
        "POST /openai/v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nx-ember-session-id: openai-test-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request_body.len()
    );
    client.write_all(req.as_bytes()).expect("send headers");
    client
        .write_all(request_body.as_bytes())
        .expect("send body");
    client.flush().ok();
    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");

    stop.store(true, Ordering::Relaxed);
    upstream_stop.store(true, Ordering::Relaxed);
    drop(client);
    thread::sleep(Duration::from_millis(50));

    // Assertion 1: upstream saw the prefix-stripped path.
    let paths = received_paths.lock().unwrap();
    assert!(
        paths
            .iter()
            .any(|p| p.contains("/v1/chat/completions") && !p.contains("/openai/")),
        "expected upstream to receive /v1/chat/completions (no /openai prefix), got: {paths:?}"
    );

    // Assertion 2: events were recorded — session log exists and contains
    // the tool result with the right trust zone.
    let session_log = data_dir.join("sessions/openai-test-1.jsonl");
    let log_content = std::fs::read_to_string(&session_log)
        .unwrap_or_else(|_| panic!("expected session log at {}", session_log.display()));
    assert!(
        log_content.contains("\"kind\":\"tool_result\"")
            || log_content.contains("\"kind\": \"tool_result\""),
        "expected tool_result event in session log; got: {log_content}"
    );
    assert!(
        log_content.contains("untrusted_tool_output"),
        "expected schema-discipline invariant: tool result trust_zone = untrusted_tool_output; got: {log_content}"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

#[test]
fn protocol_mismatch_fires_finding() {
    // Send Anthropic-shaped body to the OpenAI path. Should record a
    // `protocol_mismatch_attempt` finding regardless of upstream
    // reachability.
    let data_dir = std::env::temp_dir().join(format!(
        "eam-mismatch-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&data_dir);
    let port = pick_free_port();
    let cfg = DaemonConfig {
        proxy_port: port,
        mode: InterventionMode::Observe,
        data_dir: data_dir.clone(),
        // Point at an unreachable upstream; we don't care if the forward
        // succeeds — we only care that the finding is recorded BEFORE
        // forwarding.
        upstream_openai: "http://127.0.0.1:1".into(),
        ..DaemonConfig::default()
    };
    let ctx = Arc::new(ProxyContext::new(cfg.clone()).expect("ctx"));
    let stop = Arc::new(AtomicBool::new(false));
    let ctx_clone = Arc::clone(&ctx);
    let stop_clone = Arc::clone(&stop);
    let _proxy_thread = thread::spawn(move || {
        let _ = serve(ctx_clone, stop_clone);
    });
    thread::sleep(Duration::from_millis(200));

    // Anthropic-shaped body to OpenAI path.
    let request_body =
        r#"{"model":"claude-opus-4-7","anthropic_version":"2023-06-01","messages":[]}"#;
    let mut client = TcpStream::connect(format!("127.0.0.1:{port}")).expect("client");
    let req = format!(
        "POST /openai/v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nx-ember-session-id: mismatch-test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request_body.len()
    );
    client.write_all(req.as_bytes()).expect("send headers");
    client
        .write_all(request_body.as_bytes())
        .expect("send body");
    client.flush().ok();
    let mut response = String::new();
    let _ = client.read_to_string(&mut response);

    stop.store(true, Ordering::Relaxed);
    drop(client);
    thread::sleep(Duration::from_millis(100));

    // Finding should be recorded under findings/mismatch-test.jsonl.
    let findings_path = data_dir.join("findings/mismatch-test.jsonl");
    let findings_content = std::fs::read_to_string(&findings_path)
        .unwrap_or_else(|_| panic!("expected findings at {}", findings_path.display()));
    assert!(
        findings_content.contains("protocol_mismatch_attempt"),
        "expected protocol_mismatch_attempt finding; got: {findings_content}"
    );
    assert!(
        findings_content.contains("Anthropic-shaped body sent to OpenAI path"),
        "expected mismatch reason in rationale; got: {findings_content}"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}
