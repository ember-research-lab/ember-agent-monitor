//! End-to-end test of the `warn` intervention mode against a mock upstream.
//!
//! The mock upstream is a small TcpListener that records every request body
//! it receives and returns a canned Anthropic-shaped response. We send a
//! request through our proxy that should trigger a high-severity finding
//! (sensitive_zone_access) and assert:
//!
//!   1. The upstream received the request (proxy forwarded it).
//!   2. The forwarded request body contains our injected `[ember-agent
//!      advisory]` warning in the system prompt.
//!   3. The proxy's reply to the client carries the upstream response back.
//!   4. The finding was recorded under findings/<sid>.jsonl.
//!
//! No real Anthropic API access required.

use ember_agent_monitor::net::proxy::{serve, ProxyContext};
use ember_agent_monitor::types::{DaemonConfig, InterventionMode};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[test]
fn warn_mode_injects_system_prompt_advisory() {
    // -- Mock upstream --
    let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("upstream bind");
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let upstream_url = format!("http://127.0.0.1:{}", upstream_addr.port());

    let received_bodies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let received_bodies_clone = Arc::clone(&received_bodies);
    let upstream_stop = Arc::new(AtomicBool::new(false));
    let upstream_stop_clone = Arc::clone(&upstream_stop);
    upstream_listener
        .set_nonblocking(true)
        .expect("nonblocking");
    let _upstream_thread = thread::spawn(move || {
        loop {
            if upstream_stop_clone.load(Ordering::Relaxed) {
                return;
            }
            match upstream_listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    let mut rdr = BufReader::new(stream.try_clone().unwrap());
                    // Skip request line
                    let mut line = String::new();
                    rdr.read_line(&mut line).ok();
                    // Read headers, capture content-length
                    let mut content_length: usize = 0;
                    loop {
                        let mut h = String::new();
                        if rdr.read_line(&mut h).unwrap_or(0) == 0 {
                            break;
                        }
                        let trimmed = h.trim_end_matches(['\r', '\n']);
                        if trimmed.is_empty() {
                            break;
                        }
                        if let Some(rest) =
                            trimmed.to_ascii_lowercase().strip_prefix("content-length:")
                        {
                            content_length = rest.trim().parse().unwrap_or(0);
                        }
                    }
                    let mut body = vec![0u8; content_length];
                    if content_length > 0 {
                        rdr.read_exact(&mut body).ok();
                    }
                    let body_str = String::from_utf8_lossy(&body).to_string();
                    received_bodies_clone.lock().unwrap().push(body_str);
                    // Canned Anthropic response.
                    let resp_body = br#"{"id":"msg_x","type":"message","role":"assistant","content":[{"type":"text","text":"acknowledged"}],"model":"x","stop_reason":"end_turn"}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        resp_body.len()
                    );
                    stream.write_all(resp.as_bytes()).ok();
                    stream.write_all(resp_body).ok();
                    stream.flush().ok();
                }
                Err(_) => thread::sleep(Duration::from_millis(20)),
            }
        }
    });

    // -- Proxy in warn mode --
    let data_dir = std::env::temp_dir().join(format!("eam-warn-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let cfg = DaemonConfig {
        proxy_port: pick_free_port(),
        mode: InterventionMode::Warn,
        data_dir: data_dir.clone(),
        upstream_anthropic: upstream_url,
        ..DaemonConfig::default()
    };

    let ctx = Arc::new(ProxyContext::new(cfg.clone()).expect("ctx"));
    let stop = Arc::new(AtomicBool::new(false));
    let ctx_clone = Arc::clone(&ctx);
    let stop_clone = Arc::clone(&stop);
    let _proxy_thread = thread::spawn(move || {
        let _ = serve(ctx_clone, stop_clone);
    });
    thread::sleep(Duration::from_millis(200)); // bind delay

    // -- Send a request that should trigger a high-sev finding --
    let request_body = r#"{"model":"claude-opus","messages":[
      {"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"mcp__filesystem__write_file","input":{"path":"/Users/aaron/.ssh/.git/config","content":"x"}}]}
    ]}"#;
    let mut client = TcpStream::connect(format!("127.0.0.1:{}", cfg.proxy_port)).expect("client");
    let req = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nx-claude-session-id: warn-test-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        request_body.len()
    );
    client.write_all(req.as_bytes()).expect("send headers");
    client
        .write_all(request_body.as_bytes())
        .expect("send body");
    client.flush().ok();

    let mut response = String::new();
    client.read_to_string(&mut response).expect("read response");

    // Tear down — set stop flags but DO NOT join the proxy thread; its
    // accept loop blocks indefinitely on listener.incoming(). Test exit
    // cleans up. Documented gap in proxy::serve; fix is to switch to a
    // nonblocking-with-timeout listener.
    stop.store(true, Ordering::Relaxed);
    upstream_stop.store(true, Ordering::Relaxed);
    drop(client);
    thread::sleep(Duration::from_millis(50));

    // -- Assertions --
    let bodies = received_bodies.lock().unwrap();
    assert_eq!(
        bodies.len(),
        1,
        "expected upstream to receive exactly 1 request, got {}",
        bodies.len()
    );
    let upstream_body = &bodies[0];
    assert!(
        upstream_body.contains("[ember-agent advisory]"),
        "expected injected advisory in forwarded body, got: {upstream_body}"
    );
    assert!(
        upstream_body.contains("sensitive_zone_access"),
        "expected the advisory to name the finding type"
    );

    assert!(
        response.contains("acknowledged"),
        "expected upstream's response to flow back to client; got: {response}"
    );

    // findings.jsonl recorded
    let findings_path = data_dir.join("findings/warn-test-1.jsonl");
    let findings_content = std::fs::read_to_string(findings_path).expect("read findings");
    assert!(
        findings_content.contains("sensitive_zone_access"),
        "expected finding recorded; got: {findings_content}"
    );

    let _ = std::fs::remove_dir_all(&data_dir);
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}
