//! Claude Code request-shape smoke test (#58).
//!
//! Claude Code posts `POST /v1/messages?beta=true` with `authorization:
//! Bearer ...`, `anthropic-beta` and `anthropic-version`. A mock upstream
//! asserts the request arrives with path+query and those headers intact,
//! and that the proxy itself never answers a well-formed messages request
//! with a 4xx (Claude Code renders any non-2xx as "model may not exist").

use ember_agent_monitor::net::proxy::{serve, ProxyContext};
use ember_agent_monitor::types::{DaemonConfig, InterventionMode};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

type Seen = Arc<Mutex<Vec<(String, Vec<String>)>>>;

/// Mock upstream: records each request's request line and lowercased headers.
fn spawn_upstream(listener: TcpListener, stop: Arc<AtomicBool>, seen: Seen) {
    listener.set_nonblocking(true).expect("nonblocking");
    thread::spawn(move || loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).ok();
                let request_line = line.trim().to_string();
                let mut headers = Vec::new();
                let mut content_length = 0usize;
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    let h = h.trim_end().to_string();
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                    headers.push(h);
                }
                let mut buf = vec![0u8; content_length];
                let _ = reader.read_exact(&mut buf);
                seen.lock().unwrap().push((request_line, headers));
                let body = br#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}"#;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(head.as_bytes()).ok();
                stream.write_all(body).ok();
                stream.flush().ok();
            }
            Err(_) => thread::sleep(Duration::from_millis(20)),
        }
    });
}

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

fn post(port: u16, target: &str, body: &str) -> String {
    let mut c = TcpStream::connect(format!("127.0.0.1:{port}")).expect("client");
    let req = format!(
        "POST {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nauthorization: Bearer sk-test-123\r\nanthropic-version: 2023-06-01\r\nanthropic-beta: claude-code-20250219,interleaved-thinking-2025-05-14\r\nx-ember-session-id: shape-test-1\r\ncontent-type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    c.write_all(req.as_bytes()).expect("send");
    c.flush().ok();
    let mut resp = String::new();
    c.read_to_string(&mut resp).expect("read response");
    resp
}

#[test]
fn claude_code_messages_beta_true_arrives_intact_and_is_not_4xx() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let upstream_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let up_stop = Arc::new(AtomicBool::new(false));
    spawn_upstream(listener, Arc::clone(&up_stop), Arc::clone(&seen));

    let data_dir = std::env::temp_dir().join(format!("eam-shape-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let port = pick_free_port();
    let cfg = DaemonConfig {
        proxy_port: port,
        mode: InterventionMode::Observe,
        data_dir,
        upstream_anthropic: upstream_url,
        ..DaemonConfig::default()
    };
    let ctx = Arc::new(ProxyContext::new(cfg).expect("ctx"));
    let stop = Arc::new(AtomicBool::new(false));
    let (c2, s2) = (Arc::clone(&ctx), Arc::clone(&stop));
    thread::spawn(move || {
        let _ = serve(c2, s2);
    });
    thread::sleep(Duration::from_millis(200));

    let body =
        r#"{"model":"claude-opus-5-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
    // Both the exact Claude Code shape and the bare path must reach upstream.
    let with_query = post(port, "/v1/messages?beta=true", body);
    let bare = post(port, "/v1/messages", body);

    stop.store(true, Ordering::Relaxed);
    up_stop.store(true, Ordering::Relaxed);

    for (name, resp) in [("?beta=true", &with_query), ("bare", &bare)] {
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "proxy answered {name} with non-2xx: {}",
            resp.lines().next().unwrap_or("")
        );
    }

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "upstream should see both requests: {seen:?}");
    let (line, headers) = &seen[0];
    assert_eq!(line, "POST /v1/messages?beta=true HTTP/1.1");
    let has = |name: &str, value: &str| {
        headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case(&format!("{name}: {value}")))
    };
    assert!(has("authorization", "Bearer sk-test-123"), "{headers:?}");
    assert!(has("anthropic-version", "2023-06-01"), "{headers:?}");
    assert!(
        has(
            "anthropic-beta",
            "claude-code-20250219,interleaved-thinking-2025-05-14"
        ),
        "{headers:?}"
    );
    assert_eq!(seen[1].0, "POST /v1/messages HTTP/1.1");
}
