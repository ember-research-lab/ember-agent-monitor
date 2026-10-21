//! Local-model Anthropic route (#74): `/local/v1/messages` reaches a
//! configured local upstream (llama-server) and nothing else does.
//!
//! Two in-process stubs: a "local" upstream and a "cloud" upstream
//! (`upstream_anthropic`). The cloud stub is the tripwire: a request meant for
//! the local model that lands there is a silent cloud bill, so every test
//! asserts where it did and did not arrive. Raw sockets, no HTTP dependency.

use ember_agent_monitor::net::proxy::{serve, ProxyContext};
use ember_agent_monitor::types::{DaemonConfig, InterventionMode};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// (request line, body) per request the stub accepted.
type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
type Reply = Arc<dyn Fn(&mut TcpStream) + Send + Sync>;

struct Stub {
    url: String,
    seen: Seen,
}

fn stub(stop: &Arc<AtomicBool>, reply: Reply) -> Stub {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    listener.set_nonblocking(true).unwrap();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let (seen2, stop2) = (Arc::clone(&seen), Arc::clone(stop));
    thread::spawn(move || loop {
        if stop2.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((mut s, _)) => {
                s.set_nonblocking(false).ok();
                s.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut rdr = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                rdr.read_line(&mut line).ok();
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if rdr.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; len];
                let _ = rdr.read_exact(&mut body);
                seen2.lock().unwrap().push((line.trim().to_string(), body));
                reply(&mut s);
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    });
    Stub { url, seen }
}

fn json_reply(text: &'static str) -> Reply {
    Arc::new(move |s: &mut TcpStream| {
        let body = format!(
            r#"{{"id":"msg_1","type":"message","role":"assistant","model":"flint","content":[{{"type":"text","text":"{text}"}}],"stop_reason":"end_turn","usage":{{"input_tokens":1,"output_tokens":1}}}}"#
        );
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        s.write_all(head.as_bytes()).ok();
        s.write_all(body.as_bytes()).ok();
        s.flush().ok();
    })
}

struct Fixture {
    port: u16,
    dir: std::path::PathBuf,
    stop: Arc<AtomicBool>,
    local: Stub,
    cloud: Stub,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// `local_url`: `Some(None)` = point at a closed port; `None` = unconfigured.
fn start(tag: &str, local_reply: Reply, local_url: Option<Option<&str>>) -> Fixture {
    let stop = Arc::new(AtomicBool::new(false));
    let local = stub(&stop, local_reply);
    let cloud = stub(&stop, json_reply("CLOUD"));
    let upstream_local_anthropic = match local_url {
        None => None,
        Some(None) => Some(local.url.clone()),
        Some(Some(u)) => Some(u.to_string()),
    };
    let dir = std::env::temp_dir().join(format!("eam-local74-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let cfg = DaemonConfig {
        proxy_port: port,
        mode: InterventionMode::Observe,
        data_dir: dir.clone(),
        upstream_anthropic: cloud.url.clone(),
        upstream_local_anthropic,
        ..DaemonConfig::default()
    };
    let ctx = Arc::new(ProxyContext::new(cfg).expect("ctx"));
    let stop2 = Arc::clone(&stop);
    thread::spawn(move || {
        let _ = serve(ctx, stop2);
    });
    thread::sleep(Duration::from_millis(200));
    Fixture {
        port,
        dir,
        stop,
        local,
        cloud,
    }
}

const BODY: &str =
    r#"{"model":"flint","max_tokens":8,"messages":[{"role":"user","content":"say ok"}]}"#;
const STREAM_BODY: &str = r#"{"model":"flint","max_tokens":8,"stream":true,"messages":[{"role":"user","content":"say ok"}]}"#;

/// POST like Claude Code; returns (status line, de-chunked body, raw bytes).
fn post(port: u16, path: &str, session: &str, body: &str) -> (String, String) {
    let mut c = TcpStream::connect(format!("127.0.0.1:{port}")).expect("client");
    c.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nx-claude-session-id: {session}\r\nx-api-key: local\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    c.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = c.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text.lines().next().unwrap_or("").to_string();
    (status, text)
}

fn count(s: &Stub) -> usize {
    s.seen.lock().unwrap().len()
}

#[test]
fn local_request_reaches_local_stub_with_body_and_query_intact() {
    let f = start("route", json_reply("LOCAL-OK"), Some(None));
    let (status, text) = post(f.port, "/local/v1/messages?beta=true", "r1", BODY);
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(text.contains("LOCAL-OK"), "{text}");
    let seen = f.local.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    // `/local` prefix is stripped; query preserved.
    assert_eq!(seen[0].0, "POST /v1/messages?beta=true HTTP/1.1");
    assert_eq!(seen[0].1, BODY.as_bytes());
    assert_eq!(
        count(&f.cloud),
        0,
        "local request leaked to the cloud upstream"
    );
}

#[test]
fn unmatched_requests_are_not_routed_locally() {
    let f = start("unmatched", json_reply("LOCAL-OK"), Some(None));
    // Today's behaviour: plain /v1/messages goes to upstream_anthropic.
    let (status, text) = post(f.port, "/v1/messages?beta=true", "u1", BODY);
    assert!(
        status.starts_with("HTTP/1.1 200") && text.contains("CLOUD"),
        "{text}"
    );
    assert_eq!(count(&f.cloud), 1);
    assert_eq!(
        count(&f.local),
        0,
        "cloud request leaked to the local upstream"
    );
    // Near-miss paths are not routed anywhere (exact match, no prefix/traversal).
    for p in [
        "/local/v1/messages/extra",
        "/local/v1/../v1/messages",
        "/local/v1/messages%2f..",
        "/local/",
        "/locals/v1/messages",
    ] {
        let (status, _) = post(f.port, p, "u2", BODY);
        assert!(status.starts_with("HTTP/1.1 404"), "{p}: {status}");
    }
    assert_eq!(count(&f.cloud), 1);
    assert_eq!(count(&f.local), 0);
}

#[test]
fn unconfigured_local_route_is_an_explicit_error_not_a_cloud_fallback() {
    let f = start("unconf", json_reply("LOCAL-OK"), None);
    let (status, text) = post(f.port, "/local/v1/messages?beta=true", "c1", BODY);
    assert!(status.starts_with("HTTP/1.1 503"), "{status}");
    assert!(text.contains("ember_local_route_unconfigured"), "{text}");
    assert_eq!(count(&f.cloud), 0, "fell back to the cloud upstream");
    assert_eq!(count(&f.local), 0);
}

#[test]
fn unreachable_local_upstream_is_502_and_never_falls_back() {
    // Port 1 on loopback: connection refused.
    let f = start(
        "down",
        json_reply("LOCAL-OK"),
        Some(Some("http://127.0.0.1:1")),
    );
    let (status, text) = post(f.port, "/local/v1/messages?beta=true", "d1", BODY);
    assert!(status.starts_with("HTTP/1.1 502"), "{status}");
    assert!(text.contains("upstream"), "{text}");
    assert!(!text.contains("CLOUD"));
    assert_eq!(count(&f.cloud), 0, "fell back to the cloud upstream");
}

fn sse_reply() -> Reply {
    Arc::new(|s: &mut TcpStream| {
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").ok();
        for e in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"role\":\"assistant\",\"content\":[]}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"STREAMED-OK\"}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            s.write_all(format!("{:x}\r\n{e}\r\n", e.len()).as_bytes()).ok();
            s.flush().ok();
            thread::sleep(Duration::from_millis(300));
        }
        s.write_all(b"0\r\n\r\n").ok();
        s.flush().ok();
    })
}

#[test]
fn local_sse_streams_through_incrementally() {
    let f = start("sse", sse_reply(), Some(None));
    let mut c = TcpStream::connect(format!("127.0.0.1:{}", f.port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let req = format!(
        "POST /local/v1/messages?beta=true HTTP/1.1\r\nHost: x\r\nx-claude-session-id: s1\r\ncontent-type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{STREAM_BODY}",
        STREAM_BODY.len()
    );
    c.write_all(req.as_bytes()).unwrap();
    let t = Instant::now();
    let (mut raw, mut buf, mut first) = (Vec::new(), [0u8; 4096], None);
    loop {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if first.is_none() && String::from_utf8_lossy(&raw).contains("message_start") {
                    first = Some(t.elapsed());
                }
            }
        }
    }
    let text = String::from_utf8_lossy(&raw).to_string();
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text
        .to_ascii_lowercase()
        .contains("content-type: text/event-stream"));
    assert!(text.contains("STREAMED-OK") && text.contains("message_stop"));
    assert!(
        t.elapsed().saturating_sub(first.expect("first event")) > Duration::from_millis(600),
        "stream was buffered, not incremental"
    );
    assert_eq!(count(&f.cloud), 0);
}

/// Event-type multiset of a session log, ids and timestamps ignored.
fn event_kinds(dir: &std::path::Path, session: &str) -> Vec<String> {
    let path = dir.join(format!("sessions/{session}.jsonl"));
    let mut kinds: Vec<String> = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let i = l.find("\"kind\"")?;
            let rest = &l[i + 6..];
            let a = rest.find('"')? + 1;
            let b = a + rest[a..].find('"')?;
            Some(rest[a..b].to_string())
        })
        .collect();
    kinds.sort();
    kinds
}

#[test]
fn local_session_is_recorded_like_a_cloud_session() {
    let f = start("rec", json_reply("RECORDED-OK"), Some(None));
    // Same conversation sent down both routes, different session ids.
    post(f.port, "/v1/messages?beta=true", "cloud-sess", BODY);
    post(f.port, "/local/v1/messages?beta=true", "local-sess", BODY);
    // Observe-mode ingest is asynchronous: wait for both logs to settle.
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(10) {
        let (a, b) = (
            event_kinds(&f.dir, "cloud-sess"),
            event_kinds(&f.dir, "local-sess"),
        );
        if !a.is_empty() && a.len() == b.len() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let cloud = event_kinds(&f.dir, "cloud-sess");
    let local = event_kinds(&f.dir, "local-sess");
    assert!(
        !local.is_empty(),
        "local session not recorded in {:?}",
        f.dir
    );
    assert_eq!(
        cloud, local,
        "local session recorded differently from cloud"
    );
    let log = std::fs::read_to_string(f.dir.join("sessions/local-sess.jsonl")).unwrap();
    assert!(
        log.contains("say ok") && log.contains("RECORDED-OK"),
        "{log}"
    );
}
