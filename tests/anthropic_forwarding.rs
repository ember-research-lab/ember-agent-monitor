//! Anthropic forwarder fidelity (#60): the proxy must relay what the
//! upstream said, not what it would have liked to hear.
//!
//! Mock upstream answers like api.anthropic.com does: error statuses with
//! `retry-after` / `request-id`, a declared `Content-Encoding`, and chunked
//! `text/event-stream`. No new HTTP dependency: raw sockets on both sides.

use ember_agent_monitor::net::proxy::{serve, ProxyContext};
use ember_agent_monitor::types::{DaemonConfig, InterventionMode};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type SeenHeaders = Arc<Mutex<Vec<Vec<String>>>>;

/// What the mock upstream does with one accepted connection.
type Reply = Box<dyn Fn(&mut TcpStream) + Send + Sync>;

struct Harness {
    port: u16,
    seen: SeenHeaders,
    stop: Arc<AtomicBool>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn start(tag: &str, mode: InterventionMode, reply: Reply) -> Harness {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let upstream_url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    listener.set_nonblocking(true).unwrap();
    let seen: SeenHeaders = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (seen2, stop2) = (Arc::clone(&seen), Arc::clone(&stop));
    thread::spawn(move || loop {
        if stop2.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).ok();
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut rdr = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                rdr.read_line(&mut line).ok();
                let mut headers = vec![line.trim().to_string()];
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if rdr.read_line(&mut h).unwrap_or(0) == 0 || h == "\r\n" {
                        break;
                    }
                    let h = h.trim_end().to_string();
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    headers.push(h);
                }
                let mut body = vec![0u8; len];
                let _ = rdr.read_exact(&mut body);
                seen2.lock().unwrap().push(headers);
                reply(&mut stream);
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    });

    let data_dir = std::env::temp_dir().join(format!("eam-fwd-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let cfg = DaemonConfig {
        proxy_port: port,
        mode,
        data_dir,
        upstream_anthropic: upstream_url,
        ..DaemonConfig::default()
    };
    let ctx = Arc::new(ProxyContext::new(cfg).expect("ctx"));
    let (c2, s2) = (ctx, Arc::clone(&stop));
    thread::spawn(move || {
        let _ = serve(c2, s2);
    });
    thread::sleep(Duration::from_millis(200));
    Harness { port, seen, stop }
}

const BODY: &str =
    r#"{"model":"claude-opus-5-5","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}"#;
const STREAM_BODY: &str = r#"{"model":"claude-opus-5-5","max_tokens":1,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;

/// Send like Claude Code (incl. `accept-encoding`); return the connection.
fn send(port: u16, body: &str) -> TcpStream {
    let mut c = TcpStream::connect(format!("127.0.0.1:{port}")).expect("client");
    c.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let req = format!(
        "POST /v1/messages?beta=true HTTP/1.1\r\nHost: 127.0.0.1\r\nauthorization: Bearer x\r\nanthropic-version: 2023-06-01\r\naccept-encoding: gzip, deflate, br\r\ncontent-type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    c.write_all(req.as_bytes()).unwrap();
    c
}

struct Resp {
    status_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Resp {
    fn header(&self, n: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.as_str())
    }
}

fn split_head(raw: &[u8]) -> (Resp, usize) {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response head");
    let text = String::from_utf8_lossy(&raw[..end]).to_string();
    let mut lines = text.lines();
    let status_line = lines.next().unwrap().to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (
        Resp {
            status_line,
            headers,
            body: Vec::new(),
        },
        end + 4,
    )
}

/// Read to EOF; body is returned exactly as framed (de-chunked if chunked).
fn read_all(mut c: TcpStream) -> Resp {
    let mut raw = Vec::new();
    c.read_to_end(&mut raw).expect("read response");
    let (mut resp, at) = split_head(&raw);
    let body = &raw[at..];
    resp.body = if resp
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
    {
        dechunk(body)
    } else {
        body.to_vec()
    };
    resp
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let nl = b.windows(2).position(|w| w == b"\r\n").expect("chunk size");
        let n = usize::from_str_radix(std::str::from_utf8(&b[..nl]).unwrap().trim(), 16).unwrap();
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&b[nl + 2..nl + 2 + n]);
        b = &b[nl + 2 + n + 2..];
    }
}

fn plain(status: &str, extra: &str, body: &'static [u8]) -> Reply {
    let head = format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    Box::new(move |s: &mut TcpStream| {
        s.write_all(head.as_bytes()).ok();
        s.write_all(body).ok();
        s.flush().ok();
    })
}

#[test]
fn accept_encoding_is_not_forwarded_and_declared_encoding_stays_consistent() {
    // Not real gzip; the point is that header and bytes reach the client as sent.
    const GZ: &[u8] = &[0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
    let h = start(
        "gzip",
        InterventionMode::Observe,
        plain(
            "200 OK",
            "Content-Type: application/json\r\nContent-Encoding: gzip\r\n",
            GZ,
        ),
    );
    let resp = read_all(send(h.port, BODY));
    let seen = h.seen.lock().unwrap();
    // Fails pre-fix: curl forwarded the client's accept-encoding.
    assert!(
        !seen[0]
            .iter()
            .any(|l| l.to_ascii_lowercase().starts_with("accept-encoding")),
        "upstream must not be offered compression: {:?}",
        seen[0]
    );
    // Fails pre-fix: bytes were relayed with no Content-Encoding label.
    assert_eq!(resp.header("content-encoding"), Some("gzip"));
    assert_eq!(resp.body, GZ);
    assert_eq!(
        resp.header("content-length"),
        Some(GZ.len().to_string().as_str())
    );
}

#[test]
fn upstream_401_reaches_client_with_status_and_request_id() {
    let body: &'static [u8] =
        br#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#;
    let h = start(
        "401",
        InterventionMode::Observe,
        plain(
            "401 Unauthorized",
            "Content-Type: application/json\r\nrequest-id: req_011abc\r\n",
            body,
        ),
    );
    let resp = read_all(send(h.port, BODY));
    // Fails pre-fix: status line was always "HTTP/1.1 200 OK".
    assert_eq!(resp.status_line, "HTTP/1.1 401 Unauthorized");
    assert_eq!(resp.header("request-id"), Some("req_011abc"));
    assert_eq!(resp.body, body);
}

#[test]
fn upstream_529_keeps_retry_after_and_rate_limit_headers() {
    let body: &'static [u8] =
        br#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#;
    let h = start(
        "529",
        InterventionMode::Observe,
        plain(
            "529 Overloaded",
            "Content-Type: application/json\r\nretry-after: 7\r\nanthropic-ratelimit-requests-remaining: 0\r\n",
            body,
        ),
    );
    let resp = read_all(send(h.port, BODY));
    // Fails pre-fix: 200, and retry-after dropped.
    assert!(
        resp.status_line.starts_with("HTTP/1.1 529"),
        "{}",
        resp.status_line
    );
    assert_eq!(resp.header("retry-after"), Some("7"));
    assert_eq!(
        resp.header("anthropic-ratelimit-requests-remaining"),
        Some("0")
    );
    assert_eq!(resp.body, body);
}

fn sse_events() -> Vec<String> {
    vec![
        r#"event: message_start
data: {"type":"message_start","message":{"id":"msg_1","role":"assistant","content":[]}}

"#
        .into(),
        r#"event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

"#
        .into(),
        r#"event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}

"#
        .into(),
        r#"event: content_block_stop
data: {"type":"content_block_stop","index":0}

"#
        .into(),
        r#"event: message_stop
data: {"type":"message_stop"}

"#
        .into(),
    ]
}

fn sse_reply(events: Vec<String>) -> Reply {
    Box::new(move |s: &mut TcpStream| {
        s.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .ok();
        for e in &events {
            s.write_all(format!("{:x}\r\n{e}\r\n", e.len()).as_bytes())
                .ok();
            s.flush().ok();
            thread::sleep(Duration::from_millis(300));
        }
        s.write_all(b"0\r\n\r\n").ok();
        s.flush().ok();
    })
}

#[test]
fn sse_stream_passes_through_in_order_and_incrementally() {
    let events = sse_events();
    let h = start("sse", InterventionMode::Observe, sse_reply(events.clone()));
    let mut c = send(h.port, STREAM_BODY);
    let started = Instant::now();
    let mut raw = Vec::new();
    let mut first_event_at = None;
    let mut buf = [0u8; 4096];
    loop {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if first_event_at.is_none()
                    && String::from_utf8_lossy(&raw).contains("message_start")
                {
                    first_event_at = Some(started.elapsed());
                }
            }
        }
    }
    let total = started.elapsed();
    let (mut resp, at) = split_head(&raw);
    resp.body = dechunk(&raw[at..]);
    // Fails pre-fix: Content-Type was application/json.
    assert!(
        resp.status_line.starts_with("HTTP/1.1 200"),
        "{}",
        resp.status_line
    );
    assert_eq!(resp.header("content-type"), Some("text/event-stream"));
    assert_eq!(resp.header("transfer-encoding"), Some("chunked"));
    assert!(resp.header("content-length").is_none());
    // All events, in order, byte-for-byte.
    assert_eq!(String::from_utf8(resp.body).unwrap(), events.concat());
    // Fails pre-fix: the stream was buffered, so nothing arrived until the end.
    let first = first_event_at.expect("first event");
    assert!(
        total.saturating_sub(first) > Duration::from_millis(600),
        "first event at {first:?}, stream ended at {total:?}: not incremental"
    );
}

#[test]
fn sse_tool_use_is_inspected_in_observe_mode() {
    let events = vec![
        r#"data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"mcp__filesystem__write_file","input":{}}}

"#.to_string(),
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"path\":\"/Users/aaron/.ssh/"}}

"#.to_string(),
        r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"authorized_keys\",\"content\":\"x\"}"}}

"#.to_string(),
        r#"data: {"type":"content_block_stop","index":0}

"#.to_string(),
    ];
    let h = start(
        "ssetool",
        InterventionMode::Observe,
        sse_reply(events.clone()),
    );
    let mut body = Vec::new();
    let mut c = send(h.port, STREAM_BODY);
    c.read_to_end(&mut body).unwrap();
    assert!(String::from_utf8_lossy(&body).contains("authorized_keys"));
    // The reassembled tool_use reached the session log (x-ember session is
    // derived from the first user message: look for the ToolCall event).
    let dir = std::env::temp_dir().join(format!("eam-fwd-ssetool-{}", std::process::id()));
    let mut found = false;
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(t) = std::fs::read_to_string(&p) {
                found |= t.contains("toolu_1") && t.contains("authorized_keys");
            }
        }
    }
    assert!(found, "SSE tool_use not recorded");
}

#[test]
fn warn_mode_refuses_stream_request_naming_issue_60() {
    let h = start(
        "warnstream",
        InterventionMode::Warn,
        plain("200 OK", "Content-Type: application/json\r\n", b"{}"),
    );
    let resp = read_all(send(h.port, STREAM_BODY));
    assert!(
        resp.status_line.starts_with("HTTP/1.1 501"),
        "{}",
        resp.status_line
    );
    assert!(String::from_utf8_lossy(&resp.body).contains("#60"));
    assert!(h.seen.lock().unwrap().is_empty(), "must not forward");
}

#[test]
fn warn_mode_still_serves_non_stream_requests() {
    let body: &'static [u8] = br#"{"id":"m","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn"}"#;
    let h = start(
        "warnplain",
        InterventionMode::Warn,
        plain("200 OK", "Content-Type: application/json\r\n", body),
    );
    let resp = read_all(send(h.port, BODY));
    assert!(resp.status_line.starts_with("HTTP/1.1 200"));
    assert_eq!(resp.body, body);
}
