//! End-to-end test of the OpenAI-compatible local-lane pass-through
//! (`net::openai_pass`) against a fake llama-server: streaming relay, session
//! recording + the `/sessions/<id>` query, health/props relay, hang-up
//! propagation to the upstream, and block-mode refusal.

use ember_agent_monitor::net::proxy::{serve, ProxyContext};
use ember_agent_monitor::types::{DaemonConfig, InterventionMode};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Fake llama-server. `pieces` SSE chunks, `gap_ms` apart; counts requests and
/// notes whether a write to the client ever failed (client hung up).
struct Upstream {
    url: String,
    hits: Arc<AtomicUsize>,
    saw_hangup: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<(String, String)>>>, // (request line, lowercased headers)
}

fn fake_upstream(pieces: usize, gap_ms: u64) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let hits = Arc::new(AtomicUsize::new(0));
    let saw_hangup = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (h, hang, sn) = (hits.clone(), saw_hangup.clone(), seen.clone());
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { continue };
            let (h, hang, sn) = (h.clone(), hang.clone(), sn.clone());
            thread::spawn(move || {
                let mut rdr = BufReader::new(s.try_clone().unwrap());
                let mut line = String::new();
                rdr.read_line(&mut line).ok();
                let mut headers = String::new();
                let mut clen = 0usize;
                loop {
                    let mut l = String::new();
                    if rdr.read_line(&mut l).unwrap_or(0) == 0 || l == "\r\n" {
                        break;
                    }
                    if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
                        clen = v.trim().parse().unwrap_or(0);
                    }
                    headers.push_str(&l.to_ascii_lowercase());
                }
                let mut body = vec![0u8; clen];
                rdr.read_exact(&mut body).ok();
                h.fetch_add(1, Ordering::SeqCst);
                sn.lock().unwrap().push((line.trim().to_string(), headers));
                if line.starts_with("GET /health") {
                    let b = r#"{"status":"ok"}"#;
                    write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).ok();
                } else if line.starts_with("GET /props") {
                    let b = r#"{"model_alias":"fake-qwen"}"#;
                    write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}", b.len()).ok();
                } else {
                    // chunked SSE, like llama-server
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").ok();
                    for i in 0..pieces {
                        let ev = format!("data: {{\"model\":\"fake-qwen\",\"choices\":[{{\"delta\":{{\"content\":\"w{i} \"}}}}]}}\n\n");
                        let framed = format!("{:x}\r\n{ev}\r\n", ev.len());
                        if s.write_all(framed.as_bytes())
                            .and_then(|_| s.flush())
                            .is_err()
                        {
                            hang.store(true, Ordering::SeqCst);
                            return;
                        }
                        thread::sleep(Duration::from_millis(gap_ms));
                    }
                    let fin = "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3}}\n\ndata: [DONE]\n\n";
                    let framed = format!("{:x}\r\n{fin}\r\n0\r\n\r\n", fin.len());
                    s.write_all(framed.as_bytes()).ok();
                }
            });
        }
    });
    Upstream {
        url,
        hits,
        saw_hangup,
        seen,
    }
}

struct Proxy {
    port: u16,
    data_dir: std::path::PathBuf,
    stop: Arc<AtomicBool>,
}

fn start_proxy(upstream: &str, mode: InterventionMode, tag: &str) -> Proxy {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let data_dir =
        std::env::temp_dir().join(format!("eam-local-lane-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let cfg = DaemonConfig {
        proxy_port: port,
        mode,
        data_dir: data_dir.clone(),
        upstream_openai: upstream.to_string(),
        ..DaemonConfig::default()
    };
    let ctx = Arc::new(ProxyContext::new(cfg).unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let (c, s) = (ctx, stop.clone());
    thread::spawn(move || {
        let _ = serve(c, s);
    });
    // wait for bind
    let t0 = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(t0.elapsed() < Duration::from_secs(5), "proxy did not start");
        thread::sleep(Duration::from_millis(20));
    }
    Proxy {
        port,
        data_dir,
        stop,
    }
}

fn request(port: u16, method: &str, path: &str, extra: &str, body: &str) -> TcpStream {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    c.write_all(req.as_bytes()).unwrap();
    c
}

fn full(port: u16, method: &str, path: &str, extra: &str, body: &str) -> String {
    let mut s = String::new();
    let _ = request(port, method, path, extra, body).read_to_string(&mut s);
    s
}

const CHAT: &str = r#"{"model":"x","stream":true,"messages":[{"role":"user","content":"say hi"}]}"#;

#[test]
fn streams_records_and_session_is_queryable() {
    let up = fake_upstream(3, 10);
    let p = start_proxy(&up.url, InterventionMode::Observe, "stream");
    let resp = full(
        p.port,
        "POST",
        "/openai/v1/chat/completions",
        "x-ember-session-id: job-1\r\n",
        CHAT,
    );
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    assert!(
        resp.to_ascii_lowercase().contains("x-ember-session: job-1"),
        "{resp}"
    );
    assert!(
        resp.contains("text/event-stream") && resp.contains("[DONE]"),
        "{resp}"
    );
    assert!(
        !resp.to_ascii_lowercase().contains("transfer-encoding"),
        "chunk framing leaked: {resp}"
    );
    assert!(resp.contains("w0 ") && resp.contains("w2 "));

    let log = std::fs::read_to_string(p.data_dir.join("sessions/job-1.jsonl")).unwrap();
    assert!(log.contains("\"direction\":\"response\""), "{log}");
    assert!(
        log.contains("w0 w1 w2 "),
        "response text not recorded: {log}"
    );
    assert!(
        log.contains("\"completion_tokens\":3") && log.contains("\"prompt_tokens\":7"),
        "{log}"
    );
    assert!(
        log.contains("latency_ms") && log.contains("fake-qwen"),
        "{log}"
    );

    let q = full(p.port, "GET", "/sessions/job-1", "", "");
    assert!(
        q.starts_with("HTTP/1.1 200") && q.contains("\"responses\":1"),
        "{q}"
    );
    let missing = full(p.port, "GET", "/sessions/no-such-job", "", "");
    assert!(
        missing.starts_with("HTTP/1.1 404") && missing.contains("no_session"),
        "{missing}"
    );
    let evil = full(p.port, "GET", "/sessions/..%2f..%2fetc", "", "");
    assert!(evil.starts_with("HTTP/1.1 404"), "{evil}");
    p.stop.store(true, Ordering::Relaxed);
}

#[test]
fn health_and_props_relay_without_recording() {
    let up = fake_upstream(1, 0);
    let p = start_proxy(&up.url, InterventionMode::Observe, "health");
    let h = full(p.port, "GET", "/openai/health", "", "");
    assert!(
        h.starts_with("HTTP/1.1 200") && h.contains("\"status\":\"ok\""),
        "{h}"
    );
    let pr = full(p.port, "GET", "/openai/props", "", "");
    assert!(pr.contains("fake-qwen"), "{pr}");
    let seen = up.seen.lock().unwrap();
    assert!(
        seen.iter().any(|(l, _)| l.starts_with("GET /health ")),
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|(l, _)| l.starts_with("GET /props ")),
        "{seen:?}"
    );
    assert_eq!(
        std::fs::read_dir(p.data_dir.join("sessions"))
            .unwrap()
            .count(),
        0
    );
    p.stop.store(true, Ordering::Relaxed);
}

#[test]
fn unreachable_upstream_is_502_and_still_recorded() {
    let p = start_proxy("http://127.0.0.1:1", InterventionMode::Observe, "down");
    let resp = full(
        p.port,
        "POST",
        "/openai/v1/chat/completions",
        "x-ember-session-id: job-down\r\n",
        CHAT,
    );
    assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
    let q = full(p.port, "GET", "/sessions/job-down", "", "");
    assert!(
        q.contains("\"responses\":1"),
        "failure must still leave a graph: {q}"
    );
    p.stop.store(true, Ordering::Relaxed);
}

#[test]
fn client_hangup_reaches_the_upstream() {
    let up = fake_upstream(400, 25); // ~10 s if nobody stops it
    let p = start_proxy(&up.url, InterventionMode::Observe, "hangup");
    let mut c = request(
        p.port,
        "POST",
        "/openai/v1/chat/completions",
        "x-ember-session-id: job-h\r\n",
        CHAT,
    );
    let mut buf = [0u8; 512];
    let n = c.read(&mut buf).unwrap();
    assert!(n > 0);
    drop(c);
    let t0 = Instant::now();
    while !up.saw_hangup.load(Ordering::SeqCst) {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "upstream never saw the hang-up"
        );
        thread::sleep(Duration::from_millis(50));
    }
    p.stop.store(true, Ordering::Relaxed);
}

#[test]
fn block_mode_refuses_planted_sensitive_write_before_forwarding() {
    let up = fake_upstream(1, 0);
    let p = start_proxy(&up.url, InterventionMode::Block, "block");
    let body = r#"{"model":"x","messages":[{"role":"assistant","tool_calls":[{"id":"t1","type":"function","function":{"name":"mcp__filesystem__write_file","arguments":"{\"path\":\"/Users/aaron/.ssh/.git/config\",\"content\":\"x\"}"}}]}]}"#;
    let resp = full(
        p.port,
        "POST",
        "/openai/v1/chat/completions",
        "x-ember-session-id: job-b\r\n",
        body,
    );
    assert!(resp.starts_with("HTTP/1.1 451"), "{resp}");
    assert_eq!(
        up.hits.load(Ordering::SeqCst),
        0,
        "blocked request must not reach the model"
    );
    let findings = std::fs::read_to_string(p.data_dir.join("findings/job-b.jsonl")).unwrap();
    assert!(findings.contains("sensitive_zone_access"), "{findings}");
    p.stop.store(true, Ordering::Relaxed);
}

#[test]
fn proxy_listens_on_loopback_only() {
    let p = start_proxy("http://127.0.0.1:1", InterventionMode::Observe, "loop");
    // Bound to 127.0.0.1: a connect to the same port via the loopback works;
    // the source says `127.0.0.1:{port}` (net::proxy::serve), so no external bind.
    let src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/net/proxy.rs")).unwrap();
    assert!(src.contains(r#"format!("127.0.0.1:{}", ctx.config.proxy_port)"#));
    p.stop.store(true, Ordering::Relaxed);
}
