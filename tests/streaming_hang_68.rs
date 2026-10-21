//! #68: main-thread streaming requests hung behind analysis in the request path.
//!
//! Claude Code replays the whole conversation on every request. The proxy re-ingested all of it
//! into the session graph and ran O(n^3) spectral analysis (under a global lock, before the
//! forward), so a long session's request waited minutes and queued every other request behind
//! it. These tests pin: replayed history costs nothing, a silent upstream is failed loudly with
//! a 502 (watchdog), and the live streaming-with-thinking path (ignored, needs network).
//!
//! `EMBER_AGENT_FIRST_BYTE_SECS` is process-global, so everything that sets it lives in this one
//! test binary and is set once before any proxy starts.

use ember_agent_monitor::net::proxy::{serve, ProxyContext};
use ember_agent_monitor::types::{DaemonConfig, InterventionMode};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Mock upstream. `silent` accepts and reads the request but never answers; otherwise it
/// answers with a tiny SSE stream.
fn mock_upstream(silent: bool) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 65536];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                if silent {
                    thread::sleep(Duration::from_secs(120));
                    return;
                }
                // Drain the declared body so curl is not cut off mid-write.
                let head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                let mut have = buf.len() - head_end;
                while have < len {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => have += n,
                    }
                }
                let ev = b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
                let _ = s.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n",
                        ev.len()
                    )
                    .as_bytes(),
                );
                let _ = s.write_all(ev);
                let _ = s.write_all(b"\r\n0\r\n\r\n");
            });
        }
    });
    url
}

fn start_proxy(tag: &str, upstream: String) -> (u16, Arc<AtomicBool>) {
    let (port, stop, _, _) = start_proxy_ctx(tag, upstream);
    (port, stop)
}

fn start_proxy_ctx(
    tag: &str,
    upstream: String,
) -> (u16, Arc<AtomicBool>, Arc<ProxyContext>, std::path::PathBuf) {
    let port = free_port();
    let data_dir = std::env::temp_dir().join(format!("eam-68-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let cfg = DaemonConfig {
        proxy_port: port,
        mode: InterventionMode::Observe,
        data_dir: data_dir.clone(),
        upstream_anthropic: upstream,
        ..DaemonConfig::default()
    };
    let stop = Arc::new(AtomicBool::new(false));
    let ctx = Arc::new(ProxyContext::new(cfg).expect("ctx"));
    let (ctx2, s2) = (Arc::clone(&ctx), Arc::clone(&stop));
    thread::spawn(move || {
        let _ = serve(ctx2, s2);
    });
    thread::sleep(Duration::from_millis(200));
    (port, stop, ctx, data_dir)
}

/// A conversation shaped like Claude Code's replayed history: `turns` assistant tool_use +
/// user tool_result pairs.
fn conversation(turns: usize) -> String {
    let mut msgs =
        vec![r#"{"role":"user","content":[{"type":"text","text":"start the task"}]}"#.to_string()];
    for i in 0..turns {
        msgs.push(format!(
            r#"{{"role":"assistant","content":[{{"type":"text","text":"step {i} {pad}"}},{{"type":"tool_use","id":"tu{i}","name":"Bash","input":{{"command":"ls -la /tmp/f{i}"}}}}]}}"#,
            pad = "x".repeat(1000)
        ));
        msgs.push(format!(
            r#"{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"tu{i}","content":"output {i} {pad}"}}]}}"#,
            pad = "y".repeat(1000)
        ));
    }
    format!(
        r#"{{"model":"claude-fable-5-1","max_tokens":1000,"stream":true,"messages":[{}]}}"#,
        msgs.join(",")
    )
}

/// POST like Claude Code; return (raw response, elapsed).
fn post(port: u16, body: &str) -> (String, Duration) {
    let t = Instant::now();
    let mut c = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let req = format!(
        "POST /v1/messages?beta=true HTTP/1.1\r\nHost: x\r\nauthorization: Bearer x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    c.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    (String::from_utf8_lossy(&out).to_string(), t.elapsed())
}

#[test]
fn growing_replayed_history_never_delays_the_forward() {
    let (port, stop) = start_proxy("grow", mock_upstream(false));
    // Pre-fix: the third request took ~32 s and the fourth minutes (graph grew by the whole
    // history each request, spectral ran on it). Now each answers in well under a second.
    for turns in [60, 120, 180, 240] {
        let (resp, took) = post(port, &conversation(turns));
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "turns={turns}: {}",
            &resp[..resp.len().min(200)]
        );
        assert!(
            resp.contains("message_stop"),
            "turns={turns}: stream not relayed"
        );
        assert!(
            took < Duration::from_secs(10),
            "turns={turns} took {took:?} (#68)"
        );
    }
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn silent_upstream_stream_fails_loudly_with_502() {
    std::env::set_var("EMBER_AGENT_FIRST_BYTE_SECS", "2");
    let (port, stop) = start_proxy("silent", mock_upstream(true));
    let (resp, took) = post(port, &conversation(2));
    assert!(
        resp.starts_with("HTTP/1.1 502"),
        "expected 502, got: {}",
        &resp[..resp.len().min(200)]
    );
    assert!(
        resp.contains("watchdog"),
        "502 must name the watchdog: {resp}"
    );
    assert!(took < Duration::from_secs(15), "held for {took:?} (#68)");
    stop.store(true, Ordering::Relaxed);
}

/// Body whose history is exactly these user messages (one `user_prompt` event each).
fn history(texts: &[&str]) -> String {
    let msgs: Vec<String> = texts
        .iter()
        .map(|t| format!(r#"{{"role":"user","content":[{{"type":"text","text":"{t}"}}]}}"#))
        .collect();
    format!(
        r#"{{"model":"claude-fable-5-1","max_tokens":10,"stream":true,"messages":[{}]}}"#,
        msgs.join(",")
    )
}

/// POST with a fixed session id; wait for the background ingest to settle; return the
/// number of events recorded for the session so far.
fn send_and_count(port: u16, dir: &std::path::Path, body: &str) -> usize {
    let t = Instant::now();
    let mut c = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let req = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: x\r\nx-claude-session-id: s68\r\nauthorization: Bearer x\r\nanthropic-version: 2023-06-01\r\ncontent-type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    c.write_all(req.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = c.read_to_end(&mut out);
    // Observe-mode ingest is asynchronous: wait until the line count is stable.
    let path = dir.join("sessions/s68.jsonl");
    let count = || {
        std::fs::read_to_string(&path)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    };
    let mut last = count();
    let mut stable = 0;
    while stable < 5 && t.elapsed() < Duration::from_secs(20) {
        thread::sleep(Duration::from_millis(100));
        let n = count();
        stable = if n == last { stable + 1 } else { 0 };
        last = n;
    }
    last
}

#[test]
fn event_whose_record_failed_is_analysed_on_the_next_replay() {
    let (port, stop, ctx, dir) = start_proxy_ctx("fail", mock_upstream(false));
    ctx.inject_record_failures(1);
    assert_eq!(
        send_and_count(port, &dir, &history(&["alpha"])),
        0,
        "record was injected to fail"
    );
    // Replay of the same history: the event must NOT have been marked seen.
    assert_eq!(
        send_and_count(port, &dir, &history(&["alpha"])),
        1,
        "failed event lost forever"
    );
    // And now it is deduped.
    assert_eq!(send_and_count(port, &dir, &history(&["alpha"])), 1);
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn compaction_that_drops_an_event_lets_it_recur_and_be_analysed() {
    let (port, stop, _ctx, dir) = start_proxy_ctx("compact", mock_upstream(false));
    // Seen three times.
    assert_eq!(send_and_count(port, &dir, &history(&["X", "X", "X"])), 3);
    // Same history again: nothing new.
    assert_eq!(send_and_count(port, &dir, &history(&["X", "X", "X"])), 3);
    // Compaction rewrites the history and drops X entirely.
    assert_eq!(send_and_count(port, &dir, &history(&["Z"])), 4);
    // X recurs once: must be analysed (stale count 3 would suppress it).
    assert_eq!(send_and_count(port, &dir, &history(&["Z", "X"])), 5);
    stop.store(true, Ordering::Relaxed);
}

/// Live: streaming + extended thinking through the proxy with the real upstream. Needs the
/// `claude` CLI, network, and the claude-config smoke script (claude-config#53/#54):
/// `EMBER_PROXY_SMOKE=/path/to/proxy-smoke.sh cargo test --test streaming_hang_68 -- --ignored`.
#[test]
#[ignore = "live: #68"]
fn live_streaming_with_thinking_passes_smoke() {
    let script =
        std::env::var("EMBER_PROXY_SMOKE").expect("set EMBER_PROXY_SMOKE to proxy-smoke.sh");
    let (port, stop) = start_proxy("live", "https://api.anthropic.com".into());
    let out = std::process::Command::new("bash")
        .arg(&script)
        .arg(format!("http://127.0.0.1:{port}"))
        .arg("fable")
        .output()
        .expect("run smoke");
    stop.store(true, Ordering::Relaxed);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
