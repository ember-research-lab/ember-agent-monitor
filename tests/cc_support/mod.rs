//! cc_support — shared harness for the Claude Code compatibility gate (#64):
//! mock Anthropic upstream, in-process proxy, wire-capture fixture loader and
//! the real-`claude` runner. Not a test crate itself (directory module).
#![allow(dead_code)]

use ember_agent_monitor::net::proxy::{serve, ProxyContext};
use ember_agent_monitor::types::{DaemonConfig, InterventionMode};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Planted in every mock error body; a 400 test must find it in the client's output.
pub const SENTINEL: &str = "EMBER_UPSTREAM_400_SENTINEL";

/// One request the mock upstream received.
#[derive(Clone, Debug)]
pub struct Seen {
    pub request_line: String,
    /// `name: value` lines as sent (original case).
    pub headers: Vec<String>,
    pub body: String,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<String> {
        let p = format!("{}:", name.to_ascii_lowercase());
        self.headers
            .iter()
            .find(|h| h.to_ascii_lowercase().starts_with(&p))
            .map(|h| h[p.len()..].trim().to_string())
    }
    pub fn is_stream(&self) -> bool {
        self.body.contains("\"stream\":true")
    }
}

pub struct Upstream {
    pub url: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Mock Anthropic upstream. Answers `stream:true` with chunked
/// `text/event-stream` (one chunk per event, like the real API) and anything
/// else with `application/json`; the assistant text is always `ok`.
pub fn spawn_upstream() -> Upstream {
    spawn_upstream_status(200)
}

/// As [`spawn_upstream`], but answering every request with `status` and an
/// Anthropic-style error body (e.g. 400 `invalid_request_error`, which Claude Code does not retry).
pub fn spawn_upstream_status(status: u16) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    listener.set_nonblocking(true).unwrap();
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (seen2, stop2) = (Arc::clone(&seen), Arc::clone(&stop));
    thread::spawn(move || loop {
        if stop2.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let seen3 = Arc::clone(&seen2);
                thread::spawn(move || handle_upstream_conn(stream, seen3, status));
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    });
    Upstream { url, seen, stop }
}

fn handle_upstream_conn(mut stream: TcpStream, seen: Arc<Mutex<Vec<Seen>>>, status: u16) {
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut rdr = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    rdr.read_line(&mut line).ok();
    let request_line = line.trim().to_string();
    let mut headers = Vec::new();
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
    let body = String::from_utf8_lossy(&body).to_string();
    let is_stream = body.contains("\"stream\":true");
    let model = body
        .split("\"model\":\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap_or("claude-opus-5-5")
        .to_string();
    let offers_gzip = headers.iter().any(|h| {
        let l = h.to_ascii_lowercase();
        l.starts_with("accept-encoding:") && l.contains("gzip")
    });
    let responses_route = request_line.contains("/responses");
    let openai_route = responses_route || request_line.contains("/chat/completions");
    seen.lock().unwrap().push(Seen {
        request_line,
        headers,
        body,
    });
    if openai_route {
        // OpenAI-compatible routes (Codex today; OpenCode/Pi on their OpenAI providers).
        write_openai_reply(&mut stream, responses_route, status);
        return;
    }
    if status != 200 {
        let body = r#"{"type":"error","error":{"type":"invalid_request_error","message":"mock rejection EMBER_UPSTREAM_400_SENTINEL"},"request_id":"req_mock"}"#;
        let head = format!(
            "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nrequest-id: req_mock\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.flush();
        return;
    }
    if offers_gzip {
        // Like the real API behind its CDN: a client that offers gzip gets gzip.
        // A proxy that forwards `accept-encoding` and then drops
        // `content-encoding` hands the client compressed bytes (#60).
        let plain = if is_stream {
            [
                format!("event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"{model}\",\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{{\"input_tokens\":1,\"output_tokens\":1}}}}}}\n\n"),
                "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n".to_string(),
                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n".to_string(),
                "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n".to_string(),
                "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\n".to_string(),
                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
            ]
            .concat()
        } else {
            format!(
                r#"{{"id":"msg_1","type":"message","role":"assistant","model":"{model}","content":[{{"type":"text","text":"ok"}}],"stop_reason":"end_turn","stop_sequence":null,"usage":{{"input_tokens":1,"output_tokens":1}}}}"#
            )
        };
        let ct = if is_stream {
            "text/event-stream"
        } else {
            "application/json"
        };
        let gz = gzip_stored(plain.as_bytes());
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            gz.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(&gz);
        let _ = stream.flush();
        return;
    }
    if is_stream {
        let events = [
            ("message_start", format!(r#"{{"type":"message_start","message":{{"id":"msg_1","type":"message","role":"assistant","model":"{model}","content":[],"stop_reason":null,"stop_sequence":null,"usage":{{"input_tokens":1,"output_tokens":1}}}}}}"#)),
            ("content_block_start", r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#.to_string()),
            ("content_block_delta", r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}"#.to_string()),
            ("content_block_stop", r#"{"type":"content_block_stop","index":0}"#.to_string()),
            ("message_delta", r#"{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}"#.to_string()),
            ("message_stop", r#"{"type":"message_stop"}"#.to_string()),
        ];
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        );
        for (name, data) in events {
            let chunk = format!("event: {name}\ndata: {data}\n\n");
            let _ = stream.write_all(format!("{:x}\r\n{chunk}\r\n", chunk.len()).as_bytes());
            let _ = stream.flush();
            thread::sleep(Duration::from_millis(5));
        }
        let _ = stream.write_all(b"0\r\n\r\n");
    } else {
        let body = format!(
            r#"{{"id":"msg_1","type":"message","role":"assistant","model":"{model}","content":[{{"type":"text","text":"ok"}}],"stop_reason":"end_turn","stop_sequence":null,"usage":{{"input_tokens":1,"output_tokens":1}}}}"#
        );
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(body.as_bytes());
    }
    let _ = stream.flush();
}

/// Answer an OpenAI-compatible request the way the real API does: a Responses
/// API SSE stream for `/responses`, Chat Completions chunks for
/// `/chat/completions`; the assistant text is always `ok`. `status != 200`
/// gives an OpenAI-style error body.
fn write_openai_reply(stream: &mut TcpStream, responses: bool, status: u16) {
    if status != 200 {
        let body = r#"{"error":{"message":"mock rejection EMBER_UPSTREAM_400_SENTINEL","type":"invalid_request_error","param":null,"code":null}}"#;
        let head = format!(
            "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.flush();
        return;
    }
    let events: Vec<(&str, String)> = if responses {
        let item = r#"{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"ok","annotations":[]}]}"#;
        let resp = r#"{"id":"resp_1","object":"response","created_at":1,"status":"in_progress","model":"gpt-5","output":[]}"#;
        vec![
            ("response.created", format!(r#"{{"type":"response.created","response":{resp}}}"#)),
            ("response.output_item.added", r#"{"type":"response.output_item.added","output_index":0,"item":{"type":"message","id":"msg_1","role":"assistant","status":"in_progress","content":[]}}"#.to_string()),
            ("response.content_part.added", r#"{"type":"response.content_part.added","item_id":"msg_1","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}"#.to_string()),
            ("response.output_text.delta", r#"{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"ok"}"#.to_string()),
            ("response.output_text.done", r#"{"type":"response.output_text.done","item_id":"msg_1","output_index":0,"content_index":0,"text":"ok"}"#.to_string()),
            ("response.output_item.done", format!(r#"{{"type":"response.output_item.done","output_index":0,"item":{item}}}"#)),
            ("response.completed", format!(r#"{{"type":"response.completed","response":{{"id":"resp_1","object":"response","created_at":1,"status":"completed","model":"gpt-5","output":[{item}],"usage":{{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}}}}"#)),
        ]
    } else {
        vec![
            ("", r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-5","choices":[{"index":0,"delta":{"role":"assistant","content":"ok"},"finish_reason":null}]}"#.to_string()),
            ("", r#"{"id":"chatcmpl-1","object":"chat.completion.chunk","created":1,"model":"gpt-5","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#.to_string()),
            ("", "[DONE]".to_string()),
        ]
    };
    let _ = stream.write_all(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
    );
    for (name, data) in events {
        let chunk = if name.is_empty() {
            format!("data: {data}\n\n")
        } else {
            format!("event: {name}\ndata: {data}\n\n")
        };
        let _ = stream.write_all(format!("{:x}\r\n{chunk}\r\n", chunk.len()).as_bytes());
        let _ = stream.flush();
        thread::sleep(Duration::from_millis(5));
    }
    let _ = stream.write_all(b"0\r\n\r\n");
    let _ = stream.flush();
}

/// Minimal valid gzip (single stored deflate block; body must be < 64 KiB).
fn gzip_stored(data: &[u8]) -> Vec<u8> {
    assert!(data.len() < 65535);
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc = !crc;
    let n = data.len() as u16;
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff, 1];
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&(!n).to_le_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

pub struct Proxy {
    pub port: u16,
    stop: Arc<AtomicBool>,
}

impl Proxy {
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// In-process proxy on a free port (never :9452) in front of `upstream_url`.
pub fn start_proxy(tag: &str, mode: InterventionMode, upstream_url: &str) -> Proxy {
    let data_dir = std::env::temp_dir().join(format!("eam-cc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data_dir);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let cfg = DaemonConfig {
        proxy_port: port,
        mode,
        data_dir,
        upstream_anthropic: upstream_url.to_string(),
        upstream_openai: upstream_url.to_string(),
        ..DaemonConfig::default()
    };
    let ctx = Arc::new(ProxyContext::new(cfg).expect("ctx"));
    let stop = Arc::new(AtomicBool::new(false));
    let (c2, s2) = (ctx, Arc::clone(&stop));
    thread::spawn(move || {
        let _ = serve(c2, s2);
    });
    // Wait until the listener accepts, instead of sleeping and hoping.
    let t0 = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            t0.elapsed() < Duration::from_secs(5),
            "proxy never listened"
        );
        thread::sleep(Duration::from_millis(20));
    }
    Proxy { port, stop }
}

// ---------------------------------------------------------------- fixture

pub fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/claude-code")
}

fn version_key(v: &str) -> Vec<u64> {
    v.split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

/// Newest captured Claude Code version (directory name under the fixtures root).
pub fn newest_fixture_version() -> Option<String> {
    let mut dirs: Vec<String> = std::fs::read_dir(fixtures_root())
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    dirs.sort_by_key(|d| version_key(d));
    dirs.pop()
}

pub struct Capture {
    pub version: String,
    pub request_line: String,
    /// `name: value`, already redacted; excludes host/content-length/connection.
    pub headers: Vec<String>,
    pub body: String,
}

pub fn load_capture() -> Capture {
    let version = newest_fixture_version().expect("no claude-code fixture directory");
    let dir = fixtures_root().join(&version);
    let head = std::fs::read_to_string(dir.join("request.head")).expect("request.head");
    let mut lines = head.lines();
    let request_line = lines.next().expect("request line").to_string();
    let headers = lines
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.to_string())
        .collect();
    let body = std::fs::read_to_string(dir.join("request.body.json")).expect("request.body.json");
    Capture {
        version,
        request_line,
        headers,
        body,
    }
}

impl Capture {
    /// The captured request, sent verbatim to `port` (secrets are the redaction
    /// placeholders). `stream` rewrites only the body's `"stream":` flag.
    /// Returns the raw response bytes.
    pub fn replay(&self, port: u16, stream: bool) -> Vec<u8> {
        let body = if stream {
            self.body.clone()
        } else {
            assert!(
                self.body.contains("\"stream\":true"),
                "fixture lost stream flag"
            );
            self.body.replace("\"stream\":true", "\"stream\":false")
        };
        let mut req = format!("{}\r\n", self.request_line);
        for h in &self.headers {
            req.push_str(h);
            req.push_str("\r\n");
        }
        req.push_str(&format!(
            "host: 127.0.0.1:{port}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        ));
        let mut c = TcpStream::connect(("127.0.0.1", port)).expect("client");
        c.set_read_timeout(Some(Duration::from_secs(15))).ok();
        c.write_all(req.as_bytes()).expect("send");
        let mut out = Vec::new();
        let _ = c.read_to_end(&mut out);
        out
    }
}

// ------------------------------------------------------------ real claude

fn in_ci() -> bool {
    std::env::var("CI")
        .map(|v| !v.is_empty() && v != "false")
        .unwrap_or(false)
}

/// `claude --version` (first token), or None when the binary is absent.
fn claude_version() -> Option<String> {
    let out = Command::new("claude")
        .arg("--version")
        .env_remove("ANTHROPIC_BASE_URL")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .map(|s| s.to_string())
}

/// Gate for tests that need the real client. Returns the version when present.
/// Absent: loud message and `None` locally; **panics when `CI` is set** so a
/// broken CI install can never turn the gate into a silent pass.
pub fn require_claude(test: &str) -> Option<String> {
    match claude_version() {
        Some(v) => {
            eprintln!("[cc-gate] {test}: claude --version = {v}");
            let newest = newest_fixture_version().unwrap_or_default();
            if version_key(&v) > version_key(&newest) {
                eprintln!(
                    "[cc-gate] WARNING: installed Claude Code {v} is newer than the newest wire-capture fixture {newest}; \
                     run `just capture-claude-code` and commit tests/fixtures/claude-code/{v}/"
                );
            }
            Some(v)
        }
        None => {
            let msg = format!(
                "[cc-gate] {test}: `claude` binary NOT FOUND on PATH. The real-client compatibility gate (#64) did NOT run. \
                 Install Claude Code (npm i -g @anthropic-ai/claude-code@2.1.305) and re-run."
            );
            if in_ci() {
                panic!("{msg} CI is set: refusing to skip.");
            }
            eprintln!("{msg} SKIPPING (local run; CI would fail here).");
            None
        }
    }
}

pub enum Auth {
    /// `ANTHROPIC_API_KEY` -> `x-api-key` header.
    ApiKey,
    /// `ANTHROPIC_AUTH_TOKEN` -> `authorization: Bearer` header (the OAuth/gateway shape).
    Bearer,
}

pub struct ClaudeRun {
    pub stdout: String,
    pub stderr: String,
    pub code: Option<i32>,
}

/// Run `claude -p` against `base_url` with a scrubbed environment: nothing
/// inherited (the user's `ANTHROPIC_BASE_URL`, `CLAUDE_*` session vars and
/// `~/.claude` never leak in), HOME and `CLAUDE_CONFIG_DIR` in a scratch dir.
pub fn run_claude(tag: &str, base_url: &str, auth: Auth, model: &str, extra: &[&str]) -> ClaudeRun {
    let scratch = std::env::temp_dir().join(format!("eam-cc-claude-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let cwd = scratch.join("cwd");
    let cfg = scratch.join("cfg");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(&cfg).unwrap();
    let mut cmd = Command::new("claude");
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &scratch)
        .env("CLAUDE_CONFIG_DIR", &cfg)
        .env("ANTHROPIC_BASE_URL", base_url)
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .env("DISABLE_AUTOUPDATER", "1")
        .env("DISABLE_TELEMETRY", "1")
        .current_dir(&cwd)
        .arg("-p")
        .arg("reply with the single word ok")
        .arg("--model")
        .arg(model)
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match auth {
        Auth::ApiKey => cmd.env("ANTHROPIC_API_KEY", "sk-ant-api03-dummy-for-cc-gate"),
        Auth::Bearer => cmd.env("ANTHROPIC_AUTH_TOKEN", "dummy-bearer-for-cc-gate"),
    };
    run_command(cmd, &scratch)
}

/// Spawn `cmd` (stdout/stderr piped), kill it after 120 s (`code == Some(-9)`),
/// and remove `scratch` afterwards.
fn run_command(mut cmd: Command, scratch: &Path) -> ClaudeRun {
    let mut child = cmd.spawn().expect("spawn client");
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let t_out = thread::spawn(move || {
        let mut s = String::new();
        let _ = so.read_to_string(&mut s);
        s
    });
    let t_err = thread::spawn(move || {
        let mut s = String::new();
        let _ = se.read_to_string(&mut s);
        s
    });
    let t0 = Instant::now();
    let code = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st.code();
        }
        if t0.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            let _ = child.wait();
            break Some(-9);
        }
        thread::sleep(Duration::from_millis(50));
    };
    let run = ClaudeRun {
        stdout: t_out.join().unwrap(),
        stderr: t_err.join().unwrap(),
        code,
    };
    let _ = std::fs::remove_dir_all(scratch);
    run
}

/// A non-Claude harness under test (#64 scope add): Codex CLI, OpenCode, Pi.
pub struct Harness {
    pub name: &'static str,
    /// Executable on PATH.
    pub bin: &'static str,
    /// Version pinned in CI (`ci.yml`); a different local version only warns.
    pub pinned: &'static str,
}

/// Gate for tests that need a real harness binary; same contract as
/// [`require_claude`]: absent means loud skip locally and a panic under `CI`.
pub fn require_harness(h: &Harness, test: &str) -> Option<String> {
    let out = Command::new(h.bin).arg("--version").output().ok();
    match out.filter(|o| o.status.success()) {
        Some(o) => {
            // Pi prints its version on stderr, the others on stdout.
            let text = format!(
                "{} {}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            );
            let v = text
                .split_whitespace()
                .rev()
                .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .unwrap_or("")
                .to_string();
            eprintln!("[cc-gate] {test}: {} --version = {v}", h.bin);
            if v != h.pinned {
                if in_ci() {
                    panic!(
                        "[cc-gate] {test}: {} {v} installed, CI pins {}",
                        h.bin, h.pinned
                    );
                }
                eprintln!(
                    "[cc-gate] WARNING: {} {v} differs from the pinned {}; results may not match CI",
                    h.bin, h.pinned
                );
            }
            Some(v)
        }
        None => {
            let msg = format!(
                "[cc-gate] {test}: `{}` binary NOT FOUND on PATH. The {} compatibility gate (#64) did NOT run. \
                 Install the pinned version ({}) and re-run.",
                h.bin, h.name, h.pinned
            );
            if in_ci() {
                panic!("{msg} CI is set: refusing to skip.");
            }
            eprintln!("{msg} SKIPPING (local run; CI would fail here).");
            None
        }
    }
}

/// Run `h.bin args` in a scratch `HOME` with a scrubbed environment (PATH only,
/// plus `env`). `files` are written under the scratch HOME first (relative
/// paths); `{HOME}` in `args`, `env` values and file contents expands to it.
/// The working directory is `<HOME>/cwd`.
pub fn run_harness(
    h: &Harness,
    tag: &str,
    args: &[&str],
    env: &[(&str, &str)],
    files: &[(&str, &str)],
) -> ClaudeRun {
    let scratch =
        std::env::temp_dir().join(format!("eam-cc-{}-{tag}-{}", h.name, std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let cwd = scratch.join("cwd");
    std::fs::create_dir_all(&cwd).unwrap();
    let home = scratch.to_string_lossy().to_string();
    let x = |t: &str| t.replace("{HOME}", &home);
    for (rel, content) in files {
        let path = scratch.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, x(content)).unwrap();
    }
    let mut cmd = Command::new(h.bin);
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", &scratch)
        .current_dir(&cwd)
        .args(args.iter().map(|a| x(a)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, x(v));
    }
    run_command(cmd, &scratch)
}

impl ClaudeRun {
    /// Panics with the full transcript unless claude answered `ok` cleanly.
    pub fn assert_answered_ok(&self, what: &str) {
        let all = format!("{}\n{}", self.stdout, self.stderr);
        assert!(
            !all.contains("API Error"),
            "{what}: claude reported an API Error\nstdout: {}\nstderr: {}",
            self.stdout,
            self.stderr
        );
        assert_eq!(
            self.code,
            Some(0),
            "{what}: exit code\nstdout: {}\nstderr: {}",
            self.stdout,
            self.stderr
        );
    }
}
