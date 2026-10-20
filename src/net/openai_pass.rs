//! openai_pass — streaming OpenAI-compatible pass-through to a local
//! llama-server, with the exchange recorded in the session graph.
//!
//! Routes (all loopback, like the rest of the proxy):
//! - `POST /openai/v1/chat/completions` (and `/responses`): request events are
//!   ingested and analyzed exactly as for any OpenAI-protocol traffic
//!   (`proxy::ingest_request`; `block` mode refuses before forwarding). The
//!   upstream reply is relayed to the client as it arrives (SSE included) and
//!   then recorded as one `model_text` event with `direction=response`, the
//!   model, token usage, finish reason and latency. Response-side analysis is
//!   observe-only (the bytes are already with the client); tool calls are not
//!   interpreted here.
//! - `GET /openai/health`, `GET /openai/props`: relayed to the upstream's
//!   `/health` and `/props` (llama-server), nothing recorded.
//! - `GET /sessions/<id>`: has the proxy recorded this session? 200 with
//!   event counts, or 404 `{"error":"no_session"}`. The caller sends
//!   `X-Ember-Session-Id: <id>` on its requests; every relayed reply echoes
//!   `X-Ember-Session: <id>`. This is how ember-local learns whether a job has
//!   a session graph (spec invariant 3).
//!
//! If the client hangs up mid-stream the upstream curl is killed, which closes
//! the upstream connection and stops generation.

use crate::event::Event;
use crate::json::{parse, JsonValue};
use crate::net::http::{HttpRequest, HttpResponse};
use crate::net::proxy::{header_passthrough_blocked, ingest_request, which_curl, ProxyContext};
use crate::proto::Protocol;
use crate::store::log::read_all;
use crate::types::{EventKind, InterventionMode, TrustZone};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Command, Stdio};
use std::time::Instant;

const UPSTREAM_TIMEOUT_SECS: u32 = 600;
const CAPTURE_CAP: usize = 4 * 1024 * 1024;
const HEAD_CAP: usize = 64 * 1024;
const SESSION_ID_MAX: usize = 128;
const ECHO_HEADER: &str = "X-Ember-Session";

/// Handle the request if it is one of this module's routes; `false` = not ours.
pub fn route(req: &HttpRequest, ctx: &ProxyContext, out: &mut TcpStream) -> bool {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/openai/health") => relay_get(req, ctx, "/health", out),
        ("GET", "/openai/props") => relay_get(req, ctx, "/props", out),
        ("POST", p) if Protocol::for_path(p) == Some(Protocol::OpenAI) => post(req, ctx, out),
        ("GET", p) if p.starts_with("/sessions/") => {
            let _ = session_status(ctx, &p["/sessions/".len()..]).write_to(out);
        }
        _ => return false,
    }
    true
}

fn json_response(status: u16, text: &str, body: String) -> HttpResponse {
    let bytes = body.into_bytes();
    HttpResponse {
        status,
        status_text: text.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Length".into(), bytes.len().to_string()),
            ("Connection".into(), "close".into()),
        ],
        body: bytes,
    }
}

fn session_status(ctx: &ProxyContext, id: &str) -> HttpResponse {
    if id.is_empty() || id.len() > SESSION_ID_MAX {
        return json_response(400, "Bad Request", r#"{"error":"bad_session_id"}"#.into());
    }
    let events = read_all(&ctx.store.session_log_path(id)).unwrap_or_default();
    if events.is_empty() {
        return json_response(404, "Not Found", r#"{"error":"no_session"}"#.into());
    }
    let responses = events
        .iter()
        .filter(|e| matches!(e.body.get("direction"), Some(JsonValue::Str(d)) if d == "response"))
        .count();
    json_response(
        200,
        "OK",
        format!(
            r#"{{"session_id":{},"events":{},"responses":{}}}"#,
            crate::json::to_json_string(&JsonValue::Str(id.into())),
            events.len(),
            responses
        ),
    )
}

fn upstream_url(ctx: &ProxyContext, path: &str) -> String {
    format!(
        "{}{}",
        ctx.config.upstream_openai.trim_end_matches('/'),
        path
    )
}

fn relay_get(req: &HttpRequest, ctx: &ProxyContext, path: &str, out: &mut TcpStream) {
    if let Err(e) = relay(
        "GET",
        &upstream_url(ctx, path),
        None,
        &req.headers,
        None,
        out,
    ) {
        let _ = bad_gateway(&e).write_to(out);
    }
}

fn bad_gateway(detail: &str) -> HttpResponse {
    json_response(
        502,
        "Bad Gateway",
        format!(
            r#"{{"error":"upstream","detail":{}}}"#,
            crate::json::to_json_string(&JsonValue::Str(detail.into()))
        ),
    )
}

fn post(req: &HttpRequest, ctx: &ProxyContext, out: &mut TcpStream) {
    let (sid, high) = ingest_request(req, ctx, Protocol::OpenAI);
    let echo = |mut r: HttpResponse| {
        r.headers.push((ECHO_HEADER.into(), sid.clone()));
        r
    };
    if ctx.config.mode == InterventionMode::Block && !high.is_empty() {
        let names: Vec<&str> = high
            .iter()
            .take(3)
            .map(|f| f.finding_type.as_str())
            .collect();
        let reason = format!("ember-agent blocked this request: {}", names.join(" | "));
        let _ = echo(HttpResponse::refusal(&reason)).write_to(out);
        return;
    }
    let url = upstream_url(ctx, &Protocol::OpenAI.upstream_path(&req.path));
    let started = Instant::now();
    let result = relay("POST", &url, Some(&req.body), &req.headers, Some(&sid), out);
    let ms = started.elapsed().as_millis() as f64;
    match result {
        Ok(r) => record_response(ctx, &sid, &r, ms),
        Err(e) => {
            let _ = echo(bad_gateway(&e)).write_to(out);
            record_response(ctx, &sid, &Relayed::failed(&e), ms);
        }
    }
}

struct Relayed {
    status: u16,
    captured: Vec<u8>,
    truncated: bool,
    client_gone: bool,
    error: Option<String>,
}

impl Relayed {
    fn failed(e: &str) -> Self {
        Self {
            status: 0,
            captured: Vec::new(),
            truncated: false,
            client_gone: false,
            error: Some(e.to_string()),
        }
    }
}

/// Run curl against the upstream and copy its reply to `out` as it arrives.
/// `Err` means nothing has been sent to the client yet.
fn relay(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    headers: &[(String, String)],
    session: Option<&str>,
    out: &mut TcpStream,
) -> Result<Relayed, String> {
    let mut cmd = Command::new(which_curl()?);
    cmd.args(["-sS", "-i", "-N", "--connect-timeout", "10", "--max-time"])
        .arg(UPSTREAM_TIMEOUT_SECS.to_string())
        .args(["-X", method, "-H", "Expect:"]);
    if body.is_some() {
        cmd.args(["--data-binary", "@-"]);
    }
    for (k, v) in headers {
        if !header_passthrough_blocked(k) {
            cmd.arg("-H").arg(format!("{k}: {v}"));
        }
    }
    cmd.arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("curl spawn: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("curl stdin")?;
    let payload = body.map(<[u8]>::to_vec);
    std::thread::spawn(move || {
        if let Some(b) = payload {
            let _ = stdin.write_all(&b);
        }
    });
    let mut stdout = child.stdout.take().ok_or("curl stdout")?;
    let mut stderr = child.stderr.take().ok_or("curl stderr")?;
    let err_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });

    let mut head: Vec<u8> = Vec::new();
    let mut sent_head = false;
    let mut res = Relayed {
        status: 0,
        captured: Vec::new(),
        truncated: false,
        client_gone: false,
        error: None,
    };
    let mut buf = [0u8; 8192];
    loop {
        let n = match stdout.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let chunk = &buf[..n];
        if !sent_head {
            head.extend_from_slice(chunk);
            if head.len() > HEAD_CAP {
                let _ = child.kill();
                let _ = child.wait();
                return Err("upstream response head too large".into());
            }
            // Skip interim `100 Continue` blocks, then relay the real head.
            let Some((status, ctype, reason, end)) = parse_head(&head) else {
                continue;
            };
            let mut resp_head = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\n");
            resp_head.push_str("Connection: close\r\n");
            if let Some(s) = session {
                resp_head.push_str(&format!("{ECHO_HEADER}: {s}\r\n"));
            }
            resp_head.push_str("\r\n");
            res.status = status;
            if out.write_all(resp_head.as_bytes()).is_err() {
                res.client_gone = true;
                break;
            }
            sent_head = true;
            let rest = head.split_off(end);
            head.clear();
            if rest.is_empty() {
                continue;
            }
            capture(&mut res, &rest);
            if out.write_all(&rest).and_then(|_| out.flush()).is_err() {
                res.client_gone = true;
                break;
            }
            continue;
        }
        capture(&mut res, chunk);
        if out.write_all(chunk).and_then(|_| out.flush()).is_err() {
            res.client_gone = true;
            break;
        }
    }
    if res.client_gone {
        let _ = child.kill(); // closing the upstream connection stops generation
    }
    let status = child.wait().map_err(|e| format!("curl wait: {e}"))?;
    let err_text = err_reader.join().unwrap_or_default();
    if !status.success() && !res.client_gone {
        let msg = format!("curl exit {:?}: {}", status.code(), err_text.trim());
        if !sent_head {
            return Err(msg);
        }
        res.error = Some(msg);
    } else if !sent_head && !res.client_gone {
        return Err("upstream sent no response".into());
    }
    Ok(res)
}

fn capture(res: &mut Relayed, chunk: &[u8]) {
    let room = CAPTURE_CAP.saturating_sub(res.captured.len());
    if chunk.len() > room {
        res.truncated = true;
    }
    res.captured
        .extend_from_slice(&chunk[..chunk.len().min(room)]);
}

/// (status, content-type, reason, end-of-head offset) of the first non-1xx
/// head block in `buf`, or None while the head is incomplete.
fn parse_head(buf: &[u8]) -> Option<(u16, String, String, usize)> {
    let mut start = 0;
    loop {
        let rel = buf[start..].windows(4).position(|w| w == b"\r\n\r\n")?;
        let end = start + rel + 4;
        let text = String::from_utf8_lossy(&buf[start..start + rel]).to_string();
        let mut lines = text.lines();
        let mut parts = lines.next()?.splitn(3, ' ');
        let _version = parts.next()?;
        let status: u16 = parts.next()?.trim().parse().ok()?;
        let reason = parts.next().unwrap_or("").trim().to_string();
        if (100..200).contains(&status) {
            start = end;
            continue;
        }
        let ctype = lines
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_else(|| "application/json".into());
        return Some((status, ctype, reason, end));
    }
}

fn field<'a>(v: &'a JsonValue, key: &str) -> Option<&'a JsonValue> {
    match v {
        JsonValue::Object(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn str_of(v: Option<&JsonValue>) -> Option<&str> {
    match v {
        Some(JsonValue::Str(s)) => Some(s),
        _ => None,
    }
}

fn num_of(v: Option<&JsonValue>) -> f64 {
    match v {
        Some(JsonValue::Number(n)) => *n,
        _ => 0.0,
    }
}

#[derive(Default)]
struct Summary {
    text: String,
    model: String,
    finish_reason: String,
    prompt_tokens: f64,
    completion_tokens: f64,
    streamed: bool,
}

/// Fold one chat-completion object (a stream chunk or a whole reply).
fn fold(sum: &mut Summary, v: &JsonValue) {
    if let Some(m) = str_of(field(v, "model")) {
        sum.model = m.to_string();
    }
    if let Some(JsonValue::Array(choices)) = field(v, "choices") {
        for c in choices {
            for holder in ["delta", "message"] {
                if let Some(t) = field(c, holder).and_then(|d| str_of(field(d, "content"))) {
                    sum.text.push_str(t);
                }
            }
            if let Some(f) = str_of(field(c, "finish_reason")) {
                sum.finish_reason = f.to_string();
            }
        }
    }
    if let Some(u) = field(v, "usage") {
        sum.prompt_tokens = num_of(field(u, "prompt_tokens"));
        sum.completion_tokens = num_of(field(u, "completion_tokens"));
    }
}

fn summarize(bytes: &[u8]) -> Summary {
    let mut sum = Summary::default();
    let text = String::from_utf8_lossy(bytes);
    if text.trim_start().starts_with("data:") {
        sum.streamed = true;
        for line in text.lines() {
            if let Some(d) = line.strip_prefix("data:") {
                if let Ok(v) = parse(d.trim()) {
                    fold(&mut sum, &v);
                }
            }
        }
    } else if let Ok(v) = parse(&text) {
        fold(&mut sum, &v);
    }
    sum
}

fn record_response(ctx: &ProxyContext, sid: &str, r: &Relayed, latency_ms: f64) {
    let sum = summarize(&r.captured);
    let mut body: HashMap<String, JsonValue> = HashMap::new();
    let s = |v: &str| JsonValue::Str(v.to_string());
    body.insert("direction".into(), s("response"));
    body.insert("text".into(), JsonValue::Str(sum.text));
    body.insert("model".into(), JsonValue::Str(sum.model));
    body.insert("finish_reason".into(), JsonValue::Str(sum.finish_reason));
    body.insert("prompt_tokens".into(), JsonValue::Number(sum.prompt_tokens));
    body.insert(
        "completion_tokens".into(),
        JsonValue::Number(sum.completion_tokens),
    );
    body.insert("latency_ms".into(), JsonValue::Number(latency_ms));
    body.insert(
        "upstream_status".into(),
        JsonValue::Number(f64::from(r.status)),
    );
    body.insert("streamed".into(), JsonValue::Bool(sum.streamed));
    body.insert("client_gone".into(), JsonValue::Bool(r.client_gone));
    body.insert("capture_truncated".into(), JsonValue::Bool(r.truncated));
    if let Some(e) = &r.error {
        body.insert("error".into(), s(e));
    }
    let ev = Event::new(sid, EventKind::ModelText, TrustZone::WorkspaceLocal, body);
    ctx.record(&ev);
    ctx.analyze(&ev);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_skips_100_continue_and_reads_content_type() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\ndata: x";
        let (st, ct, reason, end) = parse_head(raw).unwrap();
        assert_eq!(
            (st, ct.as_str(), reason.as_str()),
            (200, "text/event-stream", "OK")
        );
        assert_eq!(&raw[end..], b"data: x");
    }

    #[test]
    fn head_incomplete_is_none() {
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nContent-Ty").is_none());
    }

    #[test]
    fn summarize_sse_and_json() {
        let sse = b"data: {\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"llo\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n";
        let s = summarize(sse);
        assert_eq!(
            (s.text.as_str(), s.model.as_str(), s.finish_reason.as_str()),
            ("hello", "m", "stop")
        );
        assert_eq!(
            (s.prompt_tokens, s.completion_tokens, s.streamed),
            (3.0, 2.0, true)
        );
        let j = summarize(br#"{"model":"m","choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#);
        assert_eq!((j.text.as_str(), j.streamed), ("ok", false));
    }
}
