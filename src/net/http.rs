//! HTTP request/response primitives — direct port of vetpkg/src/net/http_server.rs
//! with the same hard caps. The agent monitor proxies a single endpoint
//! shape (`/v1/messages`) so we don't need vetpkg's tier-orchestration; just
//! the parser and writer.

use std::io::{self, BufRead, BufReader, Read, Write};

pub const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
pub const MAX_HEADERS: usize = 100;
/// 16 MiB ceiling — Anthropic message payloads with multi-megabyte
/// tool_results stay well under this. Larger uploads suggest abuse.
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == n)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn ok_json(body: Vec<u8>) -> Self {
        let len = body.len();
        Self {
            status: 200,
            status_text: "OK".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), len.to_string()),
            ],
            body,
        }
    }

    pub fn refusal(reason: &str) -> Self {
        let body = format!(
            r#"{{"error":{{"type":"ember_block","message":{}}}}}"#,
            crate::json::to_json_string(&crate::json::JsonValue::Str(reason.into())),
        );
        let bytes = body.into_bytes();
        let len = bytes.len();
        Self {
            status: 451, // Unavailable For Legal Reasons — fits "blocked by policy"
            status_text: "Blocked by Policy".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Content-Length".into(), len.to_string()),
            ],
            body: bytes,
        }
    }

    pub fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write!(w, "HTTP/1.1 {} {}\r\n", self.status, self.status_text)?;
        for (k, v) in &self.headers {
            write!(w, "{k}: {v}\r\n")?;
        }
        write!(w, "\r\n")?;
        w.write_all(&self.body)?;
        w.flush()
    }
}

pub fn read_request<R: Read>(stream: R) -> io::Result<HttpRequest> {
    let mut rdr = BufReader::new(stream);
    let line = read_bounded_line(&mut rdr, MAX_REQUEST_LINE_BYTES)?;
    if line.is_empty() {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty request"));
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);
    let mut parts = trimmed.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing path"))?
        .to_string();
    let version = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing version"))?
        .to_string();
    if !version.starts_with("HTTP/") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad version"));
    }

    let mut headers = Vec::new();
    loop {
        if headers.len() >= MAX_HEADERS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many headers"));
        }
        let h = read_bounded_line(&mut rdr, MAX_HEADER_BYTES)?;
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some(colon) = h.find(':') {
            let name = h[..colon].trim();
            let value = h[colon + 1..].trim();
            if name.bytes().any(|b| b < 0x20 || b == 0x7F) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "bad header name"));
            }
            headers.push((name.to_string(), value.to_string()));
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "missing colon"));
        }
    }

    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        rdr.read_exact(&mut body)?;
    }

    Ok(HttpRequest {
        method,
        path,
        version,
        headers,
        body,
    })
}

fn read_bounded_line<R: BufRead>(rdr: &mut R, cap: usize) -> io::Result<String> {
    let mut buf = String::new();
    let mut total = 0usize;
    loop {
        let mut chunk = String::new();
        let n = rdr.read_line(&mut chunk)?;
        if n == 0 {
            break;
        }
        total += n;
        if total > cap {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        buf.push_str(&chunk);
        if chunk.ends_with('\n') {
            break;
        }
    }
    Ok(buf)
}
