//! Append-only event log: schema, ID generation, JSONL serialization.
//!
//! See design/agent-monitor-spec.md §3. Every event is a row with
//! `event_id`, `session_id`, `timestamp`, `parent_event_id`, `trust_zone`,
//! `content_hash`, `kind`, plus a `body` map of kind-specific fields.
//!
//! Critical invariant: `tool_result` and `user_prompt` are *separate*
//! EventKinds even though Anthropic delivers both as `role: user`. The
//! protocol parser disambiguates and writes the correct kind here.

use crate::crypto::sha256;
use crate::json::{parse, to_json_string, JsonValue};
use crate::types::{EventKind, TrustZone};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Event {
    pub event_id: String,
    pub session_id: String,
    pub timestamp_ms: u64,
    pub parent_event_id: Option<String>,
    pub trust_zone: TrustZone,
    pub content_hash: String,
    pub kind: EventKind,
    pub body: HashMap<String, JsonValue>,
}

impl Event {
    pub fn new(
        session_id: impl Into<String>,
        kind: EventKind,
        trust_zone: TrustZone,
        body: HashMap<String, JsonValue>,
    ) -> Self {
        let session_id = session_id.into();
        let timestamp_ms = now_ms();
        let event_id = generate_id(&session_id, kind, timestamp_ms, &body);
        let content_hash = hash_body(&body);
        Self {
            event_id,
            session_id,
            timestamp_ms,
            parent_event_id: None,
            trust_zone,
            content_hash,
            kind,
            body,
        }
    }

    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.parent_event_id = Some(parent.into());
        self
    }

    pub fn to_json(&self) -> JsonValue {
        let mut top: Vec<(String, JsonValue)> = Vec::with_capacity(8);
        top.push(("event_id".into(), JsonValue::Str(self.event_id.clone())));
        top.push(("session_id".into(), JsonValue::Str(self.session_id.clone())));
        top.push((
            "timestamp_ms".into(),
            JsonValue::Number(self.timestamp_ms as f64),
        ));
        top.push((
            "parent_event_id".into(),
            match &self.parent_event_id {
                Some(s) => JsonValue::Str(s.clone()),
                None => JsonValue::Null,
            },
        ));
        top.push((
            "trust_zone".into(),
            JsonValue::Str(self.trust_zone.as_str().into()),
        ));
        top.push((
            "content_hash".into(),
            JsonValue::Str(self.content_hash.clone()),
        ));
        top.push(("kind".into(), JsonValue::Str(self.kind.as_str().into())));
        let mut body_pairs: Vec<(String, JsonValue)> = self
            .body
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        body_pairs.sort_by(|a, b| a.0.cmp(&b.0));
        top.push(("body".into(), JsonValue::Object(body_pairs)));
        JsonValue::Object(top)
    }

    pub fn to_jsonl_line(&self) -> String {
        let mut s = to_json_string(&self.to_json());
        s.push('\n');
        s
    }

    pub fn from_json(v: &JsonValue) -> Result<Event, String> {
        let obj = match v {
            JsonValue::Object(o) => o,
            _ => return Err("event must be a JSON object".into()),
        };
        let event_id = string_field(obj, "event_id")?;
        let session_id = string_field(obj, "session_id")?;
        let timestamp_ms = number_field(obj, "timestamp_ms")? as u64;
        let parent_event_id = optional_string_field(obj, "parent_event_id");
        let trust_zone_raw = string_field(obj, "trust_zone")?;
        let trust_zone = TrustZone::parse(&trust_zone_raw)
            .ok_or_else(|| format!("unknown trust_zone: {trust_zone_raw}"))?;
        let content_hash = string_field(obj, "content_hash")?;
        let kind_raw = string_field(obj, "kind")?;
        let kind = EventKind::parse(&kind_raw)
            .ok_or_else(|| format!("unknown event kind: {kind_raw}"))?;
        let body = match find_field(obj, "body") {
            Some(JsonValue::Object(b)) => b.iter().cloned().collect(),
            Some(_) => return Err("body must be object".into()),
            None => HashMap::new(),
        };
        Ok(Event {
            event_id,
            session_id,
            timestamp_ms,
            parent_event_id,
            trust_zone,
            content_hash,
            kind,
            body,
        })
    }
}

pub fn parse_jsonl_line(line: &str) -> Result<Event, String> {
    let v = parse(line).map_err(|e| format!("json parse: {e:?}"))?;
    Event::from_json(&v).or_else(|_| Event::from_legacy_json(&v))
}

impl Event {
    /// Parse the flat Python proxy_emit.py format (spec-validation fixture).
    /// All non-protocol fields go into `body`. Trust zone defaults to Unknown
    /// since the Python format doesn't tag zones — the Rust pipeline will
    /// re-tag from path/content during ingest.
    pub fn from_legacy_json(v: &JsonValue) -> Result<Event, String> {
        let obj = match v {
            JsonValue::Object(o) => o,
            _ => return Err("event must be a JSON object".into()),
        };
        let session_id = string_or_default(obj, "session_id");
        let kind_raw = obj
            .iter()
            .find(|(k, _)| k == "kind")
            .and_then(|(_, v)| match v {
                JsonValue::Str(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| "missing field kind".to_string())?;
        let kind = EventKind::parse(&kind_raw)
            .ok_or_else(|| format!("unknown event kind: {kind_raw}"))?;

        // Map Python field name conventions to ours.
        let mut body: HashMap<String, JsonValue> = HashMap::new();
        for (k, v) in obj {
            if matches!(
                k.as_str(),
                "kind" | "session_id" | "timestamp" | "trust_zone" | "event_id"
                    | "parent_event_id" | "content_hash"
            ) {
                continue;
            }
            // Python uses server_name / args; we normalize to server / input.
            let key = match k.as_str() {
                "server_name" => "server".to_string(),
                "args" => "input".to_string(),
                other => other.to_string(),
            };
            body.insert(key, v.clone());
        }

        let trust_zone = obj
            .iter()
            .find(|(k, _)| k == "trust_zone")
            .and_then(|(_, v)| match v {
                JsonValue::Str(s) => TrustZone::parse(s),
                _ => None,
            })
            .unwrap_or_else(|| default_zone_for_kind(kind));

        let timestamp_ms = obj
            .iter()
            .find(|(k, _)| k == "timestamp")
            .and_then(|(_, v)| match v {
                JsonValue::Str(s) => parse_iso8601_ms(s),
                JsonValue::Number(n) => Some(*n as u64),
                _ => None,
            })
            .unwrap_or(0);

        let content_hash = hash_body(&body);
        let mut id_buf = String::with_capacity(64);
        id_buf.push_str(&session_id);
        id_buf.push('|');
        id_buf.push_str(kind.as_str());
        id_buf.push('|');
        id_buf.push_str(&timestamp_ms.to_string());
        id_buf.push('|');
        id_buf.push_str(&content_hash);
        let event_id = hex_prefix(&crate::crypto::sha256::sha256(id_buf.as_bytes()), 16);

        let parent_event_id = obj
            .iter()
            .find(|(k, _)| k == "parent_event_id")
            .and_then(|(_, v)| match v {
                JsonValue::Str(s) => Some(s.clone()),
                _ => None,
            });

        Ok(Event {
            event_id,
            session_id,
            timestamp_ms,
            parent_event_id,
            trust_zone,
            content_hash,
            kind,
            body,
        })
    }
}

fn string_or_default(obj: &[(String, JsonValue)], key: &str) -> String {
    obj.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

fn default_zone_for_kind(kind: EventKind) -> TrustZone {
    match kind {
        EventKind::UserPrompt => TrustZone::UserInput,
        EventKind::ToolResult => TrustZone::UntrustedToolOutput,
        _ => TrustZone::Unknown,
    }
}

fn parse_iso8601_ms(s: &str) -> Option<u64> {
    // Tiny parser: YYYY-MM-DDTHH:MM:SS[.fff][Z|±hh:mm]
    // Returns Unix ms. Best-effort; failures yield None.
    let s = s.trim().trim_end_matches('Z');
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let year: i64 = std::str::from_utf8(&bytes[0..4]).ok()?.parse().ok()?;
    let month: u32 = std::str::from_utf8(&bytes[5..7]).ok()?.parse().ok()?;
    let day: u32 = std::str::from_utf8(&bytes[8..10]).ok()?.parse().ok()?;
    let hour: u32 = std::str::from_utf8(&bytes[11..13]).ok()?.parse().ok()?;
    let min: u32 = std::str::from_utf8(&bytes[14..16]).ok()?.parse().ok()?;
    let sec: u32 = std::str::from_utf8(&bytes[17..19]).ok()?.parse().ok()?;
    let mut ms: u64 = 0;
    if bytes.len() > 20 && bytes[19] == b'.' {
        let mut i = 20;
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() && i - start < 3 {
            ms = ms * 10 + (bytes[i] - b'0') as u64;
            i += 1;
        }
        let digits = i - start;
        for _ in digits..3 {
            ms *= 10;
        }
    }
    let unix_secs = days_from_civil(year, month as i64, day as i64) * 86400
        + hour as i64 * 3600
        + min as i64 * 60
        + sec as i64;
    if unix_secs < 0 {
        return None;
    }
    Some(unix_secs as u64 * 1000 + ms)
}

/// Howard Hinnant's days_from_civil. Returns days since 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64; // [0, 399]
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn generate_id(
    session_id: &str,
    kind: EventKind,
    ts: u64,
    body: &HashMap<String, JsonValue>,
) -> String {
    let mut buf = String::with_capacity(128);
    buf.push_str(session_id);
    buf.push('|');
    buf.push_str(kind.as_str());
    buf.push('|');
    buf.push_str(&ts.to_string());
    buf.push('|');
    buf.push_str(&hash_body(body));
    let digest = sha256::sha256(buf.as_bytes());
    hex_prefix(&digest, 16)
}

fn hash_body(body: &HashMap<String, JsonValue>) -> String {
    let mut pairs: Vec<(&String, &JsonValue)> = body.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let canonical = JsonValue::Object(
        pairs
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    );
    let s = to_json_string(&canonical);
    let digest = sha256::sha256(s.as_bytes());
    hex_prefix(&digest, 16)
}

fn hex_prefix(bytes: &[u8], n_hex_chars: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(n_hex_chars);
    for &b in bytes.iter().take(n_hex_chars / 2) {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn find_field<'a>(obj: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    obj.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Result<String, String> {
    match find_field(obj, key) {
        Some(JsonValue::Str(s)) => Ok(s.clone()),
        Some(_) => Err(format!("field {key} not a string")),
        None => Err(format!("missing field {key}")),
    }
}

fn optional_string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    match find_field(obj, key) {
        Some(JsonValue::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

fn number_field(obj: &[(String, JsonValue)], key: &str) -> Result<f64, String> {
    match find_field(obj, key) {
        Some(JsonValue::Number(n)) => Ok(*n),
        Some(_) => Err(format!("field {key} not a number")),
        None => Err(format!("missing field {key}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_event() {
        let mut body = HashMap::new();
        body.insert("text".into(), JsonValue::Str("hello world".into()));
        let e = Event::new("sess-1", EventKind::UserPrompt, TrustZone::UserInput, body);
        let line = e.to_jsonl_line();
        let parsed = parse_jsonl_line(line.trim_end()).expect("roundtrip");
        assert_eq!(parsed.session_id, "sess-1");
        assert_eq!(parsed.kind, EventKind::UserPrompt);
        assert_eq!(parsed.trust_zone, TrustZone::UserInput);
    }

    #[test]
    fn deterministic_ids() {
        let mut body = HashMap::new();
        body.insert("k".into(), JsonValue::Number(1.0));
        let e1 = Event::new("s", EventKind::ModelText, TrustZone::UserInput, body.clone());
        let h1 = e1.content_hash.clone();
        let e2 = Event::new("s", EventKind::ModelText, TrustZone::UserInput, body);
        // content hash depends only on body, so should match
        assert_eq!(h1, e2.content_hash);
    }
}
