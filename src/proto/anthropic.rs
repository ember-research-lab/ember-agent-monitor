//! Anthropic Messages API protocol parser.
//!
//! One of two protocols agent-monitor speaks (the other is `openai`). Both
//! parsers emit the same internal `Event` type, so detection rules and
//! spectral analysis are vendor-independent.
//!
//! Spec §3 ("Critical schema discipline"): `tool_result` is structurally
//! distinct from `user_prompt` even though both arrive as `role: user` in
//! Anthropic's wire format. We disambiguate at parse time here, never
//! downstream. Each `messages[i].content` block is inspected for its `type`
//! field — `tool_use`, `tool_result`, `text`, `image`, etc. — and the
//! corresponding event kind is emitted.

use crate::event::Event;
use crate::json::{parse, JsonValue};
use crate::types::{EventKind, TrustZone};
use std::collections::HashMap;

/// Parsed Anthropic request: messages array + system prompt + model.
#[derive(Debug, Clone)]
pub struct AnthropicRequest {
    pub model: Option<String>,
    pub system_prompt: Option<String>,
    pub messages: Vec<Message>,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub role: String,
    pub blocks: Vec<ContentBlock>,
}

#[derive(Debug, Clone)]
pub enum ContentBlock {
    Text(String),
    ToolUse {
        id: String,
        name: String,
        input: JsonValue,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
        /// Non-text content block types observed in this result (e.g.
        /// "image", "audio", "document"). Empty if the result was
        /// text-only. Drives the multimodal injection rule (v1.5 #4).
        media_types: Vec<String>,
    },
    Other(String), // e.g. image, document — type name preserved
}

pub fn parse_request(body: &[u8]) -> Result<AnthropicRequest, String> {
    let s = std::str::from_utf8(body).map_err(|e| format!("utf8: {e}"))?;
    let v = parse(s).map_err(|e| format!("json: {e:?}"))?;
    let obj = match v {
        JsonValue::Object(o) => o,
        _ => return Err("request body must be a JSON object".into()),
    };

    let model = obj
        .iter()
        .find(|(k, _)| k == "model")
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        });

    let system_prompt = obj
        .iter()
        .find(|(k, _)| k == "system")
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.clone()),
            // System can also be an array of content blocks; flatten text.
            JsonValue::Array(arr) => {
                let mut buf = String::new();
                for b in arr {
                    if let JsonValue::Object(o) = b {
                        if let Some((_, JsonValue::Str(t))) = o.iter().find(|(k, _)| k == "text") {
                            if !buf.is_empty() {
                                buf.push('\n');
                            }
                            buf.push_str(t);
                        }
                    }
                }
                if buf.is_empty() {
                    None
                } else {
                    Some(buf)
                }
            }
            _ => None,
        });

    let messages_v = obj
        .iter()
        .find(|(k, _)| k == "messages")
        .map(|(_, v)| v.clone())
        .unwrap_or(JsonValue::Array(vec![]));
    let messages = parse_messages(&messages_v)?;

    Ok(AnthropicRequest {
        model,
        system_prompt,
        messages,
    })
}

fn parse_messages(v: &JsonValue) -> Result<Vec<Message>, String> {
    let arr = match v {
        JsonValue::Array(a) => a,
        _ => return Err("messages must be array".into()),
    };
    let mut out = Vec::with_capacity(arr.len());
    for m in arr {
        let m_obj = match m {
            JsonValue::Object(o) => o,
            _ => continue,
        };
        let role = m_obj
            .iter()
            .find(|(k, _)| k == "role")
            .and_then(|(_, v)| match v {
                JsonValue::Str(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "user".into());
        let content_v = m_obj
            .iter()
            .find(|(k, _)| k == "content")
            .map(|(_, v)| v.clone())
            .unwrap_or(JsonValue::Array(vec![]));
        let blocks = parse_blocks(&content_v);
        out.push(Message { role, blocks });
    }
    Ok(out)
}

fn parse_blocks(v: &JsonValue) -> Vec<ContentBlock> {
    match v {
        JsonValue::Str(s) => vec![ContentBlock::Text(s.clone())],
        JsonValue::Array(arr) => arr.iter().filter_map(parse_block).collect(),
        _ => vec![],
    }
}

fn parse_block(v: &JsonValue) -> Option<ContentBlock> {
    let obj = match v {
        JsonValue::Object(o) => o,
        _ => return None,
    };
    let block_type = obj
        .iter()
        .find(|(k, _)| k == "type")
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        })?;
    match block_type.as_str() {
        "text" => {
            let t = obj
                .iter()
                .find(|(k, _)| k == "text")
                .and_then(|(_, v)| match v {
                    JsonValue::Str(s) => Some(s.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            Some(ContentBlock::Text(t))
        }
        "tool_use" => {
            let id = string_field(obj, "id").unwrap_or_default();
            let name = string_field(obj, "name").unwrap_or_default();
            let input = obj
                .iter()
                .find(|(k, _)| k == "input")
                .map(|(_, v)| v.clone())
                .unwrap_or(JsonValue::Null);
            Some(ContentBlock::ToolUse { id, name, input })
        }
        "tool_result" => {
            let tool_use_id = string_field(obj, "tool_use_id").unwrap_or_default();
            let is_error = obj
                .iter()
                .find(|(k, _)| k == "is_error")
                .and_then(|(_, v)| match v {
                    JsonValue::Bool(b) => Some(*b),
                    _ => None,
                })
                .unwrap_or(false);
            // content can be a string, an array of text blocks, or a single block
            let content_raw = obj
                .iter()
                .find(|(k, _)| k == "content")
                .map(|(_, v)| v.clone())
                .unwrap_or(JsonValue::Str(String::new()));
            let content = stringify_tool_result_content(&content_raw);
            let media_types = extract_media_types(&content_raw);
            Some(ContentBlock::ToolResult {
                tool_use_id,
                content,
                is_error,
                media_types,
            })
        }
        other => Some(ContentBlock::Other(other.to_string())),
    }
}

fn stringify_tool_result_content(v: &JsonValue) -> String {
    match v {
        JsonValue::Str(s) => s.clone(),
        JsonValue::Array(arr) => {
            let mut buf = String::new();
            for b in arr {
                if let JsonValue::Object(o) = b {
                    if let Some((_, JsonValue::Str(t))) = o.iter().find(|(k, _)| k == "text") {
                        if !buf.is_empty() {
                            buf.push('\n');
                        }
                        buf.push_str(t);
                    }
                }
            }
            buf
        }
        _ => String::new(),
    }
}

/// Walk a tool_result content payload and return any non-text media types
/// it contains: `image`, `audio`, `document`, etc. Multimodal content
/// arriving in a tool_result is a structurally distinct trust surface —
/// the model can be influenced by image text (typographic prompt
/// injection) or sub-audible audio that the developer's terminal will
/// never render. v1.5 #4 fires `multimodal_in_tool_result` on hits.
pub fn extract_media_types(v: &JsonValue) -> Vec<String> {
    let mut out = Vec::new();
    if let JsonValue::Array(arr) = v {
        for b in arr {
            if let JsonValue::Object(o) = b {
                if let Some((_, JsonValue::Str(t))) = o.iter().find(|(k, _)| k == "type") {
                    match t.as_str() {
                        "text" => continue,
                        other => out.push(other.to_string()),
                    }
                }
            }
        }
    }
    out
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    obj.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        })
}

/// Convert a parsed Anthropic request into the event stream the schema
/// expects. The disambiguation between `user_prompt` and `tool_result` is
/// the spec's non-negotiable invariant; this is where it happens.
pub fn request_to_events(req: &AnthropicRequest, session_id: &str) -> Vec<Event> {
    let mut events = Vec::new();
    for msg in &req.messages {
        for block in &msg.blocks {
            match block {
                ContentBlock::Text(text) => {
                    let kind = if msg.role == "assistant" {
                        EventKind::ModelText
                    } else {
                        EventKind::UserPrompt
                    };
                    let zone = if msg.role == "assistant" {
                        TrustZone::WorkspaceLocal
                    } else {
                        TrustZone::UserInput
                    };
                    let mut body = HashMap::new();
                    body.insert("text".into(), JsonValue::Str(text.clone()));
                    events.push(Event::new(session_id, kind, zone, body));
                }
                ContentBlock::ToolUse { id, name, input } => {
                    let mut body = HashMap::new();
                    body.insert("tool_use_id".into(), JsonValue::Str(id.clone()));
                    body.insert("tool_name".into(), JsonValue::Str(name.clone()));
                    body.insert("input".into(), input.clone());
                    events.push(Event::new(
                        session_id,
                        EventKind::ToolCall,
                        TrustZone::WorkspaceLocal,
                        body,
                    ));
                }
                ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    is_error,
                    media_types,
                } => {
                    let mut body = HashMap::new();
                    body.insert("tool_use_id".into(), JsonValue::Str(tool_use_id.clone()));
                    body.insert("content".into(), JsonValue::Str(content.clone()));
                    body.insert("is_error".into(), JsonValue::Bool(*is_error));
                    if !media_types.is_empty() {
                        body.insert(
                            "media_types".into(),
                            JsonValue::Array(
                                media_types
                                    .iter()
                                    .map(|s| JsonValue::Str(s.clone()))
                                    .collect(),
                            ),
                        );
                    }
                    // tool_result is ALWAYS untrusted_tool_output — this is the
                    // schema-disambiguation invariant from spec §3.
                    events.push(Event::new(
                        session_id,
                        EventKind::ToolResult,
                        TrustZone::UntrustedToolOutput,
                        body,
                    ));
                }
                ContentBlock::Other(_) => {}
            }
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_message() {
        let body = br#"{
            "model": "claude-opus-4-7",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hello"}]}
            ]
        }"#;
        let req = parse_request(body).expect("parse");
        assert_eq!(req.messages.len(), 1);
        match &req.messages[0].blocks[0] {
            ContentBlock::Text(t) => assert_eq!(t, "hello"),
            _ => panic!("expected text"),
        }
    }

    #[test]
    fn distinguishes_tool_result_from_user_prompt() {
        let body = br#"{
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "do it"}]},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "read", "input": {"path": "/etc/passwd"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "root:x:0:0"}]}
            ]
        }"#;
        let req = parse_request(body).expect("parse");
        let events = request_to_events(&req, "sess");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, EventKind::UserPrompt);
        assert_eq!(events[0].trust_zone, TrustZone::UserInput);
        assert_eq!(events[1].kind, EventKind::ToolCall);
        assert_eq!(events[2].kind, EventKind::ToolResult);
        // The schema-discipline invariant:
        assert_eq!(events[2].trust_zone, TrustZone::UntrustedToolOutput);
    }
}
