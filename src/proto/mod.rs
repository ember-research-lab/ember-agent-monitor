//! Protocol abstraction for agent-monitor.
//!
//! agent-monitor proxies LLM API traffic from any vendor that speaks one
//! of the supported protocols. Detection rules + spectral analysis
//! operate on the shared `Event` type emitted by every parser, so the
//! framework is vendor-independent by construction — adding a new
//! vendor = adding a new parser file, with no rule or fixture changes.
//!
//! # Supported protocols (v1.5)
//!
//! | Protocol | Path prefix | Vendors |
//! |---|---|---|
//! | `Anthropic` | `/v1/...` | Anthropic, AWS Bedrock with Claude |
//! | `OpenAI` (Chat Completions) | `/openai/v1/...` | OpenAI, Codex, Gemini via `/v1beta/openai/`, xAI Grok, Mistral, Together, Fireworks, Groq, Azure OpenAI, Ollama, llama.cpp |
//!
//! Together this covers ~95% of the commercial + local-model ecosystem.
//! Cohere native and Gemini native are deferred until someone shows up
//! needing them — adding either is one new file under `src/proto/`.
//!
//! # Routing model
//!
//! Path-prefix routing: the URL deterministically picks the protocol.
//! Auto-detection by body shape was rejected because protocol-confusion
//! attacks (a body that parses as both Anthropic and OpenAI but with
//! different effective semantics) become controllable by the attacker.
//! Path-prefix puts the choice in a single deterministic place under
//! operator control via client config.
//!
//! Path-prefix isn't free of attack surface either — an attacker who
//! mismatches body and path can probe for parser confusion. We catch
//! that with the `protocol_mismatch_attempt` rule, which fires when the
//! body shape disagrees with the path's protocol. Routing stays
//! deterministic; probing becomes observable.
//!
//! # Adding a new protocol
//!
//! 1. Create `src/proto/<name>.rs` with `parse_request` /
//!    `parse_response` returning a `Vec<Event>`.
//! 2. Add a variant to `Protocol`.
//! 3. Add the path prefix to `Protocol::for_path` and the upstream
//!    config key to `DaemonConfig::upstream_for`.
//! 4. Implement intervention helpers (`inject_advisory`, `strip_dangerous`,
//!    `refusal_response`).
//! 5. Add a fixture under `threat-intel/fixtures/` exercising a
//!    representative tool-use sequence in the new protocol.
//!
//! All existing rules apply to the new parser's emitted events
//! automatically. No rule changes required.

pub mod anthropic;
pub mod openai;

use crate::event::Event;

/// The set of vendor protocols agent-monitor's proxy can dispatch.
///
/// Closed enum on purpose: every supported protocol is shipped, audited,
/// and fixture-tested. Adding a new variant is a deliberate code change,
/// not a runtime plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Anthropic,
    OpenAI,
}

impl Protocol {
    /// Stable string id for telemetry and config keys.
    pub fn id(&self) -> &'static str {
        match self {
            Protocol::Anthropic => "anthropic",
            Protocol::OpenAI => "openai",
        }
    }

    /// Resolve a request path to its protocol, if any.
    ///
    /// Anthropic owns `/v1/...` (its canonical Messages API path).
    /// OpenAI traffic is namespaced under `/openai/v1/...` so the two
    /// don't collide on `/v1`. The user configures their client with
    /// the corresponding base URL — e.g.
    /// `OPENAI_BASE_URL=http://127.0.0.1:9452/openai/v1`.
    pub fn for_path(path: &str) -> Option<Protocol> {
        // Conservative: only accept exact known endpoints. New endpoints
        // require an explicit code change here, not a permissive wildcard.
        if path == "/v1/messages" {
            return Some(Protocol::Anthropic);
        }
        if path == "/openai/v1/chat/completions" || path == "/openai/v1/responses" {
            return Some(Protocol::OpenAI);
        }
        None
    }

    /// Health/status routes that bypass the protocol layer entirely.
    pub fn is_health_path(path: &str) -> bool {
        matches!(path, "/health" | "/status")
    }

    /// Upstream URL suffix for forwarding. The proxy concatenates this
    /// onto the configured upstream base for this protocol.
    pub fn upstream_path(&self, request_path: &str) -> String {
        match self {
            Protocol::Anthropic => "/v1/messages".to_string(),
            Protocol::OpenAI => {
                // Strip the local `/openai` prefix; the upstream
                // (api.openai.com, api.x.ai, etc.) doesn't have it.
                request_path
                    .strip_prefix("/openai")
                    .unwrap_or(request_path)
                    .to_string()
            }
        }
    }

    /// Parse a request body into events. Errors carry a short reason
    /// suitable for inclusion in a finding rationale.
    pub fn parse_request(&self, body: &[u8], session_id: &str) -> Result<Vec<Event>, String> {
        match self {
            Protocol::Anthropic => anthropic::parse_request(body)
                .map(|req| anthropic::request_to_events(&req, session_id)),
            Protocol::OpenAI => openai::parse_request(body)
                .map(|req| openai::request_to_events(&req, session_id)),
        }
    }

    /// Detect bodies whose shape disagrees with the path's protocol.
    /// Used by the `protocol_mismatch_attempt` rule. Returns a
    /// human-readable mismatch reason if one is found, `None` if the
    /// body is consistent with this protocol.
    pub fn body_disagrees(&self, body: &[u8]) -> Option<&'static str> {
        let s = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return None, // not JSON; let the parser error normally
        };
        let v = match crate::json::parse(s) {
            Ok(v) => v,
            Err(_) => return None,
        };
        let obj = match &v {
            crate::json::JsonValue::Object(o) => o,
            _ => return None,
        };
        let has_anthropic_marker = obj.iter().any(|(k, _)| {
            k == "anthropic_version" || k == "anthropic_beta"
        }) || obj.iter().any(|(k, v)| {
            k == "model" && matches!(v, crate::json::JsonValue::Str(s) if s.starts_with("claude"))
        });
        let has_openai_marker = obj.iter().any(|(k, _)| {
            k == "frequency_penalty" || k == "presence_penalty" || k == "logit_bias"
                || k == "n" || k == "response_format"
        }) || obj.iter().any(|(k, v)| {
            k == "model"
                && matches!(v, crate::json::JsonValue::Str(s)
                    if s.starts_with("gpt-")
                        || s.starts_with("o1")
                        || s.starts_with("o3")
                        || s.starts_with("o4")
                        || s.starts_with("gemini-")
                        || s.starts_with("grok-"))
        });
        match self {
            Protocol::Anthropic if has_openai_marker && !has_anthropic_marker => {
                Some("OpenAI-shaped body sent to Anthropic path")
            }
            Protocol::OpenAI if has_anthropic_marker && !has_openai_marker => {
                Some("Anthropic-shaped body sent to OpenAI path")
            }
            _ if has_anthropic_marker && has_openai_marker => {
                Some("body contains markers of both protocols (polyglot)")
            }
            _ => None,
        }
    }
}

// Re-exports for callers that still use the un-namespaced types from when
// agent-monitor was Anthropic-only. New code should go through `Protocol`.
#[allow(deprecated)]
pub use anthropic::{parse_request, request_to_events, AnthropicRequest, ContentBlock};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_path_anthropic() {
        assert_eq!(Protocol::for_path("/v1/messages"), Some(Protocol::Anthropic));
    }

    #[test]
    fn for_path_openai_chat() {
        assert_eq!(
            Protocol::for_path("/openai/v1/chat/completions"),
            Some(Protocol::OpenAI)
        );
    }

    #[test]
    fn for_path_openai_responses() {
        assert_eq!(
            Protocol::for_path("/openai/v1/responses"),
            Some(Protocol::OpenAI)
        );
    }

    #[test]
    fn for_path_unknown() {
        assert_eq!(Protocol::for_path("/v2/messages"), None);
        assert_eq!(Protocol::for_path("/openai/v2/chat"), None);
        assert_eq!(Protocol::for_path("/random"), None);
    }

    #[test]
    fn for_path_does_not_strip_path_traversal() {
        // Path normalisation happens upstream of this function — we only
        // accept exact known strings, so traversal-style paths fail
        // closed.
        assert_eq!(Protocol::for_path("/openai/v1/../v1/messages"), None);
        assert_eq!(Protocol::for_path("/v1/messages/../"), None);
    }

    #[test]
    fn body_disagrees_anthropic_path_with_openai_body() {
        let body = br#"{"model":"gpt-4o","messages":[],"frequency_penalty":0.0}"#;
        assert!(Protocol::Anthropic.body_disagrees(body).is_some());
    }

    #[test]
    fn body_disagrees_openai_path_with_anthropic_body() {
        let body = br#"{"model":"claude-opus-4-7","anthropic_version":"2023-06-01","messages":[]}"#;
        assert!(Protocol::OpenAI.body_disagrees(body).is_some());
    }

    #[test]
    fn body_disagrees_polyglot() {
        let body = br#"{"anthropic_version":"2023-06-01","frequency_penalty":0.0,"messages":[]}"#;
        assert_eq!(
            Protocol::Anthropic.body_disagrees(body),
            Some("body contains markers of both protocols (polyglot)")
        );
        assert_eq!(
            Protocol::OpenAI.body_disagrees(body),
            Some("body contains markers of both protocols (polyglot)")
        );
    }

    #[test]
    fn body_consistent_anthropic() {
        let body = br#"{"model":"claude-opus-4-7","messages":[]}"#;
        assert_eq!(Protocol::Anthropic.body_disagrees(body), None);
    }

    #[test]
    fn body_consistent_openai() {
        let body = br#"{"model":"gpt-4o","messages":[]}"#;
        assert_eq!(Protocol::OpenAI.body_disagrees(body), None);
    }

    #[test]
    fn upstream_path_strips_openai_prefix() {
        assert_eq!(
            Protocol::OpenAI.upstream_path("/openai/v1/chat/completions"),
            "/v1/chat/completions"
        );
        assert_eq!(
            Protocol::Anthropic.upstream_path("/v1/messages"),
            "/v1/messages"
        );
    }
}

