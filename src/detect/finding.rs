//! Finding type and JSON serialization.

use crate::json::{to_json_string, JsonValue};
use crate::types::{Severity, TrustZone};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingScope {
    Static,
    Dynamic,
}

impl FindingScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingScope::Static => "static",
            FindingScope::Dynamic => "dynamic",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub finding_type: String,
    pub scope: FindingScope,
    pub severity: Severity,
    pub session_id: String,
    pub event_id: Option<String>,
    pub tool: Option<String>,
    pub argument: Option<String>,
    pub matched_value: Option<String>,
    pub pattern: Option<String>,
    pub trust_zone: Option<TrustZone>,
    pub rationale: String,
    pub score: f64,
}

impl Finding {
    pub fn to_json(&self) -> JsonValue {
        let mut o: Vec<(String, JsonValue)> = Vec::with_capacity(12);
        o.push(("type".into(), JsonValue::Str(self.finding_type.clone())));
        o.push(("scope".into(), JsonValue::Str(self.scope.as_str().into())));
        o.push((
            "severity".into(),
            JsonValue::Str(self.severity.as_str().into()),
        ));
        o.push(("session_id".into(), JsonValue::Str(self.session_id.clone())));
        if let Some(e) = &self.event_id {
            o.push(("event_id".into(), JsonValue::Str(e.clone())));
        }
        if let Some(t) = &self.tool {
            o.push(("tool".into(), JsonValue::Str(t.clone())));
        }
        if let Some(a) = &self.argument {
            o.push(("argument".into(), JsonValue::Str(a.clone())));
        }
        if let Some(v) = &self.matched_value {
            o.push(("matched_value".into(), JsonValue::Str(v.clone())));
        }
        if let Some(p) = &self.pattern {
            o.push(("pattern".into(), JsonValue::Str(p.clone())));
        }
        if let Some(z) = &self.trust_zone {
            o.push(("trust_zone".into(), JsonValue::Str(z.as_str().into())));
        }
        o.push(("rationale".into(), JsonValue::Str(self.rationale.clone())));
        o.push(("score".into(), JsonValue::Number(self.score)));
        JsonValue::Object(o)
    }

    pub fn to_jsonl(&self) -> String {
        let mut s = to_json_string(&self.to_json());
        s.push('\n');
        s
    }
}
