//! Individual detection rules. One function per rule.
//!
//! Each rule appends to a `&mut Vec<Finding>`. Score is computed at emit
//! time as `pattern × source_trust_inverse × severity` per spec §4.

use super::finding::{Finding, FindingScope};
use super::patterns;
use super::toxic;
use crate::event::Event;
use crate::graph::SessionGraph;
use crate::json::JsonValue;
use crate::trust::{classify_path, normalize_path};
use crate::types::{EventKind, Severity, TrustZone};

const PATTERN_HIT_WEIGHT: f64 = 1.0;

/// Spec §4 ("Static detections"): toxic_capability_composition.
pub fn toxic_capability_composition(graph: &SessionGraph, out: &mut Vec<Finding>) {
    let caps = graph.capability_set();
    for tc in toxic::check(&caps) {
        let score = PATTERN_HIT_WEIGHT * 1.0 * tc.severity.weight();
        out.push(Finding {
            finding_type: "toxic_capability_composition".into(),
            scope: FindingScope::Static,
            severity: tc.severity,
            session_id: graph
                .dynamic_graph
                .events
                .first()
                .map(|e| e.session_id.clone())
                .unwrap_or_default(),
            event_id: None,
            tool: None,
            argument: None,
            matched_value: Some(tc.name.into()),
            pattern: None,
            trust_zone: None,
            rationale: tc.rationale.into(),
            score,
        });
    }
}

/// Spec §4 (static): high_risk_plugin_composition. A plugin bundle that
/// simultaneously registers an MCP server, a hook, AND a subagent has a
/// large collusion surface — any one of those three can call into either
/// of the other two without re-authorization, and the surface area for
/// capability injection grows multiplicatively rather than additively.
///
/// We detect this by inspecting the static graph after all registration
/// events have arrived. If the same `plugin_install` event ID (or
/// equivalent plugin scoping) brought in MCP + hook + subagent at session
/// start, fire a static finding.
///
/// v0.5 substrate: persistent stores plugin-install events but the
/// per-plugin scoping isn't yet correlated. v1 ties this together via the
/// `plugin_id` field that mcp_registration / hook_registration events
/// carry when they were sourced from a plugin.
pub fn high_risk_plugin_composition(graph: &SessionGraph, out: &mut Vec<Finding>) {
    // For each installed plugin, count whether it brought in
    // (mcp_registration, hook_registration, subagent_invocation) events.
    use std::collections::BTreeMap;

    #[derive(Default, Debug)]
    struct PluginSurface {
        mcp: usize,
        hook: usize,
        subagent: usize,
    }

    let mut by_plugin: BTreeMap<String, PluginSurface> = BTreeMap::new();
    let plugins = &graph.static_graph.plugins;
    if plugins.is_empty() {
        return;
    }
    for ev in &graph.dynamic_graph.events {
        let plugin_id = match string_from_body(ev, "plugin_id") {
            Some(p) if !p.is_empty() => p,
            _ => continue,
        };
        let entry = by_plugin.entry(plugin_id).or_default();
        match ev.kind {
            EventKind::McpRegistration => entry.mcp += 1,
            EventKind::HookRegistration => entry.hook += 1,
            EventKind::SubagentInvocation => entry.subagent += 1,
            _ => {}
        }
    }
    for (plugin_id, surface) in &by_plugin {
        if surface.mcp > 0 && surface.hook > 0 && surface.subagent > 0 {
            let session_id = graph
                .dynamic_graph
                .events
                .first()
                .map(|e| e.session_id.clone())
                .unwrap_or_default();
            out.push(Finding {
                finding_type: "high_risk_plugin_composition".into(),
                scope: FindingScope::Static,
                severity: Severity::High,
                session_id,
                event_id: None,
                tool: Some(format!("plugin:{plugin_id}")),
                argument: None,
                matched_value: Some(format!(
                    "mcp={} hook={} subagent={}",
                    surface.mcp, surface.hook, surface.subagent
                )),
                pattern: None,
                trust_zone: None,
                rationale: format!(
                    "plugin '{plugin_id}' bundles MCP server(s) + hook(s) + subagent(s) \
                     simultaneously. The collusion surface — MCP can fire a hook that \
                     spawns a subagent that calls back into the MCP — grows \
                     multiplicatively, not additively. Per spec §4, this is the highest \
                     pre-execution risk class because a single compromised plugin \
                     attestation defeats every layer's per-component review."
                ),
                score: 0.85,
            });
        }
    }
}

/// Spec §4 (dynamic): classifier_disagreement. When the agent runtime emits
/// an auto-mode classifier verdict (`classifier_decision` event) and our
/// own runtime detection produced a finding for the same turn, surface any
/// disagreement as a calibration finding.
///
/// The directionality matters: classifier says "safe" + we say "high
/// severity" is the more interesting case (we caught something the
/// upstream classifier missed). The reverse — classifier high + we miss —
/// is also useful but we won't see it in the same data path; we only know
/// what *we* observed.
pub fn classifier_disagreement(event: &Event, graph: &SessionGraph, out: &mut Vec<Finding>) {
    if event.kind != EventKind::ClassifierDecision {
        return;
    }
    let classifier_verdict = string_from_body(event, "verdict").unwrap_or_default();
    if classifier_verdict.is_empty() {
        return;
    }
    // "Recent" = within the last 20 events of the session. Adjustable.
    let recent_window = 20usize;
    let recent_events = graph.dynamic_graph.last_n(recent_window);
    let our_high_count = recent_events
        .iter()
        .filter(|e| e.kind == EventKind::Finding)
        .filter(|e| {
            let sev = string_from_body(e, "severity").unwrap_or_default();
            matches!(sev.as_str(), "high" | "critical")
        })
        .count();

    let session_id = event.session_id.clone();
    let safe_classifier = matches!(
        classifier_verdict.to_ascii_lowercase().as_str(),
        "safe" | "allow" | "ok" | "low_risk"
    );

    if safe_classifier && our_high_count > 0 {
        out.push(Finding {
            finding_type: "classifier_disagreement".into(),
            scope: FindingScope::Dynamic,
            severity: Severity::Medium,
            session_id,
            event_id: Some(event.event_id.clone()),
            tool: None,
            argument: None,
            matched_value: Some(format!(
                "classifier={classifier_verdict} our_high={our_high_count}"
            )),
            pattern: None,
            trust_zone: None,
            rationale: format!(
                "auto-mode classifier emitted '{classifier_verdict}' verdict but ember-agent's \
                 own detection produced {our_high_count} high-severity finding(s) in the \
                 same recent window. Disagreement is calibration signal — either we are \
                 over-firing or the classifier is missing a real threat. Surfaces both \
                 directions for investigation."
            ),
            score: 0.5,
        });
    }
}

/// Spec §4: lethal_trifecta_reachability — capability lattice contains
/// paths from private-data zones through transformation tools to external
/// communication. v0.5 implements the simplest version: any session with
/// FileRead + NetworkOut where some tool is in a sensitive zone.
pub fn lethal_trifecta_reachability(graph: &SessionGraph, out: &mut Vec<Finding>) {
    use crate::types::Capability::*;
    let caps = graph.capability_set();
    let has_read = caps.contains(&FileRead);
    let has_net = caps.contains(&NetworkOut);
    let has_write = caps.contains(&FileWrite) || caps.contains(&FileWriteViaFilter);
    if has_read && has_net && has_write {
        let session_id = graph
            .dynamic_graph
            .events
            .first()
            .map(|e| e.session_id.clone())
            .unwrap_or_default();
        out.push(Finding {
            finding_type: "lethal_trifecta_reachability".into(),
            scope: FindingScope::Static,
            severity: Severity::High,
            session_id,
            event_id: None,
            tool: None,
            argument: None,
            matched_value: None,
            pattern: None,
            trust_zone: None,
            rationale: "session has read + transform + network_out — \
                       full lethal-trifecta capability lattice reachable"
                .into(),
            score: 0.8,
        });
    }
}

/// Spec §4: sensitive_zone_access. Walks tool_call input args, classifies
/// any path-shaped value, fires HIGH if it lands in `sensitive_local`.
pub fn sensitive_zone_access(event: &Event, cfg: &super::DetectionConfig, out: &mut Vec<Finding>) {
    if event.kind != EventKind::ToolCall {
        return;
    }
    let tool = string_from_body(event, "tool_name").unwrap_or_default();
    let input = match event.body.get("input") {
        Some(JsonValue::Object(o)) => o.clone(),
        _ => return,
    };
    for (k, v) in &input {
        let s = match v {
            JsonValue::Str(s) => s.clone(),
            _ => continue,
        };
        if !looks_path_like(&s) {
            continue;
        }
        let normalized = normalize_path(&s);
        let zone = classify_path(&normalized, cfg.workspace_root.as_deref(), &cfg.sensitive);
        if zone == TrustZone::SensitiveLocal {
            let score = PATTERN_HIT_WEIGHT * zone.inverse_trust() * Severity::High.weight();
            out.push(Finding {
                finding_type: "sensitive_zone_access".into(),
                scope: FindingScope::Dynamic,
                severity: Severity::High,
                session_id: event.session_id.clone(),
                event_id: Some(event.event_id.clone()),
                tool: Some(tool.clone()),
                argument: Some(k.clone()),
                matched_value: Some(s.clone()),
                pattern: None,
                trust_zone: Some(zone),
                rationale: format!("Tool call to {tool} references sensitive path via {k}"),
                score,
            });
        }
    }
}

/// v1.5 #2: webhook_destination_arg. Scans tool_call URL arguments for
/// hosts in a curated exfil block-list (Discord/Slack incoming webhooks,
/// paste sites, anonymous file hosts, request bins, tunnel services).
///
/// Mirrors the network-layer `webhook_destination` rule but at the
/// API-proxy boundary: catches the attempt before bytes leave. The
/// network tool's version catches subprocess-spawned exfil that bypasses
/// the proxy — both layers fire and the user sees the layered detection.
///
/// Severity: HIGH. Block-list hits are not legitimate workflow noise.
pub fn webhook_destination_arg(event: &Event, out: &mut Vec<Finding>) {
    if event.kind != EventKind::ToolCall {
        return;
    }
    let tool = string_from_body(event, "tool_name").unwrap_or_default();
    let input = match event.body.get("input") {
        Some(JsonValue::Object(o)) => o.clone(),
        _ => return,
    };
    for (k, v) in &input {
        let url = match v {
            JsonValue::Str(s) => s.clone(),
            _ => continue,
        };
        let host = match extract_url_host(&url) {
            Some(h) => h,
            None => continue,
        };
        let label = match webhook_blocklist_match(&host) {
            Some(l) => l,
            None => continue,
        };
        let score = PATTERN_HIT_WEIGHT * Severity::High.weight();
        out.push(Finding {
            finding_type: "webhook_destination_arg".into(),
            scope: FindingScope::Dynamic,
            severity: Severity::High,
            session_id: event.session_id.clone(),
            event_id: Some(event.event_id.clone()),
            tool: Some(tool.clone()),
            argument: Some(k.clone()),
            matched_value: Some(url.clone()),
            pattern: Some(label.into()),
            trust_zone: None,
            rationale: format!(
                "tool_call to {tool} with {k} pointing at {host} matches the curated \
                 webhook/exfil block-list ({label}). Destinations on this list have no \
                 reasonable use-case in an agent's data plane — high-confidence exfil \
                 indicator at the API-proxy boundary."
            ),
            score,
        });
    }
}

fn extract_url_host(url: &str) -> Option<String> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = after_scheme.split(['/', '?', ':', '#']).next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

/// Block-list mirror of network's WebhookBlocklist. We don't share the
/// type (loose-coupling discipline — no shared library) but the entries
/// are kept in lock-step. Updates land in both crates' threat-intel
/// CHANGELOGs.
fn webhook_blocklist_match(host: &str) -> Option<&'static str> {
    const EXACT: &[(&str, &str)] = &[
        ("pastebin.com", "paste-site"),
        ("paste.ee", "paste-site"),
        ("dpaste.com", "paste-site"),
        ("hastebin.com", "paste-site"),
        ("transfer.sh", "anonymous-file-host"),
        ("ix.io", "paste-site"),
        ("0x0.st", "anonymous-file-host"),
        ("file.io", "anonymous-file-host"),
        ("anonfiles.com", "anonymous-file-host"),
        ("bashupload.com", "anonymous-file-host"),
        ("requestbin.com", "request-bin"),
        ("webhook.site", "request-bin"),
        ("pipedream.com", "request-bin"),
        ("ngrok.io", "tunnel"),
        ("localtunnel.me", "tunnel"),
        ("ngrok-free.app", "tunnel"),
        ("hooks.slack.com", "slack-incoming-webhook"),
        ("api.telegram.org", "telegram-bot-api"),
    ];
    const SUFFIXES: &[(&str, &str)] = &[
        (".discord.com", "discord-webhook"),
        (".discordapp.com", "discord-webhook"),
        (".ngrok.io", "tunnel"),
        (".ngrok-free.app", "tunnel"),
        (".ngrok.app", "tunnel"),
        (".gist.github.com", "github-gist"),
    ];
    for (h, label) in EXACT {
        if host == *h {
            return Some(*label);
        }
    }
    for (suffix, label) in SUFFIXES {
        if host.ends_with(suffix) || host == suffix.trim_start_matches('.') {
            return Some(*label);
        }
    }
    None
}

/// Spec §4: argument_injection_pattern. Scans every string-typed value in
/// the tool_call input map against the argument-injection pattern list.
pub fn argument_injection_pattern(event: &Event, out: &mut Vec<Finding>) {
    if event.kind != EventKind::ToolCall {
        return;
    }
    let tool = string_from_body(event, "tool_name").unwrap_or_default();
    let input = match event.body.get("input") {
        Some(JsonValue::Object(o)) => o.clone(),
        _ => return,
    };
    for (k, v) in &input {
        let s = match v {
            JsonValue::Str(s) => s.clone(),
            _ => continue,
        };
        for (_label, matcher) in patterns::arg_injection_patterns() {
            if let Some(label) = matcher(&s) {
                // No trust-zone factor: the model's argument may itself be
                // the product of an upstream prompt injection, so we treat
                // this finding as model-emitted-regardless-of-context.
                let score = PATTERN_HIT_WEIGHT * Severity::High.weight();
                out.push(Finding {
                    finding_type: "argument_injection_pattern".into(),
                    scope: FindingScope::Dynamic,
                    severity: Severity::High,
                    session_id: event.session_id.clone(),
                    event_id: Some(event.event_id.clone()),
                    tool: Some(tool.clone()),
                    argument: Some(k.clone()),
                    matched_value: Some(s.clone()),
                    pattern: Some(label.into()),
                    trust_zone: None,
                    rationale: format!("flag- or shell-shaped pattern {label} in argument {k}"),
                    score,
                });
                break; // one finding per arg
            }
        }
    }
}

/// Spec §4 (dynamic): trigger_cause_violation. When a skill loads or a
/// hook registers, walk the causal-parent chain. If any ancestor is in
/// `untrusted_tool_output`, the activation was triggered by injected
/// content and fires HIGH severity.
///
/// Why this matters: skills and hooks expand the agent's runtime surface.
/// An attacker who can get an `untrusted_tool_output` event (a fetched
/// webpage, a poisoned README) to *cause* a skill to load has elevated
/// the attack from prompt injection into capability injection. Per-event
/// detection on the result body alone misses this — the body might be
/// innocuous text; the *consequence* (skill activation) is what's
/// suspicious.
pub fn trigger_cause_violation(event: &Event, graph: &SessionGraph, out: &mut Vec<Finding>) {
    if !matches!(
        event.kind,
        EventKind::SkillLoad | EventKind::HookRegistration
    ) {
        return;
    }
    let ancestors = graph.dynamic_graph.ancestors(&event.event_id);
    if ancestors.is_empty() {
        return;
    }
    for parent_id in &ancestors {
        let parent_event = graph
            .dynamic_graph
            .events
            .iter()
            .find(|e| e.event_id == *parent_id);
        if let Some(parent) = parent_event {
            if parent.trust_zone == TrustZone::UntrustedToolOutput {
                let activation_kind = match event.kind {
                    EventKind::SkillLoad => "skill activation",
                    EventKind::HookRegistration => "hook registration",
                    _ => "activation",
                };
                let activation_name = string_from_body(event, "name")
                    .or_else(|| string_from_body(event, "handler"))
                    .unwrap_or_else(|| "(unnamed)".into());
                let score = PATTERN_HIT_WEIGHT
                    * TrustZone::UntrustedToolOutput.inverse_trust()
                    * Severity::High.weight();
                out.push(Finding {
                    finding_type: "trigger_cause_violation".into(),
                    scope: FindingScope::Dynamic,
                    severity: Severity::High,
                    session_id: event.session_id.clone(),
                    event_id: Some(event.event_id.clone()),
                    tool: None,
                    argument: None,
                    matched_value: Some(activation_name),
                    pattern: None,
                    trust_zone: Some(TrustZone::UntrustedToolOutput),
                    rationale: format!(
                        "{activation_kind} event has an ancestor in untrusted_tool_output \
                         (parent_event_id={parent_id}). Skills and hooks expand the agent's \
                         runtime surface; activations triggered by injected content are \
                         capability-injection attacks, not just prompt injection."
                    ),
                    score,
                });
                return;
            }
        }
    }
}

/// v1.5 #6: api_base_url_redirect. Detects tool_calls that set or write
/// API-base-URL env vars to non-default values — the CVE-2026-21852 class.
///
/// Attack shape: a malicious repo's `.env` / `.envrc` / `.claude/settings.json`
/// overrides `ANTHROPIC_BASE_URL` to attacker-controlled host. The agent's
/// next request still carries the real bearer token but goes to the
/// attacker's endpoint. Same shape applies to OpenAI's `OPENAI_API_BASE`
/// and `OPENAI_BASE_URL`.
///
/// Detection: scan every string-typed input in a tool_call for the
/// `<VAR>=` pattern, where the value is not the canonical anthropic.com
/// or openai.com host. Catches both `bash` invocations setting the var
/// AND `write_file` calls dropping a config file with the override.
///
/// Severity: HIGH. The list of vars is curated; user-extensible additions
/// can land via threat-intel CHANGELOG.
pub fn api_base_url_redirect(event: &Event, out: &mut Vec<Finding>) {
    if event.kind != EventKind::ToolCall {
        return;
    }
    let tool = string_from_body(event, "tool_name").unwrap_or_default();
    let input = match event.body.get("input") {
        Some(JsonValue::Object(o)) => o.clone(),
        _ => return,
    };
    // (env_var, canonical_host_substring)
    const REDIRECT_VARS: &[(&str, &str)] = &[
        ("ANTHROPIC_BASE_URL", "anthropic.com"),
        ("OPENAI_API_BASE", "openai.com"),
        ("OPENAI_BASE_URL", "openai.com"),
        ("AZURE_OPENAI_ENDPOINT", "azure.com"),
        ("GOOGLE_API_BASE", "googleapis.com"),
    ];
    for (k, v) in &input {
        let s = match v {
            JsonValue::Str(s) => s.clone(),
            _ => continue,
        };
        for (var, canonical) in REDIRECT_VARS {
            if let Some(idx) = s.find(&format!("{var}=")) {
                let value_start = idx + var.len() + 1;
                // Take up to the next whitespace, newline, or quote.
                let rest = &s[value_start..];
                let end = rest
                    .find([' ', '\t', '\n', '"', '\''])
                    .unwrap_or(rest.len());
                let value = &rest[..end];
                let value_lower = value.to_lowercase();
                // Empty / unset isn't an attack signal.
                if value.is_empty() {
                    continue;
                }
                // Skip exact canonical matches (the var being explicitly set
                // to the legit endpoint isn't a redirect).
                if value_lower.contains(canonical) {
                    continue;
                }
                let score = PATTERN_HIT_WEIGHT * Severity::High.weight();
                out.push(Finding {
                    finding_type: "api_base_url_redirect".into(),
                    scope: FindingScope::Dynamic,
                    severity: Severity::High,
                    session_id: event.session_id.clone(),
                    event_id: Some(event.event_id.clone()),
                    tool: Some(tool.clone()),
                    argument: Some(k.clone()),
                    matched_value: Some(format!("{var}={value}")),
                    pattern: Some((*var).into()),
                    trust_zone: None,
                    rationale: format!(
                        "tool_call to {tool} sets {var} to a non-canonical host \
                         ({value}). API-base-URL redirects route the agent's bearer \
                         token to the attacker's endpoint while the agent keeps \
                         operating normally — CVE-2026-21852 family. Canonical hosts \
                         contain '{canonical}'; this value does not."
                    ),
                    score,
                });
                return;
            }
        }
    }
}

/// v1.5 #5: subagent_via_injection (control-flow hijacking across
/// subagents — CFH). When a subagent is invoked (Task / orchestrator
/// MCP tools) and its causal ancestor is in `untrusted_tool_output`,
/// the orchestrator's plan was influenced by injected content.
///
/// Distinct from cross-session `cross_orchestrator_lineage` (persistent
/// layer): this is the within-session analog. A poisoned researcher
/// subagent emits a result that gets a writer subagent spawned in the
/// same session, by the same orchestrator, but the spawn was caused by
/// the researcher's output rather than the user's request.
///
/// Detection mirrors `trigger_cause_violation` but with subagent tools
/// as the trigger event class (instead of skill_load / hook_registration).
pub fn subagent_via_injection(event: &Event, graph: &SessionGraph, out: &mut Vec<Finding>) {
    if event.kind != EventKind::ToolCall {
        return;
    }
    let tool = string_from_body(event, "tool_name").unwrap_or_default();
    if !is_subagent_tool_name(&tool) {
        return;
    }
    let ancestors = graph.dynamic_graph.ancestors(&event.event_id);
    if ancestors.is_empty() {
        return;
    }
    for parent_id in &ancestors {
        let parent_event = graph
            .dynamic_graph
            .events
            .iter()
            .find(|e| e.event_id == *parent_id);
        if let Some(parent) = parent_event {
            if parent.trust_zone == TrustZone::UntrustedToolOutput {
                let score = PATTERN_HIT_WEIGHT
                    * TrustZone::UntrustedToolOutput.inverse_trust()
                    * Severity::High.weight();
                out.push(Finding {
                    finding_type: "subagent_via_injection".into(),
                    scope: FindingScope::Dynamic,
                    severity: Severity::High,
                    session_id: event.session_id.clone(),
                    event_id: Some(event.event_id.clone()),
                    tool: Some(tool.clone()),
                    argument: None,
                    matched_value: None,
                    pattern: None,
                    trust_zone: Some(TrustZone::UntrustedToolOutput),
                    rationale: format!(
                        "subagent invocation ({tool}) has an ancestor in \
                         untrusted_tool_output (parent_event_id={parent_id}). The \
                         orchestrator's plan to spawn this subagent traces to injected \
                         content, not user input — control-flow hijacking across \
                         subagents (CFH). Distinct from cross_orchestrator_lineage \
                         which catches the cross-session variant of the same shape."
                    ),
                    score,
                });
                return;
            }
        }
    }
}

/// Subagent-spawning tool names. Mirrors persistent's
/// rules::cross_orchestrator::SUBAGENT_TOOLS list. Updates land in
/// both crates' threat-intel CHANGELOGs.
fn is_subagent_tool_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        "task"
            | "mcp__orchestrator__send_message"
            | "mcp__orchestrator__spawn_agent"
            | "mcp__send_message"
            | "spawn_agent"
    )
}

/// MCPoison-class: tool descriptions registered via MCP can carry hidden
/// instructions that influence the agent (CVE-2025-54136 and family).
/// Same pattern matcher as instruction_shape_in_tool_result, but applies
/// to mcp_registration events. Trust-zone gating: descriptions arrive over
/// local IPC (the file-watcher path), not over the API; we treat them as
/// `external_local` (slightly less hostile than untrusted_tool_output, but
/// still suspicious when they contain directive shapes).
pub fn instruction_shape_in_mcp_description(event: &Event, out: &mut Vec<Finding>) {
    if event.kind != EventKind::McpRegistration {
        return;
    }
    let server = string_from_body(event, "server").unwrap_or_default();
    // Tool descriptions can land in body either as a flat string-array of
    // descriptions or as an array of {name, description} objects. We accept
    // either shape and walk every string we find.
    let mut texts_to_scan: Vec<String> = Vec::new();
    if let Some(JsonValue::Str(s)) = event.body.get("description") {
        texts_to_scan.push(s.clone());
    }
    if let Some(JsonValue::Array(arr)) = event.body.get("descriptions") {
        for v in arr {
            if let JsonValue::Str(s) = v {
                texts_to_scan.push(s.clone());
            }
        }
    }
    if let Some(JsonValue::Array(arr)) = event.body.get("tool_details") {
        for v in arr {
            if let JsonValue::Object(o) = v {
                if let Some(JsonValue::Str(s)) =
                    o.iter().find(|(k, _)| k == "description").map(|(_, v)| v)
                {
                    texts_to_scan.push(s.clone());
                }
            }
        }
    }
    for content in &texts_to_scan {
        if content.is_empty() {
            continue;
        }
        for (_label, matcher) in patterns::instruction_patterns() {
            if let Some(label) = matcher(content) {
                let score = PATTERN_HIT_WEIGHT
                    * TrustZone::ExternalLocal.inverse_trust()
                    * Severity::High.weight();
                out.push(Finding {
                    finding_type: "instruction_shape_in_mcp_description".into(),
                    scope: FindingScope::Static,
                    severity: Severity::High,
                    session_id: event.session_id.clone(),
                    event_id: Some(event.event_id.clone()),
                    tool: Some(format!("mcp:{server}")),
                    argument: None,
                    matched_value: None,
                    pattern: Some(label.into()),
                    trust_zone: Some(TrustZone::ExternalLocal),
                    rationale: format!(
                        "MCP server '{server}' registered a tool description containing \
                         a directive-shaped pattern ({label}). MCPoison-class injection: \
                         description text becomes part of the agent's tool catalog and \
                         can influence behavior without ever appearing in a tool_result."
                    ),
                    score,
                });
                break;
            }
        }
    }
}

/// v1.5 #4: multimodal_in_tool_result. Surface any tool_result whose
/// content_blocks include image, audio, or document media. Multimodal
/// content is a structurally distinct trust surface:
///
/// - Image: typographic prompt injection (CSA research found 64% ASR
///   against GPT-4V/Claude 3 with text rendered into the image)
/// - Audio: sub-audible carriers (WhisperInject)
/// - Document: embedded PDFs / Office docs can carry hidden text
///
/// We can't analyze the bytes themselves at the proxy layer (that would
/// require a vision/audio model — outside zero-dep scope). What we can
/// do: flag every multimodal tool_result so the operator knows the
/// agent received a non-text input that COULD carry hidden instructions.
/// Severity is MEDIUM by default, HIGH when the source is `untrusted_tool_output`.
pub fn multimodal_in_tool_result(event: &Event, out: &mut Vec<Finding>) {
    if event.kind != EventKind::ToolResult {
        return;
    }
    let media_types = match event.body.get("media_types") {
        Some(JsonValue::Array(arr)) => arr,
        _ => return,
    };
    if media_types.is_empty() {
        return;
    }
    let names: Vec<String> = media_types
        .iter()
        .filter_map(|v| match v {
            JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        })
        .collect();
    if names.is_empty() {
        return;
    }
    let severity = if event.trust_zone == TrustZone::UntrustedToolOutput {
        Severity::High
    } else {
        Severity::Medium
    };
    let score = PATTERN_HIT_WEIGHT * event.trust_zone.inverse_trust() * severity.weight();
    out.push(Finding {
        finding_type: "multimodal_in_tool_result".into(),
        scope: FindingScope::Dynamic,
        severity,
        session_id: event.session_id.clone(),
        event_id: Some(event.event_id.clone()),
        tool: None,
        argument: None,
        matched_value: Some(names.join(",")),
        pattern: None,
        trust_zone: Some(event.trust_zone),
        rationale: format!(
            "tool_result contains non-text media block(s): {}. Multimodal content can \
             carry steganographic instructions invisible at the source — typographic \
             text rendered into images (high ASR vs vision LLMs), sub-audible audio \
             carriers, embedded text in documents. We don't analyze the bytes here \
             (outside zero-dep scope); this finding is a 'this surface is exposed' \
             signal so the operator can investigate or gate the tool that produced it.",
            names.join(", "),
        ),
        score,
    });
}

/// Spec §4 (the big one): instruction_shape_in_tool_result. Pattern presence
/// alone is not a finding — the source trust zone must be `untrusted_tool_output`.
/// Same `you MUST` text in a workspace doc is low-signal; in a webpage, high.
pub fn instruction_shape_in_tool_result(event: &Event, out: &mut Vec<Finding>) {
    if event.kind != EventKind::ToolResult {
        return;
    }
    if event.trust_zone != TrustZone::UntrustedToolOutput {
        return;
    }
    let content = string_from_body(event, "content")
        .or_else(|| string_from_body(event, "content_preview"))
        .unwrap_or_default();
    if content.is_empty() {
        return;
    }
    for (_label, matcher) in patterns::instruction_patterns() {
        if let Some(label) = matcher(&content) {
            let score =
                PATTERN_HIT_WEIGHT * event.trust_zone.inverse_trust() * Severity::Medium.weight();
            out.push(Finding {
                finding_type: "instruction_shape_in_tool_result".into(),
                scope: FindingScope::Dynamic,
                severity: Severity::Medium,
                session_id: event.session_id.clone(),
                event_id: Some(event.event_id.clone()),
                tool: None,
                argument: None,
                matched_value: None,
                pattern: Some(label.into()),
                trust_zone: Some(event.trust_zone),
                rationale: "Untrusted tool output contains directive-shaped text".into(),
                score,
            });
        }
    }
}

fn looks_path_like(s: &str) -> bool {
    s.contains('/') || s.contains('~') || s.contains('\\')
}

/// Spec §9 (v2): spectral_anomaly. Compute the session graph's spectral
/// fingerprint and compare against the configured baseline. Score above
/// threshold → fire.
pub fn spectral_anomaly(
    graph: &SessionGraph,
    cfg: &super::DetectionConfig,
    out: &mut Vec<Finding>,
) {
    let baseline = match &cfg.spectral_baseline {
        Some(b) => b,
        None => return,
    };
    if graph.dynamic_graph.events.len() < 4 {
        return; // too small to be meaningful
    }
    let profile = crate::spectral::SpectralProfile::from_session(graph);
    if profile.n_nodes < 3 {
        return;
    }
    let breakdown = baseline.score(&profile);
    if breakdown.total < cfg.spectral_threshold {
        return;
    }
    let session_id = graph
        .dynamic_graph
        .events
        .first()
        .map(|e| e.session_id.clone())
        .unwrap_or_default();
    let rationale = format!(
        "session graph spectrum diverges from baseline: total={:.3} \
         (fiedler dev={:.3}, spectral_dim dev={:.3}, heat_trace dev={:.3})",
        breakdown.total,
        breakdown.fiedler_dev,
        breakdown.spectral_dimension_dev,
        breakdown.heat_trace_dev,
    );
    out.push(Finding {
        finding_type: "spectral_anomaly".into(),
        scope: FindingScope::Static,
        severity: if breakdown.total >= 1.5 {
            Severity::High
        } else {
            Severity::Medium
        },
        session_id,
        event_id: None,
        tool: None,
        argument: None,
        matched_value: Some(format!(
            "λ₂={:.3} d_s={} N={}",
            profile.fiedler_value,
            profile
                .spectral_dimension
                .map(|d| format!("{d:.2}"))
                .unwrap_or_else(|| "—".into()),
            profile.n_nodes,
        )),
        pattern: None,
        trust_zone: None,
        rationale,
        score: breakdown.total.min(2.0) / 2.0,
    });
}

/// Spec §9 (v2): subgraph motif detection. The session graph's spectrum
/// is checked for known attack-motif fingerprints (read→transform→write,
/// 4-node staged exfil, convergent fan-out).
pub fn spectral_motif_match(
    graph: &SessionGraph,
    cfg: &super::DetectionConfig,
    out: &mut Vec<Finding>,
) {
    if cfg.spectral_baseline.is_none() {
        return;
    }
    if graph.dynamic_graph.events.len() < 3 {
        return;
    }
    let profile = crate::spectral::SpectralProfile::from_session(graph);
    if profile.n_nodes < 3 {
        return;
    }
    let session_id = graph
        .dynamic_graph
        .events
        .first()
        .map(|e| e.session_id.clone())
        .unwrap_or_default();
    for motif in crate::spectral::check_motifs(&profile) {
        out.push(Finding {
            finding_type: "spectral_motif_match".into(),
            scope: FindingScope::Static,
            severity: Severity::Medium,
            session_id: session_id.clone(),
            event_id: None,
            tool: None,
            argument: None,
            matched_value: Some(motif.name.into()),
            pattern: Some(motif.name.into()),
            trust_zone: None,
            rationale: motif.rationale.into(),
            score: 0.6,
        });
    }
}

fn string_from_body(event: &Event, key: &str) -> Option<String> {
    event.body.get(key).and_then(|v| match v {
        JsonValue::Str(s) => Some(s.clone()),
        _ => None,
    })
}
