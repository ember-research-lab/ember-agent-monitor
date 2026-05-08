//! Multi-protocol LLM API proxy.
//!
//! Listens on localhost (HTTP only — loopback never needs TLS), routes
//! requests by URL path to a `Protocol`-specific parser (`Anthropic` or
//! `OpenAI`), records them as `Event`s, forwards upstream via system
//! `curl`, parses the response, records it, and returns to the client.
//!
//! Path-prefix routing (see `proto::Protocol::for_path`) is intentional:
//! auto-detection by body shape was rejected because it makes
//! protocol-confusion attacks controllable by the attacker. Routing
//! stays deterministic; the `protocol_mismatch_attempt` rule catches
//! body/path disagreement as observable signal.
//!
//! curl is the same TLS primitive vetpkg uses (see vetpkg/src/net/http_client.rs).
//! It's a system tool, not a Cargo dependency, and it ships on every
//! POSIX box we target. No Rust-side TLS implementation needed.

use crate::detect::{run_dynamic, run_static, DetectionConfig, Finding};
use crate::event::Event;
use crate::graph::SessionGraph;
use crate::json::{parse, JsonValue};
use crate::net::http::{read_request, HttpRequest, HttpResponse};
#[allow(deprecated)]
use crate::proto::{anthropic, Protocol};
use crate::store::log::EventLogWriter;
use crate::store::summary::{SessionSummary, SpectralSummary};
use crate::store::Store;
use crate::types::{
    DaemonConfig, EventKind, FidelityStatus, InterventionMode, Severity, TrustZone,
};
use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const MAX_CONCURRENT: usize = 16;
const UPSTREAM_TIMEOUT_SECS: u32 = 600; // long-running streaming sessions

/// Proxy context shared across worker threads.
pub struct ProxyContext {
    pub config: DaemonConfig,
    pub store: Store,
    pub detection: DetectionConfig,
    /// session_id → log writer. Each session gets its own JSONL file.
    pub writers: Mutex<HashMap<String, EventLogWriter>>,
    /// session_id → findings file writer.
    pub finding_writers: Mutex<HashMap<String, EventLogWriter>>,
    /// session_id → running graph snapshot (for static rule recompute).
    pub graphs: Mutex<HashMap<String, SessionGraph>>,
}

impl ProxyContext {
    pub fn new(config: DaemonConfig) -> Result<Self, String> {
        let store = Store::open(&config.data_dir)?;
        let mut detection = DetectionConfig::default();
        // Layer in user additions if present.
        let user_sensitive = config.data_dir.join("state/user/sensitive.txt");
        let _ = detection.sensitive.load_additions(&user_sensitive);
        // User-calibrated spectral baseline overrides the shipped default.
        let user_baseline = config.data_dir.join("state/user/spectral_baseline.json");
        if let Ok(b) = crate::spectral::Baseline::load(&user_baseline) {
            detection.spectral_baseline = Some(b);
        }
        Ok(Self {
            config,
            store,
            detection,
            writers: Mutex::new(HashMap::new()),
            finding_writers: Mutex::new(HashMap::new()),
            graphs: Mutex::new(HashMap::new()),
        })
    }

    pub fn record(&self, event: &Event) {
        let mut writers = self.writers.lock().unwrap();
        let writer = writers.entry(event.session_id.clone()).or_insert_with(|| {
            let path = self.store.session_log_path(&event.session_id);
            EventLogWriter::open(&path).expect("open event log")
        });
        let _ = writer.append(event);
    }

    /// Public alias for the internal finding recorder. Used by handlers
    /// that detect protocol-level signals (e.g. `protocol_mismatch_attempt`)
    /// before per-event analysis runs.
    pub fn record_finding_public(&self, finding: &Finding) {
        self.record_finding(finding);
    }

    /// Append a finding to per-session findings.jsonl. Lossy on failure —
    /// we never block the data plane on observability issues.
    fn record_finding(&self, finding: &Finding) {
        let path = self.store.findings_path(&finding.session_id);
        let mut writers = self.finding_writers.lock().unwrap();
        let _writer = writers
            .entry(finding.session_id.clone())
            .or_insert_with(|| EventLogWriter::open(&path).expect("open findings log"));
        // Use direct append since findings aren't `Event` shape.
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(finding.to_jsonl().as_bytes());
        }
    }

    /// Write a session summary at session end. Idempotent — safe to call
    /// from multiple paths (proxy SessionEnd handler, daemon shutdown,
    /// CLI replay). Atomic on-disk via tempfile+rename in summary.save.
    pub fn finalize_session(&self, session_id: &str, fidelity: FidelityStatus) {
        let graphs = self.graphs.lock().unwrap();
        let graph = match graphs.get(session_id) {
            Some(g) => g.clone(),
            None => return,
        };
        drop(graphs);
        // Re-read findings from disk so we capture cross-event findings
        // including spectral that may have been emitted at non-event ticks.
        let findings = read_findings(&self.store.findings_path(session_id));
        let event_log_path = self.store.session_log_path(session_id);
        let mut summary =
            SessionSummary::build(session_id, &graph, &findings, fidelity, &event_log_path);
        // Add spectral summary if we computed one (cheap because the graph
        // is already in hand here).
        let profile = crate::spectral::SpectralProfile::from_session(&graph);
        if profile.n_nodes >= 3 {
            let baseline = self
                .detection
                .spectral_baseline
                .as_ref()
                .cloned()
                .unwrap_or_else(crate::spectral::Baseline::default_baseline);
            let breakdown = baseline.score(&profile);
            let motifs: Vec<String> = crate::spectral::check_motifs(&profile)
                .into_iter()
                .map(|m| m.name.to_string())
                .collect();
            summary = summary.with_spectral(SpectralSummary {
                n_nodes: profile.n_nodes,
                fiedler_value: profile.fiedler_value,
                spectral_dimension: profile.spectral_dimension,
                anomaly_score: breakdown.total,
                motif_matches: motifs,
            });
        }
        let dest = self.store.summary_path(session_id);
        let _ = summary.save(&dest);
    }

    /// Run static + dynamic detection for a freshly recorded event. Returns
    /// any findings emitted (callers may use these to drive intervention).
    pub fn analyze(&self, event: &Event) -> Vec<Finding> {
        let mut graphs = self.graphs.lock().unwrap();
        let graph = graphs.entry(event.session_id.clone()).or_default();
        graph.ingest(event.clone());
        let mut findings = Vec::new();
        // Static rules cheap; rerun on each event so newly registered MCP
        // servers raise composition findings as they appear.
        findings.extend(run_static(graph, &self.detection));
        findings.extend(run_dynamic(event, graph, &self.detection));
        // Spectral runs on a cadence — eigendecomp is O(N^3), so we don't
        // run it on every event. Triggered when event count is a multiple
        // of `spectral_cadence` AND we have at least 3 events.
        let n = graph.dynamic_graph.events.len();
        if self.detection.spectral_cadence > 0 && n >= 3 && n % self.detection.spectral_cadence == 0
        {
            findings.extend(crate::detect::run_spectral(graph, &self.detection));
        }
        drop(graphs);
        for f in &findings {
            self.record_finding(f);
        }
        findings
    }
}

pub fn serve(ctx: Arc<ProxyContext>, stop: Arc<AtomicBool>) -> Result<(), String> {
    let addr = format!("127.0.0.1:{}", ctx.config.proxy_port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("bind {addr}: {e}"))?;
    listener
        .set_nonblocking(false)
        .map_err(|e| format!("listener config: {e}"))?;
    eprintln!(
        "ember-agent: proxy on http://{}, forwarding anthropic→{} openai→{}",
        addr, ctx.config.upstream_anthropic, ctx.config.upstream_openai,
    );

    let active: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    for incoming in listener.incoming() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Backpressure: cap concurrent requests so a flood doesn't OOM us.
        loop {
            let n = *active.lock().unwrap();
            if n < MAX_CONCURRENT {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        *active.lock().unwrap() += 1;
        let ctx2 = Arc::clone(&ctx);
        let active2 = Arc::clone(&active);
        thread::spawn(move || {
            handle_connection(stream, ctx2);
            *active2.lock().unwrap() -= 1;
        });
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, ctx: Arc<ProxyContext>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));

    let req = match read_request(&stream) {
        Ok(r) => r,
        Err(_) => return,
    };

    let resp = if req.method == "GET" && Protocol::is_health_path(&req.path) {
        HttpResponse::ok_json(br#"{"status":"ok","tool":"ember-agent-monitor"}"#.to_vec())
    } else if req.method == "POST" {
        match Protocol::for_path(&req.path) {
            Some(protocol) => handle_messages(&req, &ctx, protocol),
            None => HttpResponse {
                status: 404,
                status_text: "Not Found".into(),
                headers: vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("Content-Length".into(), "23".into()),
                ],
                body: br#"{"error":"not_handled"}"#.to_vec(),
            },
        }
    } else {
        HttpResponse {
            status: 405,
            status_text: "Method Not Allowed".into(),
            headers: vec![("Content-Length".into(), "0".into())],
            body: Vec::new(),
        }
    };
    let _ = resp.write_to(&mut stream);
}

fn handle_messages(req: &HttpRequest, ctx: &ProxyContext, protocol: Protocol) -> HttpResponse {
    // Detect protocol/body mismatch as a finding before parsing — even if
    // the body parses cleanly, a mismatch is signal worth recording.
    let mismatch_reason = protocol.body_disagrees(&req.body);
    let session_id = derive_session_id_for(req, &req.body, protocol);

    if let Some(reason) = mismatch_reason {
        let finding = Finding {
            finding_type: "protocol_mismatch_attempt".into(),
            scope: crate::detect::FindingScope::Static,
            severity: Severity::Medium,
            session_id: session_id.clone(),
            event_id: None,
            tool: None,
            argument: Some(req.path.clone()),
            matched_value: Some(protocol.id().to_string()),
            pattern: None,
            trust_zone: None,
            rationale: format!(
                "request to {} ({}); body disagrees: {}",
                req.path,
                protocol.id(),
                reason
            ),
            score: Severity::Medium.weight(),
        };
        ctx.record_finding_public(&finding);
    }

    // Parse + record + analyze every event from the inbound request.
    let mut high_findings: Vec<Finding> = Vec::new();
    if let Ok(events) = protocol.parse_request(&req.body, &session_id) {
        for ev in events {
            ctx.record(&ev);
            for f in ctx.analyze(&ev) {
                if matches!(f.severity, Severity::High | Severity::Critical) {
                    high_findings.push(f);
                }
            }
        }
    }

    // Forward-direction intervention.
    match ctx.config.mode {
        InterventionMode::Block if !high_findings.is_empty() => {
            let reason = format_refusal(&high_findings);
            return HttpResponse::refusal(&reason);
        }
        InterventionMode::Warn if !high_findings.is_empty() => {
            // Append a system-prompt warning to the outbound request.
            // Forward warnings are advisory — they don't stop a committed
            // model (spec §5). Backward intervention is the actual safety
            // mechanism for the response path.
            //
            // Anthropic-only for now: OpenAI's `system` role lives in
            // `messages` rather than as a top-level field, and the
            // forward-warn path needs more care to preserve message
            // ordering. Backward strip works for both protocols (the
            // committed-model invariant is the real safety mechanism).
            let body = if protocol == Protocol::Anthropic {
                inject_system_warning(&req.body, &high_findings).unwrap_or_else(|| req.body.clone())
            } else {
                req.body.clone()
            };
            let upstream_url = format!(
                "{}{}",
                ctx.config.upstream_for(protocol),
                protocol.upstream_path(&req.path)
            );
            return forward_and_intervene(
                &upstream_url,
                &body,
                &req.headers,
                ctx,
                &session_id,
                protocol,
            );
        }
        _ => {}
    }

    let upstream_url = format!(
        "{}{}",
        ctx.config.upstream_for(protocol),
        protocol.upstream_path(&req.path)
    );
    forward_and_intervene(
        &upstream_url,
        &req.body,
        &req.headers,
        ctx,
        &session_id,
        protocol,
    )
}

fn forward_and_intervene(
    upstream_url: &str,
    body: &[u8],
    headers: &[(String, String)],
    ctx: &ProxyContext,
    session_id: &str,
    protocol: Protocol,
) -> HttpResponse {
    let response_body = match forward_via_curl(upstream_url, body, headers) {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse {
                status: 502,
                status_text: "Bad Gateway".into(),
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: format!(
                    r#"{{"error":"upstream","detail":{}}}"#,
                    crate::json::to_json_string(&JsonValue::Str(e))
                )
                .into_bytes(),
            };
        }
    };

    // Record response events and run dynamic detection.
    // OpenAI response parsing is currently best-effort observe-only; the
    // backward-strip path is Anthropic-tested and protocol-shaped. We
    // log openai response events to the session graph but defer
    // strip-and-substitute to a follow-up so the existing Anthropic
    // intervention surface stays untouched in this refactor.
    let response_findings = if protocol == Protocol::Anthropic {
        record_and_analyze_response(&response_body, session_id, ctx)
    } else {
        Vec::new()
    };
    let blocked: Vec<&Finding> = response_findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
        .collect();

    // Backward-direction intervention: strip dangerous tool_use blocks.
    // Anthropic-only at the moment; the OpenAI strip path lands when
    // OpenAI response analysis lands (same follow-up as above).
    let final_body = if protocol == Protocol::Anthropic
        && matches!(
            ctx.config.mode,
            InterventionMode::Warn | InterventionMode::Block
        )
        && !blocked.is_empty()
    {
        strip_tool_use_in_response(&response_body, &blocked).unwrap_or(response_body.clone())
    } else {
        response_body
    };

    HttpResponse::ok_json(final_body)
}

fn format_refusal(findings: &[Finding]) -> String {
    let mut buf = String::from("ember-agent blocked this request: ");
    let mut first = true;
    for f in findings.iter().take(3) {
        if !first {
            buf.push_str(" | ");
        }
        first = false;
        buf.push_str(&f.finding_type);
        if let Some(t) = &f.tool {
            buf.push_str(" (tool ");
            buf.push_str(t);
            buf.push(')');
        }
    }
    if findings.len() > 3 {
        buf.push_str(&format!(" (+{} more)", findings.len() - 3));
    }
    buf
}

fn inject_system_warning(body: &[u8], findings: &[Finding]) -> Option<Vec<u8>> {
    // Decode → modify `system` prompt → re-encode.
    let s = std::str::from_utf8(body).ok()?;
    let v = parse(s).ok()?;
    let mut obj = match v {
        JsonValue::Object(o) => o,
        _ => return None,
    };
    let warning = format!(
        "[ember-agent advisory] {} high-severity finding(s) detected: {}. \
         These are detector warnings, not authoritative blocks.",
        findings.len(),
        findings
            .iter()
            .take(3)
            .map(|f| f.finding_type.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );
    let new_system = match obj.iter().find(|(k, _)| k == "system") {
        Some((_, JsonValue::Str(existing))) => format!("{warning}\n\n{existing}"),
        _ => warning,
    };
    obj.retain(|(k, _)| k != "system");
    obj.push(("system".into(), JsonValue::Str(new_system)));
    Some(crate::json::to_json_string(&JsonValue::Object(obj)).into_bytes())
}

fn strip_tool_use_in_response(body: &[u8], findings: &[&Finding]) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(body).ok()?;
    let v = parse(s).ok()?;
    let mut obj = match v {
        JsonValue::Object(o) => o,
        _ => return None,
    };
    let mut content_arr = match obj
        .iter()
        .find(|(k, _)| k == "content")
        .map(|(_, v)| v.clone())
    {
        Some(JsonValue::Array(a)) => a,
        _ => return None,
    };
    // Remove every tool_use block; replace with text refusal.
    content_arr.retain(|block| {
        if let JsonValue::Object(o) = block {
            !matches!(
                o.iter().find(|(k, _)| k == "type").map(|(_, v)| v),
                Some(JsonValue::Str(t)) if t == "tool_use"
            )
        } else {
            true
        }
    });
    let refusal = format!(
        "ember-agent stripped {} tool_use block(s): {}",
        findings.len(),
        findings
            .iter()
            .take(3)
            .map(|f| f.finding_type.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    );
    let mut block: Vec<(String, JsonValue)> = Vec::with_capacity(2);
    block.push(("type".into(), JsonValue::Str("text".into())));
    block.push(("text".into(), JsonValue::Str(refusal)));
    content_arr.push(JsonValue::Object(block));
    obj.retain(|(k, _)| k != "content");
    obj.push(("content".into(), JsonValue::Array(content_arr)));
    obj.retain(|(k, _)| k != "stop_reason");
    obj.push(("stop_reason".into(), JsonValue::Str("ember_block".into())));
    Some(crate::json::to_json_string(&JsonValue::Object(obj)).into_bytes())
}

fn record_and_analyze_response(body: &[u8], session_id: &str, ctx: &ProxyContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let s = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return findings,
    };
    let v = match parse(s) {
        Ok(v) => v,
        Err(_) => return findings,
    };
    let obj = match v {
        JsonValue::Object(o) => o,
        _ => return findings,
    };
    let content = obj.iter().find(|(k, _)| k == "content").map(|(_, v)| v);
    if let Some(JsonValue::Array(arr)) = content {
        for block in arr {
            if let JsonValue::Object(b) = block {
                let bt = b
                    .iter()
                    .find(|(k, _)| k == "type")
                    .and_then(|(_, v)| match v {
                        JsonValue::Str(s) => Some(s.as_str()),
                        _ => None,
                    });
                let event = match bt {
                    Some("text") => {
                        let text = b
                            .iter()
                            .find(|(k, _)| k == "text")
                            .and_then(|(_, v)| match v {
                                JsonValue::Str(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let mut body_map = HashMap::new();
                        body_map.insert("text".into(), JsonValue::Str(text));
                        Some(Event::new(
                            session_id,
                            EventKind::ModelText,
                            TrustZone::WorkspaceLocal,
                            body_map,
                        ))
                    }
                    Some("tool_use") => {
                        let id = string_field(b, "id").unwrap_or_default();
                        let name = string_field(b, "name").unwrap_or_default();
                        let input = b
                            .iter()
                            .find(|(k, _)| k == "input")
                            .map(|(_, v)| v.clone())
                            .unwrap_or(JsonValue::Null);
                        let mut body_map = HashMap::new();
                        body_map.insert("tool_use_id".into(), JsonValue::Str(id));
                        body_map.insert("tool_name".into(), JsonValue::Str(name));
                        body_map.insert("input".into(), input);
                        Some(Event::new(
                            session_id,
                            EventKind::ToolCall,
                            TrustZone::WorkspaceLocal,
                            body_map,
                        ))
                    }
                    _ => None,
                };
                if let Some(ev) = event {
                    ctx.record(&ev);
                    findings.extend(ctx.analyze(&ev));
                }
            }
        }
    }
    findings
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    obj.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        })
}

fn read_findings(path: &std::path::Path) -> Vec<Finding> {
    use crate::detect::FindingScope;
    let text = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v = match parse(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let JsonValue::Object(o) = v {
            // Reconstruct just enough of the Finding to populate the summary
            // counts. The summary writer cares about type/scope/severity.
            let finding_type = string_field(&o, "type").unwrap_or_default();
            let scope_str = string_field(&o, "scope").unwrap_or_default();
            let severity_str = string_field(&o, "severity").unwrap_or_default();
            let scope = match scope_str.as_str() {
                "static" => FindingScope::Static,
                _ => FindingScope::Dynamic,
            };
            let severity = match severity_str.as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                _ => Severity::Low,
            };
            out.push(Finding {
                finding_type,
                scope,
                severity,
                session_id: string_field(&o, "session_id").unwrap_or_default(),
                event_id: None,
                tool: None,
                argument: None,
                matched_value: None,
                pattern: None,
                trust_zone: None,
                rationale: String::new(),
                score: 0.0,
            });
        }
    }
    out
}

fn derive_session_id_for(req: &HttpRequest, body: &[u8], protocol: Protocol) -> String {
    // 1. Explicit per-turn session headers — both vendors-of-record use
    //    one. Claude Code sets `x-claude-session-id`; Codex / OpenAI
    //    SDKs commonly set `openai-conversation-id` or
    //    `x-request-id`. We accept any of the three so a single client
    //    that switches protocols mid-flight (e.g., the math-delegation
    //    case) maintains session continuity.
    for h in [
        "x-claude-session-id",
        "openai-conversation-id",
        "x-ember-session-id",
    ] {
        if let Some(s) = req.header(h) {
            return s.to_string();
        }
    }

    // 2. Hash of the first user message text — same turn → same hash.
    let first_user_text = match protocol {
        Protocol::Anthropic => {
            #[allow(deprecated)]
            anthropic::parse_request(body).ok().and_then(|p| {
                p.messages.first().and_then(|m| {
                    m.blocks.iter().find_map(|b| match b {
                        anthropic::ContentBlock::Text(t) => Some(t.clone()),
                        _ => None,
                    })
                })
            })
        }
        Protocol::OpenAI => crate::proto::openai::parse_request(body)
            .ok()
            .and_then(|p| p.messages.first().and_then(|m| m.content.clone())),
    };

    if let Some(t) = first_user_text {
        let h = crate::crypto::sha256::sha256(t.as_bytes());
        let mut out = String::with_capacity(16);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for b in h.iter().take(8) {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
        return format!("anon-{}-{out}", protocol.id());
    }

    format!("anon-{}-{}", protocol.id(), std::process::id())
}

fn forward_via_curl(
    url: &str,
    body: &[u8],
    headers: &[(String, String)],
) -> Result<Vec<u8>, String> {
    let curl = which_curl()?;
    let mut cmd = Command::new(curl);
    cmd.arg("-sS")
        .arg("-X")
        .arg("POST")
        .arg("--connect-timeout")
        .arg("10")
        .arg("--max-time")
        .arg(UPSTREAM_TIMEOUT_SECS.to_string())
        .arg("--data-binary")
        .arg("@-");
    for (k, v) in headers {
        if header_passthrough_blocked(k) {
            continue;
        }
        cmd.arg("-H").arg(format!("{k}: {v}"));
    }
    cmd.arg(url);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("curl spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(body)
            .map_err(|e| format!("curl stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("curl wait: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("curl exit {:?}: {}", out.status.code(), err));
    }
    Ok(out.stdout)
}

fn which_curl() -> Result<String, String> {
    for candidate in [
        "/usr/bin/curl",
        "/opt/homebrew/bin/curl",
        "/usr/local/bin/curl",
    ] {
        if std::path::Path::new(candidate).exists() {
            return Ok(candidate.to_string());
        }
    }
    Err("curl not found in standard paths".into())
}

fn header_passthrough_blocked(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "host" | "content-length" | "connection" | "transfer-encoding" | "expect"
    )
}
