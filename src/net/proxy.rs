//! Multi-protocol LLM API proxy.
//!
//! Listens on localhost (HTTP only — loopback never needs TLS), routes
//! requests by URL path to a `Protocol`-specific parser (`Anthropic` or
//! `OpenAI`), records them as `Event`s, forwards upstream via system
//! `curl -i`, parses the response, records it, and relays it to the client with
//! the upstream's own status and headers (#60). SSE replies stream through in
//! observe mode; warn/block need a buffered body and refuse streams.
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
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const MAX_CONCURRENT: usize = 16;
const UPSTREAM_TIMEOUT_SECS: u32 = 600; // long-running streaming sessions

/// Largest session graph the O(n^3) spectral pass runs on (#68). Claude Code
/// replays the whole conversation on every request, so an uncapped graph
/// grows past what Jacobi can finish in minutes. Above the cap the spectral
/// rules are skipped and the skip is logged once per session.
pub const SPECTRAL_MAX_NODES: usize = 256;

/// Watchdog (#68): a streaming request whose upstream has sent no response
/// head within this many seconds is failed with a 502 and a log line instead
/// of being held. Override with `EMBER_AGENT_FIRST_BYTE_SECS`.
const FIRST_BYTE_SECS_DEFAULT: u64 = 60;

fn first_byte_secs() -> u64 {
    std::env::var("EMBER_AGENT_FIRST_BYTE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(FIRST_BYTE_SECS_DEFAULT)
}

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
    /// `<data_dir>/events.sock` — tool_call stream for ember-network (spec §6).
    /// `None` only if the bind failed, which is reported on stderr at startup.
    pub events_sock: Option<Arc<crate::net::socket::EventSocket>>,
    /// session_id → (event kind + content hash → occurrences already ingested).
    /// Requests replay the full history; observe mode ingests only what is new (#68).
    seen: Mutex<HashMap<String, HashMap<String, usize>>>,
    /// Sessions whose spectral skip was already logged (#68).
    spectral_skip_logged: Mutex<HashSet<String>>,
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
        // Session posture reads the sibling tools' findings next to our data
        // dir (`~/.ember/{vetpkg,persistent,network}`).
        match config.data_dir.parent() {
            Some(root) => {
                detection.posture = Some(Arc::new(crate::posture::SessionPosture::new(root)))
            }
            None => eprintln!(
                "ember-agent: posture off — data dir has no parent to find sibling findings"
            ),
        }
        let sock_path = config.data_dir.join("events.sock");
        let events_sock = match crate::net::socket::EventSocket::open(&sock_path) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!(
                    "ember-agent: events.sock unavailable, ember-network cannot subscribe: {e}"
                );
                None
            }
        };
        Ok(Self {
            config,
            store,
            detection,
            writers: Mutex::new(HashMap::new()),
            finding_writers: Mutex::new(HashMap::new()),
            graphs: Mutex::new(HashMap::new()),
            events_sock,
            seen: Mutex::new(HashMap::new()),
            spectral_skip_logged: Mutex::new(HashSet::new()),
        })
    }

    pub fn record(&self, event: &Event) {
        self.record_from(event, crate::net::socket::Source::Proxy);
    }

    /// `record`, naming the ingest path for the events.sock `source` field.
    pub fn record_from(&self, event: &Event, source: crate::net::socket::Source) {
        let mut writers = self.writers.lock().unwrap();
        let writer = writers.entry(event.session_id.clone()).or_insert_with(|| {
            let path = self.store.session_log_path(&event.session_id);
            EventLogWriter::open(&path).expect("open event log")
        });
        let _ = writer.append(event);
        drop(writers);
        if event.kind == crate::types::EventKind::ToolCall {
            if let Some(sock) = &self.events_sock {
                sock.broadcast(event, source);
            }
        }
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
        if let Some(p) = &self.detection.posture {
            summary = summary.with_vetpkg_packages(p.packages_seen(session_id));
        }
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

    /// Observe mode: drop the events of a replayed history that were already
    /// ingested for this session, so a request costs O(new events), not
    /// O(conversation) (#68). Identity is event kind + body hash, counted, so
    /// a genuinely repeated message still ingests when it occurs more often
    /// than before. Warn/block keep full replay: a replayed event that
    /// triggered a finding must keep triggering it on the retry.
    fn new_events_only(&self, session_id: &str, events: Vec<Event>) -> Vec<Event> {
        if self.config.mode != InterventionMode::Observe {
            return events;
        }
        let mut seen = self.seen.lock().unwrap();
        let known = seen.entry(session_id.to_string()).or_default();
        let mut in_request: HashMap<String, usize> = HashMap::new();
        let mut fresh = Vec::new();
        for ev in events {
            let key = format!("{:?}|{}", ev.kind, ev.content_hash);
            let n = in_request.entry(key.clone()).or_insert(0);
            *n += 1;
            if *n > known.get(&key).copied().unwrap_or(0) {
                fresh.push(ev);
            }
        }
        for (k, n) in in_request {
            let e = known.entry(k).or_insert(0);
            *e = (*e).max(n);
        }
        fresh
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
        let spectral_due = self.detection.spectral_cadence > 0
            && n >= 3
            && n % self.detection.spectral_cadence == 0;
        // Eigendecomposition runs on a snapshot, outside the graphs lock: the
        // lock is shared by every session and by the SSE relay (#68).
        let snapshot = if spectral_due && n <= SPECTRAL_MAX_NODES {
            Some(graph.clone())
        } else {
            None
        };
        drop(graphs);
        if spectral_due && snapshot.is_none() {
            let first = self
                .spectral_skip_logged
                .lock()
                .unwrap()
                .insert(event.session_id.clone());
            if first {
                eprintln!(
                    "ember-agent: spectral analysis skipped for session {} — {n} events exceed SPECTRAL_MAX_NODES={SPECTRAL_MAX_NODES} (#68)",
                    event.session_id
                );
            }
        }
        if let Some(g) = snapshot {
            findings.extend(crate::detect::run_spectral(&g, &self.detection));
        }
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

    // OpenAI-compatible pass-through (local llama-server lane): streams, so it
    // writes to the socket itself instead of returning a buffered response.
    if crate::net::openai_pass::route(&req, &ctx, &mut stream) {
        return;
    }

    let resp = if req.method == "GET" && Protocol::is_health_path(&req.path) {
        HttpResponse::ok_json(br#"{"status":"ok","tool":"ember-agent-monitor"}"#.to_vec())
    } else if req.method == "POST" {
        match Protocol::for_path(&req.path) {
            Some(protocol) => {
                // Writes its own reply: upstream status/headers are relayed
                // and SSE streams as they arrive (#60).
                handle_messages(&req, &ctx, protocol, &mut stream);
                return;
            }
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

/// Record + analyze every event of an inbound request (and the
/// `protocol_mismatch_attempt` signal). Returns the session id and the
/// high/critical findings that drive forward intervention.
pub(crate) fn ingest_request(
    req: &HttpRequest,
    ctx: &ProxyContext,
    protocol: Protocol,
) -> (String, Vec<Finding>) {
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
        for ev in ctx.new_events_only(&session_id, events) {
            ctx.record(&ev);
            for f in ctx.analyze(&ev) {
                if matches!(f.severity, Severity::High | Severity::Critical) {
                    high_findings.push(f);
                }
            }
        }
    }

    (session_id, high_findings)
}

fn handle_messages(
    req: &HttpRequest,
    ctx: &Arc<ProxyContext>,
    protocol: Protocol,
    out: &mut TcpStream,
) {
    // Observe mode forwards whatever the analysis finds, so analysis must not
    // sit in front of the forward: it ran inline until #68 and held a 170 K
    // token main-thread request for minutes before curl was even spawned.
    // Warn/block need the findings first and keep the inline path.
    let (session_id, high_findings) = if ctx.config.mode == InterventionMode::Observe {
        let (ctx2, req2) = (Arc::clone(ctx), req.clone());
        thread::spawn(move || {
            ingest_request(&req2, &ctx2, protocol);
        });
        (derive_session_id_for(req, &req.body, protocol), Vec::new())
    } else {
        ingest_request(req, ctx, protocol)
    };

    // Warn/block must be able to rewrite the reply; a stream cannot be
    // rewritten yet (#60), so refuse loudly instead of forwarding unchecked.
    if protocol == Protocol::Anthropic
        && ctx.config.mode != InterventionMode::Observe
        && request_wants_stream(&req.body)
    {
        let _ = stream_unsupported_response(ctx.config.mode).write_to(out);
        return;
    }

    let mut body = req.body.clone();
    // Forward-direction intervention.
    match ctx.config.mode {
        InterventionMode::Block if !high_findings.is_empty() => {
            let reason = format_refusal(&high_findings);
            let _ = HttpResponse::refusal(&reason).write_to(out);
            return;
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
            if protocol == Protocol::Anthropic {
                body = inject_system_warning(&req.body, &high_findings)
                    .unwrap_or_else(|| req.body.clone());
            }
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
        &body,
        &req.headers,
        ctx,
        &session_id,
        protocol,
        out,
    );
}

/// True when the JSON request body asks for an SSE reply (`"stream": true`).
fn request_wants_stream(body: &[u8]) -> bool {
    let Some(JsonValue::Object(o)) = std::str::from_utf8(body).ok().and_then(|s| parse(s).ok())
    else {
        return false;
    };
    matches!(
        o.iter().find(|(k, _)| k == "stream"),
        Some((_, JsonValue::Bool(true)))
    )
}

/// Message naming #60: warn/block cannot yet rewrite an SSE reply.
pub(crate) fn stream_unsupported_message(mode: InterventionMode) -> String {
    format!(
        "ember-agent --mode {} cannot yet rewrite streaming (SSE) Anthropic replies \
         (ember-research-lab/ember-agent-monitor#60); run with --mode observe",
        mode.as_str()
    )
}

fn stream_unsupported_response(mode: InterventionMode) -> HttpResponse {
    let body = format!(
        r#"{{"type":"error","error":{{"type":"ember_unsupported","message":{}}}}}"#,
        crate::json::to_json_string(&JsonValue::Str(stream_unsupported_message(mode)))
    )
    .into_bytes();
    HttpResponse {
        status: 501,
        status_text: "Not Implemented".into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Length".into(), body.len().to_string()),
        ],
        body,
    }
}

fn bad_gateway(detail: &str) -> HttpResponse {
    let body = format!(
        r#"{{"error":"upstream","detail":{}}}"#,
        crate::json::to_json_string(&JsonValue::Str(detail.into()))
    )
    .into_bytes();
    HttpResponse {
        status: 502,
        status_text: "Bad Gateway".into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Content-Length".into(), body.len().to_string()),
        ],
        body,
    }
}

/// Forward to the upstream and relay its reply: status, status text and
/// headers (minus hop-by-hop) are the upstream's own (#60). `text/event-stream`
/// replies are passed through chunked as they arrive (observe mode only);
/// everything else is buffered so the response-side analysis sees one body.
fn forward_and_intervene(
    upstream_url: &str,
    body: &[u8],
    headers: &[(String, String)],
    ctx: &ProxyContext,
    session_id: &str,
    protocol: Protocol,
    out: &mut TcpStream,
) {
    if let Err(e) = relay_upstream(upstream_url, body, headers, ctx, session_id, protocol, out) {
        let _ = bad_gateway(&e).write_to(out);
    }
}

const HEAD_CAP: usize = 64 * 1024;
const BODY_CAP: usize = 64 * 1024 * 1024;

/// Sets the flag when dropped, so the watchdog thread never outlives its request.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// `Err` means nothing has been sent to the client yet.
fn relay_upstream(
    url: &str,
    body: &[u8],
    headers: &[(String, String)],
    ctx: &ProxyContext,
    session_id: &str,
    protocol: Protocol,
    out: &mut TcpStream,
) -> Result<(), String> {
    let mut cmd = Command::new(which_curl()?);
    cmd.args(["-sS", "-i", "-N", "--connect-timeout", "10", "--max-time"])
        .arg(UPSTREAM_TIMEOUT_SECS.to_string())
        .args(["-X", "POST", "--data-binary", "@-"]);
    for (k, v) in headers {
        if !header_passthrough_blocked(k) {
            cmd.arg("-H").arg(format!("{k}: {v}"));
        }
    }
    cmd.arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd.spawn().map_err(|e| format!("curl spawn: {e}"))?;
    let child = Arc::new(Mutex::new(child));
    // Watchdog (#68): a stream with no response head after N s is failed
    // loudly (502 + log line) instead of being held open.
    let head_seen = Arc::new(AtomicBool::new(false));
    let watchdog_fired = Arc::new(AtomicBool::new(false));
    let _stop_watchdog = StopOnDrop(Arc::clone(&head_seen));
    if request_wants_stream(body) {
        let secs = first_byte_secs();
        let (child2, seen2, fired2) = (
            Arc::clone(&child),
            Arc::clone(&head_seen),
            Arc::clone(&watchdog_fired),
        );
        let session = session_id.to_string();
        thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(secs);
            while std::time::Instant::now() < deadline {
                if seen2.load(Ordering::Relaxed) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            if !seen2.swap(true, Ordering::Relaxed) {
                fired2.store(true, Ordering::Relaxed);
                eprintln!(
                    "ember-agent: HIGH watchdog — no upstream response for session {session} after {secs}s, failing the request with 502 (#68)"
                );
                let _ = child2.lock().unwrap().kill();
            }
        });
    }
    let mut stdin = child.lock().unwrap().stdin.take().ok_or("curl stdin")?;
    let payload = body.to_vec();
    thread::spawn(move || {
        let _ = stdin.write_all(&payload);
    });
    let mut stdout = child.lock().unwrap().stdout.take().ok_or("curl stdout")?;
    let mut stderr = child.lock().unwrap().stderr.take().ok_or("curl stderr")?;
    let err_reader = thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    let curl_failure = |child: &Mutex<std::process::Child>, err: thread::JoinHandle<String>| {
        let status = child
            .lock()
            .unwrap()
            .wait()
            .map_err(|e| format!("curl wait: {e}"))?;
        let text = err.join().unwrap_or_default();
        if watchdog_fired.load(Ordering::Relaxed) {
            Err(format!(
                "watchdog: no upstream response within {}s (ember-agent-monitor#68)",
                first_byte_secs()
            ))
        } else if status.success() {
            Ok(())
        } else {
            Err(format!("curl exit {:?}: {}", status.code(), text.trim()))
        }
    };

    // Read until the response head (skipping interim 1xx blocks) is complete.
    let mut raw: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    let head = loop {
        let n = stdout.read(&mut buf).unwrap_or(0);
        if n == 0 {
            curl_failure(&child, err_reader)?;
            return Err("upstream sent no response".into());
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(h) = parse_response_head(&raw) {
            break h;
        }
        if raw.len() > HEAD_CAP {
            let _ = child.lock().unwrap().kill();
            let _ = child.lock().unwrap().wait();
            return Err("upstream response head too large".into());
        }
    };
    head_seen.store(true, Ordering::Relaxed);
    let rest = raw.split_off(head.end);
    let encoded = head.content_encoding().is_some();
    let enforcing = ctx.config.mode != InterventionMode::Observe;

    if head.is_event_stream() {
        if enforcing {
            let _ = child.lock().unwrap().kill();
            let _ = child.lock().unwrap().wait();
            return Err(stream_unsupported_message(ctx.config.mode));
        }
        let mut observer =
            (!encoded && protocol == Protocol::Anthropic).then(|| SseObserver::new(session_id));
        let mut resp_head = head.client_head();
        resp_head.push_str("Transfer-Encoding: chunked\r\n\r\n");
        if out.write_all(resp_head.as_bytes()).is_err() {
            let _ = child.lock().unwrap().kill();
            let _ = child.lock().unwrap().wait();
            return Ok(());
        }
        let mut client_gone = false;
        let mut relay = |chunk: &[u8]| -> bool {
            if chunk.is_empty() {
                return true;
            }
            if let Some(o) = observer.as_mut() {
                o.feed(chunk, ctx);
            }
            out.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .and_then(|_| out.write_all(chunk))
                .and_then(|_| out.write_all(b"\r\n"))
                .and_then(|_| out.flush())
                .is_ok()
        };
        client_gone |= !relay(&rest);
        while !client_gone {
            match stdout.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => client_gone |= !relay(&buf[..n]),
            }
        }
        if client_gone {
            let _ = child.lock().unwrap().kill(); // closing upstream stops generation
        }
        match curl_failure(&child, err_reader) {
            // Terminator only on a clean end: a truncated stream must look
            // truncated to the client, not complete.
            Ok(()) if !client_gone => {
                let _ = out.write_all(b"0\r\n\r\n").and_then(|_| out.flush());
            }
            Err(e) if !client_gone => eprintln!("ember-agent: upstream stream aborted: {e}"),
            _ => {}
        }
        return Ok(());
    }

    // Buffered path: one body, analysed whole.
    let mut resp_body = rest;
    loop {
        match stdout.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                resp_body.extend_from_slice(&buf[..n]);
                if resp_body.len() > BODY_CAP {
                    let _ = child.lock().unwrap().kill();
                    let _ = child.lock().unwrap().wait();
                    return Err("upstream response body too large".into());
                }
            }
        }
    }
    curl_failure(&child, err_reader)?;

    let is_ok = (200..300).contains(&head.status);
    if protocol == Protocol::Anthropic && is_ok {
        if encoded {
            // Cannot inspect bytes we cannot read. Warn/block must not pass
            // them unchecked; observe passes them through untouched.
            if enforcing {
                return Err(format!(
                    "upstream sent Content-Encoding: {} that cannot be inspected \
                     (ember-research-lab/ember-agent-monitor#60)",
                    head.content_encoding().unwrap_or_default()
                ));
            }
            eprintln!("ember-agent: encoded reply passed uninspected (#60)");
        } else {
            // Record response events and run dynamic detection. OpenAI
            // response parsing is deferred; strip is Anthropic-tested.
            let findings = record_and_analyze_response(&resp_body, session_id, ctx);
            let blocked: Vec<&Finding> = findings
                .iter()
                .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
                .collect();
            // Backward-direction intervention: strip dangerous tool_use blocks.
            if enforcing && !blocked.is_empty() {
                if let Some(stripped) = strip_tool_use_in_response(&resp_body, &blocked) {
                    resp_body = stripped;
                }
            }
        }
    }

    let mut resp_head = head.client_head();
    resp_head.push_str(&format!("Content-Length: {}\r\n\r\n", resp_body.len()));
    let _ = out
        .write_all(resp_head.as_bytes())
        .and_then(|_| out.write_all(&resp_body))
        .and_then(|_| out.flush());
    Ok(())
}

/// Parsed upstream response head.
struct UpstreamHead {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    /// Offset of the first body byte in the buffer it was parsed from.
    end: usize,
}

impl UpstreamHead {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn is_event_stream(&self) -> bool {
        self.header("content-type")
            .is_some_and(|v| v.to_ascii_lowercase().contains("text/event-stream"))
    }

    /// Declared non-identity `Content-Encoding`, if any.
    fn content_encoding(&self) -> Option<String> {
        self.header("content-encoding")
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty() && v != "identity")
    }

    /// Status line + upstream headers minus hop-by-hop, ending in
    /// `Connection: close\r\n` (framing headers are the caller's).
    fn client_head(&self) -> String {
        let mut s = format!("HTTP/1.1 {} {}\r\n", self.status, self.reason);
        for (k, v) in &self.headers {
            if !hop_by_hop(k) {
                s.push_str(&format!("{k}: {v}\r\n"));
            }
        }
        s.push_str("Connection: close\r\n");
        s
    }
}

/// Headers describing the upstream hop, not the message (RFC 9110 7.6.1),
/// plus `content-length`, which the proxy recomputes for the body it sends.
fn hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "transfer-encoding"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "upgrade"
            | "content-length"
    )
}

fn default_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        529 => "Overloaded",
        _ => "Upstream",
    }
}

/// First non-1xx head block in `buf` (curl `-i` output), or None while incomplete.
fn parse_response_head(buf: &[u8]) -> Option<UpstreamHead> {
    let mut start = 0;
    loop {
        let rel = buf[start..].windows(4).position(|w| w == b"\r\n\r\n")?;
        let end = start + rel + 4;
        let text = String::from_utf8_lossy(&buf[start..start + rel]).to_string();
        let mut lines = text.lines();
        let mut parts = lines.next()?.splitn(3, ' ');
        let _version = parts.next()?;
        let status: u16 = parts.next()?.trim().parse().ok()?;
        if (100..200).contains(&status) {
            start = end;
            continue;
        }
        let reason = match parts.next().map(str::trim) {
            Some(r) if !r.is_empty() => r.to_string(),
            _ => default_reason(status).to_string(), // HTTP/2 has no reason phrase
        };
        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();
        return Some(UpstreamHead {
            status,
            reason,
            headers,
            end,
        });
    }
}

const SSE_LINE_CAP: usize = 8 * 1024 * 1024;
const SSE_TEXT_CAP: usize = 1024 * 1024;

/// Observe-mode SSE inspection: reassembles Anthropic `content_block_*`
/// events into the same blocks the buffered path analyses, as the bytes pass.
/// Findings only; the bytes reaching the client are never altered.
struct SseObserver {
    session_id: String,
    pending: Vec<u8>,
    /// block index → (type, id, name, accumulated text, accumulated input json)
    blocks: HashMap<i64, (String, String, String, String, String)>,
}

impl SseObserver {
    fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.into(),
            pending: Vec::new(),
            blocks: HashMap::new(),
        }
    }

    fn feed(&mut self, chunk: &[u8], ctx: &ProxyContext) {
        self.pending.extend_from_slice(chunk);
        while let Some(nl) = self.pending.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=nl).collect();
            let line = String::from_utf8_lossy(&line);
            if let Some(data) = line.trim_end().strip_prefix("data:") {
                if let Ok(JsonValue::Object(ev)) = parse(data.trim()) {
                    self.event(&ev, ctx);
                }
            }
        }
        if self.pending.len() > SSE_LINE_CAP {
            eprintln!("ember-agent: SSE line over cap, inspection dropped for it");
            self.pending.clear();
        }
    }

    fn event(&mut self, ev: &[(String, JsonValue)], ctx: &ProxyContext) {
        let Some(JsonValue::Number(idx)) = field_of(ev, "index") else {
            return;
        };
        let idx = *idx as i64;
        let obj = |v: Option<&JsonValue>| match v {
            Some(JsonValue::Object(o)) => Some(o.clone()),
            _ => None,
        };
        match string_field(ev, "type").as_deref() {
            Some("content_block_start") => {
                let Some(b) = obj(field_of(ev, "content_block")) else {
                    return;
                };
                self.blocks.insert(
                    idx,
                    (
                        string_field(&b, "type").unwrap_or_default(),
                        string_field(&b, "id").unwrap_or_default(),
                        string_field(&b, "name").unwrap_or_default(),
                        string_field(&b, "text").unwrap_or_default(),
                        String::new(),
                    ),
                );
            }
            Some("content_block_delta") => {
                let (Some(d), Some(slot)) = (obj(field_of(ev, "delta")), self.blocks.get_mut(&idx))
                else {
                    return;
                };
                if let Some(t) = string_field(&d, "text") {
                    if slot.3.len() < SSE_TEXT_CAP {
                        slot.3.push_str(&t);
                    }
                }
                if let Some(j) = string_field(&d, "partial_json") {
                    if slot.4.len() < SSE_TEXT_CAP {
                        slot.4.push_str(&j);
                    }
                }
            }
            Some("content_block_stop") => {
                let Some((kind, id, name, text, json)) = self.blocks.remove(&idx) else {
                    return;
                };
                let mut block: Vec<(String, JsonValue)> =
                    vec![("type".into(), JsonValue::Str(kind.clone()))];
                match kind.as_str() {
                    "text" => block.push(("text".into(), JsonValue::Str(text))),
                    "tool_use" => {
                        let input = if json.trim().is_empty() {
                            JsonValue::Object(Vec::new())
                        } else {
                            parse(&json).unwrap_or(JsonValue::Null)
                        };
                        block.push(("id".into(), JsonValue::Str(id)));
                        block.push(("name".into(), JsonValue::Str(name)));
                        block.push(("input".into(), input));
                    }
                    _ => return,
                }
                // Findings are logged by `analyze`; observe never rewrites.
                analyze_block(&block, &self.session_id, ctx);
            }
            _ => {}
        }
    }
}

fn field_of<'a>(o: &'a [(String, JsonValue)], key: &str) -> Option<&'a JsonValue> {
    o.iter().find(|(k, _)| k == key).map(|(_, v)| v)
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
                findings.extend(analyze_block(b, session_id, ctx));
            }
        }
    }
    findings
}

/// Record + analyze one response content block (`text` / `tool_use`); shared
/// by the buffered path and the SSE observer.
fn analyze_block(b: &[(String, JsonValue)], session_id: &str, ctx: &ProxyContext) -> Vec<Finding> {
    let bt = b
        .iter()
        .find(|(k, _)| k == "type")
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.as_str()),
            _ => None,
        });
    let event = match bt {
        Some("text") => {
            let text = string_field(b, "text").unwrap_or_default();
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
    match event {
        Some(ev) => {
            ctx.record(&ev);
            ctx.analyze(&ev)
        }
        None => Vec::new(),
    }
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
        Protocol::Anthropic =>
        {
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

pub(crate) fn which_curl() -> Result<String, String> {
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

pub(crate) fn header_passthrough_blocked(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "host"
            | "content-length"
            | "connection"
            | "transfer-encoding"
            | "expect"
            // Inspection needs plaintext: never ask upstream to compress (#60).
            | "accept-encoding"
    )
}
