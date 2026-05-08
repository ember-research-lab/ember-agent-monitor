//! CLI dispatch.
//!
//! Subcommands per spec §9 (v0.5 deliverable):
//!   ember-agent init     — set up ~/.ember/agent-monitor
//!   ember-agent daemon   — run the proxy + file-watcher
//!   ember-agent status   — show daemon health, fidelity status
//!   ember-agent findings — query the findings log
//!   ember-agent replay   — re-run detection on an existing event log
//!
//! No clap dep; vetpkg-style hand-rolled arg parser.

use crate::types::{DaemonConfig, InterventionMode};
use std::path::PathBuf;

pub fn run(args: Vec<String>) -> Result<u8, String> {
    let mut iter = args.into_iter();
    let _bin = iter.next();
    let sub = iter.next();

    match sub.as_deref() {
        Some("init") => cmd_init(iter.collect()),
        Some("daemon") => cmd_daemon(iter.collect()),
        Some("status") => cmd_status(iter.collect()),
        Some("findings") => cmd_findings(iter.collect()),
        Some("replay") => cmd_replay(iter.collect()),
        Some("calibrate") => cmd_calibrate(iter.collect()),
        Some("finalize-session") => cmd_finalize_session(iter.collect()),
        Some("--help") | Some("-h") | None => {
            print_help();
            Ok(0)
        }
        Some(other) => Err(format!("unknown subcommand: {other}")),
    }
}

fn print_help() {
    eprintln!(
        "ember-agent {} — runtime observer for AI coding agents",
        env!("CARGO_PKG_VERSION")
    );
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  ember-agent <SUBCOMMAND> [OPTIONS]");
    eprintln!();
    eprintln!("SUBCOMMANDS:");
    eprintln!("  init                 Initialize ~/.ember/agent-monitor");
    eprintln!("  daemon [--mode M] [--port P] [--data-dir D] [--integrity-manifest F]");
    eprintln!("         [--upstream-anthropic URL] [--upstream-openai URL]");
    eprintln!("                       Run proxy + file-watcher (M = observe|warn|block).");
    eprintln!("                       Routes /v1/messages → Anthropic, /openai/v1/* → OpenAI-compat.");
    eprintln!("                       --integrity-manifest enables hash-pinned file checks.");
    eprintln!("  status               Show daemon health and fidelity status");
    eprintln!("  findings [--session S]");
    eprintln!("                       List findings (optionally for one session)");
    eprintln!("  replay <events.jsonl>");
    eprintln!("                       Re-run detection over a recorded event log");
    eprintln!("  calibrate <events.jsonl> [...]");
    eprintln!("                       Compute a spectral baseline envelope from clean sessions");
    eprintln!("  finalize-session <session_id>");
    eprintln!("                       Write the session-end summary.json artifact");
    eprintln!("                       (consumed by the persistent tool)");
}

fn cmd_init(_args: Vec<String>) -> Result<u8, String> {
    let cfg = DaemonConfig::default();
    crate::store::Store::open(&cfg.data_dir)?;
    eprintln!("ember-agent: initialized {}", cfg.data_dir.display());
    Ok(0)
}

fn cmd_daemon(args: Vec<String>) -> Result<u8, String> {
    let mut cfg = DaemonConfig::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--mode" => {
                let v = iter.next().ok_or("--mode requires a value")?;
                cfg.mode = InterventionMode::parse(&v)
                    .ok_or_else(|| format!("invalid mode {v} (expected observe|warn|block)"))?;
            }
            "--port" => {
                let v = iter.next().ok_or("--port requires a value")?;
                cfg.proxy_port = v.parse().map_err(|e| format!("invalid port: {e}"))?;
            }
            "--data-dir" => {
                let v = iter.next().ok_or("--data-dir requires a value")?;
                cfg.data_dir = PathBuf::from(v);
            }
            "--integrity-manifest" => {
                let v = iter.next().ok_or("--integrity-manifest requires a path")?;
                cfg.integrity_manifest = Some(PathBuf::from(v));
            }
            "--upstream-anthropic" => {
                cfg.upstream_anthropic = iter.next().ok_or("--upstream-anthropic requires a URL")?;
            }
            "--upstream-openai" => {
                cfg.upstream_openai = iter.next().ok_or("--upstream-openai requires a URL")?;
            }
            _ => return Err(format!("unknown daemon flag: {arg}")),
        }
    }
    eprintln!(
        "ember-agent: daemon — mode={} port={} data={}",
        cfg.mode.as_str(),
        cfg.proxy_port,
        cfg.data_dir.display(),
    );
    let integrity_manifest = match &cfg.integrity_manifest {
        Some(p) => Some(crate::integrity::Manifest::load(p)?),
        None => None,
    };
    if let Some(m) = &integrity_manifest {
        eprintln!(
            "ember-agent: integrity — pinning {} file(s) from {}",
            m.files.len(),
            cfg.integrity_manifest.as_ref().unwrap().display(),
        );
    }
    let ctx = std::sync::Arc::new(crate::net::proxy::ProxyContext::new(cfg.clone())?);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    // File-watcher loop in a background thread.
    let watch_cfg = cfg.clone();
    let watch_ctx = std::sync::Arc::clone(&ctx);
    let watch_stop = std::sync::Arc::clone(&stop);
    std::thread::spawn(move || run_watcher(watch_cfg, watch_ctx, watch_stop));

    // Integrity-check loop in a background thread (only if a manifest is set).
    if let Some(manifest) = integrity_manifest {
        let integrity_data_dir = cfg.data_dir.clone();
        let integrity_stop = std::sync::Arc::clone(&stop);
        std::thread::spawn(move || run_integrity(manifest, integrity_data_dir, integrity_stop));
    }

    crate::net::proxy::serve(ctx, stop)?;
    Ok(0)
}

fn run_integrity(
    manifest: crate::integrity::Manifest,
    data_dir: std::path::PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    let mut state = crate::integrity::IntegrityState::new();
    while !stop.load(Ordering::Relaxed) {
        for finding in state.check(&manifest) {
            eprintln!(
                "ember-agent: integrity HIGH — {}",
                finding.argument.as_deref().unwrap_or("?")
            );
            crate::integrity::append_finding(&data_dir, &finding);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn run_watcher(
    cfg: crate::types::DaemonConfig,
    ctx: std::sync::Arc<crate::net::proxy::ProxyContext>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    let mut state = crate::watcher::WatcherState::new();
    while !stop.load(Ordering::Relaxed) {
        if let Ok(updates) = state.poll(&cfg) {
            for (_path, lines) in updates {
                for line in lines {
                    if let Ok(ev) = crate::event::parse_jsonl_line(&line) {
                        // Watcher events feed the same recorder as proxy events,
                        // so the static graph (mcp_registration, hook_registration,
                        // skill_load, plugin_install) lands in the session log.
                        let mut writers = ctx.writers.lock().unwrap();
                        let writer = writers.entry(ev.session_id.clone()).or_insert_with(|| {
                            let p = ctx.store.session_log_path(&ev.session_id);
                            crate::store::log::EventLogWriter::open(&p).expect("open event log")
                        });
                        let _ = writer.append(&ev);
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn cmd_status(_args: Vec<String>) -> Result<u8, String> {
    let cfg = DaemonConfig::default();
    let proxy_alive = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", cfg.proxy_port).parse().unwrap(),
        std::time::Duration::from_millis(200),
    )
    .is_ok();
    let watcher_dir_exists = cfg.watch_dir.exists();
    let fidelity = match (proxy_alive, watcher_dir_exists) {
        (true, true) => "full_fidelity",
        (true, false) => "degraded_dynamic_only",
        (false, true) => "degraded_static_only",
        (false, false) => "failed",
    };
    println!("ember-agent status:");
    println!(
        "  proxy:       {}",
        if proxy_alive { "running" } else { "down" }
    );
    println!("  port:        {}", cfg.proxy_port);
    println!(
        "  watch_dir:   {} ({})",
        cfg.watch_dir.display(),
        if watcher_dir_exists {
            "exists"
        } else {
            "missing"
        }
    );
    println!("  data_dir:    {}", cfg.data_dir.display());
    println!("  fidelity:    {fidelity}");
    let sessions_dir = cfg.data_dir.join("sessions");
    let session_count = std::fs::read_dir(sessions_dir)
        .map(|d| d.flatten().count())
        .unwrap_or(0);
    println!("  sessions:    {session_count}");
    let findings_dir = cfg.data_dir.join("findings");
    let findings_count = std::fs::read_dir(findings_dir)
        .map(|d| d.flatten().count())
        .unwrap_or(0);
    println!("  with_findings: {findings_count}");
    Ok(0)
}

fn cmd_findings(args: Vec<String>) -> Result<u8, String> {
    let mut cfg = DaemonConfig::default();
    let mut session_filter: Option<String> = None;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--session" => session_filter = iter.next(),
            "--data-dir" => {
                let v = iter.next().ok_or("--data-dir requires a value")?;
                cfg.data_dir = PathBuf::from(v);
            }
            other => return Err(format!("unknown findings flag: {other}")),
        }
    }
    let dir = cfg.data_dir.join("findings");
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read findings dir: {e}"))?;
    let mut total = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if let Some(filter) = &session_filter {
            if &name != filter {
                continue;
            }
        }
        let content = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let mut session_findings = 0;
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            session_findings += 1;
            total += 1;
        }
        println!("session {name}: {session_findings} finding(s)");
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            // Simple structured-line print; full JSON if --verbose later.
            if let Ok(crate::json::JsonValue::Object(o)) = crate::json::parse(line) {
                let t = o
                    .iter()
                    .find(|(k, _)| k == "type")
                    .and_then(|(_, v)| match v {
                        crate::json::JsonValue::Str(s) => Some(s.as_str()),
                        _ => None,
                    })
                    .unwrap_or("?");
                let sev = o
                    .iter()
                    .find(|(k, _)| k == "severity")
                    .and_then(|(_, v)| match v {
                        crate::json::JsonValue::Str(s) => Some(s.as_str()),
                        _ => None,
                    })
                    .unwrap_or("?");
                let why = o
                    .iter()
                    .find(|(k, _)| k == "rationale")
                    .and_then(|(_, v)| match v {
                        crate::json::JsonValue::Str(s) => Some(s.as_str()),
                        _ => None,
                    })
                    .unwrap_or("");
                println!("  [{}] {} — {}", sev.to_uppercase(), t, why);
            }
        }
    }
    println!("---\ntotal: {total}");
    Ok(0)
}

fn cmd_calibrate(args: Vec<String>) -> Result<u8, String> {
    if args.is_empty() {
        return Err("calibrate requires at least one events.jsonl path".into());
    }
    let mut profiles: Vec<crate::spectral::SpectralProfile> = Vec::new();
    for path in &args {
        let events = crate::store::log::read_all(std::path::Path::new(path))?;
        if events.is_empty() {
            continue;
        }
        let mut graph = crate::graph::SessionGraph::default();
        for ev in events {
            graph.ingest(ev);
        }
        let profile = crate::spectral::SpectralProfile::from_session(&graph);
        if profile.n_nodes >= 3 {
            profiles.push(profile);
        }
    }
    if profiles.is_empty() {
        return Err("no usable sessions found in inputs".into());
    }

    // Compute envelopes: [min, max] of each quantity across the corpus,
    // padded by 20% on each side. A small corpus (single session) yields
    // tight bands; the user is responsible for supplying enough.
    let pad = 0.2_f64;
    let fiedlers: Vec<f64> = profiles.iter().map(|p| p.fiedler_value).collect();
    let f_min = fiedlers.iter().copied().fold(f64::INFINITY, f64::min);
    let f_max = fiedlers.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let dims: Vec<f64> = profiles
        .iter()
        .filter_map(|p| p.spectral_dimension)
        .collect();
    let (d_min, d_max) = if dims.is_empty() {
        (0.5, 4.0)
    } else {
        let lo = dims.iter().copied().fold(f64::INFINITY, f64::min);
        let hi = dims.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        (lo, hi)
    };

    let baseline = crate::spectral::Baseline {
        fiedler: crate::spectral::Envelope {
            low: (f_min * (1.0 - pad)).max(0.0),
            high: f_max * (1.0 + pad),
        },
        spectral_dimension: crate::spectral::Envelope {
            low: (d_min * (1.0 - pad)).max(0.0),
            high: d_max * (1.0 + pad),
        },
        // For heat-trace, use the default sample points but compute the
        // observed envelope at each.
        heat_trace_samples: vec![
            (0.1, normalized_heat_envelope(&profiles, 0.1, pad)),
            (1.0, normalized_heat_envelope(&profiles, 1.0, pad)),
            (10.0, normalized_heat_envelope(&profiles, 10.0, pad)),
        ],
    };

    let cfg = DaemonConfig::default();
    let dest = cfg.data_dir.join("state/user/spectral_baseline.json");
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    }
    baseline
        .save(&dest)
        .map_err(|e| format!("write baseline: {e}"))?;
    println!(
        "calibrated from {} session(s) → {}",
        profiles.len(),
        dest.display()
    );
    println!(
        "  fiedler: [{:.4}, {:.4}]",
        baseline.fiedler.low, baseline.fiedler.high
    );
    println!(
        "  spectral_dimension: [{:.3}, {:.3}]",
        baseline.spectral_dimension.low, baseline.spectral_dimension.high
    );
    Ok(0)
}

fn cmd_finalize_session(args: Vec<String>) -> Result<u8, String> {
    let mut data_dir: Option<PathBuf> = None;
    let mut session_id: Option<String> = None;
    let mut iter = args.into_iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--data-dir" => data_dir = iter.next().map(PathBuf::from),
            other if !other.starts_with("--") && session_id.is_none() => {
                session_id = Some(other.to_string());
            }
            other => return Err(format!("unknown finalize-session arg: {other}")),
        }
    }
    let session_id = session_id.ok_or("finalize-session requires <session_id>")?;
    let mut cfg = DaemonConfig::default();
    if let Some(d) = data_dir {
        cfg.data_dir = d;
    }
    let store = crate::store::Store::open(&cfg.data_dir)?;
    let log_path = store.session_log_path(&session_id);
    if !log_path.exists() {
        return Err(format!("no session log at {}", log_path.display()));
    }
    // Replay events into a graph, run detection, build + write the summary.
    let events = crate::store::log::read_all(&log_path)?;
    let mut graph = crate::graph::SessionGraph::default();
    for ev in events.iter().cloned() {
        graph.ingest(ev);
    }
    let detection_cfg = crate::detect::DetectionConfig::default();
    let findings = crate::detect::run_all(&events, &detection_cfg);
    let mut summary = crate::store::summary::SessionSummary::build(
        &session_id,
        &graph,
        &findings,
        crate::types::FidelityStatus::FullFidelity,
        &log_path,
    );
    let profile = crate::spectral::SpectralProfile::from_session(&graph);
    if profile.n_nodes >= 3 {
        let breakdown = detection_cfg
            .spectral_baseline
            .as_ref()
            .map(|b| b.score(&profile))
            .unwrap_or_else(|| crate::spectral::SpectralScoreBreakdown {
                total: 0.0,
                fiedler_dev: 0.0,
                spectral_dimension_dev: 0.0,
                heat_trace_dev: 0.0,
            });
        let motifs: Vec<String> = crate::spectral::check_motifs(&profile)
            .into_iter()
            .map(|m| m.name.to_string())
            .collect();
        summary = summary.with_spectral(crate::store::summary::SpectralSummary {
            n_nodes: profile.n_nodes,
            fiedler_value: profile.fiedler_value,
            spectral_dimension: profile.spectral_dimension,
            anomaly_score: breakdown.total,
            motif_matches: motifs,
        });
    }
    let dest = store.summary_path(&session_id);
    summary.save(&dest)?;
    println!("wrote {}", dest.display());
    Ok(0)
}

fn normalized_heat_envelope(
    profiles: &[crate::spectral::SpectralProfile],
    target_t: f64,
    pad: f64,
) -> crate::spectral::Envelope {
    let mut samples: Vec<f64> = Vec::new();
    for p in profiles {
        if p.t_grid.is_empty() || p.heat_trace.is_empty() {
            continue;
        }
        let log_t = target_t.ln();
        let mut best = 0usize;
        let mut best_dist = f64::INFINITY;
        for (i, t) in p.t_grid.iter().enumerate() {
            let d = (t.ln() - log_t).abs();
            if d < best_dist {
                best_dist = d;
                best = i;
            }
        }
        let theta = p.heat_trace[best];
        samples.push(theta / (p.n_nodes as f64).max(1.0));
    }
    if samples.is_empty() {
        return crate::spectral::Envelope {
            low: 0.0,
            high: 1.0,
        };
    }
    let lo = samples.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = samples.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    crate::spectral::Envelope {
        low: (lo * (1.0 - pad)).max(0.0),
        high: (hi * (1.0 + pad)).min(1.0),
    }
}

fn cmd_replay(args: Vec<String>) -> Result<u8, String> {
    let path = args.first().ok_or("replay requires an events.jsonl path")?;
    let events = crate::store::log::read_all(std::path::Path::new(path))?;
    let mut graph = crate::graph::SessionGraph::default();
    let mut session_id = String::new();
    for ev in events.into_iter() {
        if session_id.is_empty() {
            session_id = ev.session_id.clone();
        }
        graph.ingest(ev);
    }
    eprintln!("session: {session_id}");
    eprintln!("static graph:");
    eprintln!(
        "  mcp servers: {:?}",
        graph.static_graph.mcp_servers.keys().collect::<Vec<_>>()
    );
    eprintln!("  tools: {} registered", graph.static_graph.tools.len());
    eprintln!(
        "  capability set: {:?}",
        graph.static_graph.capabilities.iter().collect::<Vec<_>>()
    );
    eprintln!(
        "  skills: {:?}, hooks: {} kinds, plugins: {}",
        graph.static_graph.skills,
        graph.static_graph.hooks.len(),
        graph.static_graph.plugins.len(),
    );
    eprintln!("dynamic graph:");
    eprintln!("  events: {}", graph.dynamic_graph.events.len());
    eprintln!("  parent edges: {}", graph.dynamic_graph.parent_edges.len());
    let mut counts: Vec<_> = graph.dynamic_graph.kind_counts.iter().collect();
    counts.sort_by_key(|(k, _)| k.as_str());
    eprintln!("  kind counts:");
    for (k, n) in counts {
        eprintln!("    {}: {n}", k.as_str());
    }

    // Run detection over the replayed events.
    let cfg = crate::detect::DetectionConfig::default();
    let events = crate::store::log::read_all(std::path::Path::new(path))?;
    let findings = crate::detect::run_all(&events, &cfg);
    eprintln!("\n{} finding(s):", findings.len());
    let mut by_severity: std::collections::BTreeMap<&str, Vec<&crate::detect::Finding>> =
        std::collections::BTreeMap::new();
    for f in &findings {
        by_severity.entry(f.severity.as_str()).or_default().push(f);
    }
    for sev in ["critical", "high", "medium", "low"] {
        if let Some(list) = by_severity.get(sev) {
            for f in list {
                eprintln!(
                    "  [{}] {} ({})",
                    sev.to_uppercase(),
                    f.finding_type,
                    f.scope.as_str()
                );
                if let Some(t) = &f.tool {
                    eprintln!("      tool: {t}");
                }
                if let Some(a) = &f.argument {
                    eprintln!(
                        "      arg: {a} = {}",
                        f.matched_value.as_deref().unwrap_or("")
                    );
                }
                if let Some(p) = &f.pattern {
                    eprintln!("      pattern: {p}");
                }
                eprintln!("      why: {}", f.rationale);
            }
        }
    }
    Ok(0)
}
