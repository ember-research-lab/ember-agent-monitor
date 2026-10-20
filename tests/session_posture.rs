//! Session posture (#27, #31): sibling-tool findings under `~/.ember/` raise a
//! session's posture, which bumps exec/egress rule severity one step and emits
//! one `posture_elevated` marker. Sources: vetpkg (package installed/imported in
//! the session), ember-persistent (HIGH finding for the workspace, schema v2),
//! ember-network (HIGH finding for the session).

use ember_agent_monitor::detect::{run_all, DetectionConfig, Finding};
use ember_agent_monitor::event::Event;
use ember_agent_monitor::json::JsonValue;
use ember_agent_monitor::net::proxy::ProxyContext;
use ember_agent_monitor::posture::{hash_workspace, SessionPosture};
use ember_agent_monitor::types::{DaemonConfig, EventKind, FidelityStatus, Severity, TrustZone};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

const CWD: &str = "/home/aaron/work/proj";

fn root(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ember-posture-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn seed(root: &std::path::Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn ev(sid: &str, kind: EventKind, body: Vec<(&str, JsonValue)>) -> Event {
    let b: HashMap<String, JsonValue> = body.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    Event::new(sid, kind, TrustZone::WorkspaceLocal, b)
}

fn s(x: &str) -> JsonValue {
    JsonValue::Str(x.into())
}

fn start(sid: &str) -> Event {
    ev(sid, EventKind::SessionStart, vec![("cwd", s(CWD))])
}

fn call(sid: &str, tool: &str, key: &str, val: &str) -> Event {
    ev(
        sid,
        EventKind::ToolCall,
        vec![
            ("tool_name", s(tool)),
            ("input", JsonValue::Object(vec![(key.to_string(), s(val))])),
        ],
    )
}

/// A non-shell tool with a flag-injection argument: argument_injection_pattern HIGH.
fn exec_hit(sid: &str) -> Event {
    call(sid, "mcp__git__git_diff", "target", "--output=/tmp/x")
}

fn cfg_with(root: &std::path::Path) -> DetectionConfig {
    DetectionConfig {
        posture: Some(Arc::new(SessionPosture::new(root))),
        ..Default::default()
    }
}

fn by_type<'a>(f: &'a [Finding], t: &str) -> Vec<&'a Finding> {
    f.iter().filter(|x| x.finding_type == t).collect()
}

const VETPKG_MEDIUM: &str = r#"{"package":"requets","version":"0.0.1-security","ecosystem":"npm","severity":"medium","reason":"Typo(request:0.029)","score":0.35,"ts_ms":1}"#;
const VETPKG_LOW: &str = r#"{"package":"requets","version":"0.0.1","ecosystem":"npm","severity":"low","reason":"x","score":0.1,"ts_ms":1}"#;

#[test]
fn baseline_without_posture_is_unchanged() {
    let evs = vec![start("b"), exec_hit("b")];
    let f = run_all(&evs, &DetectionConfig::default());
    assert!(by_type(&f, "posture_elevated").is_empty());
    assert_eq!(
        by_type(&f, "argument_injection_pattern")[0].severity,
        Severity::High
    );
}

#[test]
fn vetpkg_package_installed_in_session_elevates_once_and_bumps_exec() {
    let r = root("vetpkg");
    seed(&r, "vetpkg/findings.jsonl", &format!("{VETPKG_MEDIUM}\n"));
    let cfg = cfg_with(&r);
    let evs = vec![
        start("v1"),
        exec_hit("v1"), // before the install: not yet elevated
        call("v1", "Bash", "command", "cd x && npm install requets@0.0.1"),
        exec_hit("v1"), // after: bumped
        call("v1", "Bash", "command", "npm install requets"),
    ];
    let f = run_all(&evs, &cfg);
    let marker = by_type(&f, "posture_elevated");
    assert_eq!(marker.len(), 1, "marker emitted once: {f:?}");
    assert_eq!(marker[0].severity, Severity::Medium);
    let src = r.join("vetpkg/findings.jsonl").display().to_string();
    assert!(
        marker[0].rationale.contains(&src),
        "{}",
        marker[0].rationale
    );
    assert!(marker[0].rationale.contains("requets"));
    let sev: Vec<Severity> = by_type(&f, "argument_injection_pattern")
        .iter()
        .map(|x| x.severity)
        .collect();
    assert_eq!(sev, vec![Severity::High, Severity::Critical]);
    let posture = cfg.posture.as_ref().unwrap();
    assert_eq!(
        posture.packages_seen("v1"),
        vec!["requets@0.0.1-security".to_string()]
    );
    // A different session is untouched.
    assert!(posture.elevation("other").is_none());
}

#[test]
fn vetpkg_low_severity_or_unrelated_session_does_not_elevate() {
    let r = root("vetpkg-low");
    seed(&r, "vetpkg/findings.jsonl", &format!("{VETPKG_LOW}\n"));
    let f = run_all(
        &[
            start("l"),
            call("l", "Bash", "command", "npm install requets"),
        ],
        &cfg_with(&r),
    );
    assert!(by_type(&f, "posture_elevated").is_empty());
    seed(&r, "vetpkg/findings.jsonl", &format!("{VETPKG_MEDIUM}\n"));
    let f = run_all(
        &[
            start("l2"),
            call(
                "l2",
                "Bash",
                "command",
                "npm install express && echo requets",
            ),
        ],
        &cfg_with(&r),
    );
    assert!(by_type(&f, "posture_elevated").is_empty());
}

#[test]
fn vetpkg_import_counts_as_use() {
    let r = root("vetpkg-import");
    seed(&r, "vetpkg/findings.jsonl", &format!("{VETPKG_MEDIUM}\n"));
    let f = run_all(
        &[
            start("i"),
            call("i", "Write", "content", "import requets\nrequets.get('x')"),
        ],
        &cfg_with(&r),
    );
    assert_eq!(by_type(&f, "posture_elevated").len(), 1);
}

fn persistent_line(ws: &str, sev: &str, ver: &str) -> String {
    format!(
        r#"{{"schema_version":{ver},"type":"flagged_recurrence","severity":"{sev}","workspace":"{ws}","session_id":"x","source_session":"y","unit_hash":"h","agent_id":"","event_id":"e","rationale":"r","ts_ms":1}}"#
    )
}

#[test]
fn persistent_high_finding_for_workspace_elevates() {
    let r = root("persistent");
    let ws = hash_workspace(CWD);
    seed(
        &r,
        "persistent/findings.jsonl",
        &format!(
            "{}\n{}\n",
            persistent_line("0000000000000000", "high", "2"),
            persistent_line(&ws, "high", "2")
        ),
    );
    let cfg = cfg_with(&r);
    let f = run_all(&[start("p"), exec_hit("p")], &cfg);
    let marker = by_type(&f, "posture_elevated");
    assert_eq!(marker.len(), 1, "{f:?}");
    assert!(marker[0].rationale.contains("persistent/findings.jsonl"));
    assert_eq!(
        by_type(&f, "argument_injection_pattern")[0].severity,
        Severity::Critical
    );
    assert!(cfg.posture.as_ref().unwrap().load_report().is_clean());
}

#[test]
fn persistent_other_workspace_or_medium_does_not_elevate() {
    let r = root("persistent-no");
    let ws = hash_workspace(CWD);
    seed(
        &r,
        "persistent/findings.jsonl",
        &format!(
            "{}\n{}\n",
            persistent_line("0000000000000000", "high", "2"),
            persistent_line(&ws, "medium", "2")
        ),
    );
    let f = run_all(&[start("n"), exec_hit("n")], &cfg_with(&r));
    assert!(by_type(&f, "posture_elevated").is_empty());
}

#[test]
fn persistent_unknown_schema_is_refused_loudly_and_unreadable_lines_counted() {
    let r = root("persistent-schema");
    let ws = hash_workspace(CWD);
    seed(
        &r,
        "persistent/findings.jsonl",
        &format!(
            "{}\nnot json\n{{\"x\":1}}\n",
            persistent_line(&ws, "high", "3")
        ),
    );
    let cfg = cfg_with(&r);
    let f = run_all(&[start("u"), exec_hit("u")], &cfg);
    assert!(
        by_type(&f, "posture_elevated").is_empty(),
        "v3 must not be trusted"
    );
    let rep = cfg.posture.as_ref().unwrap().load_report();
    assert_eq!(rep.persistent_refused_schema, 2); // v3 line + the object with no version
    assert_eq!(
        rep.persistent_refused_versions,
        vec!["3".to_string(), "missing".to_string()]
    );
    assert_eq!(rep.persistent_unreadable, 1); // "not json"
    assert!(!rep.is_clean());
}

#[test]
fn network_high_finding_for_this_session_elevates_but_unattributed_does_not() {
    let r = root("network");
    let line = |sid: &str| {
        format!(
            r#"{{"type":"uncorrelated_egress","scope":"dynamic","severity":"high","session_id":"{sid}","matched_value":"1.2.3.4:443","pattern":"p","rationale":"r","score":0.8,"ts_ms":1}}"#
        )
    };
    seed(
        &r,
        "network/findings.jsonl",
        &format!("{}\n{}\n", line(""), line("net1")),
    );
    let cfg = cfg_with(&r);
    let f = run_all(&[start("net2"), exec_hit("net2")], &cfg);
    assert!(
        by_type(&f, "posture_elevated").is_empty(),
        "session_id \"\" is unattributable"
    );
    let f = run_all(&[start("net1"), exec_hit("net1")], &cfg);
    assert_eq!(by_type(&f, "posture_elevated").len(), 1);
    assert!(by_type(&f, "posture_elevated")[0]
        .rationale
        .contains("network/findings.jsonl"));
}

#[test]
fn source_appearing_mid_session_is_picked_up() {
    let r = root("midsession");
    let cfg = cfg_with(&r);
    let posture = cfg.posture.clone().unwrap();
    assert!(posture.observe(&start("m")).is_none());
    seed(
        &r,
        "persistent/findings.jsonl",
        &format!("{}\n", persistent_line(&hash_workspace(CWD), "high", "2")),
    );
    let marker = posture.observe(&exec_hit("m"));
    assert!(marker.is_some(), "tick after the file appears must elevate");
    assert!(posture.observe(&exec_hit("m")).is_none(), "once only");
}

#[test]
fn daemon_context_wires_posture_and_summary_lists_vetpkg_packages() {
    let r = root("daemon");
    seed(&r, "vetpkg/findings.jsonl", &format!("{VETPKG_MEDIUM}\n"));
    let data = r.join("am");
    let ctx = ProxyContext::new(DaemonConfig {
        data_dir: data.clone(),
        ..Default::default()
    })
    .unwrap();
    for e in [
        start("d"),
        call("d", "Bash", "command", "npm install requets"),
        exec_hit("d"),
    ] {
        ctx.record(&e);
        ctx.analyze(&e);
    }
    ctx.finalize_session("d", FidelityStatus::FullFidelity);
    let summary = std::fs::read_to_string(ctx.store.summary_path("d")).unwrap();
    assert!(summary.contains("requets@0.0.1-security"), "{summary}");
    assert!(summary.contains("\"posture_elevated\":1"), "{summary}");
}
