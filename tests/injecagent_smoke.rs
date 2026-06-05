//! InjecAgent harness smoke test.
//!
//! Loads cases from `tests/injecagent_cases/`, converts each into
//! the agent-monitor Event schema, runs detection, asserts the
//! expected outcome:
//!
//!   - Cases named `synthetic_dh_*` or `synthetic_ds_*` are positive
//!     (injection cases). Detection MUST fire at least one of:
//!     instruction_shape_in_tool_result OR
//!     agent_as_intermediary_clickfix.
//!   - Cases named `synthetic_negative_*` are clean. Detection MUST
//!     NOT fire either rule.
//!
//! See `INJECAGENT.md` for the full integration plan. This smoke
//! tests the runner against synthetic cases in the InjecAgent shape;
//! the real 1054-case corpus lands when the curl-fetch step is wired
//! (currently behind an explicit "fetch" step in the doc, not in CI).

use ember_agent_monitor::detect::{run_dynamic, DetectionConfig};
use ember_agent_monitor::event::Event;
use ember_agent_monitor::graph::SessionGraph;
use ember_agent_monitor::json::{parse, JsonValue};
use ember_agent_monitor::types::{EventKind, TrustZone};
use std::collections::HashMap;
use std::path::PathBuf;

#[test]
fn injecagent_synthetic_cases_match_expected() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/injecagent_cases");
    let entries = match std::fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) => panic!("read {}: {e}", dir.display()),
    };
    let mut failures = Vec::new();
    let mut total = 0;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        total += 1;
        let name = path
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        let is_negative = name.contains("negative");

        if let Err(e) = run_case(&path, is_negative) {
            failures.push(format!("{name}: {e}"));
        }
    }

    assert!(total >= 3, "expected ≥3 cases, found {total}");
    assert!(
        failures.is_empty(),
        "InjecAgent synthetic case failures:\n{}",
        failures.join("\n---\n")
    );
}

fn run_case(path: &std::path::Path, is_negative: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let v = parse(&text).map_err(|e| format!("parse: {e:?}"))?;
    let obj = match v {
        JsonValue::Object(o) => o,
        _ => return Err("not an object".into()),
    };

    let user_instr = obj
        .iter()
        .find(|(k, _)| k == "User Instruction")
        .and_then(|(_, v)| v.as_str().map(String::from))
        .unwrap_or_default();
    let user_tool = obj
        .iter()
        .find(|(k, _)| k == "User Tool")
        .and_then(|(_, v)| v.as_str().map(String::from))
        .unwrap_or_default();
    let tool_response = obj
        .iter()
        .find(|(k, _)| k == "Tool Response")
        .and_then(|(_, v)| v.as_str().map(String::from))
        .unwrap_or_default();

    // Build 3 events: user_prompt → tool_call → tool_result.
    let session_id = "injecagent-smoke";
    let mut events = Vec::new();
    let mut up_body = HashMap::new();
    up_body.insert("text".into(), JsonValue::Str(user_instr));
    events.push(Event::new(
        session_id,
        EventKind::UserPrompt,
        TrustZone::UserInput,
        up_body,
    ));

    let mut tc_body = HashMap::new();
    tc_body.insert("tool_name".into(), JsonValue::Str(user_tool));
    tc_body.insert("tool_use_id".into(), JsonValue::Str("t1".into()));
    tc_body.insert("input".into(), JsonValue::Object(Vec::new()));
    events.push(Event::new(
        session_id,
        EventKind::ToolCall,
        TrustZone::WorkspaceLocal,
        tc_body,
    ));

    let mut tr_body = HashMap::new();
    tr_body.insert("tool_use_id".into(), JsonValue::Str("t1".into()));
    tr_body.insert("content".into(), JsonValue::Str(tool_response));
    tr_body.insert("is_error".into(), JsonValue::Bool(false));
    events.push(Event::new(
        session_id,
        EventKind::ToolResult,
        TrustZone::UntrustedToolOutput,
        tr_body,
    ));

    // Run detection.
    let mut graph = SessionGraph::default();
    let cfg = DetectionConfig::default();
    let mut all_findings = Vec::new();
    for ev in &events {
        graph.ingest(ev.clone());
        all_findings.extend(run_dynamic(ev, &graph, &cfg));
    }

    let injection_fired = all_findings.iter().any(|f| {
        f.finding_type == "instruction_shape_in_tool_result"
            || f.finding_type == "agent_as_intermediary_clickfix"
    });

    if is_negative {
        if injection_fired {
            return Err(format!(
                "negative case fired injection rule(s): {:?}",
                all_findings
                    .iter()
                    .map(|f| f.finding_type.clone())
                    .collect::<Vec<_>>()
            ));
        }
    } else if !injection_fired {
        return Err(format!(
            "positive case did NOT fire injection rule; got: {:?}",
            all_findings
                .iter()
                .map(|f| f.finding_type.clone())
                .collect::<Vec<_>>()
        ));
    }
    Ok(())
}
