//! Threat-intel fixture regression test.
//!
//! Walks every directory under `threat-intel/fixtures/`, loads the
//! events.jsonl + expected.json, runs detection, asserts the findings
//! match exactly. A new finding type without a corresponding expected
//! entry is a red build; a missing finding is a red build.
//!
//! Adding a fixture is one directory drop:
//!   threat-intel/fixtures/<name>/{events.jsonl, expected.json, README.md}
//!
//! No test code change required.

use ember_agent_monitor::detect::{run_all, DetectionConfig};
use ember_agent_monitor::json::{parse, JsonValue};
use ember_agent_monitor::store::log::read_all;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn all_threat_intel_fixtures_match_expected() {
    let root = fixtures_root();
    let mut fixtures = list_fixtures(&root);
    fixtures.sort();
    assert!(
        !fixtures.is_empty(),
        "no fixtures discovered under {root:?} — refusing to silently pass"
    );

    let cfg = DetectionConfig::default();
    let mut failures = Vec::new();

    for fixture_dir in &fixtures {
        let name = fixture_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        let events_path = fixture_dir.join("events.jsonl");
        let expected_path = fixture_dir.join("expected.json");
        if !events_path.exists() {
            failures.push(format!("{name}: missing events.jsonl"));
            continue;
        }
        if !expected_path.exists() {
            failures.push(format!(
                "{name}: missing expected.json (fixture incomplete — pin the contract or remove)"
            ));
            continue;
        }

        let events = match read_all(&events_path) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{name}: read events: {e}"));
                continue;
            }
        };
        let findings = run_all(&events, &cfg);

        let expected = match load_expected(&expected_path) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{name}: load expected: {e}"));
                continue;
            }
        };

        let actual_counts = count_findings(&findings);
        let expected_counts = count_expected(&expected);

        if actual_counts != expected_counts {
            failures.push(format!(
                "{name}: finding counts differ\n  expected: {expected_counts:?}\n  actual:   {actual_counts:?}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "threat-intel fixture regressions:\n{}",
        failures.join("\n---\n")
    );
}

fn fixtures_root() -> PathBuf {
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_root.join("threat-intel").join("fixtures")
}

fn list_fixtures(root: &PathBuf) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(root) {
        Ok(it) => it,
        Err(_) => return Vec::new(),
    };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect()
}

#[derive(Debug, Clone)]
struct Expected {
    by_type_severity: BTreeMap<(String, String, String), usize>,
}

fn load_expected(path: &PathBuf) -> Result<Expected, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let v = parse(&text).map_err(|e| format!("json: {e:?}"))?;
    let obj = match v {
        JsonValue::Object(o) => o,
        _ => return Err("expected.json must be a JSON object".into()),
    };
    let arr = obj
        .iter()
        .find(|(k, _)| k == "expected_findings")
        .and_then(|(_, v)| match v {
            JsonValue::Array(a) => Some(a.clone()),
            _ => None,
        })
        .ok_or_else(|| "missing expected_findings array".to_string())?;
    let mut by = BTreeMap::new();
    for entry in &arr {
        let o = match entry {
            JsonValue::Object(o) => o,
            _ => continue,
        };
        let t = string_field(o, "type").unwrap_or_default();
        let scope = string_field(o, "scope").unwrap_or_default();
        let sev = string_field(o, "severity").unwrap_or_default();
        *by.entry((t, scope, sev)).or_insert(0) += 1;
    }
    Ok(Expected { by_type_severity: by })
}

fn count_findings(
    findings: &[ember_agent_monitor::detect::Finding],
) -> BTreeMap<(String, String, String), usize> {
    let mut by = BTreeMap::new();
    for f in findings {
        *by.entry((
            f.finding_type.clone(),
            f.scope.as_str().into(),
            f.severity.as_str().into(),
        ))
        .or_insert(0) += 1;
    }
    by
}

fn count_expected(e: &Expected) -> BTreeMap<(String, String, String), usize> {
    e.by_type_severity.clone()
}

fn string_field(obj: &[(String, JsonValue)], key: &str) -> Option<String> {
    obj.iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            JsonValue::Str(s) => Some(s.clone()),
            _ => None,
        })
}
