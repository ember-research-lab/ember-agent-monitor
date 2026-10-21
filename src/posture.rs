//! posture — per-session "posture" raised by sibling-tool findings (#27, #31).
//!
//! Sources, re-checked (stat) on every observed event and read when changed:
//!   * `~/.ember/vetpkg/findings.jsonl`      — a WARN-or-higher package that a
//!     tool_call in this session installs or imports;
//!   * `~/.ember/persistent/findings.jsonl`  — a HIGH-or-higher finding for this
//!     session's workspace (schema v2 only; unknown versions refused loudly);
//!   * `~/.ember/network/findings.jsonl`     — a HIGH-or-higher finding whose
//!     `session_id` is this session (empty `session_id` cannot be attributed).
//!
//! Effect: an elevated session has its exec and egress rule findings bumped
//! one severity step (`EXEC_RULES`, `EGRESS_RULES`), and one MEDIUM
//! `posture_elevated` marker finding (source file + reason) is emitted once.
//! Posture is advisory input; it never lowers anything and never blocks.

use crate::crypto::sha256;
use crate::detect::{Finding, FindingScope};
use crate::event::Event;
use crate::integrate::{NetworkFindings, PersistentFindings, VetpkgFindings};
use crate::json::JsonValue;
use crate::types::{EventKind, Severity};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// Rules that decide whether the agent executes something.
pub const EXEC_RULES: &[&str] = &[
    "argument_injection_pattern",
    "sandbox_escape_pattern",
    "auto_approve_write_via_injection",
];
/// Rules that decide whether data or traffic leaves.
pub const EGRESS_RULES: &[&str] = &["webhook_destination_arg", "api_base_url_redirect"];

pub const MARKER_TYPE: &str = "posture_elevated";

/// Why and from where a session was elevated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Elevation {
    pub source_file: String,
    pub reason: String,
}

/// What the last read of each source found wrong (all zero = clean).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadReport {
    pub vetpkg_unreadable: usize,
    pub persistent_unreadable: usize,
    pub persistent_refused_schema: usize,
    pub persistent_refused_versions: Vec<String>,
    pub network_unreadable: usize,
}

impl LoadReport {
    pub fn is_clean(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug, Default)]
struct Cached<T> {
    stamp: Option<(SystemTime, u64)>,
    data: T,
}

#[derive(Debug, Default)]
struct SessionState {
    workspace: Option<String>,
    packages: BTreeSet<String>,
    elevation: Option<Elevation>,
}

#[derive(Debug, Default)]
struct Inner {
    vetpkg: Cached<VetpkgFindings>,
    persistent: Cached<PersistentFindings>,
    network: Cached<NetworkFindings>,
    last_reported: LoadReport,
    sessions: HashMap<String, SessionState>,
}

#[derive(Debug)]
pub struct SessionPosture {
    vetpkg_path: PathBuf,
    persistent_path: PathBuf,
    network_path: PathBuf,
    inner: Mutex<Inner>,
}

impl SessionPosture {
    /// `ember_root` is the directory holding the suite's per-tool dirs
    /// (`vetpkg/`, `persistent/`, `network/`): `~/.ember`, the parent of the
    /// monitor's own data dir.
    pub fn new(ember_root: &Path) -> Self {
        let e = ember_root;
        Self {
            vetpkg_path: e.join("vetpkg/findings.jsonl"),
            persistent_path: e.join("persistent/findings.jsonl"),
            network_path: e.join("network/findings.jsonl"),
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn elevation(&self, session_id: &str) -> Option<Elevation> {
        let g = self.inner.lock().unwrap();
        g.sessions.get(session_id).and_then(|s| s.elevation.clone())
    }

    /// `name@version` of every vetpkg-flagged package this session installed
    /// or imported (for the summary's `vetpkg_packages_seen`).
    pub fn packages_seen(&self, session_id: &str) -> Vec<String> {
        let g = self.inner.lock().unwrap();
        g.sessions
            .get(session_id)
            .map(|s| s.packages.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn load_report(&self) -> LoadReport {
        let mut g = self.inner.lock().unwrap();
        self.refresh(&mut g);
        report_of(&g)
    }

    /// Fold one event into the session's posture. Returns the one-time
    /// `posture_elevated` marker when this event raised it.
    pub fn observe(&self, event: &Event) -> Option<Finding> {
        let mut g = self.inner.lock().unwrap();
        self.refresh(&mut g);
        let inner = &mut *g;
        let st = inner.sessions.entry(event.session_id.clone()).or_default();
        if event.kind == EventKind::SessionStart {
            if let Some(JsonValue::Str(cwd)) = event.body.get("cwd") {
                st.workspace = Some(hash_workspace(cwd));
            }
        }
        if event.kind == EventKind::ToolCall {
            let strings = tool_input_strings(event);
            for (pkg, findings) in &inner.vetpkg.data.by_package {
                if !mentions_package(&strings, pkg) {
                    continue;
                }
                for f in findings {
                    let shown = if f.version.is_empty() {
                        f.package.clone()
                    } else {
                        format!("{}@{}", f.package, f.version)
                    };
                    st.packages.insert(shown);
                }
            }
        }
        if st.elevation.is_some() {
            return None;
        }
        let found = vetpkg_trigger(&inner.vetpkg.data, st, &self.vetpkg_path)
            .or_else(|| persistent_trigger(&inner.persistent.data, st, &self.persistent_path))
            .or_else(|| {
                network_trigger(&inner.network.data, &event.session_id, &self.network_path)
            });
        let elev = found?;
        st.elevation = Some(elev.clone());
        Some(Finding {
            finding_type: MARKER_TYPE.into(),
            scope: FindingScope::Dynamic,
            severity: Severity::Medium,
            session_id: event.session_id.clone(),
            event_id: Some(event.event_id.clone()),
            tool: None,
            argument: None,
            matched_value: Some(elev.source_file.clone()),
            pattern: None,
            trust_zone: None,
            rationale: format!(
                "session posture elevated: {} (source {}); exec and egress rules bump one severity step",
                elev.reason, elev.source_file
            ),
            score: Severity::Medium.weight(),
        })
    }

    /// Bump exec and egress rule findings one step for an elevated session.
    /// The marker itself and every other rule are left alone.
    pub fn bump(&self, session_id: &str, findings: &mut [Finding]) {
        if self.elevation(session_id).is_none() {
            return;
        }
        for f in findings.iter_mut() {
            let t = f.finding_type.as_str();
            if !(EXEC_RULES.contains(&t) || EGRESS_RULES.contains(&t)) {
                continue;
            }
            let next = match f.severity {
                Severity::Low => Severity::Medium,
                Severity::Medium => Severity::High,
                Severity::High | Severity::Critical => Severity::Critical,
            };
            if next != f.severity {
                f.score *= next.weight() / f.severity.weight();
                f.severity = next;
            }
        }
    }

    fn refresh(&self, g: &mut Inner) {
        reload(&self.vetpkg_path, &mut g.vetpkg, |p| {
            VetpkgFindings::load_from(&p.to_path_buf())
        });
        reload(
            &self.persistent_path,
            &mut g.persistent,
            PersistentFindings::load_from,
        );
        reload(
            &self.network_path,
            &mut g.network,
            NetworkFindings::load_from,
        );
        let report = report_of(g);
        if report != g.last_reported {
            if !report.is_clean() {
                eprintln!(
                    "ember-agent: posture — source files not fully readable: {report:?} (refused or unreadable lines are ignored, not trusted)"
                );
            }
            g.last_reported = report;
        }
    }
}

fn reload<T: Default>(path: &Path, c: &mut Cached<T>, load: impl Fn(&Path) -> T) {
    let stamp = std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok().map(|t| (t, m.len())));
    if stamp == c.stamp {
        return;
    }
    c.stamp = stamp;
    c.data = if stamp.is_some() {
        load(path)
    } else {
        T::default()
    };
}

fn report_of(g: &Inner) -> LoadReport {
    LoadReport {
        vetpkg_unreadable: g.vetpkg.data.unreadable_lines,
        persistent_unreadable: g.persistent.data.unreadable_lines,
        persistent_refused_schema: g.persistent.data.refused_schema,
        persistent_refused_versions: g.persistent.data.refused_versions.clone(),
        network_unreadable: g.network.data.unreadable_lines,
    }
}

fn vetpkg_trigger(v: &VetpkgFindings, st: &SessionState, path: &Path) -> Option<Elevation> {
    for (pkg, findings) in &v.by_package {
        let Some(f) = findings.iter().find(|f| f.is_warn_or_higher()) else {
            continue;
        };
        let seen = st
            .packages
            .iter()
            .any(|p| p == pkg || p.starts_with(&format!("{pkg}@")));
        if seen {
            return Some(Elevation {
                source_file: path.display().to_string(),
                reason: format!(
                    "vetpkg flagged {pkg} ({}, {}) and this session installs or imports it",
                    f.severity, f.reason
                ),
            });
        }
    }
    None
}

fn persistent_trigger(p: &PersistentFindings, st: &SessionState, path: &Path) -> Option<Elevation> {
    let ws = st.workspace.as_deref()?;
    let f = p
        .findings
        .iter()
        .find(|f| f.workspace == ws && is_high(&f.severity))?;
    Some(Elevation {
        source_file: path.display().to_string(),
        reason: format!(
            "ember-persistent {} finding {} for this workspace",
            f.severity, f.finding_type
        ),
    })
}

fn network_trigger(n: &NetworkFindings, session_id: &str, path: &Path) -> Option<Elevation> {
    let f = n
        .findings
        .iter()
        .find(|f| f.session_id == session_id && is_high(&f.severity))?;
    Some(Elevation {
        source_file: path.display().to_string(),
        reason: format!(
            "ember-network {} finding {} for this session",
            f.severity, f.finding_type
        ),
    })
}

fn is_high(sev: &str) -> bool {
    matches!(sev, "high" | "critical")
}

/// Persistent's workspace key: sha256 of the lexically normalised cwd, first
/// 16 hex chars (ember-persistent `workspace::hash_workspace`; lock-step copy,
/// no shared library).
pub fn hash_workspace(cwd: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    let expanded = if cwd == "~" {
        home
    } else if let Some(rest) = cwd.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        cwd.to_string()
    };
    let p = Path::new(&expanded);
    let mut out = PathBuf::new();
    if p.is_absolute() {
        out.push("/");
    }
    for comp in p.components() {
        match comp {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                out = PathBuf::from("/");
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(s) => out.push(s),
        }
    }
    let digest = sha256::sha256(out.display().to_string().as_bytes());
    digest
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn tool_input_strings(event: &Event) -> Vec<String> {
    match event.body.get("input") {
        Some(JsonValue::Object(o)) => o
            .iter()
            .filter_map(|(_, v)| match v {
                JsonValue::Str(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

const INSTALLERS: &[&str] = &[
    "npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "pipx", "poetry", "cargo", "gem", "go",
    "deno",
];
const INSTALL_VERBS: &[&str] = &["install", "i", "add", "get"];

fn norm_name(s: &str) -> String {
    s.to_ascii_lowercase().replace('_', "-")
}

/// Strip quotes and a version/extras suffix: `lodash@4.1`, `requests==2.0`,
/// `serde@1`, `@scope/pkg@1.0`, `pkg[extra]>=1`.
fn bare_package(tok: &str) -> String {
    let t = tok.trim_matches(|c| c == '"' || c == '\'' || c == '`');
    let (lead, rest) = match t.strip_prefix('@') {
        Some(r) => ("@", r),
        None => ("", t),
    };
    let end = rest
        .find(['@', '=', '<', '>', '~', '[', '!', ','])
        .unwrap_or(rest.len());
    format!("{lead}{}", &rest[..end])
}

/// Does any tool input install or import `pkg`?
fn mentions_package(strings: &[String], pkg: &str) -> bool {
    let want = norm_name(pkg);
    strings
        .iter()
        .any(|s| installs(s, &want) || imports(s, &want))
}

fn installs(s: &str, want: &str) -> bool {
    let toks: Vec<&str> = s.split_whitespace().collect();
    for (i, t) in toks.iter().enumerate() {
        if !INSTALL_VERBS.contains(t) || i == 0 {
            continue;
        }
        let prev_is_installer = toks[i.saturating_sub(2)..i]
            .iter()
            .any(|p| INSTALLERS.contains(p));
        if !prev_is_installer {
            continue;
        }
        for cand in &toks[i + 1..] {
            if matches!(*cand, "&&" | "||" | ";" | "|") || cand.ends_with(';') && cand.len() == 1 {
                break;
            }
            if cand.starts_with('-') {
                continue;
            }
            let trimmed = cand.trim_end_matches(';');
            if norm_name(&bare_package(trimmed)) == want {
                return true;
            }
            if cand.ends_with(';') {
                break;
            }
        }
    }
    false
}

fn imports(s: &str, want: &str) -> bool {
    let l = s.to_ascii_lowercase().replace('_', "-");
    let boundary = |after: Option<char>| match after {
        None => true,
        Some(c) => !(c.is_ascii_alphanumeric() || c == '-'),
    };
    let rust_want = want.replace('-', "_");
    let forms: Vec<(String, bool)> = vec![
        (format!("import {want}"), false),
        (format!("from {want}"), false),
        (format!("require(\"{want}\")"), true),
        (format!("require('{want}')"), true),
        (format!("from \"{want}\""), true),
        (format!("from '{want}'"), true),
        (format!("import \"{want}\""), true),
        (format!("import '{want}'"), true),
        (format!("use {rust_want}::"), true),
    ];
    for (f, exact) in forms {
        let hay = if f.starts_with("use ") {
            s.to_ascii_lowercase()
        } else {
            l.clone()
        };
        let mut from = 0;
        while let Some(p) = hay[from..].find(&f) {
            let at = from + p;
            let end = at + f.len();
            if exact || boundary(hay[end..].chars().next()) {
                return true;
            }
            from = end;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(s: &str, pkg: &str) -> bool {
        mentions_package(&[s.to_string()], pkg)
    }

    #[test]
    fn install_and_import_forms() {
        assert!(m("npm install lodash", "lodash"));
        assert!(m("npm i -D lodash@4.17.21 && npm test", "lodash"));
        assert!(m("uv add requets==0.0.1", "requets"));
        assert!(m("cd x && pip install -q Requets_x", "requets-x"));
        assert!(m("cargo add serde@1", "serde"));
        assert!(m("npm install @scope/pkg@1.0.0", "@scope/pkg"));
        assert!(m("import requets\nprint(1)", "requets"));
        assert!(m("from requets import get", "requets"));
        assert!(m("const x = require('lodash')", "lodash"));
        assert!(m("import x from \"lodash\"", "lodash"));
        assert!(!m("npm install lodash-es", "lodash"));
        assert!(!m("import requetsx", "requets"));
        assert!(!m("echo lodash is nice", "lodash"));
        assert!(!m("npm install other && echo lodash", "lodash"));
    }

    #[test]
    fn workspace_hash_matches_persistent_algorithm() {
        let a = hash_workspace("/home/a/proj");
        assert_eq!(a.len(), 16);
        assert_eq!(a, hash_workspace("/home/a/./proj/../proj"));
        assert_ne!(a, hash_workspace("/home/a/other"));
    }
}
