//! Stat-based file-watcher for ~/.claude/projects/.
//!
//! Spec §2 ("Hybrid observer"): MCP server registration happens at agent
//! startup over local IPC, never over the API. A pure HTTP proxy cannot see
//! that — only the file-watcher does. We poll session JSONL files in the
//! Claude Code projects directory, parse new lines as they arrive, and emit
//! the corresponding events to the event log.
//!
//! Polling instead of inotify because zero-dep + cross-platform. 250ms tick.

use crate::types::DaemonConfig;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Default)]
pub struct WatcherState {
    /// File path → byte offset already consumed.
    pub offsets: HashMap<PathBuf, u64>,
    /// True once the first poll has recorded the pre-existing files' ends.
    primed: bool,
}

impl WatcherState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan the watch directory for changed files. Returns a list of
    /// `(path, new_lines)` tuples for each file with appended content.
    ///
    /// Three layouts are watched: Claude Code's real ones,
    /// `<root>/<project>/<session>.jsonl` and
    /// `<root>/<project>/<session>/subagents/*.jsonl`, and the spec's
    /// `<root>/<project>/sessions/*.jsonl`. A file first seen after the
    /// first poll is read from byte 0; a file that already exists on the
    /// first poll is tailed from its current end (the daemon watches live
    /// activity, it does not replay gigabytes of history). Only complete
    /// (newline-terminated) lines are consumed, so a half-written line is
    /// picked up whole on the next tick.
    pub fn poll(&mut self, cfg: &DaemonConfig) -> Result<Vec<(PathBuf, Vec<String>)>, String> {
        let mut updates = Vec::new();
        let root = &cfg.watch_dir;
        if !root.exists() {
            return Ok(updates);
        }
        let first_poll = !self.primed;
        let entries = fs::read_dir(root).map_err(|e| format!("read_dir {root:?}: {e}"))?;
        for entry in entries.flatten() {
            let project_dir = entry.path();
            if !project_dir.is_dir() {
                continue;
            }
            let mut files = jsonl_files(&project_dir);
            files.extend(jsonl_files(&project_dir.join("sessions")));
            // Subagent transcripts: <project>/<session>/subagents/agent-*.jsonl
            if let Ok(it) = fs::read_dir(&project_dir) {
                for sub in it.flatten().filter(|e| e.path().is_dir()) {
                    files.extend(jsonl_files(&sub.path().join("subagents")));
                }
            }
            for path in files {
                let len = match path.metadata() {
                    Ok(m) => m.len(),
                    Err(_) => continue,
                };
                let prev = match self.offsets.get(&path) {
                    Some(p) => *p,
                    None if first_poll => {
                        self.offsets.insert(path.clone(), len);
                        continue;
                    }
                    None => 0,
                };
                if len <= prev {
                    continue;
                }
                let (new_lines, consumed) = read_from_offset(&path, prev)
                    .map_err(|e| format!("read {path:?} at {prev}: {e}"))?;
                self.offsets.insert(path.clone(), prev + consumed);
                if !new_lines.is_empty() {
                    updates.push((path, new_lines));
                }
            }
        }
        self.primed = true;
        Ok(updates)
    }
}

fn jsonl_files(dir: &std::path::Path) -> Vec<PathBuf> {
    match fs::read_dir(dir) {
        Ok(it) => it
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("jsonl"))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// What the adapter does with a top-level Claude Code transcript field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldDisposition {
    /// Copied into every event body under the given key.
    Carried(&'static str),
    /// Used to build the event (kind, session, message content) but not copied.
    Consumed,
    /// Deliberately not carried.
    Dropped,
}

/// Every top-level transcript field the adapter has an opinion about. The
/// `watcher_transcript` test fails if a sample record has a field missing
/// here, so a new field must be carried or dropped on purpose (#30).
pub const TRANSCRIPT_FIELDS: &[(&str, FieldDisposition)] = &[
    ("agentId", FieldDisposition::Carried("agent_id")),
    ("isSidechain", FieldDisposition::Carried("is_sidechain")),
    ("uuid", FieldDisposition::Carried("uuid")),
    ("type", FieldDisposition::Consumed),
    ("message", FieldDisposition::Consumed),
    ("sessionId", FieldDisposition::Consumed),
    ("cwd", FieldDisposition::Consumed),
    ("gitBranch", FieldDisposition::Consumed),
    ("parentUuid", FieldDisposition::Dropped),
    ("userType", FieldDisposition::Dropped),
    ("version", FieldDisposition::Dropped),
    ("timestamp", FieldDisposition::Dropped),
    ("requestId", FieldDisposition::Dropped),
    ("toolUseResult", FieldDisposition::Dropped),
    ("isMeta", FieldDisposition::Dropped),
    ("slug", FieldDisposition::Dropped),
    ("permissionMode", FieldDisposition::Dropped),
    ("promptId", FieldDisposition::Dropped),
    ("entrypoint", FieldDisposition::Dropped),
    ("sourceToolAssistantUUID", FieldDisposition::Dropped),
];

/// What one watched line turned into.
pub enum LineOutcome {
    /// Events to record + analyze.
    Events(Vec<crate::event::Event>),
    /// A well-formed Claude Code record that carries no conversation
    /// content (system, queue-operation, attachment, ...). Not an error.
    NotConversation,
    /// Neither a monitor event nor a Claude Code transcript record.
    Malformed(String),
}

/// Interpret one watched line: a monitor-native event (the spec layout), or a
/// Claude Code transcript record (`{"type":"user"|"assistant","message":{..},
/// "sessionId":..}`) whose `message` is converted by the Anthropic protocol
/// parser so the `tool_result` vs `user_prompt` invariant (spec §3) holds.
///
/// The first record seen for a session (`seen` tracks them) also yields a
/// `session_start` event carrying the record's `cwd` / `gitBranch`, so the
/// session summary has the workspace that ember-persistent partitions on.
pub fn interpret_line(line: &str, seen: &mut std::collections::HashSet<String>) -> LineOutcome {
    use crate::json::{parse, to_json_string, JsonValue};
    let v = match parse(line) {
        Ok(v) => v,
        Err(e) => return LineOutcome::Malformed(format!("json parse: {e:?}")),
    };
    let field = |k: &str| -> Option<&JsonValue> {
        match &v {
            JsonValue::Object(o) => o.iter().find(|(n, _)| n == k).map(|(_, x)| x),
            _ => None,
        }
    };
    let ty = match field("type") {
        Some(JsonValue::Str(s)) => Some(s.as_str()),
        _ => None,
    };
    if let (Some("user" | "assistant"), Some(msg @ JsonValue::Object(_))) = (ty, field("message")) {
        let sid = match field("sessionId") {
            Some(JsonValue::Str(s)) if !s.is_empty() => s.clone(),
            _ => return LineOutcome::Malformed("transcript record without sessionId".into()),
        };
        let wrapped = JsonValue::Object(vec![(
            "messages".to_string(),
            JsonValue::Array(vec![msg.clone()]),
        )]);
        let req = match crate::proto::anthropic::parse_request(to_json_string(&wrapped).as_bytes())
        {
            Ok(r) => r,
            Err(e) => return LineOutcome::Malformed(format!("transcript message: {e}")),
        };
        let mut events = Vec::new();
        if seen.insert(sid.clone()) {
            let mut body = std::collections::HashMap::new();
            for (src, dst) in [("cwd", "cwd"), ("gitBranch", "git_branch")] {
                if let Some(x @ JsonValue::Str(_)) = field(src) {
                    body.insert(dst.to_string(), x.clone());
                }
            }
            if let Some(m) = &req.model {
                body.insert("model".to_string(), JsonValue::Str(m.clone()));
            }
            events.push(crate::event::Event::new(
                sid.clone(),
                crate::types::EventKind::SessionStart,
                crate::types::TrustZone::WorkspaceLocal,
                body,
            ));
        }
        events.extend(crate::proto::anthropic::request_to_events(&req, &sid));
        for (src, disp) in TRANSCRIPT_FIELDS {
            let FieldDisposition::Carried(dst) = disp else {
                continue;
            };
            if let Some(x @ (JsonValue::Str(_) | JsonValue::Bool(_))) = field(src) {
                for ev in events.iter_mut() {
                    ev.set_body_field(dst, x.clone());
                }
            }
        }
        return LineOutcome::Events(events);
    }
    if ty.is_some() && field("kind").is_none() {
        return LineOutcome::NotConversation;
    }
    match crate::event::parse_jsonl_line(line) {
        Ok(ev) => LineOutcome::Events(vec![ev]),
        Err(e) => LineOutcome::Malformed(e),
    }
}

/// Read complete lines from `offset`; returns them and the bytes consumed
/// (up to and including the last newline).
fn read_from_offset(path: &PathBuf, offset: u64) -> std::io::Result<(Vec<String>, u64)> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    let end = match buf.iter().rposition(|b| *b == b'\n') {
        Some(i) => i + 1,
        None => return Ok((Vec::new(), 0)),
    };
    let text = String::from_utf8_lossy(&buf[..end]);
    let lines = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|s| s.to_string())
        .collect();
    Ok((lines, end as u64))
}
