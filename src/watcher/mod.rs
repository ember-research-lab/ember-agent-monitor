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
}

impl WatcherState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan the watch directory for changed files. Returns a list of
    /// `(path, new_lines)` tuples for each file with appended content.
    pub fn poll(&mut self, cfg: &DaemonConfig) -> Result<Vec<(PathBuf, Vec<String>)>, String> {
        let mut updates = Vec::new();
        let root = &cfg.watch_dir;
        if !root.exists() {
            return Ok(updates);
        }
        let entries = fs::read_dir(root).map_err(|e| format!("read_dir {root:?}: {e}"))?;
        for entry in entries.flatten() {
            let project_dir = entry.path();
            if !project_dir.is_dir() {
                continue;
            }
            let sessions_dir = project_dir.join("sessions");
            if !sessions_dir.exists() {
                continue;
            }
            let session_entries = match fs::read_dir(&sessions_dir) {
                Ok(it) => it,
                Err(_) => continue,
            };
            for s in session_entries.flatten() {
                let path = s.path();
                if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                    continue;
                }
                let metadata = match path.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let len = metadata.len();
                let prev = *self.offsets.get(&path).unwrap_or(&0);
                if len <= prev {
                    continue;
                }
                if let Ok(new_lines) = read_from_offset(&path, prev) {
                    self.offsets.insert(path.clone(), len);
                    if !new_lines.is_empty() {
                        updates.push((path, new_lines));
                    }
                }
            }
        }
        Ok(updates)
    }
}

fn read_from_offset(path: &PathBuf, offset: u64) -> std::io::Result<Vec<String>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    Ok(buf
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|s| s.to_string())
        .collect())
}
