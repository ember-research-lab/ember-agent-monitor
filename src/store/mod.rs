//! Append-only event log + state scope hierarchy.
//!
//! Spec §10 says "SQLite via direct syscalls, bundled". For v0 we use
//! append-only JSONL — same on-disk contract as the spec's session graphs
//! (`~/.ember/agent-monitor/sessions/<id>.jsonl`), zero deps, simpler audit
//! surface. Findings DB is a separate JSONL; SQLite-or-equivalent is a v1+
//! decision once we know the access patterns under load.
//!
//! State scope hierarchy (spec §2): UserState → ProjectState → SessionState.
//! `Store::session_log_path` resolves the path; lookups walk the hierarchy.

pub mod log;
pub mod summary;

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Store {
    base_dir: PathBuf,
}

impl Store {
    pub fn open(base_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(base_dir.join("sessions"))
            .map_err(|e| format!("create sessions dir: {e}"))?;
        std::fs::create_dir_all(base_dir.join("findings"))
            .map_err(|e| format!("create findings dir: {e}"))?;
        std::fs::create_dir_all(base_dir.join("state/user"))
            .map_err(|e| format!("create state/user dir: {e}"))?;
        std::fs::create_dir_all(base_dir.join("state/project"))
            .map_err(|e| format!("create state/project dir: {e}"))?;
        Ok(Self {
            base_dir: base_dir.to_path_buf(),
        })
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn session_log_path(&self, session_id: &str) -> PathBuf {
        // Sanitize: only allow alphanumeric, dash, underscore.
        let safe: String = session_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.base_dir.join("sessions").join(format!("{safe}.jsonl"))
    }

    pub fn findings_path(&self, session_id: &str) -> PathBuf {
        let safe = sanitize(session_id);
        self.base_dir
            .join("findings")
            .join(format!("{safe}.jsonl"))
    }

    pub fn summary_path(&self, session_id: &str) -> PathBuf {
        let safe = sanitize(session_id);
        self.base_dir
            .join("sessions")
            .join(format!("{safe}.summary.json"))
    }
}

fn sanitize(session_id: &str) -> String {
    session_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
