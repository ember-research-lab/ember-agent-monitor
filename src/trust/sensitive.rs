//! Sensitive-path classification.
//!
//! Default list per spec §2. User-extensible via `~/.ember/agent-monitor/state/user/sensitive.txt`
//! (one path-or-fragment per line). Fragment matching is suffix-based on
//! path components — e.g., `.env` matches any path whose last component
//! starts with `.env`; `.ssh` matches any path that contains a `.ssh`
//! directory component.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SensitiveSet {
    /// Absolute path prefixes (HOME-expanded). A path is sensitive if it
    /// equals or descends from any of these.
    pub roots: Vec<PathBuf>,
    /// Component fragments. A path is sensitive if any of its components
    /// equals one of these (exact match, not substring).
    pub component_names: Vec<String>,
    /// Filename suffixes. `.env`, `.env.local`, etc. all match any file
    /// whose name begins with `.env`.
    pub filename_prefixes: Vec<String>,
    /// Filename exact matches.
    pub filename_exact: Vec<String>,
}

impl SensitiveSet {
    /// Defaults straight from spec §2 plus 2026 threat-intel additions
    /// (CVE-2025-48384 git submodule writes, CVE-2025-59536 .claude
    /// settings tampering).
    pub fn default_set() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/"));
        let h = Path::new(&home);
        Self {
            roots: vec![
                h.join(".ssh"),
                h.join(".aws"),
                h.join(".gnupg"),
                h.join(".config/gh"),
                h.join(".docker"),
                h.join(".cursor"), // CVE-2025-54135 mcp.json target
            ],
            component_names: vec![
                ".ssh".into(),
                ".aws".into(),
                ".gnupg".into(),
                ".gcp".into(),
                ".kube".into(),
                ".claude".into(), // settings.json + skills + hooks live here
                "hooks".into(),   // .git/hooks — CVE-2025-48384
            ],
            filename_prefixes: vec![".env".into()],
            filename_exact: vec![
                ".netrc".into(),
                "credentials".into(),
                "id_rsa".into(),
                "id_ed25519".into(),
                "id_dsa".into(),
                "id_ecdsa".into(),
                "config.json".into(),      // Docker etc. — coarse but per spec
                ".gitmodules".into(),      // CVE-2025-48384 submodule poisoning
                "mcp.json".into(),         // CurXecute (CVE-2025-54135)
                "mcp_servers.json".into(), // .claude variant
                "settings.json".into(),    // .claude/settings.json (CVE-2025-59536)
            ],
        }
    }

    pub fn matches(&self, path: &Path) -> bool {
        for root in &self.roots {
            if path.starts_with(root) {
                return true;
            }
        }
        for comp in path.components() {
            if let std::path::Component::Normal(name) = comp {
                if let Some(s) = name.to_str() {
                    if self.component_names.iter().any(|c| c == s) {
                        return true;
                    }
                }
            }
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if self.filename_exact.iter().any(|f| f == name) {
                return true;
            }
            if self.filename_prefixes.iter().any(|p| name.starts_with(p)) {
                return true;
            }
        }
        false
    }

    /// Load user additions from a config file. Each non-empty, non-comment
    /// line is interpreted as: an absolute path → `roots`; a leading `.`
    /// followed by chars → component name; anything containing only
    /// alphanumerics/underscore/dash → filename exact match.
    pub fn load_additions(&mut self, path: &Path) -> std::io::Result<()> {
        if !path.exists() {
            return Ok(());
        }
        let text = std::fs::read_to_string(path)?;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('/') || line.starts_with('~') {
                let home = std::env::var("HOME").unwrap_or_default();
                let resolved = if let Some(rest) = line.strip_prefix("~/") {
                    PathBuf::from(home).join(rest)
                } else {
                    PathBuf::from(line)
                };
                self.roots.push(resolved);
            } else if line.starts_with('.') {
                self.component_names.push(line.into());
            } else {
                self.filename_exact.push(line.into());
            }
        }
        Ok(())
    }
}
