//! Trust zone tagging.
//!
//! Spec §2 ("Trust boundaries"): every byte sequence the monitor sees gets
//! tagged. Path normalization is *substrate-required*, not optional —
//! tilde-expand and resolve before zone classification, or `~/.ssh` slips
//! past as `external_local`.

use crate::types::TrustZone;
use std::path::{Component, Path, PathBuf};

pub mod sensitive;

/// Resolve a path-shaped string to a canonical absolute form for trust
/// classification. We *do not* call `canonicalize()` because the path may
/// not exist (the agent could be probing) and canonicalize would error.
/// Instead we expand `~` and lexically resolve `..`/`.`. Symlink resolution
/// is intentionally deferred — symlinks pointing into sensitive zones are a
/// known evasion vector and are caught by re-tagging the resolved target
/// downstream when the OS actually opens the file.
pub fn normalize_path(raw: &str) -> PathBuf {
    let expanded = expand_tilde(raw);
    let path = Path::new(&expanded);
    let mut out = PathBuf::new();

    if path.is_absolute() {
        out.push("/");
    } else {
        // Best-effort: prepend cwd. If cwd lookup fails, we just collapse the
        // relative path on its own — caller's job to recognize the result is
        // not absolute.
        if let Ok(cwd) = std::env::current_dir() {
            out = cwd;
        }
    }

    for comp in path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                out = PathBuf::from("/");
            }
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s),
        }
    }
    out
}

fn expand_tilde(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    if s == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    s.to_string()
}

/// Classify a path into a trust zone.
///
/// Args:
///   path        — already-normalized absolute path (call `normalize_path` first).
///   workspace   — current project working directory (also normalized).
///   sensitive   — list of normalized sensitive-zone path roots and glob fragments.
pub fn classify_path(
    path: &Path,
    workspace: Option<&Path>,
    sensitive: &sensitive::SensitiveSet,
) -> TrustZone {
    if sensitive.matches(path) {
        return TrustZone::SensitiveLocal;
    }
    if path.starts_with("/tmp") || path.starts_with("/var/tmp") {
        return TrustZone::Ephemeral;
    }
    if let Some(ws) = workspace {
        if path.starts_with(ws) {
            return TrustZone::WorkspaceLocal;
        }
    }
    TrustZone::ExternalLocal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tilde_expansion() {
        std::env::set_var("HOME", "/Users/aaron");
        let p = normalize_path("~/.ssh/id_rsa");
        assert_eq!(p, PathBuf::from("/Users/aaron/.ssh/id_rsa"));
    }

    #[test]
    fn parent_dir_collapse() {
        std::env::set_var("HOME", "/Users/aaron");
        let p = normalize_path("~/projects/../.ssh");
        assert_eq!(p, PathBuf::from("/Users/aaron/.ssh"));
    }

    #[test]
    fn classify_sensitive() {
        std::env::set_var("HOME", "/Users/aaron");
        let s = sensitive::SensitiveSet::default_set();
        let p = normalize_path("~/.ssh/id_rsa");
        assert_eq!(classify_path(&p, None, &s), TrustZone::SensitiveLocal);
    }
}
