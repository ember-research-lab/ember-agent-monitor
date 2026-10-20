//! memory_paths — memory-class path list and matcher for `memory_write_by_subagent` (#32).
//!
//! The list is a hard-coded copy of ember-persistent's `MEMORY_CLASS_PATHS`
//! (`src/rules/recurrence.rs`); the suite keeps no shared library (loose
//! coupling), so the two stay in lock-step by hand and each pins the literal
//! list in a test.

/// `*` matches any run of characters including `/`; a pattern with no `*`
/// matches a final path component.
pub const MEMORY_CLASS_PATHS: &[&str] = &[
    "CLAUDE.md",
    "*/memory/*",
    "*/charters/*",
    "*/.claude/rules/*",
    "*/.claude/hooks/*",
    "*/.claude/settings*",
];

/// Input keys that name a write target.
pub const PATH_KEYS: &[&str] = &["file_path", "path", "filepath", "filename", "notebook_path"];

/// Lexically normalise: backslashes to `/`, resolve `.`/`..`, always rooted.
fn normalise_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split(['/', '\\']) {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    format!("/{}", parts.join("/"))
}

fn glob_match(pat: &[u8], s: &[u8]) -> bool {
    let (mut p, mut i) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while i < s.len() {
        if p < pat.len() && pat[p] == b'*' {
            star = Some(p);
            mark = i;
            p += 1;
        } else if p < pat.len() && pat[p] == s[i] {
            p += 1;
            i += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

pub fn is_memory_class_path(path: &str) -> bool {
    let norm = normalise_path(path);
    MEMORY_CLASS_PATHS.iter().any(|pat| {
        if pat.contains('*') {
            glob_match(pat.as_bytes(), norm.as_bytes())
        } else {
            norm == format!("/{pat}") || norm.ends_with(&format!("/{pat}"))
        }
    })
}

/// Case-insensitive: `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, MCP `write_file`...
pub fn is_write_tool(tool: &str) -> bool {
    let t = tool.to_ascii_lowercase();
    t.contains("write") || t.contains("edit")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_pinned_in_lock_step_with_persistent() {
        assert_eq!(
            MEMORY_CLASS_PATHS,
            &[
                "CLAUDE.md",
                "*/memory/*",
                "*/charters/*",
                "*/.claude/rules/*",
                "*/.claude/hooks/*",
                "*/.claude/settings*"
            ]
        );
    }

    #[test]
    fn matches_memory_class_and_not_ordinary_paths() {
        for p in [
            "/home/a/proj/CLAUDE.md",
            "CLAUDE.md",
            "/home/a/.claude/projects/x/memory/m.md",
            "/home/a/.claude/charters/s.md",
            "/home/a/.claude/rules/o.md",
            "/home/a/.claude/hooks/h.sh",
            "/home/a/.claude/settings.json",
            "/home/a/proj/../.claude/rules/x.md",
        ] {
            assert!(is_memory_class_path(p), "{p}");
        }
        for p in [
            "/home/a/proj/src/main.rs",
            "/home/a/notes/README.md",
            "/home/a/CLAUDE.md.bak",
        ] {
            assert!(!is_memory_class_path(p), "{p}");
        }
    }
}
