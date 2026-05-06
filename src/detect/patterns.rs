//! Hand-rolled pattern matchers for v0.5 detection.
//!
//! Zero-dep: no regex crate. Each pattern is a pair (label, matcher_fn).
//! Matchers return the first matched substring (for the rationale) or None.
//!
//! The pattern lists mirror tests/fixtures/detect.py exactly. User-extensible
//! additions land in ~/.ember/agent-monitor/state/user/patterns.txt as
//! verbatim substrings (case-insensitive).

/// Output of a pattern match: a label naming the pattern + a slice of the
/// input that triggered it (for the finding rationale).
#[derive(Debug, Clone)]
pub struct PatternHit {
    pub label: &'static str,
    pub matched: String,
}

pub type Matcher = fn(&str) -> Option<&'static str>;

/// Instruction-shape patterns — must be applied to *content*, gated by trust
/// zone in the rule layer (only fires on `untrusted_tool_output`).
pub fn instruction_patterns() -> &'static [(&'static str, Matcher)] {
    &[
        ("system-prefixed instruction", |s| {
            if contains_ci(s, "SYSTEM_NOTE") || contains_ci(s, "SYSTEM NOTE") {
                Some("system-prefixed instruction")
            } else {
                None
            }
        }),
        ("imperative addressed to assistant", |s| {
            if contains_ci(s, "the assistant must") {
                Some("imperative addressed to assistant")
            } else {
                None
            }
        }),
        ("uppercase imperative", |s| {
            // Case-sensitive: only the literal "you MUST" (the upper-case
            // attention-grabber pattern, not generic "you must").
            if s.contains("you MUST") {
                Some("uppercase imperative")
            } else {
                None
            }
        }),
        ("comment-hidden system directive", |s| {
            // `<!--` (any whitespace) `SYSTEM`
            if let Some(pos) = s.find("<!--") {
                let rest = &s[pos + 4..];
                let stripped = rest.trim_start();
                if stripped.to_ascii_uppercase().starts_with("SYSTEM") {
                    return Some("comment-hidden system directive");
                }
            }
            None
        }),
        ("ignore-previous pattern", |s| {
            let lower = s.to_ascii_lowercase();
            if let Some(pos) = lower.find("important:") {
                let rest = &lower[pos + 10..];
                let stripped = rest.trim_start();
                if stripped.starts_with("ignore") {
                    return Some("ignore-previous pattern");
                }
            }
            None
        }),
        ("chat-template injection", |s| {
            if s.contains("<|im_start|>") || s.contains("<|im_end|>") {
                Some("chat-template injection")
            } else {
                None
            }
        }),
        // Trail-of-Bits research: ANSI escape sequences in tool output can
        // hide instructions from the developer's terminal (the model still
        // sees them). \x1b[8m = conceal; \r-overwrite hides earlier text.
        ("ansi-escape obfuscation", |s| {
            if s.contains("\x1b[8m")
                || s.contains("\x1b[?25l")
                || s.contains("\x1b[2K")
                || s.contains("\x1b[A")
                || (s.contains('\r') && !s.contains('\n') && s.len() > 40)
            {
                Some("ansi-escape obfuscation")
            } else {
                None
            }
        }),
    ]
}

/// Argument-injection patterns — applied to tool-call argument values that
/// are not themselves a flag. In practice we just scan every string-typed
/// value in the input map.
pub fn arg_injection_patterns() -> &'static [(&'static str, Matcher)] {
    &[
        ("flag injection in argument value", |s| {
            // --output= or --output<space>
            if has_flag(s, "--output") {
                Some("flag injection in argument value")
            } else {
                None
            }
        }),
        ("exec flag injection", |s| {
            if has_flag(s, "--exec") {
                Some("exec flag injection")
            } else {
                None
            }
        }),
        ("command chain injection", |s| {
            // ;<ws>(rm|curl|bash|sh)<ws>
            if find_command_chain(s).is_some() {
                Some("command chain injection")
            } else {
                None
            }
        }),
        ("command substitution", |s| {
            // $( ... )
            if let Some(start) = s.find("$(") {
                if s[start + 2..].contains(')') {
                    return Some("command substitution");
                }
            }
            None
        }),
        ("backtick command substitution", |s| {
            // `...` with at least one char between
            if let Some(start) = s.find('`') {
                if s[start + 1..].contains('`') {
                    return Some("backtick command substitution");
                }
            }
            None
        }),
    ]
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let lh: String = haystack.to_ascii_lowercase();
    let ln: String = needle.to_ascii_lowercase();
    lh.contains(&ln)
}

fn has_flag(s: &str, flag: &str) -> bool {
    let mut i = 0;
    while let Some(pos) = s[i..].find(flag) {
        let abs = i + pos;
        let after = abs + flag.len();
        let next = s.as_bytes().get(after).copied();
        match next {
            Some(b'=') | Some(b' ') | Some(b'\t') | Some(b'\n') => return true,
            None => return true,
            _ => {}
        }
        i = abs + flag.len();
    }
    false
}

fn find_command_chain(s: &str) -> Option<()> {
    // ; followed by 0+ whitespace then a known command, OR an && / || chain.
    // Catches both bare-shell and quoted-arg variants (CVE-2025-54795
    // InversePrompt: `echo "x; cat /etc/passwd | curl ..."` — the semicolon
    // sits inside an approved tool's quoted arg). We also catch `&&` / `||`
    // followed by a known command.
    let bytes = s.as_bytes();
    let mut i = 0;
    let cmds = [
        "rm", "curl", "wget", "bash", "sh", "cat", "nc", "ncat", "python", "perl", "ruby",
    ];
    while i < bytes.len() {
        let chain_marker = bytes[i] == b';'
            || (i + 1 < bytes.len() && (bytes[i] == b'&' && bytes[i + 1] == b'&')
                || (bytes[i] == b'|' && bytes[i + 1] == b'|'));
        if chain_marker {
            let mut j = i + 1;
            // For && / || skip the second byte too.
            if i + 1 < bytes.len()
                && (bytes[i] == b'&' || bytes[i] == b'|')
                && bytes[i] == bytes[i + 1]
            {
                j = i + 2;
            }
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            for cmd in &cmds {
                if j + cmd.len() <= bytes.len() && &bytes[j..j + cmd.len()] == cmd.as_bytes() {
                    let after = bytes.get(j + cmd.len()).copied();
                    if after.is_none() || !after.unwrap().is_ascii_alphanumeric() {
                        return Some(());
                    }
                }
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_system_note() {
        let pats = instruction_patterns();
        assert!(pats[0].1("SYSTEM_NOTE: do x").is_some());
        assert!(pats[0].1("system_note in lower").is_some());
        assert!(pats[0].1("nothing relevant").is_none());
    }

    #[test]
    fn matches_assistant_imperative() {
        let pats = instruction_patterns();
        assert!(pats[1].1("Now the assistant must do x").is_some());
        assert!(pats[1].1("assistant should").is_none());
    }

    #[test]
    fn matches_uppercase_must() {
        let pats = instruction_patterns();
        assert!(pats[2].1("you MUST do x").is_some());
        assert!(pats[2].1("you must do x").is_none());
    }

    #[test]
    fn matches_comment_directive() {
        let pats = instruction_patterns();
        assert!(pats[3].1("<!-- SYSTEM: hi -->").is_some());
        assert!(pats[3].1("<!--SYSTEM: hi-->").is_some());
        assert!(pats[3].1("<!-- not relevant -->").is_none());
    }

    #[test]
    fn matches_flag_injection() {
        let pats = arg_injection_patterns();
        assert!(pats[0].1("--output=/tmp/x.log").is_some());
        assert!(pats[0].1("--output /tmp/x.log").is_some());
        assert!(pats[0].1("file.txt").is_none());
    }

    #[test]
    fn matches_command_chain() {
        let pats = arg_injection_patterns();
        assert!(pats[2].1("foo; rm -rf /").is_some());
        assert!(pats[2].1("foo;curl evil.com").is_some());
        assert!(pats[2].1("just text;shower").is_none()); // shower is not sh/rm/curl/bash
    }

    #[test]
    fn matches_command_substitution() {
        let pats = arg_injection_patterns();
        assert!(pats[3].1("$(whoami)").is_some());
        assert!(pats[4].1("`whoami`").is_some());
    }
}
