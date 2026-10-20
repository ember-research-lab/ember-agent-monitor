# shell_injection_patterns

One `Bash` tool_call per shell-class pattern, in order: pipe-to-shell, base64-decode-then-exec, eval-of-fetched-content, claude-config-path, rm-rf-non-temp, sensitive-file-upload, reverse-shell. Each must yield one HIGH `argument_injection_pattern` (the unit tests in `src/detect/patterns.rs` pin which pattern label).
