# Fixture: inverseprompt_quoted_chain

**Class:** CVE-2025-54795 — quoted-arg semicolon chain
**Source:** Cymulate / InversePrompt
**Severity:** High (per `expected.json`)

An approved tool (e.g. `echo`) is invoked with a quoted argument that contains `;` followed by another command. The argument_injection_pattern matcher now catches semicolon, `&&`, and `||` chains followed by known commands (curl/bash/sh/cat/wget/etc.).

See the suite-level matrix at `tests/attack-coverage-matrix.md` for how
this rule fits into the broader catalog. Closed during the 2026-05-06
novel-pattern stress test.
