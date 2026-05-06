# Fixture: ansi_escape_obfuscation

**Class:** ANSI escape obfuscation in tool output
**Source:** Trail-of-Bits research
**Severity:** High (per `expected.json`)

Tool returns visually-clean text but contains hidden instructions inside ANSI conceal sequences (`\x1b[8m`). The terminal renders nothing but the model sees the directive. Caught by the new `ansi-escape obfuscation` instruction-shape pattern.

See the suite-level matrix at `tests/attack-coverage-matrix.md` for how
this rule fits into the broader catalog. Closed during the 2026-05-06
novel-pattern stress test.
