# Fixture: git_hooks_write

**Class:** CVE-2025-48384 — git submodule poisoning writes .git/hooks/
**Source:** Datadog / CrowdStrike
**Severity:** High (per `expected.json`)

A malicious `.gitmodules` triggers writes to `.git/hooks/post-checkout` during clone. Sensitive_zone_access now fires because `hooks` is a sensitive component name and `.gitmodules` / `mcp.json` are sensitive filenames.

See the suite-level matrix at `tests/attack-coverage-matrix.md` for how
this rule fits into the broader catalog. Closed during the 2026-05-06
novel-pattern stress test.
