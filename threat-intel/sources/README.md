# Monitored Sources

Curated list of feeds, advisories, and research streams that the
threat-intel triage process monitors for new attack patterns.

This is a living list. Add new sources via PR; remove sources that have
gone dark. Each entry has a one-line rationale so future maintainers know
why it's on the list.

## Vulnerability databases (high-signal, structured)

- **OSV** — `https://osv.dev/list?ecosystem=PyPI&q=mcp` and equivalent for
  npm. Fastest source for package-level CVEs that affect the agent
  ecosystem.
- **GitHub Security Advisories** — `https://github.com/advisories?query=mcp`
  and `query=ai-agent`. Often include reproduction notes that translate
  directly to fixtures.
- **Snyk Vulnerability DB** — `https://security.snyk.io/`. Useful cross-check
  but not authoritative; verify against OSV/GHSA before adding fixtures.

## Research labs (high-signal, narrative)

- **Invariant Labs blog** — `https://invariantlabs.ai/blog`. Original
  source for many MCP poisoning patterns including the toxic-flow research.
- **Cyata research** — public disclosures around CVE-2025-68143 and the
  mcp-server-git RCE chain.
- **Embrace the Red** — `https://embracethered.com/blog/`. Long-running
  prompt-injection research, useful for understanding evasion patterns.
- **Simon Willison's Weblog** — `https://simonwillison.net/`. High-quality
  ongoing commentary on prompt injection in the wild.

## Standards / advisories

- **OWASP MCP Top 10** — once it stabilizes, every category gets at least
  one fixture. Update fixtures when OWASP revises the list.
- **OWASP LLM Top 10** — broader scope; relevant categories (LLM01, LLM06,
  LLM08) inform agent monitor rules.

## Internal sources

- **Issue tracker** — `internal/threat-intel` label. Anything we discover
  ourselves (red-team exercises, customer reports, dogfooding) starts here.
- **vetpkg findings stream** — high-confidence advisories from vetpkg's
  install-time scanner are inputs to our integration layer (spec §6).

## Process

Each PR that adds a fixture or rule cites at least one source from this
list (or a new one with rationale). "Source: internal" is acceptable but
must reference an issue.

CHANGELOG.md aggregates these citations at release time.
