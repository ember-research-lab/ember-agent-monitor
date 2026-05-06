# Threat-Intel — Rule Currency as Process

The agent monitor's detection rules are not a fire-and-forget asset. New
attack patterns surface continuously: prompt-injection variants, MCP
poisoning techniques, novel tool-composition exploits, lateral movement
through skills/hooks. The shipped rule library has to keep pace.

This directory is where that process lives. It has three things:

- **`sources/`** — curated list of feeds we monitor for new attack patterns.
- **`fixtures/`** — canonical synthetic-attack scenarios. Each fixture pins
  an expected detection outcome; CI runs them on every change. A regression
  that drops a finding is a red build.
- **`CHANGELOG.md`** — every change to the rule library, every new fixture,
  every new pattern. Releases reference this file.

## Operating cadence

The discipline is "intel-driven, not feature-driven":

1. New attack pattern surfaces (CVE, blog post, OWASP advisory, internal red-team).
2. Triage to one of three buckets:
   - **Signal addition** — extend an existing rule (new pattern, new toxic
     combination, new sensitive path default).
   - **New fixture** — an attack we *should* catch but don't yet, captured
     as a synthetic regression test even before we ship the rule.
   - **Roadmap item** — out of v1's scope; recorded against the appropriate
     phase (persistent tool, network tool, v2 spectral).
3. Implement, test, document. The fixture must pass before the change merges.
4. Ship via normal release. CHANGELOG entry references the upstream source.

This is the same shape as a defensive antivirus signature pipeline — the
*signatures* (rules) update faster than the *engine* (substrate). v0/v0.5
of the substrate may be stable for months while the rule library iterates
weekly.

## What's NOT here

- Live network access at runtime. The threat-intel pipeline is offline:
  developers monitor sources, hand-curate fixtures, ship via release. The
  agent monitor binary never phones home. (This is non-negotiable per spec
  §10.)
- Auto-generated rules from upstream feeds. Every fixture and every rule
  is hand-reviewed. Automated ingestion of unverified attack signatures
  would itself be an injection vector.

## Adding a fixture

```
threat-intel/fixtures/<short-name>/
├── README.md              — what attack class, what CVE/source, why it matters
├── events.jsonl           — synthetic event stream (Python proxy_emit format)
├── expected.json          — pinned detection output: list of expected finding types
```

The regression runner (`tests/threat_intel_fixtures.rs`) walks every
fixture directory and asserts the detection output matches `expected.json`
exactly. A new fixture without `expected.json` triggers a "fixture
incomplete" error to prevent silent skips.
