# Contributing

This crate is part of the Ember security suite. Contribution discipline
is shared across all four tools — see the per-tool
`docs/internal-threat-model.md` for the AI-assisted-development review
requirements.

## Code discipline

- Zero Cargo dependencies. Empty `[dependencies]` is enforced by
  convention; PRs that add a dep need explicit justification + threat-
  model update.
- `#![forbid(unsafe_code)]` at crate root. Platform FFI modules (kernel
  hooks for ember-network) are the only exception, and are gated by
  feature flag.
- Every JSON output goes through `to_json_string`. Never `format!` for
  structured output.
- Path-shaped values are normalized before any zone or boundary check.

## Threat-intel pipeline

New attack patterns land as fixtures under `threat-intel/fixtures/`,
not as inline tests. Pin expected verdicts. CHANGELOG entry under
`threat-intel/CHANGELOG.md` cites the source.

A regression that drops a pinned finding is a red CI build.

## Commit messages

Conventional commits: `feat(scope): ...`, `fix(scope): ...`,
`docs(scope): ...`, `refactor(scope): ...`, `test(scope): ...`.
