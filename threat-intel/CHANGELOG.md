# Threat-Intel Changelog

All changes to the shipped rule library, attack-pattern catalog, or
fixture set are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions tracking the package's `Cargo.toml` `version`.

## [Unreleased]

### Added — 2026-05-06 novel-pattern stress test
- **5 new fixtures** from a research pass over 2025-2026 AI agent CVEs:
  - `ansi_escape_obfuscation` — Trail-of-Bits ANSI conceal-in-tool-output
  - `inverseprompt_quoted_chain` — CVE-2025-54795 quoted-arg semicolon
  - `curxecute_mcp_rewrite` — CVE-2025-54135 external-driven mcp.json write
  - `git_hooks_write` — CVE-2025-48384 submodule → .git/hooks
  - `line_jumping_initial_tools_list` — TrailOfBits initial tools/list injection
- **Default sensitive set extended** (covers CVE-2025-48384 +
  CVE-2025-54135 + CVE-2025-59536): `.cursor/`, `.claude/` component,
  `hooks` component (catches `.git/hooks/*`), `.gitmodules`, `mcp.json`,
  `mcp_servers.json`, `settings.json` filenames.
- **`ansi-escape obfuscation`** added to `instruction_patterns`: detects
  `\x1b[8m` (conceal), cursor-hide, line-erase, and lone `\r`-overwrite.
- **`argument_injection_pattern` chain matcher** extended to cover `&&`
  and `||` in addition to `;`, and to recognize `wget`, `cat`, `nc`,
  `python`, `perl`, `ruby` as the trailing command.
- **`spectral_motif_match` size-guard** added: motifs only match when
  the session has at most 2x the motif's node count. Eliminated a class
  of false positives on long legitimate dev workflows where path-graph
  eigenvalues happened to coincide with smaller motif spectra.

False-positive sweep across the 5-fixture clean calibration corpus
returns ZERO findings under the updated rule set. True-positive sweep
across all 11 attack fixtures matches pinned expected output exactly.

### Added — fixtures
- `cyata_mcp_git_rce` — synthetic Cyata 2026 RCE chain (CVE-2025-68143/144/145)
  via mcp-server-git. Indirect prompt injection initiating `repo_init` +
  `file_write_via_filter` toxic composition. 8 expected findings: 1 toxic
  capability composition, 3 sensitive zone access, 1 argument injection,
  3 instruction shape in tool result.

### Added — patterns
- Instruction-shape: SYSTEM_NOTE/SYSTEM NOTE, "the assistant must",
  uppercase "you MUST", `<!-- SYSTEM`, "important: ignore", chat-template
  injection (`<|im_start|>`).
- Argument-injection: `--output=`/`--output ` flag, `--exec=`/`--exec ` flag,
  command-chain `;<ws>(rm|curl|bash|sh)`, `$(...)` substitution, backtick
  substitution.

### Added — toxic combinations
- `repo_init + file_write` (Cyata RCE primitive)
- `credential_access + network_out` (single-step exfil)
- `file_read + network_out` (lethal-trifecta gating; medium severity)

### Added — spectral (v2)
- `spectral_anomaly` rule: heat-kernel + Fiedler + spectral-dimension
  envelope deviation against a configurable baseline.
- `spectral_motif_match` rule: subgraph spectrum match against a
  catalog of 8 attack-shape graphs (3-path, 4-path, 3-star, 5-star,
  triangle, 4-cycle, K_{2,2} bipartite, Y-fork).
- Fixture `spectral_clean_pipeline` — exfiltration pipeline with no
  v0.5 pattern trips; verifies the v2 layer sees graph shape where
  v0.5 sees only strings.
- In-house symmetric eigendecomposition (Jacobi rotation), zero-dep
  Laplacian builder (combinatorial + normalized symmetric variants),
  heat-kernel distance + Davis-Kahan stability ratio.
- Calibration corpus at `threat-intel/calibration/clean_corpus/` —
  five typical-session shapes (edit-test loop, debug-explore,
  research-and-writeup, multi-edit refactor, pure conversation).
  Default baseline now ships calibrated from this corpus; was
  hand-set in initial v2 commit.

## How to amend

When adding a rule, pattern, fixture, or toxic combination:

1. Add the implementation under `src/detect/`.
2. Add or extend a fixture under `threat-intel/fixtures/`.
3. Pin expected findings in the fixture's `expected.json`.
4. Add a CHANGELOG entry under `[Unreleased]` with the source citation.
5. Bump version in `Cargo.toml` only at release time.

Releases include a "what new attack patterns this version catches" section
generated from the moved-to-released entries.
