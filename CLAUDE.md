# CLAUDE.md — ember-agent-monitor

Orientation for anyone (human or Claude) working in this repo. Read this
first; it's the context a fresh session doesn't have. Only state what you
can verify in the source — this file does.

## What this is

A **zero-dependency runtime observer for AI coding agents** (Cargo.toml
`description`). Tool 2 of 4 in the Ember security suite. It sits between an
agent (Claude Code, Codex, Cursor, custom) and its API endpoints as a hybrid
observer: an HTTP proxy on `localhost:9452` (Anthropic / OpenAI-compatible)
plus a file-watcher on `~/.claude/projects/**`. From that vantage it builds a
structural execution graph, applies detection rules (v0.5 pattern rules + v2
spectral methods), and intervenes — `observe` / `warn` / `block`. Binary
`ember-agent`; library `ember_agent_monitor`.

The **egress gate** (`src/egress/mod.rs`, merged in PR #2) is the step past
`Block`: it *holds* an outfacing action (HTTP/SMTP/payment/subprocess)
pending a human decision, then resumes or cancels it — a neutral state
machine (`principal` performs an `OutfacingAction` in a `namespace`). See
`design/egress-gate.md` for why enforcement is consumer-side, not in the LLM
proxy. Scaffold is state machine + tests; `net::proxy`/`store` wiring is TBD.

## Read the design docs in this order

The documented read order (`README.md`, `design/README.md`):

1. `design/ember-suite-overview.md` — the four-tool architecture + OSS/premium
   split. Read first: it explains *why* this tool's scope is what it is.
2. `design/agent-monitor-spec.md` — the v1 spec (scope, trust zones, event
   schema, detection rules §4, intervention §5, constraints §10). The
   implementer's contract; modules cite its section numbers.
3. `design/egress-gate.md` — the hold-and-resume gate design note.
4. `docs/internal-threat-model.md` — disciplines on this tool's *own* code
   (the substrate is trusted by assumption).
5. `docs/session-graph-contract.md` — on-disk contract to persistent + network.
6. `threat-intel/README.md` — the regression-fixture catalog + intel cadence.

(The task brief referenced a `runtime-abstraction.md`; no such file exists
in the repo — the docs above are the actual set.)

## Honest scope — quote the spec, don't overclaim

The spec is deliberate about what this tool is **not** (`agent-monitor-spec.md`
§1 / §7 "Out of scope"):

- **NOT a network tool.** "Network-layer observation. What actually crosses
  the wire after a tool fires is out of scope. The network tool addresses
  this." `ember-network` is the *passive* wire observer behind the gate; it
  does not enforce (`egress-gate.md`).
- **NOT a multi-session / persistent tool.** "Multi-session content
  tracking … out of scope. The persistent tool addresses this."
- **NOT a supply-chain tool (not an EPP).** "Package supply chain … out of
  scope. vetpkg addresses this." A runtime observer, not endpoint protection.
- **Hook *runtime* behavior is out of scope** — only static analysis of hook
  configs at registration is in scope.
- v1 rule detection has a **known evasion ceiling** against adaptive
  attackers with source access; the v2 spectral layer addresses it.

Each gap names the Ember tool that covers it — keep them honest, and don't
grow this tool into another tool's layer.

## House rules (CI enforces — `.github/workflows/ci.yml`)

CI matrix: `{ubuntu-latest, macos-latest} × {stable, 1.75}`. Every job runs:

1. **Zero external dependencies.** `Cargo.toml [dependencies]` MUST be empty
   — CI greps it and fails on any non-comment line. Every primitive (JSON,
   SHA-256, HTTP parse, eigendecomposition, Laplacian) is in-repo. Security
   premise (matches vetpkg), not style. New dep = threat-model update +
   explicit justification (`CONTRIBUTING.md`).
2. **`#![forbid(unsafe_code)]`** at crate root (`src/lib.rs`). No exceptions.
3. **`fmt --check`, `clippy --all-targets --no-deps -- -D warnings`, `build`,
   `test`** all clean (see Commands).
4. Every structured output goes through the JSON writer (`to_json_string`),
   never `format!`. Path-shaped values are normalized before any zone/
   boundary check (substrate-required, spec §2).

**Commit format:** conventional commits, `type(scope): description — detail`
(types: `feat` `fix` `docs` `refactor` `test` `chore`; cf. `CONTRIBUTING.md`
and the log, e.g. `feat(egress): … (#2)`).

## Fixture discipline

Two validation surfaces under `tests/fixtures/`, both kept green:

- **Offline pipeline:** `proxy_emit.py session_cve_chain.jsonl > events.jsonl`
  then `detect.py events.jsonl` — JSONL → event stream → graph → detection;
  the synthetic Cyata CVE chain produces 8 findings.
- **In-line proxy:** `inline_proxy_server.py` + `inline_replay_client.py` —
  live HTTP interception both directions, three intervention modes,
  self-contained mock upstream.

**Regression fixtures** live under `threat-intel/fixtures/<name>/`
(`events.jsonl` + `expected.json` + usually `README.md`). The runner
`tests/threat_intel_fixtures.rs` walks every directory and asserts finding
counts match `expected.json` **exactly** — a dropped *or* unexpected finding
is a red build, and a fixture missing `expected.json` errors rather than
silently skipping. Adding a fixture is a one-directory drop, no test-code
change. Currently 15 fixtures + a 5-session clean calibration corpus
(`threat-intel/calibration/clean_corpus/`).

**Honest-negative fixtures.** `spectral_clean_pipeline/` pins a case the
v0.5 pattern rules *deliberately miss* (read → transform → webfetch, each
step innocent; only the graph SHAPE trips `spectral_motif_match`). Its final
`webfetch` egress is exactly the wire-level signal whose catch surface is
**ember-network**, not this tool — the fixture proves the spectral layer
sees structure where the per-string rules, by design, see nothing. Don't
"fix" these into pattern hits; that erases the scope line.

New rule? Land it as a `threat-intel` fixture with pinned verdict (+ a
`threat-intel/CHANGELOG.md` entry citing the source), not an inline test.

## Commands

```sh
cargo build --release
cargo test                                          # unit + fixtures + integration
cargo fmt --all -- --check                          # CI bar
cargo clippy --all-targets --no-deps -- -D warnings # CI bar

# run the tool (subcommands: init|daemon|status|findings|replay|calibrate)
./target/release/ember-agent init                   # ~/.ember/agent-monitor/
./target/release/ember-agent daemon --mode warn     # proxy :9452 + file-watcher
# point an agent at it:  export ANTHROPIC_BASE_URL=http://localhost:9452

# offline validation (Python, stdlib only); in-line: inline_proxy_server.py warn
python3 tests/fixtures/proxy_emit.py tests/fixtures/session_cve_chain.jsonl > /tmp/events.jsonl
python3 tests/fixtures/detect.py /tmp/events.jsonl
```
