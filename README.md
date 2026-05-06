# ember-agent-monitor

Runtime observer for AI coding agents. Sits between the agent and its
API endpoints, builds a structural graph of execution, applies detection
rules — including v2 spectral methods — and intervenes (observe / warn /
block) on findings.

Tool 2 of 4 in the Ember security suite. Open source. Zero dependencies.
`#![forbid(unsafe_code)]`. Auditable in one sitting (~6300 LOC).

## Documents

Read in this order:

- [`design/ember-suite-overview.md`](design/ember-suite-overview.md) —
  the four-tool architecture, the OSS/premium split, and why no single
  tool tries to be the answer.
- [`design/agent-monitor-spec.md`](design/agent-monitor-spec.md) — the
  v1 specification for this tool. Architecture, data model, detection
  rules, intervention semantics.
- [`docs/internal-threat-model.md`](docs/internal-threat-model.md) — the
  disciplines applied to this tool's *own* code (zero-dep, schema
  discipline, output escaping, AI-assisted-development review).
- [`docs/session-graph-contract.md`](docs/session-graph-contract.md) —
  the on-disk contract between this tool and the persistent / network
  consumers.
- [`threat-intel/README.md`](threat-intel/README.md) — the regression
  fixture catalog. Each adopted attack pattern lands here as a fixture
  with pinned expected verdicts.

## Quick start

```bash
# Build
cargo build --release

# Initialize ~/.ember/agent-monitor/
./target/release/ember-agent init

# Run the daemon (proxy on localhost:9452 + file-watcher)
./target/release/ember-agent daemon --mode warn

# In another terminal: point Claude Code (or any Anthropic-protocol
# client) at the proxy:
export ANTHROPIC_BASE_URL=http://localhost:9452
claude   # or your agent of choice

# Inspect findings as they accrue
./target/release/ember-agent findings
```

## Detection layers

- **v0 substrate** — HTTP proxy, file-watcher, append-only event log,
  trust-zone tagging, capability tagging, session graph.
- **v0.5 rules** — sensitive_zone_access, argument_injection_pattern,
  instruction_shape_in_tool_result, instruction_shape_in_mcp_description,
  trigger_cause_violation, classifier_disagreement,
  toxic_capability_composition, lethal_trifecta_reachability,
  high_risk_plugin_composition.
- **v2 spectral** — in-house Jacobi eigendecomposition, Laplacian
  builder, heat-kernel fingerprint, motif catalog (8 attack-shape
  graphs), spectral_anomaly + spectral_motif_match. Calibrated against
  a 5-fixture clean-session corpus.

## Intervention modes

- `observe` — log findings, no rewrite.
- `warn` — forward: inject system-prompt advisory; backward: strip
  dangerous tool_use, substitute refusal text.
- `block` — forward: refuse to forward request; backward: strip
  dangerous tool_use.

Forward warnings are advisory; backward strips are the actual safety
mechanism (a committed model ignores forward-direction prompts).

## Status

- v1 spec deliverables complete.
- 46 unit tests + 11 attack-pattern fixtures + 1 forward-warn integration test.
- 0 false positives on the 5-fixture clean calibration corpus.
- Suite-level integration validated via
  [`../tests/e2e_full_chain.sh`](../tests/e2e_full_chain.sh).

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT License ([`LICENSE-MIT`](LICENSE-MIT))

at your option.
