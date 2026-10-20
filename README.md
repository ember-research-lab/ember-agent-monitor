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

### Local llama-server lane (OpenAI-compatible, streaming)

```bash
./target/release/ember-agent daemon --mode observe --upstream-openai http://127.0.0.1:11436
# client base URL: http://127.0.0.1:9452/openai   (adds /v1/chat/completions, /health, /props)
# send  X-Ember-Session-Id: <id>  on requests; then  GET /sessions/<id>  says whether a
# session graph was recorded (200 {events, responses} / 404 no_session).
```

### Run as a user service

A systemd user unit keeps the daemon up across logins and restarts it on failure.
Save as `~/.config/systemd/user/ember-agent-monitor.service`:

```ini
[Unit]
Description=Ember Agent Monitor (proxy on 127.0.0.1:9452 + file-watcher)
After=network-online.target

[Service]
Type=simple
ExecStart=%h/ember-research-lab/ember-agent-monitor/target/release/ember-agent daemon --mode warn --port 9452 --upstream-openai http://127.0.0.1:11436
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload && systemctl --user enable --now ember-agent-monitor.service
curl -s http://127.0.0.1:9452/health          # {"status":"ok","tool":"ember-agent-monitor"}
curl -s http://127.0.0.1:9452/openai/health   # relayed from the local llama-server
journalctl --user -u ember-agent-monitor -f
```

`--upstream-openai` points `/openai/*` at the local llama-server (ember-local); drop it if
you do not use that lane.

## Dogfood (Aaron's Claude Code sessions)

User service `~/.config/systemd/user/ember-agent-monitor.service` runs the daemon in warn mode; the
file-watcher tails `~/.claude/projects/**` (live activity only, not history).

```bash
systemctl --user status ember-agent-monitor          # running?
journalctl --user -u ember-agent-monitor -n 20       # "watcher — events=… malformed=…" tally every 5 min
./target/release/ember-agent status                  # proxy / watch_dir / sessions
./target/release/ember-agent findings                # detector output, incl. watched transcripts
```

Suite wiring: the daemon serves `~/.ember/agent-monitor/events.sock` (tool_calls → `ember-network monitor`, from both the proxy and the file-watcher, each line tagged `source`, one line per `tool_use_id`);
`ember-agent finalize-idle` (run by ember-persistent's ingest timer, see that repo's `contrib/systemd/`)
hands quiet sessions to ember-persistent. In the other direction the daemon reads `~/.ember/{vetpkg,persistent,network}/findings.jsonl`
to raise a session's posture (exec and egress rules bump one severity step, one `posture_elevated` marker); see spec §6.

Claude Code only goes through the proxy if `ANTHROPIC_BASE_URL=http://127.0.0.1:9452` is set in its
environment; without it the watcher is the only view (no intervention, observe/warn findings only).

## Detection layers

- **v0 substrate** — HTTP proxy, file-watcher, append-only event log,
  trust-zone tagging, capability tagging, session graph.
- **v0.5 rules** — sensitive_zone_access, argument_injection_pattern,
  instruction_shape_in_tool_result (incl. tag-decoded hidden text),
  invisible_unicode_in_tool_result, instruction_shape_in_mcp_description,
  trigger_cause_violation, classifier_disagreement,
  toxic_capability_composition, lethal_trifecta_reachability,
  high_risk_plugin_composition.
  `argument_injection_pattern` is tool-class aware and provenance-gated (#45):
  shell chains, `$(..)` and backticks in non-shell tools fire only when the text
  traces to an earlier external tool result. `ember-agent replay --transcript <file>`
  replays a raw Claude Code transcript; `cargo test --release --test benign_budget
  -- --ignored --nocapture` prints each rule's benign FP per 1000 events and fails
  over the pinned budgets.
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
