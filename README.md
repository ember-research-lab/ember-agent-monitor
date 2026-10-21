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
./target/release/ember-agent daemon --mode observe

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
ExecStart=%h/ember-research-lab/ember-agent-monitor/target/release/ember-agent daemon --mode observe --port 9452 --upstream-openai http://127.0.0.1:11436
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

### Local-model Anthropic route (#74)

Headless `claude -p` workers on a local model (ember-local "Route B") speak the Anthropic Messages
wire format to a llama-server's `/v1/messages`. To keep them in the monitor like every other session,
give the daemon the llama-server URL:

```
ember-agent daemon --mode observe --port 9452 \
  --upstream-openai http://127.0.0.1:11436 \
  --upstream-local-anthropic http://127.0.0.1:11436
```

The worker sets `ANTHROPIC_BASE_URL=http://127.0.0.1:9452/local` (Claude Code appends `/v1/messages?beta=true`).

- **Selection is the exact path `/local/v1/messages`** (query kept, `/local` stripped upstream). Nothing else
  reaches the local upstream, and `/v1/messages` still goes only to `--upstream-anthropic`
  (default `https://api.anthropic.com`). `/local/v1/messages/x`, `/local/v1/../v1/messages` etc. are 404.
- **Fail-closed.** Without `--upstream-local-anthropic` the route answers `503 ember_local_route_unconfigured`; with an
  unreachable upstream it answers `502`. Neither ever falls back to Anthropic, so a "local" job cannot bill the cloud.
- Recording, SSE passthrough and detection are the Anthropic lane's, session ids are `anon-anthropic-local-*` when no
  `x-claude-session-id` is sent. Warn/block are refused for streams exactly as for the cloud lane (#60); the daemon
  currently starts in `observe` only.

## Claude Code compatibility gate and install (#64)

Claude Code is the primary client, so it is tested as a real binary, not as a belief about its requests.

- **Real-client e2e** (`tests/claude_code_e2e.rs`): runs the installed `claude -p` (scrubbed env, scratch `HOME`/`CLAUDE_CONFIG_DIR`,
  dummy credentials) through the proxy to a mock Anthropic upstream; asserts `ok`, no `API Error`, `POST /v1/messages?beta=true` with
  `anthropic-beta`/`anthropic-version`/auth intact, the SSE reply, and that an upstream 400 fails the run. Covers `ANTHROPIC_API_KEY`
  (`x-api-key`), `ANTHROPIC_AUTH_TOKEN` (`authorization: Bearer`), `--model fable|opus` and `--output-format stream-json`. Findings:
  `-p` always sends `stream:true`; no login is needed when the mock answers. CI installs a **pinned** Claude Code (`ci.yml`) and
  prints `claude --version`; with `CI=true` a missing binary fails the tests. Locally an absent binary prints a loud SKIP.
- **Wire capture** (`tests/fixtures/claude-code/<version>/`): the real request (headers + body, secrets redacted) replayed by
  `claude_code_request_shape.rs` and `anthropic_forwarding.rs`. A newer installed `claude` than the newest fixture prints a warning;
  `just capture-claude-code` refreshes it.
- **Other harnesses** (`tests/harness_e2e.rs`): the same contract for Codex CLI (`codex exec`, Responses API via `/openai/v1`), OpenCode
  (`opencode run`, Anthropic provider) and Pi (`pi -p`, Anthropic provider): scrubbed env, scratch `HOME`, mock upstream, `ok` reply, wire
  line/auth/stream asserted, upstream 400 must fail. CI pins Codex 0.163.0, OpenCode 1.19.3, Pi 0.73.1; a different version fails under
  `CI=true` and warns locally. No wire-capture fixtures for these yet (Claude Code only).
- **`just gate`**: fmt + clippy + the compat tests with `CI=true`. Mandatory before merging any proxy change.
- **`just install`** (`scripts/install.sh`) is the only sanctioned way to put a build live: it keeps the running binary as
  `<bin>.prev`, builds, restarts the unit, and requires `claude -p` to answer `ok` for `fable` and `opus` through the live port; on any
  failure it reinstalls `.prev`, restarts, and exits non-zero. Override `UNIT`/`PORT`/`BIN`/`BUILD_CMD` only to test the script against a
  throwaway unit.

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

**Before adding `ANTHROPIC_BASE_URL`:** Claude Code reads `env` from `settings.json` live, so a broken proxy kills the *running*
session (any non-2xx from the messages endpoint is shown as "the selected model may not exist"). Run the acceptance check first,
with the env var on the command line only, and expect `ok`:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:9452 claude -p "reply with the single word ok" --model opus
```

Claude Code posts `/v1/messages?beta=true`; the proxy routes on the path only and forwards the query upstream unchanged
(regression test: `tests/claude_code_request_shape.rs`, #58).

**What the Anthropic forwarder relays (#60).** The proxy forwards through `curl -i` and hands the client the upstream's own status,
status text and headers (`request-id`, `retry-after`, `anthropic-ratelimit-*`, ...) minus hop-by-hop ones; a 401/429/529 stays a
401/429/529, so Claude Code's auth and backoff logic works. `accept-encoding` is **stripped** on the way upstream so replies are
plaintext for inspection; the cost is uncompressed replies (larger on the wire, loopback-to-curl-to-Anthropic only). If an upstream
compresses anyway, header and bytes pass through unchanged (observe) or the request fails with a 502 naming #60 (warn/block, which
cannot inspect or strip bytes they cannot read).

| Anthropic reply shape | observe | warn / block |
| --- | --- | --- |
| JSON (`stream` absent/false), any status | relayed, tool_use/text analysed, findings logged | relayed, dangerous `tool_use` blocks stripped |
| `stream: true` (SSE) | passed through chunked as it arrives; events inspected in flight (findings only, never rewritten) | **not supported**: `ember-agent daemon --mode warn\|block` refuses to start, and a library `serve` answers `stream:true` with 501 `ember_unsupported`, both naming #60 |
| Upstream `Content-Encoding` despite stripped `accept-encoding` | passed through untouched, uninspected | 502 naming #60 |

Warn/block need a stream-aware strip (buffering would defeat streaming and a silent pass-through would defeat the mode); until that
lands run `--mode observe`. Tests: `tests/anthropic_forwarding.rs`.

## Cost accounting

`ember-agent cost [--since YYYY-MM-DD] [--session ID] [--by model|actor|project|session|day|week] [--json] [--strict]` totals tokens
and **list-price** cost from the `usage` block of every assistant message in `~/.claude/projects/**` (top-level sessions and
`subagents/*.jsonl`; actor = `subagent` for those files or `isSidechain`, else `driver`). Local file reads only.

- **Prices** are pinned in [`prices.toml`](prices.toml) (compiled in; `--prices FILE` overrides) with `valid_from`, `reviewed_until`
  and the source path. Every table prints the dates. A message dated after `reviewed_until` prints a `STALE PRICES` warning.
- **Unknown model = `UNPRICED`**, excluded from the dollar total and called out on stderr; `--strict` exits 3. Aliases (`opus`) are not guessed;
  a dated id (`-20251001`) and `[1m]` are normalised to the base id.
- **One message, counted once.** Claude Code writes one transcript line per content block, each repeating `usage`. Lines are keyed on
  `message.id` and the largest value of each field is kept (only `output_tokens` grows). Counting lines instead overstates the total 2.4x since 2026-10-20 (up to 7x on one session).
- A `cache_creation` object splits 5-minute and 1-hour writes; an unsplit total is priced as 5-minute. `<synthetic>` all-zero messages are skipped.
- Known understatement: `claude-haiku-5-5` is dearer above 100K prompt tokens; the table applies the lower rate throughout.
- The daemon's watcher rewrites `<data-dir>/cost-rollup.json` (last 8 days, by day and by model) every 5 minutes.

**This is not a bill.** A subscription (Claude Code Pro/Max) is metered against a rolling usage limit, not per token, so list-price
dollars say what the same tokens would cost on the API, nothing about what you pay. The `[pace] weekly N% used` hook reads
`~/.claude/usage-log.jsonl` (percent of the subscription limit, reported by Claude Code) and parses no tokens, so the two cannot be
converted into one another; it is the limit signal, this command is the volume and mix signal. Reconciliation on 2026-10-20 is in the
PR for #63.

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
  over the pinned budgets (all-severity and HIGH-only per rule, plus a combined
  HIGH ceiling).
  Severity follows actor, path class and tool class (#52-#54): `claude-config-path`
  is HIGH only for a subagent (`is_sidechain`) or a path that traces to external
  tool output, else MEDIUM; `sensitive_zone_access` is MEDIUM for the driver's own
  `.claude` data (`charters/`, `memory/`, `projects/`, `worktrees/`) and HIGH for
  config and anything executable or permission-bearing; `multimodal_in_tool_result`
  fires only for external-tool results (web, mail, MCP, unknown), at MEDIUM.
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
