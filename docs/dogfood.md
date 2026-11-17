This page describes the lab's own setup and is an example, not a required configuration.

# Dogfood (the lab's own sessions)

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
