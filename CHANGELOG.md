# Changelog

All notable changes to this crate. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions tracking `Cargo.toml` `version`.

This file covers code changes. Detection-rule and fixture changes live
in [`threat-intel/CHANGELOG.md`](threat-intel/CHANGELOG.md).

## [Unreleased]

### Added
- **Benchmark harness (#42).** Converters for InjecAgent, AgentDojo, BIPIA, Open-Prompt-Injection, ASB and LLMail-Inject, 3-case offline
  fixtures, and an `#[ignore]` full-corpus run with a 70/30 split and a benign-transcript FP replay. See `tests/bench/README.md`.
### Fixed
- **`argument_injection_pattern` no longer fires HIGH on benign shell commands (#26).** The rule is tool-class
  aware: shell tools (`Bash`, names containing `shell`/`exec`) get their own pattern list (pipe-to-shell,
  base64-decode-then-exec, eval of fetched content, Claude config paths, `rm -rf` on non-temp paths,
  credential-file upload, reverse shells); `&&`, `;`, `|`, backticks, `$(..)` and heredocs are no longer signals
  for them. Other tools keep the old list. In `warn` mode the proxy would have stripped most `Bash` calls.
- **`events.sock` tool_calls are tagged and de-duplicated (#35).** Watcher-derived tool_calls (transcripts
  read with Claude Code not routed through the proxy) are broadcast on `events.sock` in the same line shape as
  proxy-derived ones, now with an additive top-level `source: "watcher" | "proxy"`. A `tool_use_id` is
  broadcast once even when a session is both proxied and watched (bounded 4096-entry FIFO, no new crate).
  A daemon started before #29 never bound the socket: restart it to pick this up.
- **File-watcher watched nothing on a real Claude Code tree.** It only looked at the spec's
  `<project>/sessions/*.jsonl`, which Claude Code does not write; real transcripts are
  `<project>/<session>.jsonl` and `<project>/<session>/subagents/agent-*.jsonl`. It also dropped every
  transcript line silently (not monitor-event shaped), ran no detectors, replayed from byte 0, could
  consume a half-written line, and a failed event-log open panicked the thread. Now: all three layouts,
  Claude Code `user`/`assistant` records converted through the Anthropic parser (tool_result stays
  distinct from user_prompt) and run through the same record + detect path as proxy events, tail-from-EOF
  for pre-existing files, complete lines only, and stderr (journal) lines for poll errors, malformed
  lines and a 5-minute event/ignored/malformed tally.

### Added
- **`memory_write_by_subagent` rule (#32).** HIGH when a write/edit tool_call on a memory-class path comes from
  an event with non-empty `agent_id` (needs #30). Path list pinned in `detect::memory_paths`, a lock-step copy
  of ember-persistent's `MEMORY_CLASS_PATHS`.
- **Transcript events carry `agent_id`, `is_sidechain`, `uuid` (#30).** Additive body fields from the
  transcript's `agentId` / `isSidechain` / `uuid`, so persistent and the per-session rules can attribute events
  to a subagent. `watcher::TRANSCRIPT_FIELDS` records every transcript field as carried, consumed or dropped;
  a test fails on an unlisted field.
- **Session posture from sibling findings (#27, #31).** `~/.ember/vetpkg/findings.jsonl` (a WARN-or-higher package
  installed or imported in the session), `~/.ember/persistent/findings.jsonl` (HIGH finding for the session's
  workspace; schema v2 only, others refused and counted loudly) and `~/.ember/network/findings.jsonl` (HIGH
  finding for the session) raise the session's posture: exec and egress rule findings bump one severity step and
  one MEDIUM `posture_elevated` marker (source file + reason) is emitted once. `integrate::VetpkgFindings` now has
  a caller, counts unreadable lines, and the session summary's `vetpkg_packages_seen` is populated. New
  `src/posture.rs`; `DetectionConfig.posture` is `None` by default (fixtures unchanged), set by the daemon and
  `finalize-session`.
- **InjecAgent real-corpus harness, commit-pinned (#17).** `tests/injecagent_pinned.rs` (`#[ignore]`, CI stays offline)
  fetches DH/DS base and enhanced cases at upstream f19c9f2, verifies SHA-256, runs every case and prints
  detection counts plus a false-negative list. Result: 0 / 2108 detected (see `tests/INJECAGENT.md`; follow-up #42).
- **`events.sock` is now actually served** (`ProxyContext` binds `<data_dir>/events.sock` and broadcasts every
  recorded `tool_call`; it was specified in §6 and implemented in `net::socket` but never instantiated, so
  `ember-network subscribe/monitor` could not connect). A bind failure is reported on stderr at startup.
- **`ember-agent finalize-idle [--idle-secs N]`** writes `<sid>.summary.json` for sessions quiet for N seconds
  (default 600) whose summary is missing/stale. Watched Claude Code sessions never emit `session_end`, so
  without this ember-persistent never receives them. Exits non-zero if any session fails.
- Watched transcripts get a synthesized `session_start` carrying `cwd` / `git_branch` / `model`, so the
  summary's `cwd` (ember-persistent's workspace key) is real instead of empty.
### Added
- docs: README "Run as a user service" — systemd user unit running `daemon --mode warn` with the
  `/openai` upstream pointed at the local llama-server.

### Changed
- CI: every job has `timeout-minutes` (whale-signal#258).

### Added
- **OpenAI-compatible local-lane pass-through (`net::openai_pass`).** `POST /openai/v1/chat/completions`
  is now relayed *streaming* (SSE included, chunk framing stripped, upstream status passed through, a
  client hang-up kills the upstream curl so generation stops) instead of buffered. `GET /openai/health`
  and `GET /openai/props` relay to the upstream's `/health` and `/props` (llama-server). Each exchange
  is recorded in the session graph: request events as before, plus one `model_text` event with
  `direction=response`, model, prompt/completion tokens, finish reason, latency, upstream status
  (also recorded when the upstream is unreachable: 502). `GET /sessions/<id>` reports whether a session
  exists (`{events, responses}` or 404 `no_session`); replies echo `X-Ember-Session`. Session id comes
  from the existing `x-ember-session-id` header. Configure with `--upstream-openai http://127.0.0.1:11436`
  and point the client at `http://127.0.0.1:9452/openai`. Response-side analysis is observe-only;
  tool calls in replies are not interpreted. Bound to 127.0.0.1 as before. Tests: `tests/local_lane.rs`.
  (ember-local#1)
- **`invisible_unicode_in_tool_result` rule (MEDIUM).** Flags untrusted tool output carrying
  invisible/format codepoints: Unicode tag characters (outside the three RGI flag tag sequences;
  fake or unterminated flags count), the private-use ASCII-shift band plus supplementary
  private-use planes, bidi overrides/isolates, zero-width. ZWJ/ZWNJ, a BOM at a line start,
  bidi embeddings, icon-font private use and variation selectors are excluded.
  - This is the carrier of the GLOSSOPETRAE cross-family covert channel (June 2026).
  - `instruction_shape_in_tool_result` and `instruction_shape_in_mcp_description` now also rescan
    text hidden as shifted ASCII (pattern prefixes `tag-hidden:` / `pua-hidden:`).
  - Known gaps: variation-selector and ZWJ/ZWNJ binary stego; tool-call arguments, user prompts and
    model output are not scanned.
  - Fixtures: `glossopetrae_tag_char_covert_jun2026` (now caught), `glossopetrae_semantic_stego_jun2026`
    (honest negative; a codepoint pass cannot see it), `unicode_tag_flag_emoji_benign` (false-positive control).
- **`agent_as_intermediary_clickfix` rule (severity HIGH).** New attack
  class per corpus extension §3.1: tool-result content socially
  engineers the *user* (via the agent) rather than injecting the model.
  Conservative pattern set for v1.5: `base64-decode-to-shell`,
  `powershell-iex-download`, `powershell-encoded-command` (with ≥8-char
  payload check), `open-terminal-and-run` (proximity-windowed match
  for "open <shell>" + "and run/paste/enter"). `curl ... | sh` is
  intentionally NOT in v1.5 — too many legit installers ship that
  pattern; tracked for v1.6 with a destination-allowlist
  discriminator. New fixture `clawhavoc_clickfix_jan2026` pins
  2× HIGH findings + 2× spectral signals against a malicious skill
  metadata sample modelled from Koi Security / BulwarkAI / Trend Micro
  Feb 2026 disclosures.
- **Model-agnostic protocol layer.** `proto::Protocol` enum routes by URL
  path (`/v1/messages` → Anthropic; `/openai/v1/chat/completions` and
  `/openai/v1/responses` → OpenAI). All detection rules and spectral
  motifs operate on the shared internal `Event` type, so they apply
  identically to both protocols. `proto::openai` is the new parser:
  Chat Completions + Responses API, `role: tool` → `UntrustedToolOutput`
  schema-discipline invariant preserved across vendors. Coverage:
  Anthropic + OpenAI together = ~95% of the commercial + local-model
  ecosystem (OpenAI, Codex, Gemini via `/v1beta/openai/`, xAI Grok,
  Mistral, Together, Fireworks, Groq, Azure OpenAI, Ollama, llama.cpp).
- New rule `protocol_mismatch_attempt` (severity MEDIUM) — fires when a
  request body's shape disagrees with the path's protocol (Anthropic
  body to OpenAI path, polyglot bodies, etc.). Catches probing for
  parser-confusion attacks even when the parse itself fails.
- Daemon flags `--upstream-anthropic <URL>` and `--upstream-openai <URL>`.
- `integrity` module: hash-pinned file watcher. Daemon flag
  `--integrity-manifest <path>` enables a background thread that hashes a
  fixed manifest of files (sha256 + path) and emits
  `frozen_file_modification` findings (severity HIGH) on drift, missing
  file, or unreadable file. Findings flow under the sentinel session id
  `__integrity__`. Stat-based fast path skips re-hashing when size and
  mtime are unchanged; periodic forced re-hash (~1/min at the 250 ms
  tick) defends against stat-preserving tampers. Same-tamper fires once;
  a different tamper hash reopens the firing path. Designed for the
  Ember presence agent's `chmod 444` workspace files; generalises to any
  caller wanting a frozen manifest enforced.

## [0.1.0] — Unreleased

Initial commit. See `design/spec.md` for the architecture and the
threat-intel/CHANGELOG for rule + fixture history.
