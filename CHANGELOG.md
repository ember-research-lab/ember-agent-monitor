# Changelog

All notable changes to this crate. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions tracking `Cargo.toml` `version`.

This file covers code changes. Detection-rule and fixture changes live
in [`threat-intel/CHANGELOG.md`](threat-intel/CHANGELOG.md).

## [Unreleased]

### Fixed
- **Proxy 404'd Claude Code's `POST /v1/messages?beta=true` (#58).** Routes now match on the URI path only (`proto::path_only`); the
  original query string is forwarded upstream unchanged (Anthropic `upstream_path` previously hard-coded `/v1/messages`). Same for
  OpenAI routes and `/health`. Tests: proto unit tests and `tests/claude_code_request_shape.rs` (mock upstream, exact header shape).

### Added
- **`instruction_directive_in_tool_result` (MEDIUM, #42).** Scores untrusted tool output for *directive shape* (request verb plus
  first-person or destination cues, override of earlier instructions, role claims, concealment, tool-invocation requests) instead of
  literal markers. Local file/shell/subagent tool output is discounted.
- **Benchmark harness (#42).** Converters for InjecAgent, AgentDojo, BIPIA, Open-Prompt-Injection, ASB and LLMail-Inject, 3-case offline
  fixtures, and an `#[ignore]` full-corpus run with a 70/30 split and a benign-transcript FP replay. See `tests/bench/README.md`.
### Added (class guard, #45)
- **`replay --transcript <path>`.** Replays a raw Claude Code transcript through the detectors using the watcher's adapter (pattern rules;
  the spectral layer is skipped because it is cubic in session events). Without the flag `replay` still takes a monitor event log.
- **Per-rule benign FP budget.** `cargo test --release --test benign_budget -- --ignored --nocapture` replays `~/.claude/projects` plus the
  benign fixtures, prints each rule's FP per 1000 events and fails when a pinned budget is exceeded (rules without a budget default to
  1.0/1000) or when a shell chain / `$(..)` in a shell tool or a backtick in a prose tool fires at all. The replay code moved from
  `bench_full.rs` into `tests/bench_support/`.
### Changed (severity follows actor, path class and tool class; fixes #52 #53 #54)
- **`claude-config-path` is HIGH only for a subagent or provenance (#52).** The shell-list label stays HIGH when the event carries
  `is_sidechain` or a path token of the command appears in an earlier external tool result (the #45 gate); otherwise MEDIUM. A MEDIUM
  `claude-config-path` no longer hides a dangerous label matching the same argument. `rm-rf-non-temp` unchanged (see the premise note in
  the PR: the benign hits are `$VAR` and relative targets, not literal `/tmp/claude-<uid>/` paths, which `/tmp/` already allowlists).
- **`sensitive_zone_access` splits the `.claude` component (#53).** MEDIUM for `charters/`, `memory/`, `projects/`, `worktrees/`; HIGH for
  config, executable or permission-bearing paths and every unlisted subdirectory. `memory_write_by_subagent` untouched.
- **`multimodal_in_tool_result` fires only for external-tool results, at MEDIUM (#54).** Local tools (`Read`, screenshots) are silent.
- **`benign_budget` pins HIGH-only ceilings** per rule and a combined HIGH ceiling. Benign replay (133,613 events): HIGH per 1000
  `argument_injection_pattern` 8.84 -> 5.11, `sensitive_zone_access` 46.30 -> 12.61, `multimodal_in_tool_result` 8.37 -> 0.00;
  combined HIGH, all rules, 63.9 -> 18.14.
### Fixed
- **`argument_injection_pattern` is provenance-gated for non-shell tools (#45, refs #26, #39).** A shell chain (`;`/`&&`/`||` + command),
  `$(..)` or backticks in a non-shell tool's argument now fires only when the matched span (>= 8 bytes, whitespace-collapsed) also
  appears in an earlier tool result of the same session produced by an external tool (web, mail, MCP, unknown; last 256 events).
  Markdown backticks in prose tools (`Agent`, `Task`, `SendMessage`, `SubagentHandback`, `Artifact`, ...) never count. Flag injection and
  the whole shell-tool list (pipe-to-shell, base64-exec, eval-of-fetched, `.claude` config path, `rm -rf`, upload, reverse shell) are
  unchanged. Benign replay of `~/.claude/projects` (~133k events): 35.45 -> 8.82 `argument_injection_pattern` per 1000 events; the
  residual is the shell-tool list (`claude-config-path`, `rm-rf-non-temp`), tracked separately.
- **Detector no longer panics on real tool output (#47).** The clickfix `open-terminal-and-run` window sliced a byte range that could
  end inside a multibyte character, and `find_command_chain` indexed one past the end on a trailing `|`. Both found by replaying
  real transcripts; regression tests added.
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
