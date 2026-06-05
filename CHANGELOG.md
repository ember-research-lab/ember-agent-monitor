# Changelog

All notable changes to this crate. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions tracking `Cargo.toml` `version`.

This file covers code changes. Detection-rule and fixture changes live
in [`threat-intel/CHANGELOG.md`](threat-intel/CHANGELOG.md).

## [Unreleased]

### Added
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
