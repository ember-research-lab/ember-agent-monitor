# Runtime Abstraction — making agent-monitor agent-agnostic

**Status:** Design, pre-implementation. Targets agent-monitor v1.6.
**Companion docs:** `design/ember-suite-overview.md`, `design/agent-monitor-spec.md`, `src/proto/mod.rs`.

---

## 1. Why

agent-monitor v1.5 is **model-agnostic** at the wire layer (Anthropic + OpenAI parsers behind a `Protocol` enum). It is NOT yet **agent-runtime-agnostic**: several invariants assume Claude Code's runtime conventions:

- **Session id**: derived from `x-claude-session-id` HTTP header
- **File-watcher**: walks `~/.claude/projects/<dir>/sessions/<id>.jsonl`
- **Static-graph events** (mcp_registration, hook_registration, skill_load, plugin_install): parsed from the Claude Code session-log JSONL format
- **Workspace integrity manifest**: paths assume the operator's chosen layout, but the *concept* of a "frozen workspace" maps to Claude Code + OpenClaw cleanly and not to Hermes at all

The Ember suite's market thesis is that a security tool must work against *whatever agent the operator runs*. Single-runtime coupling is a regression on that thesis.

This document specifies the runtime adapter layer — how to keep the rule engine, spectral motifs, and findings store untouched while letting the same proxy serve three (and eventually more) different agent runtimes.

## 2. The three runtimes (v1.6 baseline)

Per the May 2026 research pass:

| Runtime | Vendor | Wire protocol(s) | Session id | Workspace layout | Static-graph source |
|---|---|---|---|---|---|
| **Claude Code** | Anthropic | Anthropic Messages API (`/v1/messages`) | `x-claude-session-id` HTTP header | `~/.claude/projects/<dir>/` ; loose convention | `~/.claude/projects/<dir>/sessions/<id>.jsonl` |
| **OpenClaw** | Peter Steinberger / OpenClaw Foundation | OpenAI Chat Completions + OpenResponses (default); Anthropic via provider config | **No HTTP header.** Sessions filesystem-rooted at `~/.openclaw/agents/<agentId>/sessions/<id>/` | Bootstrap files: SOUL.md, AGENTS.md, IDENTITY.md, USER.md, TOOLS.md, HEARTBEAT.md, MEMORY/ | Format unconfirmed at this design stage; probe at install |
| **Hermes Agent** | Nous Research | Provider-pluggable LLM upstream | `session_id` inside JSON-RPC payloads / hook contexts; **not** in HTTP headers | No mandated frozen files; settings in `~/.hermes/config.yaml` | `~/.hermes/sessions/<id>.jsonl` + `~/.hermes/sessions/sessions.json` index + plugin hooks |

The structural shapes that diverge:

- **Where session-id lives** — header vs filesystem vs internal RPC payload
- **Where session events live** — JSONL on disk in three different directories with three different schemas
- **Whether there's a "bootstrap" surface** — yes for Claude Code/OpenClaw, no for Hermes
- **Whether the runtime offers a hook API the suite can register against** — yes for Hermes (rich), implicit for the others

## 3. Design — `Runtime` enum sitting above `Protocol`

```
agent-monitor proxy / watcher
        │
        ▼
   ┌─────────────┐         ┌──────────────────────────────┐
   │  Runtime    │  picks  │  Protocol  (Anthropic|OpenAI) │
   │  (CC/OC/HE) │ ───────►│  + parser + intervention      │
   └─────────────┘         └──────────────────────────────┘
        │
        │  defines
        ▼
   ┌───────────────────────────────────┐
   │  RuntimeAdapter trait             │
   │   ┌────────────────────────────┐  │
   │   │ session_id_for(req)        │  │
   │   │ workspace_root_default()   │  │
   │   │ session_log_paths()        │  │
   │   │ parse_session_log(line)    │  │
   │   │ frozen_files_default()     │  │
   │   │ register_hooks(...)        │  │
   │   └────────────────────────────┘  │
   └───────────────────────────────────┘
```

**Key invariant:** `Protocol` (wire-level) is orthogonal to `Runtime` (agent-level). OpenClaw can use either Anthropic or OpenAI protocol; Hermes can use either; the runtime adapter answers "which is in use right now?" via config rather than auto-detection.

### 3.1 Trait sketch

```rust
// ember-agent-monitor/src/runtime/mod.rs

pub mod claude_code;
pub mod openclaw;
pub mod hermes;

use crate::event::Event;
use crate::net::http::HttpRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Runtime {
    ClaudeCode,
    OpenClaw,
    Hermes,
}

pub trait RuntimeAdapter {
    /// Stable identifier for telemetry + config keys.
    fn id() -> &'static str;

    /// Resolve a session id for an inbound request.
    /// Returns `None` if the runtime can't be observed at the wire
    /// layer alone — caller falls back to a content-hash anonymous
    /// id, or to a per-runtime side-channel (filesystem, hook).
    fn session_id_for(req: &HttpRequest, body: &[u8]) -> Option<String>;

    /// Default workspace root if the operator hasn't overridden.
    fn workspace_root_default() -> std::path::PathBuf;

    /// Per-runtime list of paths to watch for session-event JSONL.
    /// Returns absolute paths the watcher should poll.
    fn session_log_paths(workspace_root: &std::path::Path) -> Vec<std::path::PathBuf>;

    /// Parse a single session-log line into events for the static graph.
    /// Different runtimes use different schemas; this is the seam.
    fn parse_session_log(line: &str) -> Result<Vec<Event>, String>;

    /// The runtime's documented "frozen workspace" file list, if any.
    /// Used by the integrity-manifest auto-generator (`ember-integrity-
    /// manifest generate <workspace>` could pick the right file list per
    /// runtime). Hermes returns an empty Vec.
    fn frozen_files_default() -> Vec<&'static str>;

    /// Optional: register the suite as a runtime-native plugin/hook.
    /// Hermes returns hook-registration metadata; Claude Code + OpenClaw
    /// return None.
    fn hook_integration() -> Option<HookIntegration> { None }
}

pub struct HookIntegration {
    pub plugin_name: &'static str,
    pub events: &'static [&'static str],  // "pre_tool_call", etc.
    pub config_path_relative: &'static str,
}
```

### 3.2 Runtime selection at proxy boot

Three options, in order of preference:

1. **Operator config** (cleanest): `--runtime claude-code | openclaw | hermes` CLI flag, or `runtime: ...` field in a config file. Default `claude-code` for backwards compat.
2. **Auto-detect by header pattern**: if request has `x-claude-session-id` → Claude Code. If body shape matches OpenClaw's gateway shape → OpenClaw. Hermes never reaches this layer (uses plugin hooks). Auto-detect is a fallback for ergonomics; explicit config is the primary path.
3. **Per-request override** (expert mode): a header like `x-ember-runtime: openclaw` on the request body lets multiple runtimes share a single proxy on the same port.

For v1.6 we ship (1) + (2). (3) is a v1.7 hardening if we see customer demand.

### 3.3 Per-runtime adapter sketches

#### 3.3.1 ClaudeCodeAdapter

```rust
impl RuntimeAdapter for ClaudeCodeAdapter {
    fn id() -> &'static str { "claude-code" }

    fn session_id_for(req: &HttpRequest, _body: &[u8]) -> Option<String> {
        req.header("x-claude-session-id").map(String::from)
    }

    fn workspace_root_default() -> PathBuf {
        // Loose — Claude Code projects live anywhere the user opened
        // them. The default *watch* root is the projects dir, not a
        // workspace-content dir.
        dirs_home().join(".claude/projects")
    }

    fn session_log_paths(root: &Path) -> Vec<PathBuf> {
        // Walk every <root>/<dir>/sessions/<id>.jsonl
        walk_session_jsonl(root, "sessions/*.jsonl")
    }

    fn parse_session_log(line: &str) -> Result<Vec<Event>, String> {
        // Existing parser path — Claude Code's JSONL format is what
        // proto::anthropic was designed against
        crate::event::parse_jsonl_line(line).map(|e| vec![e])
    }

    fn frozen_files_default() -> Vec<&'static str> {
        Vec::new()  // Claude Code has no mandated frozen files
    }
}
```

This is essentially the v1.5 code path, refactored behind the trait. **Zero-functional-change to existing fixtures.**

#### 3.3.2 OpenClawAdapter

```rust
impl RuntimeAdapter for OpenClawAdapter {
    fn id() -> &'static str { "openclaw" }

    fn session_id_for(req: &HttpRequest, body: &[u8]) -> Option<String> {
        // OpenClaw doesn't ship a header. Three fallbacks:
        // 1. If the operator configured a wrapper that adds
        //    `x-ember-session-id`, use it.
        if let Some(s) = req.header("x-ember-session-id") {
            return Some(s.to_string());
        }
        // 2. Filesystem-derived: the proxy can ask the watcher
        //    "which OpenClaw session is currently active?" — a
        //    side-channel that requires watcher state, returned via
        //    a SessionResolver helper. Skipped here for brevity.
        // 3. Anonymous id from body hash, with a "rt=openclaw" prefix.
        let h = crate::crypto::sha256::sha256(body);
        Some(format!("openclaw-{}", crate::crypto::sha256::hex_encode(&h[..8])))
    }

    fn workspace_root_default() -> PathBuf {
        dirs_home().join(".openclaw/workspace")
    }

    fn session_log_paths(_root: &Path) -> Vec<PathBuf> {
        // Sessions are in agents/<agentId>/sessions/, not workspace/
        vec![dirs_home().join(".openclaw/agents")]
    }

    fn parse_session_log(line: &str) -> Result<Vec<Event>, String> {
        // OpenClaw session-log format is undocumented at this design
        // stage. Probe at install time, then write a parser.
        // Placeholder: try the Claude Code parser (because OpenClaw
        // borrows Claude Code's session shape in some configs); fall
        // through to a JSON-as-best-effort parser.
        if let Ok(ev) = crate::event::parse_jsonl_line(line) {
            return Ok(vec![ev]);
        }
        // TODO: real OpenClaw parser
        Ok(Vec::new())
    }

    fn frozen_files_default() -> Vec<&'static str> {
        vec![
            "SOUL.md", "AGENTS.md", "IDENTITY.md", "USER.md",
            "TOOLS.md", "HEARTBEAT.md", "STYLE.md",
        ]
    }
}
```

#### 3.3.3 HermesAdapter

```rust
impl RuntimeAdapter for HermesAdapter {
    fn id() -> &'static str { "hermes" }

    fn session_id_for(_req: &HttpRequest, _body: &[u8]) -> Option<String> {
        // Hermes session id lives inside JSON-RPC payloads, not at the
        // wire layer reaching this proxy. Always None — the hook
        // integration is the right observation point.
        None
    }

    fn workspace_root_default() -> PathBuf {
        dirs_home().join(".hermes")
    }

    fn session_log_paths(_root: &Path) -> Vec<PathBuf> {
        vec![
            dirs_home().join(".hermes/sessions"),
            dirs_home().join(".hermes/logs/command_usage.jsonl"),
        ]
    }

    fn parse_session_log(line: &str) -> Result<Vec<Event>, String> {
        // Hermes JSONL has its own schema — role/content/tool_calls.
        // Stub for v1.6; real parser ships with HermesAdapter v1.6.1.
        Ok(Vec::new())
    }

    fn frozen_files_default() -> Vec<&'static str> {
        Vec::new()  // Hermes mandates none; operator can opt in
    }

    fn hook_integration() -> Option<HookIntegration> {
        Some(HookIntegration {
            plugin_name: "ember-agent-monitor",
            events: &[
                "pre_tool_call", "post_tool_call",
                "pre_llm_call", "post_llm_call",
                "on_session_start", "on_session_end",
                "subagent_stop", "transform_tool_result",
            ],
            config_path_relative: ".hermes/config.yaml",
        })
    }
}
```

For Hermes specifically, the suite ships a small Hermes-plugin manifest + a tiny hook handler that POSTs hook events into agent-monitor's `events.sock` — same Unix socket ember-network already subscribes to. This unifies the dataflow: regardless of whether events came from a proxy intercept or a hook callback, the rule engine sees the same Event stream.

## 4. Layered changes per existing module

| Module | Change |
|---|---|
| `src/proto/mod.rs` | No change. `Protocol` is wire-level; `Runtime` is agent-level. |
| `src/proto/anthropic.rs` / `openai.rs` | No change. Parsers don't care about runtime. |
| `src/types.rs` | `DaemonConfig` gains `runtime: Runtime` field (default `Runtime::ClaudeCode`). |
| `src/cli/mod.rs` | New flag `--runtime claude-code\|openclaw\|hermes`. |
| `src/net/proxy.rs` | `derive_session_id_for` becomes runtime-aware: dispatch to `Runtime::session_id_for`. Existing `x-claude-session-id` lookup moves into `ClaudeCodeAdapter`. |
| `src/watcher/mod.rs` | Watch-roots come from `runtime::session_log_paths(workspace_root)`. Per-runtime jsonl parser. |
| `src/integrity/mod.rs` | Unchanged — manifest is path-list driven, no runtime dependency. |
| `src/integrate/mod.rs` (NEW) | Hermes plugin server: tiny HTTP/Unix socket handler that accepts hook callback events and emits Events into the existing pipeline. |
| `bin/ember-integrity-manifest` (presence) | New flag `--runtime <name>` that picks the per-runtime `frozen_files_default` list. |

## 5. Detection-rule impact (the load-bearing question)

**Almost zero.** All 30+ rules in `src/detect/rules.rs` operate on the internal `Event` type. Three rules touch runtime-specific fields:

| Rule | Concern | Resolution |
|---|---|---|
| `frozen_file_modification` | Path to watched files | Driven by integrity manifest, not runtime. Already agent-agnostic. |
| `subagent_via_injection` | Looks for cross-orchestrator events | Runtime-agnostic in shape; per-runtime parser must emit consistent `event.kind` and `inter_agent_message` shape. |
| `instruction_shape_in_mcp_description` | Reads MCP server descriptions | MCP is a standard protocol — Claude Code + OpenClaw both use it the same way. Hermes registers MCP servers via plugin layer; the description content reaches us via `pre_llm_call` hook. Same rule, different ingest path. |

The remaining 27+ rules don't touch any runtime-specific surface.

**Existing 38 fixtures across the corpus remain valid.** They're Event-typed JSONL, runtime-agnostic by construction.

## 6. Config + deploy contract

`DaemonConfig` becomes:

```rust
pub struct DaemonConfig {
    pub runtime: Runtime,                  // NEW
    pub proxy_port: u16,
    pub mode: InterventionMode,
    pub data_dir: PathBuf,
    pub watch_dir: PathBuf,                 // resolved per-runtime if not set
    pub upstream_anthropic: String,
    pub upstream_openai: String,
    pub integrity_manifest: Option<PathBuf>,
    pub hermes_hook_socket: Option<PathBuf>, // NEW: only if runtime==Hermes
}
```

CLI:

```bash
# Claude Code (default — same as v1.5 behavior)
ember-agent daemon --mode warn --port 9452

# OpenClaw — different watch root, different protocol default
ember-agent daemon --mode warn --runtime openclaw \
  --upstream-openai https://api.openai.com

# Hermes — proxy still listens for outbound LLM calls,
# plus a hook socket
ember-agent daemon --mode warn --runtime hermes \
  --hermes-hook-socket /run/ember-hermes-hook.sock
```

## 7. Build sequence

| Step | Tokens | Notes |
|---|---|---|
| 1. Refactor existing CC code path into `runtime::claude_code::ClaudeCodeAdapter` | ~80K | Pure refactor, no functional change. Tests + clippy stay green. |
| 2. `Runtime` enum + `DaemonConfig.runtime` + CLI flag | ~30K | Default `ClaudeCode` preserves backward compat |
| 3. `runtime::openclaw::OpenClawAdapter` (without real session-log parser yet) | ~80K | Lands the trait shape and the static-graph path; session-log parser stubs |
| 4. `runtime::hermes::HermesAdapter` + `integrate::hermes_plugin` | ~150K | Hermes is the most distinct shape — biggest module |
| 5. OpenClaw session-log parser | ~80K | Requires real-install probe to confirm format |
| 6. Hermes session-log parser | ~50K | JSONL with documented schema |
| 7. Integrity-manifest tool: per-runtime frozen-file defaults | ~30K | Small ember-presence change |
| 8. Threat-intel fixtures: at least one per runtime | ~80K | Sanity-check the full pipeline |
| 9. README + docs update | ~30K | Suite-overview, agent-monitor README, INFRA.md |
| **Total v1.6** | **~610K** | ~2 sessions of focused work |

## 8. What this enables

- **The suite becomes a real product**, not a Claude Code companion. The same `ember-agent monitor` binary works against any of three popular runtimes; new runtimes = new file under `src/runtime/`.
- **Cross-runtime correlation in `ember-persistent`** — a customer running Claude Code on dev and OpenClaw on staging gets a unified persistent ledger.
- **Honest "vendor-independent" claim** — currently the suite-overview makes this claim at the wire layer; v1.6 makes it true at the runtime layer too.
- **The presence-agent deploy decision unblocks**: ember-presence picks `Runtime::ClaudeCode` (lowest CVE surface), suite stays compatible with everything else.

## 9. Open design questions

1. **Hermes hook server transport**: Unix socket vs HTTP loopback? Unix socket is more secure (SO_PEERCRED auth) but requires Hermes plugins to support that — verify before locking.
2. **OpenClaw session-log format**: actually probe a live OpenClaw install to capture the real JSONL/SQLite schema before writing the parser. This is install-time research, not desk research.
3. **Per-runtime fixture format**: do we keep the existing `events.jsonl` format for fixtures (they're internal Event type) or also support per-runtime native session-log replay? My vote: keep Event-typed for the rule-engine fixtures; add per-runtime native fixtures only for parser regression tests.
4. **Hot-swap runtime mid-deploy**: probably no. Operator picks one runtime at install; switching means a fresh deploy. The Runtime enum is set at daemon boot.
5. **Cross-runtime threats** (the corpus extension §3.x classes — multi-agent collusion, multi-runtime pivots): handled by `ember-persistent`'s cross-session lineage, not by per-runtime adapters. Adapter just feeds events; persistent correlates across runtimes.

## 10. Migration path

For agent-monitor v1.5 → v1.6:
- All existing CLI invocations work unchanged (default `--runtime claude-code`).
- All existing fixtures pass unchanged (Event-typed, runtime-agnostic).
- All existing rules fire unchanged.
- New: operators who want OpenClaw or Hermes set the flag.

No deprecations. v1.6 is a strict superset of v1.5.
