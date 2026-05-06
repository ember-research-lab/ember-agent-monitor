# Ember Agent Monitor — v1 Specification

**Layer:** Runtime  
**Distribution:** Open source  
**Position in suite:** Tool 2 of 4 (see `ember-suite-overview.md`)  
**Status:** Design locked, ready for implementation

---

## 1. Scope

### What this tool does

The agent monitor observes a single AI agent session in real time, builds a structural graph of its execution, and detects anomalous patterns that indicate prompt injection, tool poisoning, scope escape, credential exfiltration, or capability composition attacks. It runs locally, ships zero dependencies, and never sends data off the user's machine.

It sits between an AI coding agent (Claude Code, Codex, Cursor, custom agents) and the API endpoints those agents speak to. Through that vantage point, it sees the conversation, the tool calls the agent makes, the results those tools return, and the model's decisions about what to do next. From this stream, it reconstructs an execution graph and applies structural detection methods to that graph.

### What this tool does not do

- **Multi-session content tracking.** Agents that stage payloads in the codebase across sessions are out of scope. The persistent tool addresses this.
- **Network-layer observation.** What actually crosses the wire after a tool fires is out of scope. The network tool addresses this.
- **Package supply chain.** What gets installed before the agent runs is out of scope. vetpkg addresses this.
- **Hook runtime behavior.** Hooks execute locally between the model decision and the API call — invisible to a network-layer observer. Static analysis of hook configurations at registration time is in scope; runtime behavior of hooks is not.
- **Adaptive adversaries with full source access who tune attacks against the rule set.** Spectral methods (planned for v2) address this; v1 rule-based detection has a known evasion ceiling.

This scope discipline is intentional. Each Ember tool covers its layer and integrates with the others. See "Limitations and integration points" below for the explicit gap-coverage matrix.

---

## 2. Architecture

### Hybrid observer

The monitor is two cooperating processes plus a shared substrate:

**API proxy.** Local HTTP server, default port `9452`. Speaks the Anthropic and OpenAI-compatible protocols upstream. Users point their agent at `localhost:9452` via standard env vars (`ANTHROPIC_BASE_URL`, `OPENAI_API_BASE`). The proxy intercepts requests in both directions, runs detection, optionally intervenes, and forwards or substitutes responses.

**File-watcher.** Watches `~/.claude/projects/<hash>/sessions/*.jsonl` (and equivalent paths for other agent runtimes). Reads session metadata, MCP server registrations, subagent parent-child relationships, and other static-graph data that doesn't flow through the API.

Both processes write to a shared SQLite store. Each process runs detection independently against the data it sees; findings from both feed the same per-session findings table.

### Why hybrid

The in-line validation made the necessity explicit. MCP server registration happens during agent startup over local IPC, never over the API. A pure HTTP proxy cannot see the static graph. A pure file-watcher cannot intervene in real time. Both are required.

### Trust boundaries

The monitor itself is trusted by assumption. The user's machine, the user's stated intent, and the user's standing configuration are trusted. Everything else is graded:

- **`user_input`** — text the user typed directly. Trusted.
- **`workspace_local`** — files within the project working directory. Mostly trusted but verifiable.
- **`sensitive_local`** — known-sensitive paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, `~/.netrc`, `~/.docker/config.json`, `.env*`, `id_rsa`, `id_ed25519`, `credentials`, plus user-extensible additions). Operations on these zones get scrutiny regardless of who initiated them.
- **`external_local`** — local files outside the workspace. Suspicious by default.
- **`untrusted_tool_output`** — content returned from any tool that ingested external data (web fetches, MCP servers reading files, GitHub issue contents, etc.). Treated as adversarial.
- **`ephemeral`** — `/tmp`, `/var/tmp`. Low-stakes by default but watched.

Trust zones are applied via path normalization first. All paths are tilde-expanded and resolved before tagging — this is non-optional substrate behavior, surfaced by the in-line validation as a real bug class.

### State scope hierarchy

State exists at three explicit scopes:

```
UserState            (persistent across all sessions, all projects)
└── ProjectState     (one per workspace directory)
    └── SessionState (one per agent session)
```

State lookups walk the hierarchy. Configuration writes target a specific scope explicitly. Without this hierarchy, the tool either over-shares state (boundary set in project A leaks to project C) or under-shares (user retrains calibration in every project). Scope is not optional.

### Detection-fidelity status

Each session carries a status flag in metadata:

- `full_fidelity` — both proxy and file-watcher are observing this session
- `degraded_static_only` — file-watcher running, proxy missing or restarted
- `degraded_dynamic_only` — proxy running, file-watcher missed events
- `failed` — neither observer producing data

The user sees this status in the UI. Silent degradation of detection coverage is a documented failure mode; the status flag makes it explicit. Required, not optional.

---

## 3. Data model

### Event schema

The substrate is an append-only event log, one event per row. Every event has:

```
event_id        UUID
session_id      string
timestamp       ISO 8601
parent_event_id UUID | null
trust_zone      enum (see above)
content_hash    SHA-256 prefix
kind            enum (see below)
```

### Event kinds

```
session_start           — session metadata (model, cwd, git branch)
mcp_registration        — MCP server connected, with declared tools
skill_load              — skill activated (latent → active)
hook_registration       — hook configured (PreToolUse, PostToolUse, etc.)
plugin_install          — plugin bundle registered
user_prompt             — text the user typed
model_text              — text the model produced
tool_call               — model invoked a tool, with args
tool_result             — tool returned content (back-injected as role:user)
subagent_invocation     — orchestrator spawned a subagent
inter_agent_message     — explicit message between orchestrators (SendMessage)
classifier_decision     — auto-mode classifier verdict, when present
finding                 — detection result emitted by the monitor
intervention            — action the monitor took (warn, block)
session_end             — session terminated
```

### Critical schema discipline

`tool_result` is structurally different from `user_prompt` even though Anthropic's protocol delivers both as `role: user`. A naive parser treating all `role: user` as user-trusted would misclassify trust zones catastrophically. **The schema disambiguates at parse time, never downstream.** This was surfaced by the offline validation as a real implementation gap.

### Graph construction

From the event log, two graphs are built:

**Static graph** — populated at session start from `mcp_registration`, `skill_load`, `hook_registration`, `plugin_install` events. Captures what tools and capabilities the agent has access to before any execution.

**Dynamic graph** — populated as the session runs. Nodes are events, edges are causal (parent_event_id) and trust-cross (when an edge crosses a trust zone boundary).

For Anthropic's protocol, the parent_uuid chain encodes both causal and data-flow relationships, so a single edge type suffices. For protocols with looser causality (raw OpenAI function calling, custom agents), separate edge types may be needed. **Edge schema is protocol-parametric, not hardcoded.**

### Capability composition

Each tool is tagged with capability classes:

```
file_read             repo_init             credential_access
file_write            repo_read             email_send
file_write_via_filter repo_write            network_out
list_directory        code_execute          shell_exec
```

The session's capability set is the union of capabilities across registered tools. Toxic combinations are computed against this set:

- `repo_init + file_write` → arbitrary code execution via git filters (CVE-2025-68143/144/145 mechanism)
- `file_read(sensitive) + network_out` → credential exfiltration primitive
- `file_write + file_read` + untrusted ingestion → multi-step staged exfil primitive

Capability composition operates on the lattice, not the server topology. A single tool exposing multiple capabilities still triggers the rule. A user repackaging an MCP server cannot evade the check by rearranging tool grouping.

---

## 4. Detection rules (v1)

### Static-graph detections

Run at session start, before any agent action:

- **`toxic_capability_composition`** — capability set contains a known-toxic combination
- **`lethal_trifecta_reachability`** — capability lattice contains paths from private-data zones through transformation tools to external communication
- **`high_risk_plugin_composition`** — plugin bundles MCP + hook + subagent simultaneously (high collusion surface)
- **`unaudited_mcp_registration`** — MCP server registered without a corresponding entry in vetpkg's findings (when vetpkg is integrated)

### Dynamic detections (per-event)

Run as the session executes:

- **`sensitive_zone_access`** — tool call argument references a path in `sensitive_local` zone
- **`argument_injection_pattern`** — tool argument matches flag-injection or shell-injection pattern (`--output=`, `; rm`, `$(...)`, backtick substitution, etc.)
- **`instruction_shape_in_tool_result`** — tool result content matches directive-shaped patterns (`SYSTEM_NOTE`, `the assistant must`, `<!-- SYSTEM`, etc.) **AND** the source trust zone is `untrusted_tool_output`. Trust zone is required context — a `you MUST` in a workspace doc is low signal; the same in a fetched webpage is high signal.
- **`scope_escape`** — tool operates outside the project's working directory without explicit user authorization
- **`exfil_shape`** — outbound tool call args contain base64 sequences, long URL parameters, credential-shaped strings
- **`trigger_cause_violation`** — a `skill_load` or `hook_registration` was triggered by content from `untrusted_tool_output` zone (skill activation by injection)
- **`classifier_disagreement`** — auto-mode classifier verdict differs from monitor's verdict (in either direction; surfaces calibration signal)

### Cross-session detections

Out of scope for v1. The persistent tool consumes session graphs and detects patterns spanning sessions.

### User-extensible signals

`SENSITIVE_PATHS`, `INSTRUCTION_PATTERNS`, `ARG_INJECTION_PATTERNS`, `TOXIC_COMBINATIONS` are all user-extensible via local config. Defaults ship with the binary; users add per-environment additions. **The published rule set is not the deployed rule set** — every user has their own additions, which raises the bar against attackers who tune against the OSS source.

### Pattern matching is contextualized, not raw

Detection score = `pattern_match × source_trust_inverse × severity_class`. Raw pattern presence alone is not a finding. This avoids the false-positive class where legitimate technical writing trips imperative-shape patterns. Spec implication: every pattern-match detection includes the trust zone of the source, and the score scales accordingly.

---

## 5. Intervention model

### Three modes with distinct semantics

| Mode | Forward direction | Backward direction |
|---|---|---|
| `observe` | Log finding only, no rewrite | Log finding only, no rewrite |
| `warn` | Inject system-prompt warning when finding fires | Strip dangerous tool_use, substitute refusal text |
| `block` | Refuse to forward request, return synthetic refusal to client | Strip dangerous tool_use, substitute refusal text |

`warn` and `block` differ on forward-direction handling of high-severity findings — `warn` lets the agent see the warning and decide, `block` prevents the request from reaching the upstream model at all.

### Forward warnings are advisory

A system-prompt warning injection does not stop a committed model. The validation showed the mock upstream proceeded with the dangerous tool call despite the warning. **Forward warnings are reactive, not preventive.** Backward blocks are the actual safety mechanism. Spec design reflects this: backward detection is more aggressive than forward detection, and high-severity backward findings always trigger intervention regardless of mode (except `observe`).

### Block mechanics

When the monitor blocks a tool_use, it strips the tool_use blocks from the response and substitutes a refusal text. The client sees a normal-looking assistant message that explains the block. Claude Code handles this gracefully (ends the turn, displays text to user). Custom agents must be capable of handling "model returned text without tool_use" — documented requirement.

### Configuration scope

Intervention mode is a global proxy configuration, not a per-session attribute. The in-line validation surfaced this conflation as a real bug — per-session-state for what's actually configuration leads to silent failures. Mode is set at proxy startup and applies uniformly.

### Escalation thresholds

After 5 consecutive blocks within a session, the monitor pauses interception and surfaces a "session-level concern" alert. After 20 cumulative blocks, the session terminates with a critical alert. Mirrors Anthropic's auto-mode escalation pattern.

---

## 6. Integration points

### Inputs to the agent monitor

**vetpkg findings.** vetpkg writes its install-time risk scores to `~/.ember/vetpkg/findings.jsonl`. The agent monitor reads this at session start. Sessions with packages flagged by vetpkg get elevated detection sensitivity. Read-only consumption; no shared state.

### Outputs from the agent monitor

**Session graph artifacts.** At session end (or on demand), the monitor emits the full execution graph as a JSONL file under `~/.ember/agent-monitor/sessions/<session-id>.jsonl`. Schema documented. Consumed by the persistent tool when installed.

**Tool-call event stream.** While running, the monitor emits tool-call events to a Unix socket at `~/.ember/agent-monitor/events.sock`. The network tool subscribes to this stream and correlates against observed network connections by timing and process. Loose temporal coupling — both tools share wall-clock and process tree, no direct state sharing.

### No tight coupling

Each tool has its own data model, substrate, and failure modes. They share a coordination protocol (event formats, file paths, socket interfaces) but not libraries or runtime state. **A user can run any subset of the four tools.** The agent monitor is fully functional standalone — its outputs are upgrades when other tools consume them, not dependencies.

---

## 7. Threat model

### In scope

- **Prompt injection** via tool results (poisoned READMEs, webpages, GitHub issues)
- **Tool poisoning** via MCP server descriptions or skill content
- **Scope escape** — agent operating outside stated user intent
- **Credential exfiltration** via single-session tool composition
- **Argument injection** in tool call parameters
- **Capability composition attacks** (Cyata-style toxic combinations)
- **Hook configuration attacks** at registration time (static analysis)
- **Skill-trigger manipulation** via untrusted content
- **Auto-mode classifier disagreement** as calibration signal

### Out of scope

- **Multi-session staged attacks** (codebase-as-persistent-memory) — persistent tool
- **Network-layer egress detection** — network tool
- **Package-level supply chain** — vetpkg
- **Hook runtime behavior** — out of scope, document-only static analysis
- **Adaptive attackers with full source-code knowledge tuning attacks against published rules** — accepted ceiling for v1; spectral layer (v2) addresses
- **Attacks on the monitor itself** — the substrate is trusted; if the monitor is compromised the threat model fails

### Documented limitations

The user should understand:

1. **Cold-start case.** The monitor installed *after* a malicious modification has no clean baseline. Rules and patterns catch known-bad shapes; novel attacks may slip through. Other Ember tools (vetpkg static checks, persistent tool baselines) reduce this surface.

2. **Tuned attackers.** An attacker with full source-code knowledge can craft attacks that evade the rule library. Mitigations: capability composition is structurally evasion-resistant; user-extensible patterns are not in the published source; spectral methods (v2) operate on graph structure rather than strings; the suite layers (network, persistent) catch what the agent monitor misses.

3. **Hook runtime blind spot.** Hooks execute in Claude Code's process between model decision and API call. The proxy doesn't see them. Static analysis of hook configs at registration is in scope; runtime hook behavior is not.

4. **Distributed-trifecta detection requires hybrid observation.** When attack components span multiple sessions or orchestrators, single-session detection is insufficient. Persistent tool covers cross-session; agent monitor covers per-session.

---

## 8. Validation status

The design has been pressure-tested through:

- **18 attack scenarios** across single-tool, plugin-bundled, multi-orchestrator, and adaptive-adversary cases
- **3 real CVEs** walked end-to-end: MCPoison (CVE-2025-54136), postmark-mcp backdoor, mcp-server-git RCE chain (CVE-2025-68143/144/145)
- **Offline validation pipeline** — JSONL session → event log → graph → detection layer, with the CVE chain producing 8 independent findings across 4 detection classes
- **In-line proxy validation** — HTTP proxy intercepting both directions, three intervention modes, real-time graph construction
- **Auto-mode integration analysis** — Anthropic's classifier as a complementary layer, with cross-validation as a feature

Three implementation bugs and five architectural observations were surfaced during validation:

- Path normalization is substrate-required, not optional (must precede zone tagging)
- Configuration vs per-session state must be separate concerns
- Three intervention modes need distinct semantics on both directions
- Static graph requires file-watcher in addition to API proxy
- State scope hierarchy (user / project / session) is required for production usability

All five are addressed in the design above.

### Test fixtures

Synthetic CVE chain session in real Claude Code JSONL format, with reference detection output, has been built and validates the pipeline end-to-end. Becomes a regression test in the codebase: any future modification runs the pipeline and expects exactly the documented finding set.

---

## 9. Implementation roadmap

### v0 — substrate (week 1-2)

- HTTP proxy on `localhost:9452`, Anthropic protocol, forward-only (no detection, no intervention)
- File-watcher on `~/.claude/projects/`
- SQLite append-only event log
- JSONL → event parser
- Graph constructor

Deliverable: a proxy that captures everything and writes it to SQLite, no detection. **Useful as a transparent audit log even with no detection.**

### v0.5 — rules-based detection (week 3-4)

- Static-graph detections: toxic_capability_composition, lethal_trifecta_reachability
- Dynamic detections: sensitive_zone_access, argument_injection_pattern, instruction_shape_in_tool_result (with trust-zone contextualization)
- User-extensible config for paths and patterns
- Three intervention modes
- CLI command suite (`ember-agent init`, `ember-agent daemon`, `ember-agent status`, `ember-agent findings`)

Deliverable: useful tool that catches OWASP MCP Top 10 categories at runtime.

### v1 — production polish (week 5-6)

- State scope hierarchy (user / project / session)
- Detection-fidelity status
- Persistent boundary store (per-session)
- Auto-mode classifier integration (when present, cross-validate)
- vetpkg integration (read findings, elevate sensitivity)
- Event stream socket for network tool
- Documentation, README, threat model

Deliverable: ship-ready v1.

### v2 — spectral layer (TBD)

- Eigenvector tracking on prompt-context subspace
- Spectral gap analysis on trajectory vs initial task
- Subgraph motif detection for exfil patterns
- User-baseline calibration

This is the answer to tuned adaptive attackers. Earned its priority through the validation work. Not v1, but on the explicit roadmap.

---

## 10. Constraints

- **Language:** Rust, 2021 edition, no unsafe code
- **Dependencies:** zero (matches vetpkg's posture)
- **Storage:** SQLite via direct syscalls, bundled
- **Embeddings:** small encoder-only model, weights bundled or downloaded once with hash-pinning
- **Cross-platform:** macOS and Linux first; Windows after v1
- **No network egress from the tool itself** — never phone home, never report metrics, never download updates without user action
- **Auditable in one sitting:** total codebase target < 5000 lines, single-file binary

---

## 11. Notes

This spec is the artifact of extensive design pressure-testing. Decisions that may look conservative or narrow are intentional — every "we should add X" item was weighed against "is this the agent monitor's layer or another Ember tool's?" The discipline of layered architecture is structural, not just stylistic.

The biggest insight from the validation work: **a working v0 of this tool is a long weekend's effort.** The substrate is small; the detection layer is mostly pattern lists; the intelligence is in the rules and the integration. Ship the substrate first as a transparent audit log (useful standalone), layer detection on top, add intervention last. Each step has independent value.

The relationship to the broader suite is documented in `ember-suite-overview.md`. Read that next if you haven't.
