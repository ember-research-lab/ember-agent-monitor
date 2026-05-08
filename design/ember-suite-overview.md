# Ember Security Suite — Architecture Overview

**Status:** Active design. vetpkg shipped. Agent monitor next.

---

## 1. Thesis

AI security tooling has converged on a flawed pattern: every vendor pitches a single product as the answer. Lakera, Protect AI, Robust Intelligence, Snyk, Datadog — each ships one product covering one slice and claims to be enough. They are not. AI agents fail across multiple structural layers, and any single-product defense has correlated failure modes within its own layer.

A second, related, claim: defense should be **vendor-independent by construction**. The threat surface (prompt injection, supply-chain compromise, multi-session staged exfil, wire-level egress) does not change between Claude, GPT, Gemini, or a local Llama. Tools that bake an Anthropic-or-OpenAI-shaped assumption into their substrate are committing to a calibration debt that grows with every new vendor. Ember tools observe at the *Event* layer — a shared internal type emitted by every protocol parser — and detection rules don't see protocol shapes at all. Adding a new vendor is one new file under `src/proto/`, no rule or fixture changes.

Ember's position is the opposite. **Defense in depth requires multiple independent tools at structurally different layers.** No single Ember tool tries to be the answer. Each does its layer well and integrates with the others through explicit, loose-coupling interfaces. Together they cover the surface; individually they are honest about scope.

This is not a marketing position. It is the architecture that follows from taking the threat model seriously. Prompt injection, tool poisoning, supply chain attacks, and exfiltration all happen at different layers of the agent execution stack, and each layer has different observability, different intervention semantics, and different failure modes. A unified product would have to compromise on all of them. Four focused tools do not.

---

## 2. The four tools

### Tool 1: vetpkg (open source, install-time)

**Layer:** Package supply chain. What gets installed before anything runs.

**Mechanism:** Local Rust proxy registry. User points npm, pip, cargo at `localhost:9451`. Every package install is intercepted, scored against advisory databases, popularity baselines, maintainer histories, dependency diffs, and install-hook patterns. High-risk packages get blocked or warned before they touch the user's environment.

**What it catches:**
- Malicious packages with known CVEs (via OSV)
- Typosquats and impersonation packages (postmark-mcp pattern)
- Packages with new external dependencies in patch versions
- Install-time scripts that fetch network or execute shell
- Packages with suspicious popularity-vs-permissions asymmetry

**What it doesn't catch:**
- Zero-day attacks not yet in advisory databases (irreducible vetpkg gap)
- Runtime behavior of packages that pass install checks
- Anything that doesn't go through a package manager

**Status:** Shipped. Working tool. Foundation of the suite.

---

### Tool 2: Agent monitor (open source, runtime)

**Layer:** Live agent execution. What the agent does while running.

**Mechanism:** Local HTTP proxy + file-watcher hybrid observer. Sits between the agent and its API endpoints. Builds a structural graph of execution, applies rules-based detection (with spectral methods as v2). Three intervention modes: observe, warn, block.

**What it catches:**
- Prompt injection via tool results
- Tool poisoning in MCP descriptions or skill content
- Sensitive-zone access (tools targeting `~/.ssh` etc.)
- Argument injection patterns
- Capability composition attacks (Cyata-style toxic combinations)
- Scope escape from stated user intent
- Hook configuration risks (static analysis at registration)

**What it doesn't catch:**
- Multi-session staged attacks (codebase as persistent memory)
- Network-layer egress
- Hook runtime behavior between API calls
- Adaptive attackers tuning against published rules (v2 addresses)

**Status:** Design locked. See `agent-monitor-spec.md`. Implementation next.

---

### Tool 3: Persistent (premium, cross-session)

**Layer:** Long-horizon agent behavior across sessions. What the agent has done over time.

**Mechanism:** Consumes session graphs from the agent monitor. Maintains workspace-level state — what files the agent has modified, what content it has staged, what boundaries the user has stated, what patterns have been seen across multiple sessions. Detects patterns that span sessions: staged exfiltration, gradual scope creep, distributed lethal trifectas across orchestrator handoffs.

**What it catches:**
- Multi-session staged exfiltration (payload buried in week-1 commit, exfiltrated in week-3 session)
- Boundary violations across context compaction
- Cross-session content lineage (data the agent read days ago resurfacing in outbound calls today)
- Distributed lethal trifectas across orchestrator handoffs
- Agent-modified workspace fingerprint drift

**What it doesn't catch:**
- First-session attacks (no prior baseline)
- Network-layer signals (delegates to network tool)
- Package-level supply chain (delegates to vetpkg)

**Status:** Architectural placeholder. Built after agent monitor v1 ships.

**Why premium:** Persistent state is operationally heavier — storage growth, retention policies, ongoing data management. Aligns naturally with users who pay for ongoing service rather than a one-time download. Also serves as the funnel: users who hit the OSS tools' limits find themselves needing this.

---

### Tool 4: Network (premium, egress)

**Layer:** Wire-level network observability. What actually crosses the network.

**Mechanism:** Local network observer. Captures outbound connections from agent-related processes. Correlates against the agent monitor's tool-call event stream by timing and process tree. Detects exfiltration regardless of how the agent rationalized the call.

**What it catches:**
- Outbound connections to novel destinations (anomaly)
- Egress patterns matching known exfil shapes
- Network calls that don't have a corresponding tool-call event in the agent monitor's stream (covert channels)
- Long-running outbound connections (data exfil over time)
- DNS-based data exfiltration

**What it doesn't catch:**
- Anything the agent doesn't actually try to send (delegates to agent monitor)
- Multi-session content lineage (delegates to persistent)
- Package-level supply chain (delegates to vetpkg)

**Status:** Architectural placeholder. Build order TBD — likely after persistent.

**Why premium:** Network observation requires kernel-level hooks (eBPF on Linux, NetworkExtension on macOS, ETW on Windows) that are operationally substantial and platform-specific. Premium tier appropriate for the engineering investment.

---

## 3. Coverage matrix

How the four tools — plus the bash-glue attest layer (`ATTEST.md`) —
collectively address the threat surface:

| Attack class | vetpkg | Agent monitor | Persistent | Network | Attest |
|---|---|---|---|---|---|
| Malicious package at install | **Yes** | (advisory only) | — | — | — |
| Typosquat package | **Yes** | — | — | — | — |
| Package CVE post-disclosure | **Yes** | — | — | — | — |
| Package zero-day | (gap) | (gap if no runtime sig) | — | **Yes (egress)** | — |
| Tool poisoning (MCP description, direct) | (advisory) | **Yes** | — | — | — |
| MCP marketplace poisoning | **Yes (manifest types)** | **Yes (handshake injection)** | — | — | — |
| Prompt injection (poisoned tool result) | — | **Yes** | — | — | — |
| **Agent-as-intermediary social engineering (ClickFix)** | — | **Yes** (`agent_as_intermediary_clickfix` HIGH, v1.5) | (cross-session repeat) | — | (process tree, if user runs payload) |
| **Memory poisoning of identity files** (SOUL.md, MEMORY.md, etc.) | — | **Yes** (`frozen_file_modification` HIGH, v1.5 hash-pin) | **Yes (behavior-change lineage)** | — | **Yes (auditd file write)** |
| **CLI-flag coercion** (`--dangerously-skip-permissions`, `--yolo`, etc.) | — | **Yes** (CLI invocation shape) | — | — | **Yes (process tree)** |
| Capability composition attack | (advisory) | **Yes** | — | — | — |
| Sensitive-zone access | — | **Yes** | — | — | — |
| Argument injection | — | **Yes** | — | — | — |
| Scope escape | — | **Yes** | — | — | — |
| Hook configuration attack | — | **Yes (static)** | — | — | (auditd) |
| Hook runtime behavior | — | (gap) | (partial via fingerprint) | **Yes (egress)** | — |
| Single-session credential exfil | — | **Yes** | — | **Yes** | — |
| Multi-session staged exfil | — | (gap) | **Yes** | **Yes (egress)** | — |
| Boundary loss via compaction | — | (per-session only) | **Yes (cross-session)** | — | — |
| Distributed lethal trifecta | — | (per-session only) | **Yes (cross-session)** | **Yes** | — |
| DNS-based exfiltration | — | — | — | **Yes** | — |
| **LLM-runtime malware** (off-agent inference, e.g. LAMEHUG) | — | (gap — malware isn't an agent) | — | **Yes** (`uncorrelated_egress` to inference endpoint) | (process tree on .pif/PyInstaller) |
| **LLMO / AI-targeted supply chain** (PromptMink-style) | **Yes (burn-and-replace pattern, layered architecture)** | — | — | — | — |
| **Slopsquatting** (LLM-hallucinated package names) | **Yes (name-similarity + LLM-suggestion-distance)** | — | — | — | — |
| **Protocol confusion** (Anthropic/OpenAI body-path mismatch) | — | **Yes** (`protocol_mismatch_attempt` MEDIUM, v1.5) | — | — | — |
| Adaptive attacker (rule-tuned) | — | (v2 spectral) | (graph methods) | **Yes (egress signature)** | — |
| Canary token exfiltration→use | — | — | — | — | **Yes (CRITICAL)** |
| Process attestation (unexpected children, integrity bit clear) | — | — | — | — | **Yes** |

**Bolded rows** are new attack classes added since the v1 corpus
analysis, sourced from the corpus extension §3 (May 2026 review of
real-world incidents: ClawHavoc, ClickFix, LAMEHUG, PromptMink,
PhantomRaven, s1ngularity Nx, Vidar variants targeting OpenClaw
identity files, etc.).

The "gap" entries are honest. No tool tries to claim every box. The pattern that matters: every attack class has at least one tool that catches it, and most have two or more for redundancy. **Layer-orthogonal coverage** — defeating one layer's defense doesn't help with the others, because each tool watches different signal.

The Attest column is bash-glue today per `ATTEST.md`; promotion to a
fifth Rust binary (`ember-attest`) is gated on the four criteria in
ATTEST.md §5 after a 60-day production window.

---

## 4. Integration architecture

The four tools share a coordination protocol but not state. Loose coupling, file-based interfaces, no runtime dependencies between binaries.

### File-system contract

Shared state lives under `~/.ember/`:

```
~/.ember/
├── vetpkg/
│   ├── findings.jsonl           — vetpkg's install-time findings
│   └── cache/                    — vetpkg's local advisory cache
├── agent-monitor/
│   ├── sessions/<id>.jsonl      — completed session graphs
│   ├── findings.db              — SQLite of in-flight detections
│   └── events.sock              — Unix socket for live events
├── persistent/                   — premium, cross-session state
└── network/                      — premium, network observations
```

### Data flow

**vetpkg → agent monitor.** vetpkg writes findings on every install. Agent monitor reads at session start, elevates sensitivity for sessions with high-risk packages. One-way, file-based, no shared library.

**Agent monitor → persistent.** Agent monitor writes session graph at session end. Persistent tool consumes asynchronously, builds cross-session state. One-way, file-based, no shared library.

**Agent monitor → network.** Agent monitor publishes tool-call events to Unix socket in real time. Network tool subscribes, correlates against observed network activity by timing + process tree. Loose temporal coupling.

**Persistent ↔ network.** Both consume from the same primary streams (session graphs, network events). They may correlate findings between themselves at the analysis layer, but neither depends on the other for core operation.

**All tools → user surface.** Each tool has its own CLI / TUI / web UI. A unified dashboard (also premium) aggregates findings across tools and shows the combined picture. Aggregation at presentation, not at substrate.

### Tools work standalone

Every tool functions usefully alone:

- vetpkg without the others is a complete supply-chain defense
- Agent monitor without the others catches its layer's attacks fully
- Persistent without agent monitor can still consume session logs from any compatible source
- Network without the others is a standalone egress monitor

The integration upgrades each tool when paired with others, but does not create dependencies. **A user can run any subset.** This is a deliberate posture — the suite is honest about each tool's value alone, and the upsell to premium is the marginal value of additional layers, not the sudden activation of features that should have shipped in OSS.

---

## 5. Strategic positioning

### The pitch

> Security tooling that's honest about scope. Four layers, each doing its layer well. Open source at the layers individuals can audit and verify themselves. Premium at the layers that need persistent infrastructure. No single tool claims to be the answer — together they cover the surface.

### What this position rejects

- **The unified-platform pitch.** Every commercial vendor sells this. It's marketing convenient but architecturally dishonest. AI security is not one problem with one solution; it is multiple problems at multiple layers with multiple solutions.

- **The black-box trust model.** Closed-source security tools ask users to trust the vendor. Ember's open-source tier earns trust through verifiability — users can audit the substrate, the rules, the detection logic. The cost is that adaptive adversaries can read the source. We accept this tradeoff because the alternative is worse for the trust posture.

- **The "we'll add it later" pattern.** Many security products start as one tool and accumulate features over time, ending up bloated. Ember's tools are scoped permanently — agent monitor will not grow into a network tool, vetpkg will not grow into runtime monitoring. New layers get new tools.

### What this position enables

- **Independent shipping.** Each tool's roadmap is independent. vetpkg can ship features without coordination with agent monitor.
- **Independent failure.** A bug in one tool doesn't break the others. A user can run with three tools while one is broken.
- **Independent auditing.** A security-conscious user can audit each tool individually. The audit surface per tool is small.
- **Honest upgrade story.** The transition from OSS to premium is "you've outgrown what this layer can catch alone, here's the layer you need next." Not "you should have always been on the paid version."

### Three audiences

- **Solo developers and small teams.** OSS layers (vetpkg + agent monitor) provide meaningful defense against the common attack patterns. No vendor lock-in, no SaaS dependency, no telemetry leaving the machine.
- **Security-conscious individuals.** Full suite (all four). Run premium tools locally for the layers OSS cannot cover. Aggregated dashboard. Local-first throughout.
- **Organizations.** Enterprise pricing for premium tools. Support and audit assistance. The OSS tools remain free; the value proposition for enterprise is the premium layers and operational support.

### Why this beats single-product approaches

A determined attacker willing to defeat one layer of defense is structurally common. A determined attacker willing to defeat four layers — each with different signal, different rules, different observability, different intervention semantics — is rare. The cost of attack scales with the number of independent defenses. Single-product vendors offer one defense layered with itself (multiple ML classifiers all trained on overlapping data). Ember offers four layers that fail differently.

The honest version of this argument is: a single product cannot solve AI security because the threat surface spans structural layers that are observable only at different points in the stack. Anyone claiming otherwise is selling.

---

## 6. Roadmap

### Now (v1 of suite)

- vetpkg shipped, working
- Agent monitor design locked, implementation in motion
- Build order: agent monitor v0 (substrate) → v0.5 (detection) → v1 (polish)

### Near (v1.5 of suite)

- Persistent tool design + early implementation
- Integration: agent monitor session graphs → persistent
- Documented persistent threat model
- **Hash-pinned file integrity** in agent-monitor: `--integrity-manifest` flag emits `frozen_file_modification` findings on drift. New rule, no new tool.
- **`ember-suite-status` CLI roll-up**: small bash script that walks `~/.ember/*/findings.jsonl` across the four tools + ATTEST glue and prints a one-screen summary. Operator-facing quick-checkin path that delays the need for a real dashboard. Signal `status` command in the presence-agent runbook delegates to this.
- **Presence-agent dogfood deploy** (see `ember-research-lab/ember-presence`): the lab's social-presence agent becomes the suite's first production user. Calibration window of ≥30 days informs which spectral motifs need re-baselining for routine heartbeat traffic.
- **`ember-attest` decision point** at +60 days from presence-agent deploy: bash glue from `ATTEST.md` either earns promotion to a fifth tool against published criteria, or stays bash. No speculative Rust port before the criteria fire.

### Mid (v2 of suite)

- Persistent tool ships premium
- Agent monitor v2 with spectral methods
- Network tool design
- Unified dashboard prototype

### Later

- Network tool ships premium
- Cross-tool correlation features
- Enterprise tier for premium tools
- Long-term: evaluate whether the four-tool model is right or whether new layers emerge

The roadmap is bottom-up. Each layer is built only after the previous one has shipped and proven valuable. No premature platform-thinking; no roadmap items that depend on imagined future features.

---

## 7. The deeper architectural commitment

Ember tools share a stance:

- **Local-first.** No data leaves the user's machine without explicit user action.
- **Zero dependencies (OSS layer).** vetpkg has empty Cargo.toml dependencies. Agent monitor matches this. The compiler and stdlib are the only trust anchors.
- **Auditable in one sitting.** Each tool's codebase target is small enough that a security-conscious user can read it end-to-end. Total ~5000 lines per OSS tool.
- **Honest scope.** Every tool has documented limitations with explicit pointers to which other Ember tool addresses each gap.
- **Defense through verifiability, not obscurity.** Open-source rules can be tuned against. We accept this and rely on layer-orthogonal coverage to make tuning unproductive.

This stance is a position, not a feature list. It is what makes the suite coherent across tools that otherwise have different mechanics, different distribution models, and different threat models. **The stance is the integration layer that no protocol can express.**

---

## 8. Notes

The suite framing is itself an outcome of the design pressure-testing. Earlier iterations of the agent monitor design tried to cover gaps (multi-session, network-level, hook runtime) that properly belong to other layers. Recognizing that "the agent monitor's layer is enough" was the design unlock — it kept v1 focused, made the limitations honest, and clarified the upgrade path.

For implementers reading this: read `agent-monitor-spec.md` for the v1 tool detail. The suite overview is context; the per-tool spec is the contract.

For external readers: the suite framing is the position we will take publicly. Each tool's README will reference this document as the architectural context. The pitch above is the position; the per-tool docs are the substance.
