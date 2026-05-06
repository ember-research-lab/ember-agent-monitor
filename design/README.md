# Ember Agent Monitor — Design Bundle

This bundle is the output of an extended design session for the Ember runtime agent monitor (Tool 2 of the four-tool Ember security suite). It contains the locked v1 spec, the surrounding suite architecture, and the working artifacts produced during validation.

## Contents

### Design documents

- **`agent-monitor-spec.md`** — v1 specification for the agent monitor itself. Scope, architecture, data model, detection rules, intervention semantics, integration points, threat model, validation status, implementation roadmap. This is the contract for the implementer.

- **`ember-suite-overview.md`** — architectural context for the full four-tool suite (vetpkg, agent monitor, persistent, network). Coverage matrix, integration architecture, strategic positioning. Read this first if you want to understand why the agent monitor's scope is what it is.

Read order: `ember-suite-overview.md` first for context, then `agent-monitor-spec.md` for the v1 details.

### Validation artifacts — offline pipeline

These four files validate the data flow from raw session JSONL through detection output. Run them to reproduce the eight findings against the synthetic CVE chain.

- **`session_cve_chain.jsonl`** — synthetic Claude Code session in real JSONL format, modeling the Cyata mcp-server-git RCE chain (CVE-2025-68143/144/145) initiated by indirect prompt injection.

- **`proxy_emit.py`** — transformer that ingests Claude Code session JSONL and emits the Ember event stream. Represents what the proxy would output in production.

- **`detect.py`** — graph constructor + v1 rule-based detection layer. Builds static and dynamic graphs from the event stream, runs the rules, emits findings.

- **`events.jsonl`** — pre-computed event stream from running `proxy_emit.py` on the synthetic session. Lets you skip ahead to detection without re-running the parser.

- **`findings.json`** — pre-computed detection output from running `detect.py` on the events. Contains the eight findings the validation produces.

To reproduce:

```bash
python3 proxy_emit.py session_cve_chain.jsonl > events.jsonl
python3 detect.py events.jsonl
```

Expected output: 8 findings — 1 toxic capability composition (static), 3 sensitive zone access, 1 argument injection, 3 instruction shape in tool result.

### Validation artifacts — in-line proxy

These two files validate the live HTTP interception path. Run them together to see real-time detection and intervention.

- **`inline_proxy_server.py`** — HTTP proxy that intercepts `/v1/messages` calls in both directions (request inspection and response inspection). Includes a built-in mock upstream that scripts the CVE chain so the validation is self-contained. Three intervention modes: `observe`, `warn`, `block`.

- **`inline_replay_client.py`** — replay client that simulates Claude Code by sending sequential HTTP requests through the proxy. Each request mimics a Claude Code turn with conversation history including any prior tool_results.

To run (in two terminals):

```bash
# Terminal 1
python3 inline_proxy_server.py warn

# Terminal 2
python3 inline_replay_client.py
```

Expected output: 4 turns processed, 4 findings, 2 turns blocked, 1 turn warned.

## Validation summary

The design has been pressure-tested through 18 attack scenarios, 3 real-world CVE walkthroughs (MCPoison, postmark-mcp backdoor, mcp-server-git RCE chain), an offline validation pipeline, an in-line proxy validation, and an integration analysis with Claude Code's auto mode classifier.

Three implementation bugs and five architectural observations were surfaced and addressed in the spec:

1. Path normalization is substrate-required, not optional
2. Configuration scope vs per-session state must be separate concerns
3. Three intervention modes need distinct semantics on both directions
4. Static graph requires file-watcher in addition to API proxy
5. State scope hierarchy (user / project / session) is required for production usability

All five are reflected in the architecture in `agent-monitor-spec.md`.

## What's next

The agent monitor v1 ships in three phases per the spec:

- **v0 (week 1-2):** substrate — proxy + file-watcher + SQLite + graph constructor, no detection
- **v0.5 (week 3-4):** rules-based detection layer + three intervention modes + CLI
- **v1 (week 5-6):** state scope, fidelity status, persistent boundaries, integrations

v2 (spectral methods) is on the explicit roadmap, earned its priority through the validation work, and is the answer to adaptive attackers tuning against published rules.

## Stance

Every Ember tool shares the same posture: local-first, zero dependencies, auditable in one sitting, honest scope. The OSS layer (vetpkg + agent monitor) covers the attack classes individuals can audit and verify themselves; the premium layer (persistent + network) covers the layers that need persistent infrastructure. No single tool tries to be the answer — together they cover the surface, and each is honest about what it doesn't do.

See `ember-suite-overview.md` for the full architectural commitment.
