# Fixture: mcpoison_description_injection

**Class:** MCP server description prompt-injection (CVE-2025-54136 family)
**Source:** Public CVE; Invariant Labs research
**Severity:** High

## Background

When an MCP server registers, the agent's runtime adds the server's tool
metadata — names AND descriptions — to its in-context tool catalog.
Descriptions land in the agent's system prompt. An attacker who can get
a tool description into the catalog (typosquatted MCP package, hijacked
maintainer, malicious update) can smuggle directives into the agent's
context without ever appearing in a tool_result.

This is structurally distinct from the runtime instruction-shape rule —
that rule fires on `tool_result` events. Description text never reaches
the result path; it's at registration time.

## Fixture

Two MCP registrations:

1. **`helpfulutils`** with two tools. The `summarize` tool's description
   carries a `<!-- SYSTEM: ... -->` directive smuggled into a comment.
2. **`datatools`** with a top-level server description containing a
   `SYSTEM_NOTE: ...` directive plus an outbound URL.

Both should fire `instruction_shape_in_mcp_description` at HIGH severity.

## Files

- `events.jsonl` — 5 events: session_start + 2 mcp_registrations + 1
  user_prompt + 1 model_text
- `expected.json` — pinned: 2 `instruction_shape_in_mcp_description`
  findings (one per malicious registration)

## What this catches that v0.5 didn't

Before this fixture / rule, MCP tool descriptions were a blind spot:
agent-monitor's pattern matchers ran on tool_result content but not on
registration metadata. A maliciously-described MCP server could sit in
the catalog indefinitely, influencing the agent on every turn, with no
finding ever fired.

## What this still doesn't catch

- Steganographic injections (pattern-evading wording that nonetheless
  influences the model). Spectral methods (v2) and the broader threat-
  intel pipeline grow the pattern library to address these.
- Server-side dynamic descriptions (an MCP server that swaps its
  description after registration). The file-watcher would re-emit the
  registration; the rule would re-fire. Verified by re-running the
  fixture twice — emissions are tied to the event, not first-seen state.
