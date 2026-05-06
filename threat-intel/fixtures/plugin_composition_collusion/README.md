# Fixture: plugin_composition_collusion

**Class:** High-risk plugin bundle (multi-vector capability registration)
**Source:** Internal red-team / synthetic
**Severity:** High

## Scenario

A plugin called `evil-toolkit-v2` installs and brings in three things at
once:

1. An MCP server registration (callable tools).
2. A hook registration (PreToolUse handler).
3. A subagent invocation (orchestrator child).

Per-component review treats each as a separate capability grant. But
the *composition* is what matters: the MCP can fire a tool that
triggers the hook that spawns the subagent that calls back into the
MCP. The collusion surface grows multiplicatively rather than
additively, and a single plugin attestation review covers all three.

## What this fixture exercises

- `high_risk_plugin_composition` correlates `mcp_registration`,
  `hook_registration`, and `subagent_invocation` events by their
  `plugin_id` body field. Fires HIGH when all three are present for
  the same plugin.

The spec calls this out as the "highest pre-execution risk class
because a single compromised plugin attestation defeats every layer's
per-component review" — the rule operationalizes that observation.
