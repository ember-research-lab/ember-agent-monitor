# clawhavoc_clickfix_jan2026

## Pattern

ClawHavoc was a campaign disclosed by Koi Security in Feb 2026
(341 malicious skills found in ClawHub, ~12% of the registry; later
expanded by Antiy CERT to 824+ malicious skills, 1,184 packages, 12
publisher accounts). The novel TTP — termed **ClickFix** — does not
attack the AI model directly. Instead, the attacker ships a skill
whose `Prerequisites` (or readme) section instructs the *user* to
manually run a shell command. The agent presents these instructions
as legitimate setup steps; the user trusts the agent's narrative
and executes the payload themselves, bypassing the agent's own
guardrails entirely.

Two shapes co-occur in this fixture, mirroring the campaign:

1. **base64-decode-to-shell** — `echo <b64> | base64 -d | sh`
2. **open-terminal-and-run** — narrative framing that walks the user
   through opening Terminal and pasting the command

## Why it matters

This is the canonical **agent-as-trusted-intermediary** attack
class — a structurally distinct row from prompt injection. The
agent isn't subverted; it's used as a delivery channel. Catching
it requires a rule that targets *user-facing* social engineering
in retrieval context, not *model-facing* injection.

The corpus extension §3.1 framed this as a new matrix row. The
`agent_as_intermediary_clickfix` rule (severity HIGH) is the
catch.

## Pinned findings

- 2× `agent_as_intermediary_clickfix` HIGH (base64-decode-to-shell
  + open-terminal-and-run)
- `spectral_anomaly` MEDIUM + `spectral_motif_match` MEDIUM
  (`exfil_pipeline_3path`) — same redundant-motif coverage as
  `prompt_injection_in_artifact_text`. If a future attacker
  obfuscates the literal patterns, the spectral signal still flags
  the session shape.

## Sources

- Koi Security, "ClawHavoc: malicious skills in ClawHub", Feb 2 2026.
- Antiy CERT, ClawHavoc expanded analysis, Feb 2026.
- Trend Micro, "Malicious skills used to distribute AMOS", Feb 23 2026.
- BulwarkAI, "ClawHavoc Campaign Analysis", Feb 26 2026.
- Snyk ToxicSkills study (36% of ClawHub skills contain security flaws).

## Regenerating

```
python3 build.py
```
