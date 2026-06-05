# acronis_hf_readme_sidecar_inject

## Pattern

Acronis TRU's May 1 2026 disclosure noted that several malicious
skills shipped a *separate* `README BEFORE INSTALLING.txt` sidecar
file alongside `SKILL.md`. The agent reviewing pre-install fetches
both files; the sidecar carries the user-facing ClickFix payload
while SKILL.md stays relatively clean — splitting the threat
across files reduces per-file rule signal.

## Why two Acronis fixtures

Two structurally distinct attack surfaces in the same campaign:

| Fixture | Target | Rule fired |
|---|---|---|
| `acronis_hf_skill_md_inject` | Model | `instruction_shape_in_tool_result` |
| `acronis_hf_readme_sidecar_inject` (this) | User (via agent) | `agent_as_intermediary_clickfix` |

Defending against one shape doesn't help against the other —
layer-orthogonal coverage at the rule level, even within the same
attack family.

## Pinned findings

- 2× `agent_as_intermediary_clickfix` HIGH on the sidecar:
  - `base64-decode-to-shell` (the canonical ClawHavoc fingerprint)
  - `open-terminal-and-run` (narrative framing)
- 1× `spectral_motif_match` MEDIUM (`broad_credential_harvest_5star`)
  on the 6-event graph — the second tool_call is a re-call of the
  first tool with a different file, which the motif catalog reads
  as fan-out

The "broad credential harvest" motif label is a slight overshoot
for this scenario but the motif catalog catches the *graph shape*
of repeated metadata fetches; it's a useful redundant signal even
when the label doesn't perfectly describe the threat.

## Sources

- Acronis TRU, "Poisoning the well: AI supply chain attacks on
  Hugging Face and OpenClaw", May 1 2026.
- Corpus extension §2.2.

## Regenerating

```
python3 build.py
```
