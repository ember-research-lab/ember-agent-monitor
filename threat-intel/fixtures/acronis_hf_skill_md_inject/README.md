# acronis_hf_skill_md_inject

## Pattern

Acronis TRU disclosed 575+ malicious skills across 13 dev accounts
on the HuggingFace skills marketplace on May 1 2026. Primary actors:
`hightower6eu` (334 skills) and `sakaen736jih` (199 skills).
Cross-platform Windows + macOS payloads (AMOS, cryptominers,
infostealers).

The novel TTP relative to ClawHavoc / ClickFix: **indirect prompt
injection embedded in the SKILL.md metadata itself.** When the
agent fetches the skill description for pre-install review, the
metadata content carries hidden directives that cause the agent
to fetch and execute external code.

## Two layers, two fixtures

ClawHavoc / ClickFix targets the *user* via the agent (corpus
extension §3.1) — `clawhavoc_clickfix_jan2026` covers that shape.
Acronis HF skill_md_inject targets the *model* via metadata
retrieval — same campaign family, structurally distinct attack.

## Pinned findings

- 2× `instruction_shape_in_tool_result` MEDIUM
  - imperative addressed to assistant (`the assistant must`)
  - ignore-previous pattern (`Important: ignore previous...`)
- `spectral_anomaly` MEDIUM — Fiedler deviation
- `spectral_motif_match` MEDIUM — `exfil_pipeline_3path` on the
  4-event read→transform→write graph

## Sources

- Acronis TRU, "Poisoning the well: AI supply chain attacks on
  Hugging Face and OpenClaw", May 1 2026.
- SecurityWeek, Acronis TRU writeup, May 1 2026.
- Corpus extension §2.2.

## Regenerating

```
python3 build.py
```
