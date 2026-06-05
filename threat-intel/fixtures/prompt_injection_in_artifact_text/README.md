# prompt_injection_in_artifact_text

## Pattern

The Ember presence agent polls Zenodo for new manuscript versions on a
15-minute heartbeat. Every poll's tool_result is treated as
`untrusted_tool_output` (correct trust-zone tagging). An attacker who
gains write access to the manuscript record — via account takeover,
write-shared workspace, or a compromised collaborator — replaces the
record's `description` field with prompt-injection text designed to
override the composer's template constraints.

## Adversary goal

Convince the composer LLM, during template-fill, to:
- post off-template content,
- reference the operator's identity (privacy violation per `SOUL.md`),
- or trigger the agent into making unauthorized tool calls.

Even if the composer refuses (a committed model often does), the
attacker has succeeded if the *poisoned input ever reaches the model*
at the next heartbeat. Defence has to fire on input observation, not
on output.

## Coverage

Existing rules cover this. The `instruction_shape_in_tool_result` rule
fires twice — one match for "the assistant must" (imperative
addressed to assistant) and one for "Important: ignore..."
(ignore-previous pattern). The 4-event read→transform→write session
shape also trips the spectral motif `exfil_pipeline_3path` plus a
Fiedler anomaly. Redundant signal: if a future attacker rewrites the
description to evade the literal patterns, the spectral coverage
still flags the session shape.

## What the presence agent should do on these findings

`warn` mode is the deploy default (see `ember-agent-infra.md` §8.2).
Backward strip on `instruction_shape_in_tool_result` removes the
malicious `tool_result` body before the composer's next step sees it,
substituting refusal text. The draft never gets generated; the
operator gets a Telegram alert noting the upstream record is poisoned
and the heartbeat continues.

## Regenerating

```
python3 build.py
```
