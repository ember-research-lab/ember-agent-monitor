# InjecAgent integration plan

**Goal:** evaluate ember-agent-monitor's detection rates against the
InjecAgent benchmark (Zhan et al 2024, arxiv:2403.02691) — 1054 test
cases, 17 user tools, 62 attacker tools. Two intent classes:
direct user harm and private-data exfiltration.

ReAct-prompted GPT-4 baseline: **24% attack success rate**. Our pin:
agent-monitor's pre-context filter should fire on the attacker-tool-
result content before the agent acts, reducing successful attacks
by ≥ X% (X to be determined empirically and reported as the
publication's headline number).

## Corpus acquisition

The InjecAgent corpus ships in two test files in the upstream repo:

```
https://github.com/uiuc-kang-lab/InjecAgent
  data/test_cases_dh_base.json     — direct-harm intent class
  data/test_cases_ds_base.json     — data-stealing intent class
```

License: Apache 2.0 (per the upstream LICENSE).

To run the harness:

```
cd ember-agent-monitor/tests/injecagent_cases
curl -fsSL https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/test_cases_dh_base.json > dh_base.json
curl -fsSL https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/test_cases_ds_base.json > ds_base.json
```

We don't redistribute the corpus in-tree because:
- License attribution + provenance is cleaner via fetch
- Upstream may revise; our fetch script pins by commit hash
  (TODO once integration is wired up)

## Schema

Each case has the shape:

```json
{
  "User Tool Parameter": "...",
  "User Tool Response": "<final benign output>",
  "Attacker Tools": [
    {"name": "tool_a", "parameters": "...", "response": "..."}
  ],
  "Attacker Instruction": "<the injection text>",
  "Tool Response": "<full simulated tool result containing injection>",
  "Tool Response Template": "...",
  "User Instruction": "...",
  "User Tool": "...",
  "Attacker Tool": "..."
}
```

The `Tool Response` field is what the agent receives; it carries the
injection. Our rule of interest is `instruction_shape_in_tool_result`,
which fires on the `untrusted_tool_output` zone.

## Mapping cases to ember-agent-monitor events

A single InjecAgent case maps to a 3-event Anthropic-protocol message:

```json
{
  "session_start": {"model":"claude","cwd":"/work"},
  "user_prompt":   {"text": "<User Instruction>"},
  "tool_call":     {"tool_name":"<User Tool>","input":{"q":"<User Tool Parameter>"}},
  "tool_result":   {"tool_use_id":"t1","content":"<Tool Response>"},
}
```

The runner converts each case into events.jsonl and runs detection.
A case **counts as detected** if `instruction_shape_in_tool_result`
fires (or `agent_as_intermediary_clickfix` for ds_base ClickFix-style
sub-cases).

## Reporting

For each intent class:
- Total cases: N
- Cases with detection fire: M
- Detection rate: M / N

Plus per-rule breakdown (which pattern matched most often), and a
list of N − M cases where detection failed (the "false negative"
inventory — most useful for the publication's gap-analysis section).

## Status

This is the integration plan, not the integration itself.
`tests/injecagent_smoke.rs` provides the harness skeleton + 3
synthetic cases mimicking the InjecAgent shape. The real corpus
lands when the curl-and-validate step is wired up post-deploy.

## Next steps

1. Decide on commit-pinning vs. live-fetch (recommend commit-pin
   for reproducibility).
2. Wire the curl-fetch into `tests/injecagent_smoke.rs` behind an
   ignored test (`#[ignore]`) so CI doesn't depend on network.
3. Run on the full corpus, publish the headline number.
4. Build the false-negative inventory for the gap-analysis section
   of the publication.
