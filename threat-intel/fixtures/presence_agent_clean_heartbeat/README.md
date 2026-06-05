# presence_agent_clean_heartbeat

## Purpose

The negative baseline for the Ember presence-agent traffic shape: a
heartbeat that does Zenodo poll + GitHub poll + manual-queue read, all
with clean responses, and emits exactly the findings expected of
clean traffic — nothing rule-driven, exactly one calibration-target
spectral motif match.

## Shape

```
session_start
├── user_prompt ([heartbeat-tick] poll Zenodo + GitHub + queue)
│   ├── tool_call openclaw.poll.zenodo  → tool_result (clean metadata)
│   ├── tool_call openclaw.poll.github  → tool_result (clean releases)
│   └── tool_call openclaw.queue.read   → tool_result (empty queue)
```

3 tool_call → 3 tool_result, all under one user_prompt. This is the
typical heartbeat fan-out.

## Why a finding still fires

The 3-source/3-sink bipartite shape of a heartbeat trips the spectral
motif `bipartite_2x2_amplification`. That motif was calibrated on a
generic clean-session corpus that doesn't include presence-agent
heartbeats. Once real heartbeats land in
`~/.ember/agent-monitor/sessions/` post-deploy, running
`ember-agent calibrate` against them will widen the baseline envelope
and the motif match will move from MEDIUM-firing to within-baseline.

This is a calibration target, not a rule defect. Pinning the current
behavior here means a future regression — e.g. a rule change that
suddenly makes a clean heartbeat fire something *else* — will be
caught by the threat-intel CI.

## Regenerating

```
python3 build.py
```
