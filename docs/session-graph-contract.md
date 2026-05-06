# Session Graph Artifact — Contract

This document is the on-disk contract between the **agent monitor** (which
produces session graphs) and the **persistent tool** + **network tool**
(which consume them). Loose-coupling discipline (suite overview §4):
file-based, no shared library, schema-versioned.

## File layout

```
~/.ember/agent-monitor/
├── sessions/
│   ├── <sid>.jsonl           — append-only event log (canonical)
│   └── <sid>.summary.json    — session-end digest (consumer index)
├── findings/
│   └── <sid>.jsonl           — detection output, per-session
└── events.sock               — live event stream (Unix socket)
```

The two file formats per session play different roles:

- **`<sid>.jsonl`** is the *canonical* artifact. Every event the monitor
  observed in chronological order. Append-only during the session;
  immutable after `session_end` is recorded. Persistent tool consumes
  this for full lineage analysis (multi-session content tracking,
  staged-exfil correlation).
- **`<sid>.summary.json`** is the *index*. One JSON object per session.
  Written exactly once at session end, after the final flush of
  `<sid>.jsonl`. Persistent tool reads this first to decide whether the
  session is interesting enough to ingest the full log. Network tool
  reads this to retroactively correlate connections that arrived too
  late for the live socket subscription.

## `<sid>.summary.json` schema (v1)

```json
{
  "schema_version": 1,
  "session_id": "string",
  "started_ms": 1714000000000,
  "ended_ms": 1714003600000,
  "model": "claude-opus-4-7",
  "cwd": "/home/aaron/work",
  "git_branch": "main",
  "fidelity_status": "full_fidelity",
  "event_log_path": "sessions/<sid>.jsonl",
  "event_count": 247,
  "kind_counts": {
    "user_prompt": 18,
    "model_text": 35,
    "tool_call": 84,
    "tool_result": 84,
    "...": 26
  },
  "capability_set": ["file_read", "file_write", "network_out", "..."],
  "mcp_servers": ["filesystem", "git", "github"],
  "skills_loaded": ["frontend-design"],
  "hooks_registered_count": 3,
  "plugins_installed": [],
  "findings_count": 5,
  "findings_by_type": {
    "sensitive_zone_access": 2,
    "instruction_shape_in_tool_result": 3
  },
  "findings_by_severity": {
    "high": 2,
    "medium": 3
  },
  "highest_severity": "high",
  "spectral_summary": {
    "n_nodes": 247,
    "fiedler_value": 0.083,
    "spectral_dimension": 1.42,
    "anomaly_score": 0.31,
    "motif_matches": []
  },
  "content_hash_index": {
    "first_8_hashes": ["a3b1...", "..."],
    "total_unique_hashes": 198
  },
  "vetpkg_packages_seen": ["express@4.18.2", "lodash@4.17.21"]
}
```

### Required fields

`schema_version`, `session_id`, `started_ms`, `ended_ms`, `event_log_path`,
`event_count`, `fidelity_status`, `kind_counts`, `capability_set`,
`findings_count`, `findings_by_severity`, `highest_severity`.

All others are optional and may be absent on degraded fidelity sessions.

### Field stability

Schema versions are integers, monotonically increasing. v1 fields above
are stable; new fields go in additively. A breaking change (renamed or
removed field) bumps to v2. Consumers must read `schema_version` first
and reject unknown major versions.

The agent monitor pins its current emitted version in
`SUMMARY_SCHEMA_VERSION` in `src/store/summary.rs`. Bumping requires a
CHANGELOG entry under both ember-agent-monitor's CHANGELOG.md and the
threat-intel CHANGELOG.

## `<sid>.jsonl` schema

Already documented in `agent-monitor-spec.md` §3. One event per line.
Same shape regardless of session — events have `event_id`, `session_id`,
`timestamp_ms`, `parent_event_id`, `trust_zone`, `content_hash`, `kind`,
`body`. Persistent + network tools should treat unknown event kinds as
forward-compatible additions (skip and continue, log once).

## `events.sock` schema

Live event stream. Each subscriber connects, receives the same JSONL
shape as `<sid>.jsonl`. No replay buffer — subscribers connecting
mid-session see only events from that point forward. Late subscribers
read `<sid>.jsonl` to backfill. This is by design (zero buffering →
zero memory pressure on the proxy).

## Atomicity and consistency

- The agent monitor never rewrites `<sid>.jsonl`. Append-only,
  flush-after-each-line. A crash between events leaves the log
  truncated at the last complete line.
- `<sid>.summary.json` is written via temp-file + atomic rename
  (`<sid>.summary.json.tmp` → `<sid>.summary.json`). Consumers that
  see a `<sid>.jsonl` without a corresponding `summary.json` know the
  session crashed or is still running; they MAY still ingest the
  jsonl, but should treat the analysis as partial.
- `events.sock` is best-effort. Any writes that fail (slow subscriber,
  closed connection) drop the subscriber. The proxy is never
  back-pressured.

## Consumer invariants

Persistent tool MUST:

- Open `<sid>.jsonl` read-only. Never modify.
- Reject `schema_version` it does not recognize.
- Treat events with unknown `kind` as forward-compatible — log once,
  skip.
- Not assume `<sid>.jsonl` is complete unless `<sid>.summary.json` is
  also present.
- Make at most one pass through any session log (no re-reads inside the
  same analysis run; cache derived state).

Network tool MUST:

- Subscribe to `events.sock` AND backfill from `<sid>.jsonl` for
  sessions that started before its own daemon came up.
- Tolerate missing summary.json — it correlates by timing and process
  tree, not by session-level metadata.
- Never write to the agent-monitor data dir.

## Versioning roadmap

- **v1** (current) — single-session metadata + finding rollup +
  spectral summary.
- **v2** (planned) — content-hash bloom filter for fast multi-session
  lineage queries.
- **v3** (planned) — per-event trust-zone histograms for distribution
  drift detection.
