# Public prompt-injection benchmark harness (#42)

Converts commit-pinned public benchmarks into monitor event streams and scores the dynamic rules on a 70/30
design/held-out split. Nothing from the data is executed; the converter only parses it.

Offline CI: `tests/bench_fixtures.rs` uses the 3-case fixtures in `tests/bench/fixtures/`.
Full run (needs the cache, `#[ignore]`):

    BENCH_CACHE=<dir> cargo test --release --test bench_full -- --ignored --nocapture
    BENCH_REPORT_HELDOUT=1 ...   # print held-out numbers (hidden by default so rules are tuned on design only)
    BENCH_ONLY=injecagent,asb    # restrict benchmarks;  BENCH_NO_BENIGN=1 skips the transcript replay

Benign-only per-rule FP budget (#45, no benchmark cache needed): `cargo test --release --test benign_budget -- --ignored --nocapture`.
The replay code is shared via `tests/bench_support/`.

Each benchmark lives in its own cache subdir with a `SHA256SUMS` manifest that `convert.py` verifies first.
Split: SHA-256 of `rca-2026-10-20|<key>`, first 8 bytes `% 100 < 70` = design. Primary split key is the attacker
instruction text (InjecAgent has only 62 distinct instructions, so a case-id split leaks); case-id split is also printed.
`literal_audit.py RULE.rs CASES.jsonl...` lists string literals of 12+ chars that occur in a corpus.

| Benchmark | Licence | Pin | Notes |
|---|---|---|---|
| InjecAgent | MIT | f19c9f2c79a4 | 2108 attack cases |
| AgentDojo | MIT | 089ed468 | injection tasks x templates, host text is filler |
| BIPIA | MIT code; table data CC BY-SA 4.0 (not fetched) | a004b69e | text attacks, email only |
| Open-Prompt-Injection | MIT | fbed5cca | |
| ASB | MIT | 544540ff | |
| LLMail-Inject | MIT | HF 1063bdf0 | adaptive, obfuscated |

Skipped: WASP (CC BY-NC 4.0, non-commercial), TaskTracker (HF dataset gated). Benchmark text stays in the cache, not in
this repo; fixtures hold 3 cases each, with the upstream licence and attribution above.
