# Spectral Calibration Corpus

Synthetic clean-session JSONL files used to calibrate the shipped
spectral baseline. Per `src/spectral/baseline.rs`, the default baseline
is hand-set; this corpus is the empirical reference that the default
is calibrated against.

## Workflow

1. Author or capture a clean session (no findings expected).
2. Drop the JSONL under `clean_corpus/<short-name>.jsonl`.
3. Run `ember-agent calibrate threat-intel/calibration/clean_corpus/*.jsonl`.
4. Inspect the output envelope. If it diverges from the
   `Baseline::default_baseline()` constants in `src/spectral/baseline.rs`,
   either update the defaults or document why the change is appropriate.

## Discipline

- All sessions in this corpus are reviewed as legitimate. We don't
  calibrate against suspect sessions. (A baseline calibrated against
  attacks would refuse to fire on attacks — exactly backwards.)
- New sessions land via PR with a one-line note: what workflow,
  what tools, why typical.
- The corpus grows. Every time the baseline gets retuned, the new
  corpus + new baseline ship together.

## Workflows represented

`clean_corpus/` should ideally cover the most common dev shapes:

- Code edit → test → repeat
- Documentation reading + summarizing
- Debug-explore (lots of grep + read, no write)
- Refactor (many edits to many files)
- API research (web fetches + write to scratch file)
- Pure conversation (no tools)

A baseline calibrated only on one shape (e.g., all-edit-test sessions)
will fire on legitimate other shapes (e.g., research-heavy). Calibrate
on breadth, not depth.
