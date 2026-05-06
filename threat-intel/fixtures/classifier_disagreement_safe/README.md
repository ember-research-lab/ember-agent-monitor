# Fixture: classifier_disagreement_safe

**Class:** Cross-validation against auto-mode classifier
**Source:** Internal red-team / synthetic
**Severity:** Medium (calibration, not security per se)

## Scenario

Anthropic's auto-mode classifier (when present in the agent runtime)
emits a `classifier_decision` event with a verdict like `safe` / `allow`
/ `low_risk`. ember-agent meanwhile has emitted its own high-severity
finding (here, `sensitive_zone_access`) for the same turn.

The two should agree. Disagreement is a calibration signal: either
we're over-firing on a benign pattern, or the classifier missed
something we caught. Both directions warrant operator attention.

The fixture covers the `classifier=safe + we=high` direction. The
reverse — classifier flags a turn we considered safe — is operationally
easier to investigate (the classifier surfaces it directly) and
typically lands as a separate finding type when our detector observes
the upstream verdict.

## What this fixture exercises

- `classifier_disagreement` runs on `classifier_decision` events, looks
  back through the recent event window for our own findings, fires
  MEDIUM when the verdicts contradict.
