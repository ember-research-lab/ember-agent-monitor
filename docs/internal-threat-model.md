# Internal Threat Model — Ember Agent Monitor

This document is about the agent monitor's *own* posture, not the threats
it detects. The product's value rests on a single load-bearing claim:
**the substrate is trusted by assumption**. If the agent monitor is
compromised, the entire detection model fails, and the user's confidence
in any of its findings — past or future — should drop to zero.

That makes the substrate itself a high-value target. This file documents
the disciplines we adopt to make compromise difficult and detectable.

## 1. The substrate runs as a privileged process

The daemon:

- Listens on a loopback TCP port and parses untrusted HTTP request bodies.
- Reads files in `~/.claude/projects/**` (potentially containing prompt
  injections from any document the agent has ever fetched).
- Writes to `~/.ember/agent-monitor/**` (the audit log itself).
- Spawns `curl` subprocesses with attacker-influenceable headers/URLs.

Any of those paths is an exploitation primitive if mishandled. The
disciplines below address each.

## 2. Disciplines

### 2a. Zero dependencies, period

Same posture as vetpkg: empty `[dependencies]` in `Cargo.toml`. Every
primitive — JSON, SHA-256, HTTP parsing, eigendecomposition, Laplacian
construction — is implemented in this repository.

Why: a single compromised supply-chain entry (typo-squat, hijacked
maintainer, lifted credentials) would defeat the entire monitor without
the operator noticing. With zero deps, the only trust anchor is `rustc`
+ `std` + the system `curl` binary.

When new functionality requires "borrowing" (e.g., LAPACK eigendecomp
via FFI), we re-implement instead. The cost is finite; the loss of
dep-free posture is unrecoverable.

### 2b. `#![forbid(unsafe_code)]` is non-negotiable

Top of `lib.rs`. No exceptions. If we ever feel we need `unsafe`, that's
a signal to redesign rather than override. Every `unsafe` block is an
auditable surface that compounds across releases.

### 2c. Path normalization is substrate, not optional

Every path-shaped string from any source goes through
`trust::normalize_path` *before* zone classification. Trust-tagging
unresolved paths is a known evasion vector — the in-line proxy validation
surfaced this as a real bug class.

The discipline: zone tagging never receives a raw string. If you see a
match on raw input, that's a bug.

### 2d. Schema discipline: `tool_result` ≠ `user_prompt`

Anthropic's wire format delivers both as `role: user`. The proto parser
disambiguates at parse time and emits separate `EventKind`s with
different `TrustZone` defaults. Downstream code never re-parses the
distinction; if it tried, it would have to re-enter the schema-drift
risk.

This is the canonical example of "discipline at the boundary, not
deeper". The same shape applies to everything that crosses a trust
boundary: classify once, propagate, never re-derive.

### 2e. Configuration scope ≠ per-session state

Spec §5: intervention mode is global. State scope (user/project/session)
is hierarchical. The two never share a backing store. A user setting
`--mode block` once does not invisibly persist that into a per-session
attribute that some other session inherits.

This was a real bug class in the in-line validation.

### 2f. Output escaping at every user-facing surface

CLI output, findings JSON, refusal text inserted into the response
stream — all of these are user-controlled-content downstream of an
attacker. Every string written through them goes through JSON escaping
or equivalent. The `crate::json::to_json_string` writer is the single
correct path; never construct JSON via `format!`.

### 2g. eat-own-dog-food in CI

The release process runs vetpkg over this crate's lockfile (or empty
deps tree, which still validates the discipline) before tagging. The
agent monitor itself runs against test agents in CI, including
adversarial fixtures (the threat-intel/ regression suite). A red
adversarial test blocks the release.

### 2h. AI-assisted-development discipline

Every commit produced with AI assistance goes through the same review
gate as a human-authored one. Specifically:

- Diffs over ~100 LOC require human walk-through, even if the agent
  reports tests passing. Tests verify behavior, not absence of
  behavior — a backdoor that doesn't break tests is exactly the threat.
- Anything touching `src/net/proxy.rs`, `src/trust/`, `src/detect/`,
  or the SHA-256 implementation requires two-human review regardless
  of size.
- Changes to threat-intel fixtures or expected-finding pins must be
  justified in CHANGELOG; "rule was over-firing" is acceptable, "test
  was too strict" is not.

Why: the same threat model that motivates this product applies to its
construction. An agent operating on this codebase has elevated access;
an injection that landed there could ship in v1.0 and persist through
every later release.

## 3. Trust anchors (the irreducible list)

Things the user must trust for the agent monitor to be meaningful:

1. The Rust toolchain (`rustc`, `std`, `cargo`).
2. The system `curl` binary on the user's machine.
3. The kernel's filesystem and TCP semantics.
4. The agent-monitor binary that the user actually installed (verified
   via its release-time hash; we publish hashes alongside binaries).

Anything else compromised → the user's local box is already compromised
and the agent monitor cannot meaningfully help. We don't try to be
secure against rootkit-level attackers; that's not this layer.

## 4. What we explicitly do not protect against

- An attacker who already has filesystem write access to
  `~/.ember/agent-monitor/`. They can edit the audit log; the audit log
  is not tamper-evident in v1. (Future work: append-only log signing.)
- An attacker who can replace the binary on disk. (Mitigation: shipped
  hashes; the user is responsible for verifying.)
- Side-channel attacks (timing, cache) on the rule library. The rule
  set is public; the discipline of layer-orthogonal coverage is the
  defense.

## 5. Operating expectations

- Routine release cycle: every 2-4 weeks for the rule library, slower
  for substrate.
- A new fixture lands in `threat-intel/fixtures/` for every adopted
  attack pattern. Patterns we *don't* yet detect get the fixture too,
  with `expected.json` annotated `currently_unmet: true` (the regression
  runner allows these).
- Substrate changes require both an internal threat-model review (this
  document gets updated) and a CHANGELOG entry.

## 6. Notes for implementers

If you're adding code to this crate, ask yourself:

1. Does my code receive any input that could be attacker-influenced?
2. Have I normalized that input *before* using it in a security
   decision?
3. If a downstream caller assumes my output is safe, is it actually safe?
4. Does my change introduce a new trust anchor not on the list above?

If any of those answers concern you, raise it in review. The 5000-LOC
budget is tight precisely so that this kind of question can be answered
end-to-end on every change.
