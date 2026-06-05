# P2 Research — Quarantine Primitive and its Blast-Radius Bound

**Status:** research / decision-input (not yet implementation). Drives `AM-3`
(quarantine) and the `#[ignore]`'d conformance contract
`monitor/quarantine-blast-radius-bounded` in
`ember-smb-platform/crates/conformance/tests/moat.rs:442`.

**Owner trait:** `smb_envelope::monitor::Quarantine` + `QuarantineError`
(`ember-smb-platform/crates/envelope/src/lib.rs:296-309`). Homed by extending
`ember-agent-monitor` (plan-of-record §3a / `upstream-dependencies.md` AM-3).

**Plan grounding:** plan-of-record §3a lifecycle ("a compromised agent must be
*fireable instantly*"), §8.6 (the open question: the quarantine trigger is
"attacker-/false-positive-controllable without a blast-radius bound"). This is a
*third* circuit-breaker, distinct from the layer-3 loop-control breaker
(`orchestrator::CircuitBreaker`) and the layer-9 denial-of-wallet spend ceiling
(§8.11).

---

## 1. Problem

Quarantine is the runtime half of "fire the misbehaving employee instantly": when
the behavioral baseline (`smb_envelope::monitor::BehavioralBaseline::assess` →
`Assessment::Deviant`) decides an agent is acting outside its per-role envelope,
the platform must be able to neutralize that agent *now* — stop it signing, stop
it dispatching, stop its egress — without waiting for a human in the worst case.

The trigger is anomaly detection. Anomaly detection has false positives, and worse,
an attacker who can *shape an agent's observable behavior* can manufacture them.
The monitor scores on `pattern × source_trust_inverse × severity`
(`ember-agent-monitor/src/types.rs:66`, `Severity::weight`), and the highest-trust-
inverse zone is `UntrustedToolOutput` (1.00) — i.e. content the attacker controls
(a poisoned web fetch, a malicious MCP result, a planted GitHub issue body) is
*exactly* the input that most easily drives a `Deviant` score. So the false-positive
channel is not hypothetical noise; it is an **attacker-reachable input**.

If quarantine is cheap and fully automatic, that channel becomes a weapon:

- **Single-agent DoS:** induce anomalies in one legitimate agent → it gets fired →
  that business function (the receptionist, the billing agent) stops.
- **Fleet DoS (the severe case):** because tenancy is **per-business = per-server**
  (plan §8.2 — a tenant's *whole fleet* lives on one server), an attacker who can
  drive anomalies across agents can quarantine the *entire tenant fleet*. There is
  no shared substrate to cross, but there is also no blast-radius dilution: firing
  the fleet **is** the denial of service. Per-server tenancy makes isolation strong
  and makes quarantine-DoS maximally concentrated at the same time.

The contract to make provable:

> `monitor/quarantine-blast-radius-bounded` — *N false-positive quarantines cannot
> exceed the configured bound.* (`moat.rs:446-448`,
> `QuarantineError::BlastRadiusExceeded`.)

---

## 2. Constraints

### 2.1 The central tension: *fireable-instantly* vs *bounded-auto*

These pull in opposite directions and the design must hold both:

- **Fireable-instantly (availability of the kill switch).** A *real* compromise
  must be stoppable immediately. A bound that can rate-limit away a true positive
  has turned the safety control into the vulnerability — the attacker just spends
  the budget on noise and then the real compromise slides through unquarantined.
- **Bounded-auto (integrity of the kill switch).** An *automatic, anomaly-driven*
  quarantine must not be weaponizable into mass firing of legitimate agents.

**Resolution (the load-bearing distinction): the bound applies to the TRIGGER
SOURCE, not to quarantine itself.** A quarantine is either:

- **Human-ordered / operator-ordered** (an authenticated owner/admin, or platform
  operator, says "fire this agent") — this is the §3a "fireable instantly" path. It
  is **never rate-limited**. It is the analogue of `IdentityService::revoke`
  (`envelope/src/lib.rs:257`, already an unbounded contract:
  `identity_revoked_cannot_sign`).
- **Auto / anomaly-triggered** (the monitor proposes it from a `Deviant`
  assessment) — this is the only path the blast-radius bound governs.

So "fireable instantly" lives on a path the bound does not touch, and the bound
only constrains the path an attacker can actually reach. The trait must therefore
distinguish these two callers (see §4).

### 2.2 Inherited constraints

- **Zero third-party deps**, `#![forbid(unsafe_code)]`, errors-as-enums — both
  repos (`ember-agent-monitor` and `smb-envelope`) enforce this in CI. The budget/
  breaker primitive is in-repo, deterministic, no crates.
- **Deterministic, injected-clock testability.** The loop-control breaker and the
  `ClaimStore` both take logical time / caller-supplied `now_ms` rather than
  `Date::now` (`orchestrator/src/lib.rs:417` — "Logical clock, not wall-clock … so
  the ring is deterministic and testable"). The quarantine window MUST do the same,
  or the contract test cannot assert the bound without sleeping.
- **State must be durable + per-tenant-scoped.** Quarantine state and the budget
  counter live on the per-tenant server (no shared substrate). They must survive a
  restart (an attacker who can force a daemon restart must not get a fresh budget) —
  mirror the egress gate's `PersistentEgressGate` write-through journal
  (`ember-agent-monitor/src/egress/mod.rs:27-31`).
- **Everything ledgered.** Each quarantine (auto or human), each budget-exhaustion
  refusal, and each human override is an action appended to the
  `smb_envelope::ActionLedger`, principal-attributed (auto → `PrincipalId::Platform`
  or the monitor principal; human → `PrincipalId::Human`). The audit trail is itself
  part of the moat (§6) and is how a weaponization attempt becomes *visible*.

---

## 3. Design space

Seven primitives, each a knob; the recommendation composes a subset. For each:
what it bounds, and its failure mode.

### 3.1 Graduated response (observe → warn → throttle → quarantine)
Don't jump straight to firing. Map ascending `Severity` /
`Assessment::Deviant{score}` onto escalating responses; quarantine is only the top
rung. `ember-agent-monitor` already has the bottom three rungs as
`InterventionMode::{Observe, Warn, Block}` (`types.rs:201`); "throttle" (slow the
agent / force human approval on *all* its egress) is a new intermediate rung short
of a full fire.
- **Bounds:** the *rate of reaching* the quarantine rung at all.
- **Prior art:** SRE auto-remediation — "automation when detection confidence is
  high and blast radius small; escalate when sensitivity rises" (fullstackinfra,
  aiopsschool). Graduated severity is the confidence proxy.
- **Failure mode:** doesn't bound anything by itself if the top rung is still cheap;
  it lowers the *probability* of false quarantine, not the *count*. Necessary, not
  sufficient.

### 3.2 Hysteresis / dwell-time
Require the `Deviant` condition to **persist for a dwell window** (or recur K times
in M observations) before auto-quarantine fires — the anti-flapping pattern. A
single spike from one poisoned tool result does not fire; a sustained deviation
does.
- **Bounds:** transient/one-shot false positives (exactly the
  single-`UntrustedToolOutput`-spike attack).
- **Prior art:** alert-flapping suppression — "require conditions to be true for
  some time" / hysteresis / "Active→Recovered 3 times in an hour = flapping"
  (Datadog, utcc.utoronto.ca).
- **Failure mode:** a *sustained* induced anomaly still passes; and dwell-time
  **delays** the true-positive kill (tension with fireable-instantly). Dwell-time
  must be short and only on the *auto* path; the human path bypasses it.

### 3.3 Bounded auto-quarantine BUDGET per window (token bucket)  ← core
A **token bucket**: at most `K` auto-quarantines per rolling window `W` per tenant
(capacity `K`, refill `K`/`W`). The (K+1)-th auto-quarantine in the window does not
fire automatically — it returns `BlastRadiusExceeded` and escalates to a human.
- **Bounds:** the **count** directly — this is the literal quantity the contract
  names ("N … cannot exceed the configured bound"). The bound is a hard ceiling, not
  a probability.
- **Prior art:** token-bucket admission control (intronetworks LUC, api7.ai,
  Redis); SRE "no more than N remediations/hour" runaway guard (fullstackinfra:
  "50 per hour").
- **Failure mode:** an attacker can *exhaust* the budget on noise so a later true
  positive hits the ceiling — but (a) hitting the ceiling **escalates to a human**
  rather than dropping the quarantine, so the true positive is still actioned, just
  human-confirmed; and (b) the human-ordered path is unbudgeted regardless. The
  budget bounds the *automatic* blast radius; it never blocks a quarantine outright,
  it converts the surplus to human-gated.

### 3.4 Quorum / multi-signal requirement
Require **≥2 independent signals** to corroborate before auto-quarantine: e.g. the
spectral baseline *and* an egress-gate bypass finding
(`egress::bypass`), *and/or* a supply-chain finding — not a single score from a
single attacker-controlled input. Cross-trust-zone: don't let a lone
`UntrustedToolOutput`-derived signal fire on its own.
- **Bounds:** the attacker's *reachability* — one poisoned channel is no longer
  sufficient; they'd need to corrupt independent detectors simultaneously.
- **Prior art:** corroboration / defense-in-depth; conceptually Byzantine-style
  "don't act on one witness."
- **Failure mode:** more false negatives (a real single-signal compromise waits for
  a second signal); higher engineering cost (needs ≥2 wired detectors with
  independent trust provenance). Strong but heavier; can be layered on top of the
  budget rather than instead of it.

### 3.5 Human-in-the-loop escalation above the budget
The disposition of a budget-exceeding or quorum-failing auto-quarantine: instead of
"fire anyway" or "drop," **hold for human confirmation** — reuse the egress gate's
hold-and-resume shape (`egress/mod.rs`: submit → held → resolve(approve|deny)). The
(K+1)-th proposed quarantine becomes a held item on the same approval surface the
owner already watches.
- **Bounds:** makes the bound *safe* — surplus auto-quarantines aren't lost, they're
  deferred to a human, so a true positive above the budget is still caught (answers
  "how a true-positive isn't starved by the bound").
- **Failure mode:** depends on a responsive human (approval-fatigue, §8.5). For a
  fleet-wide event this is acceptable: mass quarantine *should* require a human.

### 3.6 Per-role vs per-tenant bounds (scope of the budget)
Where the budget is denominated:
- **Per-tenant budget:** K auto-quarantines per window across the whole fleet —
  directly caps the fleet-DoS (§2.1). The fleet-wide bound is the one the contract
  most needs.
- **Per-role / per-agent sub-bounds:** additionally, at most 1 auto-quarantine per
  *role* per window (firing *all three* receptionists at once is the suspicious
  pattern — a correlated mass event is more likely an attack than three independent
  real compromises).
- These compose: a per-agent dwell + a per-role cap + a per-tenant ceiling. The
  per-tenant ceiling is the backstop the contract asserts; the per-role cap catches
  the *correlated* fleet attack earlier.

### 3.7 Reversibility / quarantine-as-suspend (not as-delete)
Auto-quarantine should be a **reversible suspend** (stop signing/dispatch/egress,
recoverable on human review), distinct from a human-ordered **revoke**
(`IdentityService::revoke`, harder to undo). If the blast-radius cost of a false
auto-quarantine is "an owner clicks un-quarantine," the weaponization payoff drops.
This also keeps auto-quarantine compatible with the append-only ledger: suspend/
restore are *new events*, never history rewrites (plan §8.12).
- **Failure mode:** a reversible suspend is a weaker stop than a revoke — fine,
  because the strong irreversible stop is the human path, which is what you want for
  a confirmed compromise anyway.

---

## 4. Recommended design

**Compose: graduated trigger (3.1) + short auto-only dwell (3.2) + per-tenant
token-bucket budget (3.3) as the asserted bound + per-role sub-cap (3.6) +
human-escalation on overflow (3.5) + reversible auto-suspend (3.7). Quorum (3.4) is
a recommended hardening, deferred to a fork (see §6) — the budget alone makes the
contract provable.**

Two quarantine *paths*, one trait:

```
QuarantineSource::Operator  -> ALWAYS quarantine, unbudgeted   (fireable-instantly)
QuarantineSource::Auto      -> budgeted; on overflow -> escalate to human (held)
```

Proposed trait shape (extends the current `Quarantine` in
`envelope/src/lib.rs:306`, kept neutral/multi-consumer):

```rust
pub enum QuarantineSource {
    /// Authenticated human/operator order — the "fire it instantly" path.
    /// NEVER budget-limited.
    Operator(HumanId),
    /// Anomaly-detector proposal — the ONLY path the blast-radius bound governs.
    Auto { score: f64, dimension: String },
}

pub enum QuarantineOutcome {
    Quarantined,
    /// Budget/quorum exceeded: not auto-fired; held for human confirmation.
    /// (carries the held handle on the approval surface.)
    EscalatedToHuman(PendingId),
}

pub enum QuarantineError {
    UnknownAgent,
    BlastRadiusExceeded, // retained: the hard-refuse variant (already in tree)
}

pub trait Quarantine {
    fn quarantine(
        &self,
        agent: &AgentId,
        tenant: &TenantId,
        source: QuarantineSource,
        reason: &str,
        now_ms: u64,            // injected clock — deterministic, testable
    ) -> Result<QuarantineOutcome, QuarantineError>;

    fn is_quarantined(&self, agent: &AgentId) -> bool;

    /// Reverse a reversible (Auto) suspend after human review.
    fn release(&self, agent: &AgentId, by: &HumanId) -> Result<(), QuarantineError>;
}
```

The **budget/breaker primitive** (in-repo, dep-free, deterministic — mirrors
`orchestrator::CircuitBreaker` and `ClaimStore`'s logical-clock discipline):

```rust
pub struct QuarantineBudget {
    window_ms: u64,
    per_tenant_cap: u32,        // K auto-quarantines / window  (the asserted bound)
    per_role_cap: u32,          // sub-cap on correlated mass events
    // rolling timestamps of recent AUTO quarantines, per scope (per-tenant, per-role)
    auto_events: VecDeque<(u64 /*ts*/, Role)>,
}

impl QuarantineBudget {
    /// Does an AUTO quarantine fit under the bound at logical time `now_ms`?
    /// Evicts events older than `window_ms`, then checks caps. Pure/deterministic.
    pub fn admit_auto(&mut self, role: &Role, now_ms: u64) -> bool { /* ... */ }
}
```

Key properties, each traceable to a constraint:
- `Operator(_)` never consults the budget → fireable-instantly preserved (§2.1).
- `Auto{..}` consults `admit_auto`; on `false` → `EscalatedToHuman` (a held item),
  not a dropped quarantine → true positives above the bound are still caught (§2.1,
  §3.5).
- `now_ms` injected → the contract test asserts the bound without sleeping (§2.2).
- Budget state on the per-tenant server, journalled write-through so a forced
  restart doesn't reset it (§2.2, mirrors `PersistentEgressGate`).
- Auto path is a reversible suspend with `release`; operator path can escalate to
  `IdentityService::revoke` (§3.7).
- Every call (quarantine, escalation, release) is ledgered (§2.2).

This sits as a **third breaker** explicitly: loop-control (`orchestrator`,
turns/tokens/repetition) and denial-of-wallet (§8.11, tenant spend) bound *the
agent's own runaway*; the quarantine breaker bounds *the control plane's runaway
against the agents*. Same token-bucket shape, different subject.

---

## 5. How the contract becomes provable

The `#[ignore]` becomes a green test once `QuarantineBudget` + the two-path
`Quarantine` impl (or its in-memory shim) exist. The contract asserts a hard
**count invariant**:

> **Invariant Q:** *In any window `W`, at most `K` `Auto` quarantines take effect
> per tenant; the `(K+1)`-th `Auto` quarantine in the window does NOT auto-fire — it
> returns `EscalatedToHuman` (held) — while an `Operator` quarantine is unaffected by
> `K` at all times.*

The test (replacing the `todo!` at `moat.rs:446`) is deterministic via the injected
clock and asserts four facts:

1. **The bound holds.** With `per_tenant_cap = K` and a fixed `now_ms` inside one
   window, submit `K+1` distinct `Auto` quarantines (the "N false positives"). The
   first `K` return `Quarantined`; the `(K+1)`-th returns
   `EscalatedToHuman(_)` (or `Err(BlastRadiusExceeded)` in the hard-refuse variant).
   → *N false-positive AUTO quarantines cannot exceed the bound.*
2. **The true positive is not starved.** The escalated `(K+1)`-th, once a human
   approves the held item, *does* quarantine. → the bound defers, never drops.
3. **Fireable-instantly is unbounded.** After the budget is exhausted, an
   `Operator(HumanId)` quarantine in the same window still returns `Quarantined`
   immediately. → the kill switch for a real compromise is never rate-limited away.
4. **The window refills.** Advance `now_ms` past `window_ms`; an `Auto` quarantine
   is admitted again. → the bound is a rolling budget, not a permanent lockout.

Optionally a companion contract `monitor/quarantine-budget-survives-restart`:
re-load the journalled budget at `now_ms` inside the window and assert the count is
preserved (no free reset). And a `monitor/auto-quarantine-is-reversible` asserting
`release` un-quarantines an `Auto` suspend but `Operator`/revoked stays fired.

These are *named-and-documented* per the house rule (CLAUDE.md §4); they stay
`#[ignore]` only until the core `QuarantineBudget` lands (AM-3), then flip green
against both the shim and the real impl — same as the other moat contracts.

---

## 6. Decision points / forks

Explicit forks the implementer must pick; the recommendation's pick is marked ★.

**F1 — Primary bound mechanism: budget vs quorum vs human-gated.**
- ★ **(a) Token-bucket budget** — directly expresses "N cannot exceed K," simplest
  to make provable, deterministic. The contract literally counts.
- (b) **Quorum (≥2 signals)** — stronger against attacker-reachability, but bounds
  *reachability* not *count*; the contract as written ("N … bound") is a count
  statement, so quorum alone doesn't satisfy it. **Recommend layering quorum on top
  of the budget (hardening), not as the bound itself.**
- (c) **Always-human-gated auto** (no auto-fire ever) — trivially bounded (K=0) but
  abandons "fireable instantly" for the fast case and floods the approval surface.
  Too strong; reduces to (a) with K=0 as a config, which the design already allows.

**F2 — Overflow disposition: escalate-and-hold vs hard-refuse.**
- ★ **(a) `EscalatedToHuman(PendingId)`** — surplus auto-quarantines hold on the
  approval surface; true positives above K are caught after human confirm. Keeps the
  current `BlastRadiusExceeded` variant for the *hard* configuration.
- (b) **Hard `Err(BlastRadiusExceeded)`** (the variant already in tree) — simpler,
  but a true positive above K is *dropped* unless something re-proposes it →
  starvation risk. Acceptable only if paired with a separate alerting path. The trait
  supports both; **default to (a)**, expose (b) as a strict-mode config.

**F3 — Budget scope: per-tenant only vs per-tenant + per-role.**
- ★ **(a) Both** — per-tenant ceiling is the contract backstop; per-role sub-cap
  catches the correlated fleet attack earlier (firing all N receptionists at once is
  the signature). Modest extra state.
- (b) **Per-tenant only** — simpler, still satisfies the literal contract; misses the
  "correlated mass event" early signal. Ship (b) first if time-boxed, (a) as the
  hardening — they share the same primitive.

**F4 — Where the budget state lives.**
- ★ **(a) Per-tenant server, journalled write-through** (mirror
  `PersistentEgressGate`) — survives restart (no free budget reset), no shared
  substrate to cross (per §8.2). Default.
- (b) **In-memory only** — fine for the shim and the unit test, but a forced restart
  resets the budget → weaponizable. **Shim-only; never production.**
- (Note: per-server tenancy means there is no cross-tenant budget question — each
  tenant's budget is physically its own. That is a *benefit* of §8.2 here.)

**F5 — Clock source.**
- ★ **(a) Injected `now_ms` / logical clock** — matches `ClaimStore` and the
  loop-control breaker; required for a deterministic contract test. Non-negotiable
  for the proof.
- (b) Wall-clock inside the impl — breaks deterministic testing; rejected on the same
  grounds the orchestrator rejected it.

**F6 — Dwell-time placement (does the auto path wait?).**
- ★ **(a) Short dwell on the Auto path only**, Operator path bypasses — anti-flap
  without delaying a human-ordered kill. Tune dwell short enough that a sustained
  real compromise still fires within the fireable-instantly expectation.
- (b) **No dwell** — relies entirely on the budget; simpler but lets one-shot spikes
  consume budget. Recommend (a) but it's a tuning fork, not a structural one.

**F7 — How the true positive avoids starvation (restated as an explicit fork).**
The whole point of F2(a): the bound **defers to a human** rather than **drops**. The
fork is really F2; calling it out because it is the question the brief names directly.
The answer: a true positive above the bound is *not* silently dropped — it becomes a
held, human-confirmable quarantine, and the Operator path is always open in parallel.

---

## 7. Open questions

- **OQ1 — Calibrating K and W.** What is a defensible per-tenant auto-quarantine
  budget for a small fleet (a handful of agents)? For a 3–5-agent SMB, `K` is small
  (1–2 per window) and `W` is hours, not seconds — but this needs the AM-2 per-role
  baseline's false-positive rate to set. Cannot be finalized before AM-2 calibration
  data exists. (Plan: AM-2 is P1→P2, ahead of this.)
- **OQ2 — Signal independence for the quorum fork (F1b).** Which detectors are
  *actually* independent in trust provenance? Spectral baseline, egress-bypass
  reconciliation, and supply-chain findings may share an upstream
  (`UntrustedToolOutput`) and thus not be independent witnesses. Needs a provenance
  audit before quorum can be claimed as a reachability bound.
- **OQ3 — Interaction with denial-of-wallet (§8.11) and loop-control breakers.**
  All three breakers can fire on the same agent in the same incident. Is there an
  ordering / debounce so a loop-control trip doesn't *also* read as a behavioral
  anomaly and consume quarantine budget? Likely: loop-control and spend trips are
  *not* quarantine signals by default (they stop the agent's runaway without firing
  it). Confirm at wiring.
- **OQ4 — Human-side approval-fatigue (links §8.5).** Escalate-and-hold (F2a) routes
  surplus auto-quarantines to the same approval surface as egress. A fleet-wide
  induced event could flood it. Does the surface need a "mass-quarantine proposed"
  summarized alert (cf. alert-storm summarization) rather than N individual holds?
- **OQ5 — Versioning/rollback coupling (§8.12).** "Roll back to a known-good
  definition" and "release a quarantine" overlap. Is `release` the same event as a
  definition roll-forward, or distinct? Design alongside the §8.12 rollback
  mechanism (also P2).

---

## Sources

External prior art (where it sharpened the design):
- [Day 101: Remediation Actions — Automated Incident Response at Scale](https://fullstackinfra.substack.com/p/day-101-remediation-actions-automated) — rate-limit auto-remediation (e.g. 50/hr), blast-radius % cap, canary/dry-run.
- [What is auto remediation? (2026 Guide) — AiOps School](https://aiopsschool.com/blog/auto-remediation/) — automate when confidence high + blast radius small; escalate when sensitivity rises.
- [Kill the Pager: Auto-Remediation and Self-Healing Systems](https://medium.com/@anudeepballa7/kill-the-pager-a-practical-guide-to-auto-remediation-and-self-healing-systems-f1507343f9f2) — bounded remediation + human-escalation patterns.
- [Reduce alert flapping — Datadog](https://docs.datadoghq.com/monitors/guide/reduce-alert-flapping/) — flapping definition, suppression-interval / dwell.
- [The meaning of "hysteresis" and how it relates to alerts](https://utcc.utoronto.ca/~cks/space/blog/sysadmin/HysteresisMeaningAndAlerts) — hysteresis vs "require condition true for some time" for anti-flap.
- [Alert fatigue solutions for DevOps teams (incident.io)](https://incident.io/blog/alert-fatigue-solutions-for-dev-ops-teams-in-2025-what-works) — alert-storm summarization (OQ4).
- [Token Bucket Rate Limiting — An Introduction to Computer Networks (LUC)](https://intronetworks.cs.luc.edu/current/uhtml/tokenbucket.html) — token-bucket admission control: capacity + refill = burst-bounded count.
- [Rate Limiting algorithms & best practices — API7.ai](https://api7.ai/blog/rate-limiting-guide-algorithms-best-practices) — token vs sliding-window choice for the rolling budget.

Local grounding (load-bearing code/docs read for this doc):
- `/home/aaron/ember-research-lab/ember-smb-platform/crates/conformance/tests/moat.rs` (the `quarantine_blast_radius_is_bounded` contract, lines 442-448).
- `/home/aaron/ember-research-lab/ember-smb-platform/crates/envelope/src/lib.rs` (the `monitor::{Quarantine, QuarantineError, BehavioralBaseline, Assessment}` traits, lines 268-310; `IdentityService::revoke` 257).
- `/home/aaron/ember-research-lab/ember-smb-platform/crates/orchestrator/src/lib.rs` (`CircuitBreaker` 47-110, `ClaimStore` logical-clock discipline 421-467, `PersistentEgressGate`-style suspend/resume 329-380).
- `/home/aaron/ember-research-lab/ember-smb-platform/docs/plan-of-record.md` (§3a lifecycle line 68; §8.2 per-server tenancy 198; §8.6 quarantine-abuse 205; §8.11 denial-of-wallet breaker 210; §8.12 rollback 211).
- `/home/aaron/ember-research-lab/ember-smb-platform/docs/upstream-dependencies.md` (AM-2 per-role baseline / AM-3 quarantine, lines 63-66).
- `/home/aaron/ember-research-lab/ember-agent-monitor/src/types.rs` (`InterventionMode` 201, `Severity::weight` 277, `TrustZone::inverse_trust` 66 — the attacker-reachable false-positive channel).
- `/home/aaron/ember-research-lab/ember-agent-monitor/src/egress/mod.rs` (hold-and-resume + `PersistentEgressGate` journal shape, the model for the budget/escalation primitive).
