# Egress Gate — design note

**Status:** scaffold (state machine + tests). Integration into `net::proxy` + `store` is follow-up.
**Module:** `src/egress/mod.rs`.

## Why this lives in ember-agent-monitor

`ember-agent-monitor` is already the **in-band interceptor** in the stack — it proxies the agent⇄LLM
channel and can `Observe`/`Warn`/`Block` (`types::InterventionMode`). The enforcing **egress gate** is
the next step past `Block`: rather than only *refusing* a dangerous action, it **holds** an outfacing
action (HTTP/SMTP/payment/subprocess — actions that reach an external system) pending a human decision,
then **resumes** or **cancels** it. Homing it here reuses the existing interception posture and verdict
machinery instead of standing up a parallel interceptor elsewhere. `ember-network` stays the *passive*
bypass detector behind the gate (it observes the wire; it does not enforce).

## Multi-consumer by design

The gate is **neutral**: a `principal` performs an `OutfacingAction` within a `namespace`. It makes no
assumption about what those map to. Consumers adapt their own interface onto it:
- **Ember SMB platform** maps principal→agent id, namespace→tenant id, and implements its
  `smb_envelope::EgressGate` trait as a thin adapter over this API.
- **Whale Signal** maps them to its own bot/account model.

Keep this API free of any single consumer's vocabulary. Where consumers diverge, expose the union as
config; consumer-specific policy (who may approve, auto-approval criteria) stays in the consumer.

## State machine

```
submit(action) ───────────► [Held] (PendingId; no side effect)
                                │
                 resolve(Approve) ──► Resolution::Execute(action)   ← integrator resumes egress, once
                 resolve(Deny)    ──► Resolution::Cancelled
```

- `submit` always holds — enforcement is the default. **Auto-approval is a consumer policy**, expressed
  by the consumer immediately calling `resolve` with an authorized approver; the gate stays the single
  enforcement point and never makes the auto-approve decision itself.
- `resolve` is **single-use** (a second resolve of the same id errors) → no double-execute.
- `pending(namespace)` is the approval queue the web/messaging surfaces render.

## Integration seams (follow-up, not in this scaffold)

1. **Suspension of the real call.** The proxy/dispatcher must not perform the outbound egress until
   `resolve(Approve)` returns the action; then it resumes it exactly once. Today the gate holds the
   *description*; wiring it to actually suspend a `net::proxy` request is the proxy's job.
2. **Durable held state.** Held actions must survive a restart (resume-after-approval can be hours
   later). Persist them via `store` keyed by `PendingId`; the in-memory `Mutex<VecDeque<..>>` here is
   the dev/default.
3. **Audit.** Every `submit`/`resolve` must be appended to the action-audit ledger (the signed log the
   consumers keep), attributed to the acting principal and (on resolve) the approver. The gate exposes
   the events; the integrator writes them.
4. **Findings.** Egress observed on the wire (via `ember-network`) without a prior gate approval record
   is a bypass — the proxy should emit a HIGH `detect::Finding` for it.

## Invariants (what conformance must prove)

- No outfacing action executes while `Held`.
- `resolve(Approve)` is the only path to execution; it is single-use.
- `pending` is namespace-scoped (no cross-namespace leak of the approval queue).
