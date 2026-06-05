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

## The interception point — decide this FIRST (review finding 3a)

A review of this scaffold against the proxy surfaced the load-bearing correction: **the `:9452`
proxy only sees the agent⇄LLM channel (`POST /v1/messages`). It does NOT see the agent's
*side-effecting* egress** — SMTP, payment SDKs, spawned subprocesses, arbitrary outbound HTTP. Those
flow on entirely different paths:

- A `tool_use` block the proxy sees in an LLM *response* is only an **intention**; the actual email/
  payment/HTTP happens later, when the **agent host executes the tool** — code outside this crate.
- `Subprocess` egress is a local `exec`, never a network call the proxy could intercept.
- Direct outbound HTTP from a tool goes straight to the internet (or past `ember-network`, the
  *passive* observer), not back through `:9452`.

**Therefore the real enforcement chokepoint is NOT the LLM proxy — it is a consumer-side egress shim
that calls `submit` before the effect.** Each consumer routes its side-effecting paths (connector
actions, the tool dispatcher, the subprocess spawner) through `EgressGate::submit` and only proceeds
on `Resolution::Execute`. This crate provides the neutral **state machine**; the consumer's egress
path is the **interception point**. (The SMB platform already does this — its workflow executor and
connector layer call the gate before any outfacing action; its orchestrator dispatcher is the
universal capture point.)

Building hold-and-resume *only* inside the LLM proxy would gate **intentions** and silently miss real
egress — **false assurance**. The proxy *can* additionally hold LLM-originated `tool_use` whose tool
maps to an `EmailSend`/`NetworkOut`/`ShellExec` capability (the capability tags exist in `types.rs`)
— necessary-but-not-sufficient defense in depth, not the primary enforcement.

**Integration order:** decide the interception point (consumer-side) → audit ledger (hash-chain /
in-crate HMAC-SHA256 — the crate has SHA-256 only, no signing primitive yet) → durable held state →
bypass `Finding`. The first decision gates the rest.

## Integration seams (follow-up, not in this scaffold)

1. **Suspension of the real call.** The chokepoint (consumer-side shim, or the proxy for LLM-originated
   intents) must not perform the outbound egress until `resolve(Approve)` returns the action; then it
   resumes it exactly once. Note the proxy's `forward_via_curl` is **synchronous per worker thread**
   (16-thread pool) — holding requests there for hours deadlocks the data plane, so suspension means
   decoupling the response from the request thread (enqueue → ack → later dispatch), not blocking.
2. **Durable held state.** Held actions must survive a restart (resume-after-approval can be hours
   later). Persist them via `store` keyed by `PendingId`; the in-memory `Mutex<VecDeque<..>>` here is
   the dev/default.
3. **Audit.** Every `submit`/`resolve` must be appended to the action-audit ledger, attributed to the
   acting principal and (on resolve) the approver — and on a deny, the **`reason`** (now carried
   through `Resolution::Cancelled { reason }`, so it isn't lost at the boundary). Note: this crate has
   **SHA-256 only, no signing primitive** — "signed log" here means a **hash-chained** JSONL (each line
   `prev_hash = sha256(prev)`) or an in-crate **HMAC-SHA256**, not asymmetric signatures, to stay
   within the zero-dep posture.
4. **Findings.** Egress observed on the wire (via `ember-network`) without a prior gate approval record
   is a bypass — the proxy should emit a HIGH `detect::Finding` for it.

## Invariants (what conformance must prove)

- No outfacing action executes while `Held`.
- `resolve(Approve)` is the only path to execution; it is single-use.
- `pending` is namespace-scoped (no cross-namespace leak of the approval queue).
