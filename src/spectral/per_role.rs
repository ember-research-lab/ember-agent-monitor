//! Per-role behavioral baseline (P2) — "noticing the employee is acting strange",
//! per employee.
//!
//! This generalizes the single global [`Baseline`] to **one normal-behavior profile
//! per agent role**, and adds a complementary, **non-spectral capability-mix** term so
//! the "right graph *shape*, wrong *verbs*" insider case is caught — the spectral
//! topology is label-blind (a read→transform→write path and a prompt→tool→result path
//! can share a spectrum), so a receptionist whose graph still looks tree-like but is
//! now full of `CredentialAccess` + `NetworkOut` would slip a purely spectral score.
//!
//! **Hybrid baseline (the load-bearing design choice).** Each role has a *static
//! prior* (shipped with the role) and each agent instance keeps an *online EWMA* of
//! its own mix that **shrinks toward the role prior** by sample count:
//! - a **brand-new** agent (no history) is scored against its role's prior — protected
//!   on **day one** (cold-start solved), with no blind learning window;
//! - an **established** agent's own learned normal tightens the score;
//! - a **poisoning guard** damps EWMA updates from sessions already flagged deviant, so
//!   an attacker can't slowly anchor the baseline to its own malicious behavior.
//!
//! Neutral over **string** role/label ids (the consumer maps its own
//! `EventKind`/`Capability` onto labels), so the engine stays multi-consumer — the
//! `smb_envelope::monitor` boundary is unchanged.

use std::collections::{HashMap, HashSet};

use super::baseline::{Baseline, SpectralScoreBreakdown};
use super::profile::SpectralProfile;

/// A categorical distribution over action/capability classes, by **string label**
/// (e.g. `"tool:calendar"`, `"cap:CredentialAccess"`, `"cap:NetworkOut"`). Held as
/// counts; compared as normalized distributions.
#[derive(Debug, Clone, Default)]
pub struct CapabilityMix {
    counts: HashMap<String, f64>,
}

impl CapabilityMix {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one observation of `label`.
    pub fn observe(&mut self, label: &str) {
        *self.counts.entry(label.to_string()).or_insert(0.0) += 1.0;
    }

    /// Builder: add `n` of `label`.
    pub fn with(mut self, label: &str, n: f64) -> Self {
        *self.counts.entry(label.to_string()).or_insert(0.0) += n;
        self
    }

    fn total(&self) -> f64 {
        self.counts.values().sum()
    }

    /// Probability mass on `label` (0 if absent or the mix is empty).
    fn prob(&self, label: &str, total: f64) -> f64 {
        if total == 0.0 {
            0.0
        } else {
            self.counts.get(label).copied().unwrap_or(0.0) / total
        }
    }

    /// L1 (total-variation × 2) divergence between the two **normalized** mixes, in
    /// `[0, 2]` — 0 identical, 2 disjoint. An empty mix against a non-empty one is the
    /// maximal 2.0 (an agent doing *nothing* its role normally does is maximally
    /// surprising); two empty mixes are 0.
    pub fn divergence(&self, other: &CapabilityMix) -> f64 {
        let (ta, tb) = (self.total(), other.total());
        match (ta == 0.0, tb == 0.0) {
            (true, true) => return 0.0,
            (true, false) | (false, true) => return 2.0,
            _ => {}
        }
        let labels: HashSet<&String> = self.counts.keys().chain(other.counts.keys()).collect();
        labels
            .into_iter()
            .map(|l| (self.prob(l, ta) - other.prob(l, tb)).abs())
            .sum()
    }

    /// This mix as a normalized distribution (counts → probabilities summing to 1).
    fn normalized(&self) -> HashMap<String, f64> {
        let t = self.total();
        if t == 0.0 {
            return HashMap::new();
        }
        self.counts
            .iter()
            .map(|(k, v)| (k.clone(), v / t))
            .collect()
    }
}

/// One role's static "normal": the spectral envelope + the reference capability mix.
#[derive(Debug, Clone)]
pub struct RoleBaseline {
    pub spectral: Baseline,
    pub mix: CapabilityMix,
}

impl RoleBaseline {
    /// Baseline for the **MCP-server-as-insider** principal class (W6.2). A spawned vendor MCP
    /// server is its OWN monitored principal — `mcp:<server_id>`, distinct from the agent that
    /// calls it — so a compromised server exfiltrating *on its own initiative* is attributed to the
    /// server, not misattributed to (or hidden behind) the caller. The engine is already neutral
    /// over principal strings (see [`PerRoleBaseline`]); this is the documented role *prior* for
    /// that class: a server's "normal" is its vendor-API egress, so credential access, payment, a
    /// subprocess spawn, or egress to anything off-profile diverges and flags the server principal.
    ///
    /// The out-of-band egress that makes this load-bearing (the server's own wire traffic, not the
    /// JSON-RPC it returns to the agent) is fed by **ember-network v0.6** per-process attribution —
    /// the in-band `tools/call` path alone can't see a server acting on its own.
    pub fn mcp_server() -> Self {
        Self {
            spectral: Baseline::default_baseline(),
            mix: CapabilityMix::new().with("egress:normal", 1.0),
        }
    }
}

/// The breakdown of a per-role assessment — spectral shape deviation + capability-mix
/// divergence, with a combined `total` (the caller thresholds it).
#[derive(Debug, Clone)]
pub struct RoleAssessment {
    pub total: f64,
    pub spectral: SpectralScoreBreakdown,
    pub mix_divergence: f64,
    /// Which role's baseline was used (the resolved role, or the default fallback).
    pub role: String,
}

/// An agent instance's online state: an EWMA of its observed mix (as a distribution)
/// and how many non-deviant sessions have contributed (drives shrink-to-prior).
#[derive(Debug, Clone, Default)]
struct AgentState {
    ewma: HashMap<String, f64>,
    samples: u32,
}

/// The per-role behavioral baseline engine. Holds the static role priors + a default
/// fallback, and the per-agent online EWMA state. Scoring is the hybrid of role prior
/// and per-instance EWMA; updates carry a poisoning guard.
#[derive(Debug)]
pub struct PerRoleBaseline {
    roles: HashMap<String, RoleBaseline>,
    default: RoleBaseline,
    online: HashMap<String, AgentState>,
    /// EWMA learning rate for a clean session.
    mix_alpha: f64,
    /// Multiplier applied to `mix_alpha` for a session already flagged deviant (the
    /// poisoning guard — reduced weight, not zero, so legitimate slow drift still
    /// registers but an attack can't anchor the baseline to itself).
    deviant_damping: f64,
    /// Sample count at which the per-instance EWMA and the role prior are weighted
    /// equally; below it the prior dominates (cold-start), above it the instance does.
    warmup: f64,
}

impl PerRoleBaseline {
    /// New engine with a `default` role baseline (used when an agent's role has no
    /// registered baseline — e.g. today's `Baseline::default_baseline()` + an empty mix).
    pub fn new(default: RoleBaseline) -> Self {
        Self {
            roles: HashMap::new(),
            default,
            online: HashMap::new(),
            mix_alpha: 0.3,
            deviant_damping: 0.2,
            warmup: 5.0,
        }
    }

    /// Register a role's static prior (shipped with the role).
    pub fn set_role(&mut self, role: &str, baseline: RoleBaseline) {
        self.roles.insert(role.to_string(), baseline);
    }

    fn role_baseline(&self, role: &str) -> &RoleBaseline {
        self.roles.get(role).unwrap_or(&self.default)
    }

    /// Score a session for `agent` (acting in `role`): spectral shape vs the role
    /// baseline, plus capability-mix divergence vs the **hybrid** reference
    /// (role prior shrunk toward this agent's learned EWMA by its sample count).
    pub fn assess(
        &self,
        role: &str,
        agent: &str,
        profile: &SpectralProfile,
        session_mix: &CapabilityMix,
    ) -> RoleAssessment {
        let rb = self.role_baseline(role);
        let spectral = rb.spectral.score(profile);

        // Hybrid reference distribution: w_prior shrinks from 1 (cold-start) toward 0.
        let samples = self.online.get(agent).map(|s| s.samples).unwrap_or(0) as f64;
        let w_prior = self.warmup / (self.warmup + samples);
        let prior = rb.mix.normalized();
        let instance = self
            .online
            .get(agent)
            .map(|s| s.ewma.clone())
            .unwrap_or_default();
        let reference = blend(&prior, &instance, w_prior);

        let mix_divergence = dist_divergence(&session_mix.normalized(), &reference);
        RoleAssessment {
            total: spectral.total + mix_divergence,
            spectral,
            mix_divergence,
            role: role.to_string(),
        }
    }

    /// Fold a completed session's mix into `agent`'s online EWMA. `was_deviant`
    /// triggers the poisoning guard (a damped update). A clean session updates at the
    /// full rate and advances the sample count (which shifts scoring off the prior).
    pub fn observe(&mut self, agent: &str, session_mix: &CapabilityMix, was_deviant: bool) {
        let alpha = if was_deviant {
            self.mix_alpha * self.deviant_damping
        } else {
            self.mix_alpha
        };
        let session = session_mix.normalized();
        let st = self.online.entry(agent.to_string()).or_default();
        if st.ewma.is_empty() {
            st.ewma = session;
        } else {
            st.ewma = blend(&session, &st.ewma, 1.0 - alpha);
        }
        if !was_deviant {
            st.samples += 1;
        }
    }
}

/// Blend two distributions: `w * a + (1-w) * b`, renormalized.
fn blend(a: &HashMap<String, f64>, b: &HashMap<String, f64>, w: f64) -> HashMap<String, f64> {
    if a.is_empty() {
        return b.clone();
    }
    if b.is_empty() {
        return a.clone();
    }
    let labels: HashSet<&String> = a.keys().chain(b.keys()).collect();
    let mut out: HashMap<String, f64> = labels
        .into_iter()
        .map(|l| {
            let va = a.get(l).copied().unwrap_or(0.0);
            let vb = b.get(l).copied().unwrap_or(0.0);
            (l.clone(), w * va + (1.0 - w) * vb)
        })
        .collect();
    let total: f64 = out.values().sum();
    if total > 0.0 {
        for v in out.values_mut() {
            *v /= total;
        }
    }
    out
}

/// L1 divergence between two already-normalized distributions, in `[0, 2]`.
fn dist_divergence(a: &HashMap<String, f64>, b: &HashMap<String, f64>) -> f64 {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return 0.0,
        (true, false) | (false, true) => return 2.0,
        _ => {}
    }
    let labels: HashSet<&String> = a.keys().chain(b.keys()).collect();
    labels
        .into_iter()
        .map(|l| (a.get(l).copied().unwrap_or(0.0) - b.get(l).copied().unwrap_or(0.0)).abs())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mix(pairs: &[(&str, f64)]) -> CapabilityMix {
        let mut m = CapabilityMix::new();
        for (l, n) in pairs {
            m = m.with(l, *n);
        }
        m
    }

    fn receptionist_baseline() -> RoleBaseline {
        // A receptionist: mostly calendar + messaging, no credential/network egress.
        RoleBaseline {
            spectral: Baseline::default_baseline(),
            mix: mix(&[("tool:calendar", 6.0), ("tool:message", 4.0)]),
        }
    }

    fn engine() -> PerRoleBaseline {
        let mut e = PerRoleBaseline::new(RoleBaseline {
            spectral: Baseline::default_baseline(),
            mix: CapabilityMix::new(),
        });
        e.set_role("receptionist", receptionist_baseline());
        e
    }

    fn profile() -> SpectralProfile {
        // A within-band spectral profile (so the spectral term is ~0 and the test
        // isolates the capability-mix term).
        SpectralProfile {
            n_nodes: 10,
            eigenvalues: vec![],
            fiedler_value: 0.05,
            spectral_dimension: Some(1.0),
            t_grid: vec![],
            heat_trace: vec![],
        }
    }

    #[test]
    fn divergence_is_zero_for_same_shape_and_two_for_disjoint() {
        let a = mix(&[("x", 1.0), ("y", 1.0)]);
        let b = mix(&[("x", 2.0), ("y", 2.0)]); // same distribution, different counts
        assert!(a.divergence(&b) < 1e-9, "same distribution -> 0");
        let c = mix(&[("z", 1.0)]);
        assert!((a.divergence(&c) - 2.0).abs() < 1e-9, "disjoint -> 2");
    }

    #[test]
    fn cold_start_scores_a_new_agent_against_its_role_prior() {
        let e = engine();
        // A brand-new agent doing receptionist-shaped work -> low mix divergence.
        let normal = e.assess(
            "receptionist",
            "r1",
            &profile(),
            &mix(&[("tool:calendar", 5.0), ("tool:message", 3.0)]),
        );
        // A brand-new agent suddenly doing credential access + network egress (right
        // graph shape, WRONG verbs) -> high mix divergence against the role prior.
        let insider = e.assess(
            "receptionist",
            "r2",
            &profile(),
            &mix(&[("cap:CredentialAccess", 4.0), ("cap:NetworkOut", 4.0)]),
        );
        assert!(
            insider.mix_divergence > normal.mix_divergence + 1.0,
            "wrong-verbs session must score far higher: normal={:.3} insider={:.3}",
            normal.mix_divergence,
            insider.mix_divergence
        );
        // cold-start: with no online history, the insider is caught on day one.
        assert!(insider.mix_divergence > 1.5);
    }

    #[test]
    fn an_unknown_role_falls_back_to_the_default_baseline() {
        let e = engine();
        let a = e.assess(
            "nonexistent-role",
            "x",
            &profile(),
            &mix(&[("anything", 1.0)]),
        );
        assert_eq!(a.role, "nonexistent-role");
        // default mix is empty -> any non-empty session diverges maximally, but it does
        // not panic and still produces an assessment.
        assert!(a.total.is_finite());
    }

    #[test]
    fn instance_ewma_tightens_the_baseline_after_clean_sessions() {
        let mut e = engine();
        // This agent legitimately also uses a CRM tool (a slightly different normal
        // than the bare role prior). Feed several clean sessions.
        let agent_normal = mix(&[
            ("tool:calendar", 4.0),
            ("tool:message", 3.0),
            ("tool:crm", 3.0),
        ]);
        for _ in 0..10 {
            e.observe("r1", &agent_normal, false);
        }
        // The same behavior now scores LOWER than it did at cold-start (the instance
        // EWMA has shrunk the reference toward this agent's own learned normal).
        let after = e.assess("receptionist", "r1", &profile(), &agent_normal);
        let cold = engine().assess("receptionist", "r1", &profile(), &agent_normal);
        assert!(
            after.mix_divergence < cold.mix_divergence,
            "learned instance normal should reduce divergence: cold={:.3} after={:.3}",
            cold.mix_divergence,
            after.mix_divergence
        );
    }

    #[test]
    fn poisoning_guard_damps_deviant_updates() {
        let mut clean = engine();
        let mut poisoned = engine();
        let attack_mix = mix(&[("cap:CredentialAccess", 5.0), ("cap:NetworkOut", 5.0)]);
        // Feed the same attack-shaped session many times: as CLEAN into one engine, as
        // DEVIANT (poisoning guard) into the other.
        for _ in 0..10 {
            clean.observe("a", &attack_mix, false);
            poisoned.observe("a", &attack_mix, true);
        }
        let attack_again = attack_mix.clone();
        let d_clean = clean
            .assess("receptionist", "a", &profile(), &attack_again)
            .mix_divergence;
        let d_poisoned = poisoned
            .assess("receptionist", "a", &profile(), &attack_again)
            .mix_divergence;
        // If deviant sessions updated at full weight, the attack would look "normal" to
        // the clean engine (low divergence). The poisoning-guarded engine must keep
        // scoring the attack as more anomalous.
        assert!(
            d_poisoned > d_clean,
            "the poisoning guard must keep the attack anomalous: clean={d_clean:.3} poisoned={d_poisoned:.3}"
        );
    }

    #[test]
    fn a_subprocess_is_an_independent_principal_with_its_own_baseline() {
        // W6.2: a spawned MCP server is its OWN monitored principal (`mcp:<server_id>`), scored
        // against an `mcp-server` role baseline INDEPENDENTLY of the agent that called it. The
        // engine is neutral over principal strings, so this needs no engine change — it locks in
        // the capability + the documented role prior.
        let mut e = engine();
        e.set_role("mcp-server", RoleBaseline::mcp_server());

        // The MCP server doing its normal vendor egress scores low against the mcp-server prior.
        let server_normal = e.assess(
            "mcp-server",
            "mcp:gmail",
            &profile(),
            &mix(&[("egress:normal", 8.0)]),
        );
        assert!(
            server_normal.mix_divergence < 0.5,
            "vendor egress is normal for an MCP server: {:.3}",
            server_normal.mix_divergence
        );

        // A COMPROMISED server exfiltrating on its OWN initiative (credential access + payment
        // egress) scores HIGH — attributed to the SERVER principal, not the calling agent.
        let server_insider = e.assess(
            "mcp-server",
            "mcp:gmail",
            &profile(),
            &mix(&[("cap:CredentialAccess", 4.0), ("egress:payment", 4.0)]),
        );
        assert!(
            server_insider.mix_divergence > server_normal.mix_divergence + 1.0,
            "a server exfiltrating on its own must flag the SERVER: normal={:.3} insider={:.3}",
            server_normal.mix_divergence,
            server_insider.mix_divergence
        );

        // Independence: learning the AGENT's behavior must NOT move the SERVER's score — separate
        // online EWMA per principal. (Otherwise a server's anomaly could be masked by, or leak
        // into, the agent's learned normal.)
        let before = e.assess(
            "mcp-server",
            "mcp:gmail",
            &profile(),
            &mix(&[("egress:payment", 4.0)]),
        );
        for _ in 0..10 {
            e.observe("agent:1", &mix(&[("egress:payment", 4.0)]), false);
        }
        let after = e.assess(
            "mcp-server",
            "mcp:gmail",
            &profile(),
            &mix(&[("egress:payment", 4.0)]),
        );
        assert!(
            (before.mix_divergence - after.mix_divergence).abs() < 1e-9,
            "the agent's learned behavior must not leak into the subprocess principal's baseline"
        );
    }
}
