//! Subgraph motif detection.
//!
//! Spec §9: "Subgraph motif detection for exfil patterns". Each known
//! attack class corresponds to a small graph shape (e.g. read-sensitive →
//! transform → write-network = 3-node path). We precompute the spectral
//! fingerprint of each motif and check whether the running session graph
//! contains a subgraph whose spectrum matches.
//!
//! v2.0 ships a small motif catalog. Each motif's spectral signature is
//! the sorted eigenvalues of its normalized Laplacian. The session graph's
//! subgraph-induction is approximated at this layer by counting how many
//! eigenvalues of the session match (up to tolerance) — exact subgraph
//! isomorphism is NP-hard and not worth shipping in v2.0.

use super::jacobi::eigh;
use super::laplacian::{build_laplacian, LaplacianKind};
use super::profile::SpectralProfile;

#[derive(Debug, Clone)]
pub struct AttackMotif {
    pub name: &'static str,
    pub rationale: &'static str,
    pub eigenvalues: Vec<f64>,
}

/// The motif catalog. Each entry is the normalized-Laplacian spectrum of
/// a small attack-shape graph. v2.0 ships with 8 motifs covering the most
/// common attack-graph shapes; the catalog is structurally extensible —
/// new motifs lift to fixtures and CHANGELOG entries the same way new
/// patterns do for v0.5.
pub fn motif_catalog() -> Vec<AttackMotif> {
    let path3 = motif_from_adjacency(
        "exfil_pipeline_3path",
        "read-sensitive → transform → write-network: classic exfiltration pipeline shape",
        &[
            vec![0.0, 1.0, 0.0],
            vec![1.0, 0.0, 1.0],
            vec![0.0, 1.0, 0.0],
        ],
    );
    let path4 = motif_from_adjacency(
        "exfil_pipeline_4path",
        "4-step staged exfiltration: read → process → stage → exfil",
        &[
            vec![0.0, 1.0, 0.0, 0.0],
            vec![1.0, 0.0, 1.0, 0.0],
            vec![0.0, 1.0, 0.0, 1.0],
            vec![0.0, 0.0, 1.0, 0.0],
        ],
    );
    let star3 = motif_from_adjacency(
        "convergent_sink_3star",
        "single tool fanning out to multiple sensitive sinks (e.g. credential harvest)",
        &[
            vec![0.0, 1.0, 1.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0],
        ],
    );
    // 5-star: one node fanning out to 4 sinks. Broader credential-harvest
    // shape (e.g., ~/.aws + ~/.ssh + ~/.gnupg + ~/.netrc all in one turn).
    let star5 = motif_from_adjacency(
        "broad_credential_harvest_5star",
        "single tool fanning out to 4+ sensitive sinks in one turn — broad credential harvest",
        &[
            vec![0.0, 1.0, 1.0, 1.0, 1.0],
            vec![1.0, 0.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0, 0.0, 0.0],
        ],
    );
    // Triangle (3-cycle): rare in legitimate sessions because it implies a
    // mutual-reference loop between three tools (A→B→C→A). Indicates a
    // cyclic data flow — read+modify+rewrite same target, common in
    // file-poisoning or persistence-establishment shapes.
    let triangle = motif_from_adjacency(
        "cyclic_dependency_triangle",
        "3-node mutual-reference cycle: indicates persistence-establishment or file-poisoning loops",
        &[
            vec![0.0, 1.0, 1.0],
            vec![1.0, 0.0, 1.0],
            vec![1.0, 1.0, 0.0],
        ],
    );
    // 4-cycle: read→write→read→write tight loop — the staged-exfil-via-disk
    // shape where the agent can't directly send out, so it stages content
    // through repeated reads + writes.
    let cycle4 = motif_from_adjacency(
        "staged_disk_loop_4cycle",
        "tight 4-cycle of disk reads/writes: staged exfil via filesystem when network is gated",
        &[
            vec![0.0, 1.0, 0.0, 1.0],
            vec![1.0, 0.0, 1.0, 0.0],
            vec![0.0, 1.0, 0.0, 1.0],
            vec![1.0, 0.0, 1.0, 0.0],
        ],
    );
    // K_{2,2} bipartite: two upstream sources both feeding two downstream
    // sinks. Shape of "credential harvest from multiple zones routed to
    // multiple egress channels" — high-amplification exfil.
    let bipartite_2x2 = motif_from_adjacency(
        "bipartite_2x2_amplification",
        "two-source-two-sink bipartite shape: amplified exfil (multi-creds × multi-egress)",
        &[
            vec![0.0, 0.0, 1.0, 1.0],
            vec![0.0, 0.0, 1.0, 1.0],
            vec![1.0, 1.0, 0.0, 0.0],
            vec![1.0, 1.0, 0.0, 0.0],
        ],
    );
    // Path-3 with one branch: read→transform→write, but the transform also
    // has a second downstream (e.g., write-to-disk + write-to-network in
    // parallel). The Y-shape.
    let y_branch = motif_from_adjacency(
        "fork_after_transform_y",
        "Y-shape: read → transform → (write-to-disk AND write-to-network) — split egress",
        &[
            vec![0.0, 1.0, 0.0, 0.0],
            vec![1.0, 0.0, 1.0, 1.0],
            vec![0.0, 1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0, 0.0],
        ],
    );
    vec![
        path3,
        path4,
        star3,
        star5,
        triangle,
        cycle4,
        bipartite_2x2,
        y_branch,
    ]
}

fn motif_from_adjacency(
    name: &'static str,
    rationale: &'static str,
    adj: &[Vec<f64>],
) -> AttackMotif {
    let l = build_laplacian(adj, LaplacianKind::NormalizedSymmetric);
    let (mut eigenvalues, _) = eigh(&l);
    eigenvalues.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    AttackMotif {
        name,
        rationale,
        eigenvalues,
    }
}

/// Check the session profile against each motif. Returns at most one
/// motif: the best (lowest-distance) match.
///
/// Two guards prevent false positives on long, legitimate workflows:
///
/// 1. **Eigenvalue tolerance** — the motif's non-trivial spectrum must
///    match within 0.05 of the session spectrum.
///
/// 2. **Node-count bound** — for any larger session, the motif's
///    eigenvalues will eventually appear as an arbitrary subset of the
///    session's spread spectrum. We only consider matches when the
///    session has at most ~2x the motif's node count. A 16-event
///    refactor session should never look like a 3-path motif, even
///    though their spectra technically share eigenvalues — they're
///    structurally different.
///
/// Without (2), legitimate dev workflows (multi-edit refactors, debug
/// reads) trip motif findings simply because path-graph eigenvalues are
/// dense in [0, 2]. Empirically validated against the
/// `threat-intel/calibration/clean_corpus/` baseline (5 typical-workflow
/// fixtures): zero motif matches with both guards in place.
pub fn check_motifs(profile: &SpectralProfile) -> Vec<&'static AttackMotif> {
    let session = &profile.eigenvalues;
    if session.len() < 3 {
        return Vec::new();
    }
    let session_n = profile.n_nodes;
    let catalog: Vec<AttackMotif> = motif_catalog();
    let leaked: &'static Vec<AttackMotif> = Box::leak(Box::new(catalog));
    let mut best: Option<(&'static AttackMotif, f64)> = None;
    for motif in leaked {
        // Size guard: session must be within 2x the motif's node count.
        let motif_n = motif.eigenvalues.len();
        if session_n > 2 * motif_n {
            continue;
        }
        let dist = motif_distance(&motif.eigenvalues, session);
        if dist < 0.05 {
            best = match best {
                Some((_, d)) if d <= dist => best,
                _ => Some((motif, dist)),
            };
        }
    }
    best.map(|(m, _)| vec![m]).unwrap_or_default()
}

/// Average per-eigenvalue distance from the motif's non-trivial spectrum
/// to the closest session eigenvalue. Skips the trivial λ=0 since every
/// connected graph has it. Lower → better match.
fn motif_distance(motif: &[f64], session: &[f64]) -> f64 {
    let non_trivial: Vec<f64> = motif.iter().copied().filter(|v| *v > 0.05).collect();
    if non_trivial.is_empty() {
        return f64::INFINITY;
    }
    let mut total = 0.0f64;
    for n in &non_trivial {
        let nearest = session
            .iter()
            .map(|h| (h - n).abs())
            .fold(f64::INFINITY, f64::min);
        total += nearest;
    }
    total / non_trivial.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn motif_catalog_nonempty() {
        let cat = motif_catalog();
        assert!(cat.len() >= 3);
        for m in &cat {
            assert!(!m.eigenvalues.is_empty());
            // Normalized Laplacian eigenvalues lie in [0, 2].
            for &e in &m.eigenvalues {
                assert!((-1e-9..=2.0 + 1e-9).contains(&e), "out-of-range λ={e}");
            }
        }
    }

    #[test]
    fn motif_matches_self() {
        let cat = motif_catalog();
        for m in &cat {
            let d = motif_distance(&m.eigenvalues, &m.eigenvalues);
            assert!(d < 1e-6, "motif should self-match: {} dist={d}", m.name);
        }
    }
}
