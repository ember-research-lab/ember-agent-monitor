//! Distances between spectral profiles + a priori stability bounds.
//!
//! Heat-kernel distance is a size-invariant fingerprint comparator, used
//! to tell whether two sessions have structurally similar execution
//! shapes. Davis-Kahan ratio is an a-priori predictor of how much an
//! eigenvector basis can shift under a graph perturbation — useful as a
//! sensitivity threshold for change detection.

use super::profile::SpectralProfile;

/// Size-invariant heat-kernel distance:
///
///   d_HK(G1, G2) = sqrt(Δ_log_t) * || log Θ_1(t) - log Θ_2(t) ||_2
///
/// Uses the log-Θ difference so the leading t^{-d_s/2} behavior contributes
/// as a constant additive offset that the difference washes out. The
/// distance responds to deviations from the power law, not the power law
/// itself.
pub fn heat_kernel_distance(p1: &SpectralProfile, p2: &SpectralProfile) -> f64 {
    let n = p1.heat_trace.len().min(p2.heat_trace.len());
    if n < 2 {
        return 0.0;
    }
    let eps = 1e-12;
    let log_diff: Vec<f64> = (0..n)
        .map(|i| (p1.heat_trace[i].max(eps)).ln() - (p2.heat_trace[i].max(eps)).ln())
        .collect();
    let dlog_t = if p1.t_grid.len() >= 2 {
        (p1.t_grid[1] / p1.t_grid[0]).ln()
    } else {
        1.0
    };
    let l2: f64 = log_diff.iter().map(|x| x * x).sum::<f64>().sqrt();
    dlog_t.sqrt() * l2
}

/// Davis-Kahan-style stability ratio. Computes `‖δL‖_op / λ₁` where δL =
/// L_perturbed − L_original. Small ratio → eigenvectors stable; large
/// ratio → structural transition predicted.
///
/// We use the Frobenius norm as a tractable upper bound on the operator
/// norm — the sqrt(N) overestimate is acceptable as a *predictor*.
/// True operator norm requires another eigendecomposition; not worth it
/// for this layer.
pub fn davis_kahan_ratio(original: &[Vec<f64>], perturbed: &[Vec<f64>]) -> f64 {
    let n = original.len();
    if perturbed.len() != n {
        return f64::INFINITY;
    }
    if n == 0 {
        return 0.0;
    }
    let mut delta_frob = 0.0f64;
    for i in 0..n {
        for j in 0..n {
            let d = perturbed[i][j] - original[i][j];
            delta_frob += d * d;
        }
    }
    let delta_op_upper = delta_frob.sqrt();

    // Smallest non-zero eigenvalue of the original — we approximate by
    // running eigh once. For repeated calls the caller should cache this.
    let (vals, _) = super::jacobi::eigh(original);
    let lambda1 = vals.iter().copied().find(|v| *v > 1e-9).unwrap_or(0.0);

    if lambda1 == 0.0 {
        if delta_op_upper > 0.0 {
            f64::INFINITY
        } else {
            0.0
        }
    } else {
        delta_op_upper / lambda1
    }
}

#[cfg(test)]
mod tests {
    use super::super::laplacian::{build_laplacian, LaplacianKind};
    use super::super::profile::SpectralProfile;
    use super::*;

    fn build_profile(adj: &[Vec<f64>]) -> SpectralProfile {
        let l = build_laplacian(adj, LaplacianKind::NormalizedSymmetric);
        let (vals, _) = super::super::jacobi::eigh(&l);
        let n = vals.len();
        let t_grid: Vec<f64> = (0..30)
            .map(|i| (-2.0_f64 + i as f64 * 4.0 / 29.0).exp())
            .collect();
        let heat_trace: Vec<f64> = t_grid
            .iter()
            .map(|&t| vals.iter().map(|&l| (-t * l).exp()).sum())
            .collect();
        let fiedler = vals.iter().copied().find(|v| *v > 1e-9).unwrap_or(0.0);
        SpectralProfile {
            n_nodes: n,
            eigenvalues: vals,
            fiedler_value: fiedler,
            t_grid,
            heat_trace,
            spectral_dimension: None,
        }
    }

    #[test]
    fn identical_graphs_zero_distance() {
        let adj = vec![
            vec![0.0, 1.0, 0.0],
            vec![1.0, 0.0, 1.0],
            vec![0.0, 1.0, 0.0],
        ];
        let p1 = build_profile(&adj);
        let p2 = build_profile(&adj);
        let d = heat_kernel_distance(&p1, &p2);
        assert!(d < 1e-6, "expected near-zero, got {d}");
    }

    #[test]
    fn different_graphs_nonzero_distance() {
        // Path graph vs triangle.
        let path = vec![
            vec![0.0, 1.0, 0.0],
            vec![1.0, 0.0, 1.0],
            vec![0.0, 1.0, 0.0],
        ];
        let triangle = vec![
            vec![0.0, 1.0, 1.0],
            vec![1.0, 0.0, 1.0],
            vec![1.0, 1.0, 0.0],
        ];
        let pp = build_profile(&path);
        let pt = build_profile(&triangle);
        let d = heat_kernel_distance(&pp, &pt);
        assert!(d > 1e-3, "expected noticeable distance, got {d}");
    }
}
