//! Spectral fingerprint of a session graph.
//!
//! See spectral-sec-poc/src/spectral_engine.py for the reference Python
//! implementation. This module implements the same quantities (heat-kernel
//! trace, Fiedler value, spectral dimension fit) on top of in-house Jacobi
//! eigendecomposition.

use super::jacobi::eigh;
use super::laplacian::{build_session_laplacian, LaplacianKind};
use crate::graph::SessionGraph;

/// Default heat-kernel time grid: 30 points log-spaced on [1e-2, 1e2].
/// This range brackets the regime where diffusion transitions from local
/// (Θ ≈ N) to global (Θ ≈ n_components) on session-graph sizes.
fn default_t_grid() -> Vec<f64> {
    let n_points = 30;
    let log_min = -2.0_f64;
    let log_max = 2.0_f64;
    let step = (log_max - log_min) / (n_points - 1) as f64;
    (0..n_points)
        .map(|i| (log_min + i as f64 * step).exp())
        .collect()
}

#[derive(Debug, Clone)]
pub struct SpectralProfile {
    pub n_nodes: usize,
    pub eigenvalues: Vec<f64>,
    /// Smallest non-zero eigenvalue (Fiedler value, λ₂).
    pub fiedler_value: f64,
    /// Heat-kernel trace Θ(t_k) for each t in `t_grid`.
    pub t_grid: Vec<f64>,
    pub heat_trace: Vec<f64>,
    /// Spectral dimension fit from the plateau of log Θ vs log t. None if
    /// the fitting window has too few points.
    pub spectral_dimension: Option<f64>,
}

impl SpectralProfile {
    pub fn empty() -> Self {
        Self {
            n_nodes: 0,
            eigenvalues: Vec::new(),
            fiedler_value: 0.0,
            t_grid: Vec::new(),
            heat_trace: Vec::new(),
            spectral_dimension: None,
        }
    }

    pub fn from_session(graph: &SessionGraph) -> Self {
        Self::from_session_with_kind(graph, LaplacianKind::NormalizedSymmetric)
    }

    pub fn from_session_with_kind(graph: &SessionGraph, kind: LaplacianKind) -> Self {
        let (l, labels) = build_session_laplacian(graph, kind);
        let n = labels.len();
        if n == 0 {
            return Self::empty();
        }
        let (eigenvalues, _vectors) = eigh(&l);
        let fiedler_value = eigenvalues
            .iter()
            .copied()
            .find(|v| *v > 1e-9)
            .unwrap_or(0.0);

        let t_grid = default_t_grid();
        let heat_trace = compute_heat_trace(&eigenvalues, &t_grid);
        let spectral_dimension = fit_spectral_dimension(&heat_trace, &t_grid, n);

        Self {
            n_nodes: n,
            eigenvalues,
            fiedler_value,
            t_grid,
            heat_trace,
            spectral_dimension,
        }
    }
}

fn compute_heat_trace(eigenvalues: &[f64], t_grid: &[f64]) -> Vec<f64> {
    if eigenvalues.is_empty() {
        return vec![0.0; t_grid.len()];
    }
    t_grid
        .iter()
        .map(|&t| {
            eigenvalues
                .iter()
                .map(|&lam| (-t * lam).exp())
                .sum::<f64>()
        })
        .collect()
}

/// Fit d_s from Θ(t) ∼ t^(-d_s/2) in the plateau regime. Plateau:
/// e < Θ(t) < N/e. Returns None if fewer than 5 points lie in the window.
fn fit_spectral_dimension(heat_trace: &[f64], t_grid: &[f64], n_nodes: usize) -> Option<f64> {
    if n_nodes < 10 || heat_trace.len() != t_grid.len() {
        return None;
    }
    let upper = n_nodes as f64 / std::f64::consts::E;
    let lower = std::f64::consts::E;
    let mut log_t = Vec::new();
    let mut log_theta = Vec::new();
    for (t, theta) in t_grid.iter().zip(heat_trace.iter()) {
        if *theta > lower && *theta < upper && *theta > 0.0 {
            log_t.push(t.ln());
            log_theta.push(theta.ln());
        }
    }
    if log_t.len() < 5 {
        return None;
    }
    // Linear regression slope.
    let n = log_t.len() as f64;
    let mean_x: f64 = log_t.iter().sum::<f64>() / n;
    let mean_y: f64 = log_theta.iter().sum::<f64>() / n;
    let mut num = 0.0f64;
    let mut den = 0.0f64;
    for i in 0..log_t.len() {
        num += (log_t[i] - mean_x) * (log_theta[i] - mean_y);
        den += (log_t[i] - mean_x).powi(2);
    }
    if den < 1e-15 {
        return None;
    }
    let slope = num / den;
    let d_s = -2.0 * slope;
    if !d_s.is_finite() || d_s < 0.0 {
        None
    } else {
        Some(d_s)
    }
}
