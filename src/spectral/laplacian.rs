//! Graph Laplacian construction.
//!
//! Two variants per spectral-physics convention:
//!   - Combinatorial: L = D − W
//!   - Symmetric normalized: L_sym = I − D^{-1/2} W D^{-1/2}
//!
//! Both yield the same connectivity invariants (number of zero
//! eigenvalues = number of connected components), but L_sym is bounded
//! in [0, 2] and is the right choice for size-invariant fingerprints
//! across sessions of different graph orders.

use crate::graph::SessionGraph;
use crate::types::EventKind;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaplacianKind {
    Combinatorial,
    NormalizedSymmetric,
}

/// Construct a Laplacian from an arbitrary symmetric adjacency matrix.
/// Isolated nodes (degree 0) are given an epsilon self-weight to avoid
/// division-by-zero in the normalized variant — same convention as
/// spectral_engine_core/src/laplacian.rs.
pub fn build_laplacian(adjacency: &[Vec<f64>], kind: LaplacianKind) -> Vec<Vec<f64>> {
    let n = adjacency.len();
    if n == 0 {
        return Vec::new();
    }
    debug_assert!(adjacency.iter().all(|row| row.len() == n));

    let mut w: Vec<Vec<f64>> = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| if i == j { 0.0 } else { adjacency[i][j].max(0.0) })
                .collect()
        })
        .collect();
    let mut degrees: Vec<f64> = w
        .iter()
        .map(|row| row.iter().sum::<f64>())
        .collect();
    let eps = 1e-10;
    for d in degrees.iter_mut() {
        if *d == 0.0 {
            *d = eps;
        }
    }
    // Symmetrize w defensively.
    for i in 0..n {
        for j in 0..n {
            let avg = 0.5 * (w[i][j] + w[j][i]);
            w[i][j] = avg;
        }
    }

    match kind {
        LaplacianKind::Combinatorial => {
            let mut l: Vec<Vec<f64>> = (0..n).map(|_| vec![0.0; n]).collect();
            for i in 0..n {
                for j in 0..n {
                    if i == j {
                        l[i][j] = degrees[i] - w[i][j];
                    } else {
                        l[i][j] = -w[i][j];
                    }
                }
            }
            l
        }
        LaplacianKind::NormalizedSymmetric => {
            let inv_sqrt: Vec<f64> = degrees.iter().map(|d| 1.0 / d.sqrt()).collect();
            let mut l: Vec<Vec<f64>> = (0..n).map(|_| vec![0.0; n]).collect();
            for i in 0..n {
                for j in 0..n {
                    if i == j {
                        l[i][j] = 1.0 - inv_sqrt[i] * w[i][j] * inv_sqrt[j];
                    } else {
                        l[i][j] = -inv_sqrt[i] * w[i][j] * inv_sqrt[j];
                    }
                }
            }
            l
        }
    }
}

/// Build a Laplacian from a `SessionGraph`. Nodes are events of meaningful
/// kinds (we drop session_start, session_end, finding, intervention).
/// Edges are causal (parent_event_id), with an additional unit-weight edge
/// when an event crosses a trust-zone boundary from its parent.
pub fn build_session_laplacian(
    graph: &SessionGraph,
    kind: LaplacianKind,
) -> (Vec<Vec<f64>>, Vec<String>) {
    // Node selection: skip housekeeping kinds.
    let nodes: Vec<&crate::event::Event> = graph
        .dynamic_graph
        .events
        .iter()
        .filter(|e| {
            !matches!(
                e.kind,
                EventKind::SessionStart
                    | EventKind::SessionEnd
                    | EventKind::Finding
                    | EventKind::Intervention
            )
        })
        .collect();
    let n = nodes.len();
    let id_to_idx: BTreeMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, e)| (e.event_id.as_str(), i))
        .collect();

    let mut adj = vec![vec![0.0f64; n]; n];
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    for (i, ev) in nodes.iter().enumerate() {
        if let Some(parent) = &ev.parent_event_id {
            if let Some(&j) = id_to_idx.get(parent.as_str()) {
                let key = if i < j { (i, j) } else { (j, i) };
                if seen.insert(key) {
                    let weight = if ev.trust_zone == nodes[j].trust_zone {
                        1.0
                    } else {
                        // Trust-cross edges weighted higher because they
                        // are the structurally interesting boundary
                        // crossings. Spec §3 ("Graph construction").
                        2.0
                    };
                    adj[i][j] = weight;
                    adj[j][i] = weight;
                }
            }
        }
    }

    // For sessions whose JSONL fixture lacks parent_event_id (e.g. the
    // legacy Python proxy_emit format), fall back to a chain edge between
    // adjacent events of the same session. This keeps the graph connected
    // enough to have meaningful spectral properties for v2 detection.
    let has_parents = nodes.iter().any(|e| e.parent_event_id.is_some());
    if !has_parents && n >= 2 {
        for i in 0..n - 1 {
            adj[i][i + 1] = 1.0;
            adj[i + 1][i] = 1.0;
        }
    }

    let labels: Vec<String> = nodes.iter().map(|e| e.event_id.clone()).collect();
    let l = build_laplacian(&adj, kind);
    (l, labels)
}
