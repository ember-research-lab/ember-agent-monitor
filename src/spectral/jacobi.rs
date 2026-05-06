//! Symmetric eigendecomposition via cyclic Jacobi rotations.
//!
//! Implements `eigh` returning (eigenvalues sorted ascending, eigenvectors
//! as columns). Matches the contract of `scipy.linalg.eigh` on symmetric
//! input within numerical tolerance.
//!
//! Complexity O(N³) per sweep, typically converges in 6-10 sweeps. For
//! session graphs (≤ a few hundred nodes) this is comfortable; for
//! larger graphs we'd want a Lanczos approach in v2.5.
//!
//! References:
//!   - Golub & Van Loan, "Matrix Computations" 4th ed., Algorithm 8.4.2.
//!   - Press et al., "Numerical Recipes", §11.1, "Jacobi Transformations
//!     of a Symmetric Matrix".

const MAX_SWEEPS: usize = 50;
const CONVERGENCE_TOL: f64 = 1e-12;

/// Symmetric eigendecomposition. The input is assumed symmetric; the lower
/// triangle is read. Returns `(eigenvalues, eigenvectors)` where
/// eigenvectors are columns. Eigenvalues are sorted ascending.
pub fn eigh(matrix: &[Vec<f64>]) -> (Vec<f64>, Vec<Vec<f64>>) {
    let n = matrix.len();
    if n == 0 {
        return (Vec::new(), Vec::new());
    }
    debug_assert!(matrix.iter().all(|row| row.len() == n));

    // Working copy a, symmetrized for numerical safety.
    let mut a: Vec<Vec<f64>> = (0..n)
        .map(|i| {
            (0..n)
                .map(|j| 0.5 * (matrix[i][j] + matrix[j][i]))
                .collect()
        })
        .collect();

    // V starts as identity; will accumulate the eigenvector basis.
    let mut v: Vec<Vec<f64>> = (0..n)
        .map(|i| (0..n).map(|j| if i == j { 1.0 } else { 0.0 }).collect())
        .collect();

    for _sweep in 0..MAX_SWEEPS {
        let off = off_diagonal_norm(&a);
        if off < CONVERGENCE_TOL {
            break;
        }
        for p in 0..n - 1 {
            for q in p + 1..n {
                let apq = a[p][q];
                if apq.abs() < CONVERGENCE_TOL {
                    continue;
                }
                let app = a[p][p];
                let aqq = a[q][q];

                // Compute the rotation that zeros out a[p][q].
                let theta = (aqq - app) / (2.0 * apq);
                let t = if theta.abs() > 1e30 {
                    0.5 / theta
                } else {
                    let sign = if theta >= 0.0 { 1.0 } else { -1.0 };
                    sign / (theta.abs() + (1.0 + theta * theta).sqrt())
                };
                let c = 1.0 / (1.0 + t * t).sqrt();
                let s = t * c;

                // Apply the Jacobi rotation J^T A J.
                let new_app = app - t * apq;
                let new_aqq = aqq + t * apq;
                a[p][p] = new_app;
                a[q][q] = new_aqq;
                a[p][q] = 0.0;
                a[q][p] = 0.0;
                for r in 0..n {
                    if r == p || r == q {
                        continue;
                    }
                    let arp = a[r][p];
                    let arq = a[r][q];
                    let new_rp = c * arp - s * arq;
                    let new_rq = s * arp + c * arq;
                    a[r][p] = new_rp;
                    a[p][r] = new_rp;
                    a[r][q] = new_rq;
                    a[q][r] = new_rq;
                }

                // Accumulate the rotation into V.
                for r in 0..n {
                    let vrp = v[r][p];
                    let vrq = v[r][q];
                    v[r][p] = c * vrp - s * vrq;
                    v[r][q] = s * vrp + c * vrq;
                }
            }
        }
    }

    // Eigenvalues sit on the diagonal; sort and reorder eigenvectors.
    let mut indices: Vec<usize> = (0..n).collect();
    indices.sort_by(|&a_idx, &b_idx| {
        a[a_idx][a_idx]
            .partial_cmp(&a[b_idx][b_idx])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let eigenvalues: Vec<f64> = indices.iter().map(|&i| a[i][i]).collect();
    let mut eigenvectors: Vec<Vec<f64>> = vec![vec![0.0; n]; n];
    for (col, &src) in indices.iter().enumerate() {
        for row in 0..n {
            eigenvectors[row][col] = v[row][src];
        }
    }

    (eigenvalues, eigenvectors)
}

fn off_diagonal_norm(a: &[Vec<f64>]) -> f64 {
    let n = a.len();
    let mut s = 0.0f64;
    for i in 0..n {
        for j in 0..i {
            s += a[i][j] * a[i][j];
        }
    }
    s.sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() < tol
    }

    #[test]
    fn identity_matrix() {
        let m = vec![
            vec![1.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0],
            vec![0.0, 0.0, 1.0],
        ];
        let (vals, _) = eigh(&m);
        assert_eq!(vals.len(), 3);
        for v in &vals {
            assert!(approx_eq(*v, 1.0, 1e-9));
        }
    }

    #[test]
    fn diagonal_sorts() {
        let m = vec![
            vec![3.0, 0.0, 0.0],
            vec![0.0, 1.0, 0.0],
            vec![0.0, 0.0, 2.0],
        ];
        let (vals, _) = eigh(&m);
        assert!(approx_eq(vals[0], 1.0, 1e-9));
        assert!(approx_eq(vals[1], 2.0, 1e-9));
        assert!(approx_eq(vals[2], 3.0, 1e-9));
    }

    #[test]
    fn known_2x2() {
        // [[2, 1],[1, 2]] has eigenvalues 1 and 3.
        let m = vec![vec![2.0, 1.0], vec![1.0, 2.0]];
        let (vals, _) = eigh(&m);
        assert!(approx_eq(vals[0], 1.0, 1e-9));
        assert!(approx_eq(vals[1], 3.0, 1e-9));
    }

    #[test]
    fn reconstructs_matrix() {
        // A = V diag(λ) V^T should reconstruct A within tolerance.
        let m = vec![
            vec![4.0, 1.0, -2.0],
            vec![1.0, 2.0, 0.5],
            vec![-2.0, 0.5, 5.0],
        ];
        let (vals, vecs) = eigh(&m);
        let n = m.len();
        for i in 0..n {
            for j in 0..n {
                let mut acc = 0.0f64;
                for k in 0..n {
                    acc += vecs[i][k] * vals[k] * vecs[j][k];
                }
                assert!(
                    approx_eq(acc, m[i][j], 1e-8),
                    "reconstruct[{i}][{j}]={acc} vs {}",
                    m[i][j]
                );
            }
        }
    }

    #[test]
    fn laplacian_has_zero_eigenvalue() {
        // For a connected graph, the Laplacian has exactly one zero
        // eigenvalue. Triangle graph: each node has degree 2.
        // L = [[2,-1,-1],[-1,2,-1],[-1,-1,2]]
        let m = vec![
            vec![2.0, -1.0, -1.0],
            vec![-1.0, 2.0, -1.0],
            vec![-1.0, -1.0, 2.0],
        ];
        let (vals, _) = eigh(&m);
        assert!(vals[0].abs() < 1e-9);
        assert!(vals[1] > 0.5);
        assert!(vals[2] > 0.5);
    }
}
