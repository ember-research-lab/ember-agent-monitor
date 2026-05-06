//! Spectral methods layer (v2).
//!
//! Spec §9: "Spectral methods (planned for v2)" — eigenvector tracking on
//! prompt-context subspace, spectral gap on trajectory vs initial task,
//! subgraph motif detection for exfil patterns, user-baseline calibration.
//!
//! v2.0 ships the spectral primitives + a `spectral_anomaly` detection
//! rule that surfaces structural transitions in the session graph that
//! pattern-based rules can't see. Adaptive attackers tuning against the
//! v0.5 rule library still have to defeat this layer's structural
//! detection — and structural detection is harder to evade because the
//! attack graph itself has to look normal, not just the strings inside it.
//!
//! All math is in-house and zero-dep. We re-derive primitives that the
//! existing spectral_engine_core/spectral-sec-poc projects implement, but
//! without their `numpy`/`ndarray`/`pyo3`/`OpenBLAS` dependency surface.
//! Algorithms used in this module trace to:
//!
//!   - Jacobi eigenvalue rotation (Golub & Van Loan, "Matrix Computations",
//!     Algorithm 8.4.2). Stable, simple, O(N³) for symmetric N×N. Suitable
//!     for the typical session-graph size (≤ a few hundred nodes).
//!   - Combinatorial Laplacian L = D − W, normalized variant L_sym = I −
//!     D^{-1/2} W D^{-1/2}. See spectral-sec-poc/src/spectral_engine.py.
//!   - Heat-kernel trace Θ(t) = Σₖ exp(-t·λₖ) — basis-independent
//!     fingerprint per Spectral Physics Theorem 1.1.

pub mod baseline;
pub mod distance;
pub mod jacobi;
pub mod laplacian;
pub mod motif;
pub mod profile;

pub use baseline::{Baseline, Envelope, SpectralScoreBreakdown};
pub use distance::{davis_kahan_ratio, heat_kernel_distance};
pub use jacobi::eigh;
pub use laplacian::{build_laplacian, build_session_laplacian, LaplacianKind};
pub use motif::{check_motifs, AttackMotif};
pub use profile::SpectralProfile;
