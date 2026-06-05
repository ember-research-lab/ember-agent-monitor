#![forbid(unsafe_code)]
#![deny(clippy::all)]
// Some allows below name lints that were added after rustc 1.75 (our MSRV).
// Without `unknown_lints` allowed, 1.75 turns the unknown-name into a hard
// error; allowing it lets the same source compile cleanly on stable AND 1.75.
#![allow(unknown_lints)]
// Stylistic lints we've decided don't fit this codebase:
//   - `needless_range_loop`: matrix-algebra code (jacobi, laplacian) uses
//     explicit `for i in 0..n { for j in 0..n }` indexing; that's the
//     idiomatic form for symmetric pairs and clearer than `.iter().enumerate()`.
//   - `collapsible_if`: nested `if let` is sometimes more readable than
//     pattern destructuring inside an `if let` chain.
//   - `vec_init_then_push`: sequential pushes after `Vec::with_capacity` are
//     deliberately structured for clarity in JSON-builder code.
//   - `doc_lazy_continuation`: the deny-all version is too strict on
//     numbered/bulleted doc lists.
#![allow(clippy::needless_range_loop)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(clippy::field_reassign_with_default)]

pub mod cli;
pub mod crypto;
pub mod detect;
pub mod egress;
pub mod event;
pub mod graph;
pub mod integrate;
pub mod json;
pub mod net;
pub mod proto;
pub mod spectral;
pub mod store;
pub mod trust;
pub mod types;
pub mod watcher;
