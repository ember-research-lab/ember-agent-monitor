//! HTTP server primitives + Anthropic-protocol-aware proxy.
//!
//! Ported from vetpkg/src/net/{http_server,proxy} with the package-specific
//! routing replaced by Anthropic's `/v1/messages` shape. Zero deps,
//! BufReader-based parsing, hard caps on request size to defeat memory
//! exhaustion.

pub mod http;
pub mod proxy;
pub mod socket;
