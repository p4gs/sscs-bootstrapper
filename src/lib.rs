//! SSCS Bootstrapper — an opinionated, modular toolkit that bootstraps
//! software supply chain security across git repositories for solo developers
//! and small teams working in AI-heavy workflows.
//!
//! sscsb ORCHESTRATES best-in-class tools (detect → configure → invoke →
//! parse); it never reimplements scanners, signers, or SBOM engines. The
//! library is exposed so the control surface can be driven directly (and
//! tested in-process); `src/main.rs` is a thin binary over [`cli::run`].
//!
//! Module map:
//! - [`controls`] — the control registry (what exists, phase, defaults, tools)
//! - [`init`] — repository bootstrap (`sscsb init`), idempotent
//! - [`config`] — `.sscsb/config.toml`, generated from the registry
//! - [`tools`] — pinned external-tool registry, detection, degrade messages
//! - [`hooks`] — git hook engine (secrets, signing guard, AI trailers, gates)
//! - [`signers`] — signer-policy classification, agent-signing control, `signers`/`agent-key` CLI
//! - [`audit`] — GitHub Actions workflow auditing (pinning, permissions, more)
//! - [`deps`] — package trust (existence, approval, typosquat heuristics)
//! - [`sbom`] / [`scan`] / [`sast`] — Syft / Trivy+OSV / OpenGrep+Semgrep
//! - [`provenance`] — slsa-verifier, DSSE/in-toto, cosign, AI receipts
//! - [`observability`] — Dependency-Track, GUAC, OpenVEX, ORAS
//! - [`compliance`] — control → SLSA/SSDF/CRA/Badge map and `sscsb report`

pub mod audit;
pub mod cli;
pub mod compliance;
pub mod config;
pub mod context;
pub mod controls;
pub mod deps;
pub mod exec;
pub mod harden;
pub mod hooks;
pub mod init;
pub mod observability;
pub mod platform;
pub mod provenance;
pub mod sast;
pub mod sbom;
pub mod scan;
pub mod scorecard;
pub mod signers;
#[cfg(test)]
pub(crate) mod testutil;
pub mod tools;
pub mod workflows;
