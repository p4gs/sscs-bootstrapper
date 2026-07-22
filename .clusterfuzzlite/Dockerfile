# ClusterFuzzLite build environment for sscsb's cargo-fuzz targets.
# ClusterFuzzLite is the fuzzing integration OpenSSF Scorecard detects for Rust.
#
# Base image pinned by digest (Trivy DS-0001 + supply-chain hygiene — a hardening
# tool must not ship an unpinned base). This is base-builder-rust:latest as of
# 2026-07-21; bump the digest deliberately to take OSS-Fuzz toolchain updates.
#
# DS-0002 (runs as root) and DS-0026 (no HEALTHCHECK) are waived in the repo-root
# `.trivyignore` WITH CAUSE — not as safe-in-practice waivers but as category
# errors Trivy's generic *runtime*-container rules fundamentally cannot model on
# an ephemeral OSS-Fuzz *build* container: base-builder-rust REQUIRES root (the
# OSS-Fuzz toolchain and ClusterFuzzLite's runner compile into root-owned
# $OUT/$SRC/$WORK, so a non-root USER breaks the fuzz build, and there is no
# root-free way to make Rust fuzzing detectable by Scorecard), and a container
# that exits after compiling has no long-running service to health-check.
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:4541e7f7e3c8708c9fa55ec578eebbfd745987bef86bc06ed9a5ebfd8a6f42d3
COPY . $SRC/sscsb
WORKDIR $SRC/sscsb
COPY .clusterfuzzlite/build.sh $SRC/build.sh
