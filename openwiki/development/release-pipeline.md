---
type: Architecture Guide
title: How sscsb releases itself
description: The draft-then-publish pipeline that builds, verifies, attests and signs sscsb's own binaries.
tags: [release, immutability, attestation, checksums, matrix]
sources:
  - id: openwiki-source-4d1d392666be6dfdd7a91a2e
    resource: repo://.github/workflows/release.yml
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
verified:
  - by: openwiki/0.3.3
    at: 2026-08-25T03:42:40.117Z
---

# How sscsb releases itself

This is sscsb's **own** release pipeline — how the binary you install is produced. The
controls a *user* installs to release *their* software are
[release attestations](../provenance/release-attestations.md); the filenames overlap,
the files do not.

## Only a version tag starts it

The trigger matches a **strict version-tag pattern**. An arbitrary tag cannot start a
release, which removes a whole class of accident and a small class of attack.

## Build, and prove the build

Binaries are built for **three targets** in a matrix.

Each build then **verifies the tarball actually contains a runnable binary** rather
than assuming the archive step succeeded. That distinction matters: an archive command
can succeed and produce an archive of nothing.

And the check is honest about its own reach. **Only the host-native artifact can be
executed** on its runner, so a cross-built one is checked **structurally**, and the
workflow says so rather than claiming more than was proven. That single line is the
whole ethic of this project in miniature.

## Refuse to ship a partial set

The release job **refuses to publish an incomplete artifact set**.

Without that, a matrix leg failing quietly means a release that exists but is missing
a platform — the worst version of a release, because it looks complete to anyone not
checking.

## Checksums in one place

Checksums are computed **centrally in one job**, not per runner.

The reason is mundane and worth repeating for anyone copying this: the platforms
disagree about which checksum tool exists, so a per-runner split would mean **two
implementations** of the same thing. Two implementations of a checksum is one too
many.

## Draft, then publish

The release is created as a **draft**. Every asset is uploaded while it is still
mutable. **Publishing is the final step and the only immutable transition.**

That ordering is what makes an immutable release possible at all: nothing needs to be
written after publication, so nothing conflicts with immutability. It is the same
either/or the [release attestations](../provenance/release-attestations.md) page
describes, resolved here by construction.

## Evidence attached

Before publishing, the pipeline attests **build provenance** and an **SBOM** to the
artifact digest, and **keyless-signs every artifact** with a bundle carrying the
certificate, the signature and the transparency-log proof.

So a released binary arrives with three independent kinds of evidence, all bound to the
bytes actually shipped rather than to a rebuild.

## Verifying what you installed

The bundles travel with the release assets, so verification needs no forge access. See
[artifact signing](../provenance/artifact-signing.md) for the identity-pinning rules —
in particular, that verifying against *some* trusted builder is not the control.

## Source map

| Concern | Location |
|---|---|
| The pipeline | `.github/workflows/release.yml` |
| Version and metadata | `Cargo.toml` |
| Changelog | `CHANGELOG.md` |
