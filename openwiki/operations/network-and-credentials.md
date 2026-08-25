---
type: Architecture Guide
title: Network and credentials
description: Every outbound call sscsb makes, what credential each uses, and the one path on which repository content leaves your machine during normal use.
tags: [network, egress, credentials, privacy, security]
sources:
  - id: openwiki-source-8cd0c402939b31466db7a235
    resource: repo://src/audit.rs
  - id: openwiki-source-6c89c7d134c40afdab338388
    resource: repo://src/deps.rs
  - id: openwiki-source-1766497b5a6f8f7814a14672
    resource: repo://src/harden.rs
  - id: openwiki-source-9616e50e881946cd4b6ba8dd
    resource: repo://src/hooks.rs
  - id: openwiki-source-d9509f4dad4d74c41a1337b5
    resource: repo://src/observability.rs
  - id: openwiki-source-243482fac62ba19547edce46
    resource: repo://src/scorecard.rs
  - id: openwiki-source-703432bb3bdfdd93239f9c1c
    resource: repo://src/signers.rs
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
verified:
  - by: openwiki/0.3.3
    at: 2026-08-25T03:42:40.117Z
---

# Network and credentials

A supply-chain security tool that quietly phones home would be a poor advertisement
for itself. This page is the complete outbound inventory: what leaves the machine,
when, and carrying what.

## sscsb holds no forge token

Every forge query goes through **the forge's own CLI**, not a bundled HTTP client.

That is a real design decision with two effects: sscsb never stores, reads or handles
a forge token, and it inherits exactly whatever identity that CLI is already
authenticated as. Auditing what sscsb can reach on your forge means auditing that
CLI's authentication, not sscsb's configuration.

Forge calls are made by branch protection (read and write), the Scorecard integration,
the GitHub-App signer check, and the signing-environment probe.

## Registry lookups carry no credential

Dependency existence checks are **direct HTTPS requests** to five public package
registries, one per ecosystem, sent with a **self-identifying user agent** and no
credential.

What leaves your machine is a **package name**. The check exists to catch hallucinated
and slopsquatted dependencies, and `--offline` is the supported way to decline it —
see [manifests and package trust](../dependencies/manifests-and-package-trust.md).

## The one path where repository content leaves

**The secret scanner is invoked with verification enabled**, and never with
verification disabled. That means **candidate secrets found in staged content are sent
to the matching third-party API** to determine whether they are live — during a
routine `git commit`.

This is the only path on which repository content leaves the machine during normal
use, and it deserves a deliberate decision rather than a discovery.

The case for it is strong: verification is what separates a real leaked credential
from a random-looking string, and unverified secret scanning is mostly false
positives. The case against is that a candidate secret is transmitted to a third party
before a human has seen it.

Worth noting for calibration: **the same invocation disables the scanner's
self-update.** So the argument list was tuned for egress in one respect while leaving
credential verification on. That reads as unexamined rather than chosen, and if you
want it off, that is a change to make deliberately.

## Optional services

The evidence-server integration is the only one holding a credential of its own. It is
read **from the environment only** — never a config file, never a URL parameter — and
sent as a **request header**. See
[external services](../governance/external-services.md).

## Two implementation details worth copying

**The write side of branch protection sends its request body through standard input**
rather than embedding JSON in an argument list, which keeps a potentially large and
quoted payload out of the process table and shell history.

**Network calls are confined to thin functions deliberately excluded from coverage**,
so the planning, merging and parsing around them stays unit-tested. That is why the
[branch protection](../github/branch-protection.md) plan logic can be tested without a
forge.

## Offline behaviour

Most controls degrade rather than fail when the network is unavailable, because
[degraded means the check did not happen](../control-model/registry-and-outcomes.md#degraded-is-not-pass).
The dependency check has an explicit `--offline`. A registry lookup that cannot be
completed is a **problem**, not a note — an outage must not launder an unverified
package.

## Source map

| Concern | Location |
|---|---|
| Forge calls | `src/audit.rs`, `src/harden.rs`, `src/scorecard.rs`, `src/signers.rs`, `src/signing_setup.rs` |
| Registry lookups | `src/deps.rs`, `registry_exists` |
| Secret-scanner invocation | `src/hooks.rs` |
| Evidence-server credential | `src/observability.rs` |
