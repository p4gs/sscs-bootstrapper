---
type: Architecture Guide
title: External services
description: Three optional integrations with infrastructure you have to run, and the difference between checking configuration and checking reachability.
tags: [dependency-track, guac, oras, credentials, degradation]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# External services

Three controls that connect sscsb's output to infrastructure someone has to stand up:
an evidence server that ingests SBOMs, a graph that ingests supply-chain metadata, and
a registry client for pushing artifacts.

**All three are off by default**, because each needs infrastructure the user may not
have — and a control that fails on absent infrastructure would just teach people to
disable it.

## Configuration is not reachability

The evidence-server control is the one that does real work, and its history is the
lesson.

**It probes the server**, with a short timeout so verification cannot hang on a
black-holed host. Status codes map to human causes: a rejected key, a wrong port
pointing at a frontend rather than an API, an unreachable host.

The principle in the source is the one worth quoting: *could-not-reach-it* and
*it-works* must never collapse into the same verdict.

Before the probe existed, a passing verdict required only a **non-empty URL string and
a set environment variable**. So verification reported passing and the next upload
failed to connect — the tool contradicting itself between two commands in the same
session.

### The credential

Read from **the environment only**. Never from a config file, never as a URL
parameter, and sent as a **request header**.

That is three decisions, each closing a leak: config files get committed, URLs land in
logs and shell history and referrers, and headers do not. The wire shape is pinned by a
test that asserts the key travels as a header and never appears in the verdict.

## The other two check presence only

Both verify that their client tool is installed, reporting a version or a degrade
message.

**Neither can distinguish an installed client from a running service.** Having the
graph client on your machine says nothing about whether the graph is up. That limit
should shape how you read a passing verdict here, and it is why the degrade message for
one of them carries the quickstart for standing the service up.

One of them refuses when its target directory does not exist, rather than reporting an
empty success — nothing to ingest is not the same as ingesting nothing.

## The decoy incident

These two controls are where the tool-detection defect showed up most starkly: both
**passed on a non-executable three-line text file** dropped on `PATH` under the tool's
name, flipping a strict verification from failing to passing.

The regression test is the cleanest demonstration in the codebase — it changes
**only the execute bit** on the same file, with the same name in the same directory,
and both controls flip from degraded to passing. See
[external tools and degradation](../runtime/external-tools-and-degradation.md).

CI deliberately does **not** install these tools, precisely so their degrade branches
stay exercised there.

## Source map

| Concern | Location |
|---|---|
| Evidence-server probe and upload | `src/observability.rs` |
| Graph ingest | `src/observability.rs`, `guac_ingest` |
| Registry push | `src/observability.rs`, `oras_push` |
| The three verifiers | `src/observability.rs` |
| Deliberate CI omission | `tests/tool_pin_parity.rs` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib observability::
```

VEX generation also lives in this module but belongs to
[OpenVEX](../dependencies/openvex.md), which owns the whole write-then-consume seam.
