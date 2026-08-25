---
type: How-To Guide
title: Building and testing
description: The one invocation the suite requires, why it requires it, and what the coverage gate's two different thresholds mean.
tags: [testing, hermetic, coverage, fuzzing, ci]
sources:
  - id: openwiki-source-164e2da859b5277df81c7d94
    resource: repo://.github/workflows/ci.yml
  - id: openwiki-source-a2371d6362e5db4bc834ad03
    resource: repo://CLAUDE.md
  - id: openwiki-source-6cf53b42d7c28272aaf8c0f3
    resource: repo://fuzz/fuzz_targets/parse_deps.rs
  - id: openwiki-source-6b641c87e7cef0002a81c360
    resource: repo://fuzz/fuzz_targets/parse_signers.rs
  - id: openwiki-source-93cbdc9f9c6a777cb33c1ea8
    resource: repo://fuzz/fuzz_targets/parse_trailers.rs
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
verified:
  - by: openwiki/0.3.3
    at: 2026-08-25T03:42:40.117Z
---

# Building and testing

```sh
cargo build --release

GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo llvm-cov --ignore-filename-regex '(main\.rs|cli\.rs)' \
  --fail-under-lines 95 --fail-under-functions 94
```

The environment prefix on the test line is **not optional**, and understanding why
saves an afternoon.

## Why the suite needs isolation

The tests create **real git repositories and verify real signatures**. That makes them
genuinely end-to-end, and it means the suite is only hermetic when **the host's git
identity cannot reach the fixtures**.

Two leaks do that, and both manifest identically — as mass failures that look exactly
like a code regression and are not:

- An agent harness or wrapper can inject git configuration at **command-line scope**,
  which **outranks every repository-local setting** the fixtures make. Test commits
  then get signed and authored by the host identity.
- With that neutralised, the **global** configuration applies instead, so fixtures that
  never configured signing try to sign with a key they cannot use.

Disabling all three configuration scopes for the run removes both.

**This is invocation discipline, not a property of the code.** Making the helpers
self-isolating so the suite is hermetic by construction is a recorded follow-up that
**has not been done**. Until it is, forgetting the prefix produces a convincing
false alarm.

If your shell refuses that inline form, put it in a runner script that starts from an
empty environment and re-adds only the variables the toolchain needs.

## The coverage gate, and its two thresholds

The gate is **95% lines and 94% functions**, with argument parsing and printing
excluded.

Both numbers have reasons:

**The exclusion** covers argument parsing and printing, which sit over library
functions that *are* covered — the bootstrap logic lives in a library module precisely
so it can be tested in-process rather than by shelling out to the binary.

**The function threshold is lower than the line threshold** for a mechanical reason,
not a concession: the coverage tool counts **every monomorphisation and closure
instance per compilation context**, and the crate is built both **with** test
configuration for unit tests and **without** it as a dependency of the integration
tests and the binary. A function exercised in one context has a phantom twin in the
other. The gap between 95 and 94 is that artefact.

The floor is not a target to max out. The last few percent is genuinely unreachable
defensive code, and chasing it incentivises deleting graceful error handling.

## Fuzzing

The fuzz targets cover **exactly the three places the tool parses untrusted text**:
commit trailers, signer policy, and dependency manifests.

That is the right selection. Those three are where an attacker-supplied byte sequence
reaches a parser whose output gates something. See
[deep code scanning and fuzzing](../code-scanning/codeql-and-fuzzing.md) for the
control that ships this to *your* repository.

## Test isolation beyond git

One more process-global hazard worth knowing before you add a test: `PATH` is
process-global and the harness is threaded, so a test that shims a fake tool can
change what a concurrently running test resolves. Helpers exist that hold a shared lock
for exactly that reason, and tests relying on a tool's **real** presence must take the
same lock rather than assuming.

## Source map

| Concern | Location |
|---|---|
| Isolation requirement | `CLAUDE.md` |
| CI gate | `.github/workflows/ci.yml` |
| Fuzz targets | `fuzz/fuzz_targets/` |
| Test helpers | `src/testutil.rs` |
