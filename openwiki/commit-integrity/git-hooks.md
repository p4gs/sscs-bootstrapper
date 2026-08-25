---
type: Architecture Guide
title: The git hook engine
description: How sscsb installs three hooks, why the shims are dumb on purpose, and how staged content is materialised for scanning.
tags: [hooks, pre-commit, pre-push, secrets, staging]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# The git hook engine

Three hooks, installed by `sscsb init`, pointed at by `core.hooksPath`:
`pre-commit`, `commit-msg` and `pre-push`. This page covers the engine underneath
them — how they are installed, what makes them trustworthy, and the staging
machinery every content scanner sits on.

The individual gates have their own pages:
[AI provenance trailers](ai-provenance-trailers.md) for the commit-msg gates, and
[signer policy](signer-policy.md) for the pre-push signing gate.

## The shims are deliberately stupid

Each installed hook is a short POSIX shell script that does one thing: hand off to
`sscsb hook <event>`. It carries a `DO NOT EDIT — regenerate with sscsb init`
banner, and if the binary cannot be found on `PATH` or through an environment
override, it prints three explanatory lines and **exits 1**.

That last behaviour is the design in one line: **the shim fails closed.** A
half-installed sscsb blocks your commit and tells you why, rather than letting it
through as though every gate had passed. Policy lives in Rust where it can be
tested; the shell is only a doorway.

## Presence is not enforcement

A hook file existing tells you very little. `hook_integrity` therefore reports three
states, not two:

- **`Pass`** — every shim is byte-identical to the one sscsb generates.
- **`Degraded`** — a shim has been edited but still contains its `sscsb hook <event>`
  delegation line. sscsb can see the line is present; it cannot prove an edited shell
  script still *reaches* it. So it declines to call the control verified.
- **`Fail`** — `core.hooksPath` points elsewhere (the message names where), a shim is
  missing or unreadable, a shim is **not executable** (git silently skips those), or
  the delegation line is gone.

Comparison normalises line endings first, because `.sscsb/hooks/` is version
controlled and git's `autocrlf` setting must not be what decides your security
posture.

Six controls fold this integrity verdict into their own, so a broken hook install
drags them down rather than sitting beside a cheerful `PASS`. That folding rule is
described in [the verdict contract](../control-model/registry-and-outcomes.md).

## Scanning what is actually being committed

The subtlest machinery here is `stage_to_tempdir`, shared by the secret scanners and
by [SAST](../code-scanning/sast.md).

It enumerates staged paths, materialises **the staged blob** of each into a
temporary directory, and scans that. Not the working tree. The two diverge routinely
— `git add -p`, or any edit made after staging — and on an initial commit there is no
`HEAD` to diff against. The gate has to cover exactly the content about to be
committed.

Three details in that function are each defending against a specific failure:

**Paths are enumerated NUL-delimited.** Git's `core.quotePath` is on by default and
C-quotes any path containing a non-ASCII byte, a control character or a quote:
`café/Cargo.toml` becomes `"caf\303\251/Cargo.toml"`. Feed that back to git and the
object does not resolve. On an earlier continue-on-failure path, the file was
silently dropped from the scan.

> This is worth internalising as a class, not a trivium. The same file once
> contained a second enumeration that lacked this protection, and a dependency
> manifest under a non-ASCII directory walked straight past the AI dependency-review
> gate as a result.

**Content is carried as raw bytes.** The ordinary command wrapper decodes stdout
lossily, rewriting invalid UTF-8 sequences — which changes both the content and the
length of a staged PNG or zip before any scanner sees it. The staging path uses the
byte-preserving variant instead. A regression test materialises a real zip and
checks it against its own stored CRC.

**An unreadable blob is a hard error, not a skipped file.** The single exception is
a submodule gitlink, which legitimately has no blob.

## The secret gate

Two scanners, gitleaks and trufflehog, each individually toggleable.

Findings are distinguished from operational failure by **sentinel exit codes**: each
scanner is asked to report findings with a specific, unusual code, and any other
non-zero status is an error rather than a finding. That is what stops a crashed
scanner reading as a clean one — the same principle catalogued in
[process execution](../runtime/process-execution.md).

Degradation is deliberately asymmetric:

- **One scanner missing** → a printed `degraded —` note. The other still runs.
- **No scanner ran at all** → an error, which `general.fail_open` then arbitrates.

The finding parsers are lenient by design: unparseable output still yields a
non-empty finding list, so a scanner saying "I found something" is never swallowed by
a JSON shape change.

One asymmetry to know: the pre-push range scan checks only whether each tool is
available and does **not** honour the per-scanner toggles the staged scan respects.
Disabling a scanner in config therefore silences it at commit time but not at push
time. Nothing in the source states whether that is intentional.

## What each hook does

**pre-commit** runs the secret scan over staged content, and the SAST scan if that
control is on **and** its `pre_commit` option is enabled — which defaults to off.

There is one unconditional fail-open here, and it is worth knowing: **with no
`.sscsb/config.toml` at all**, the hook prints a warning and allows the commit. An
unconfigured repository is not a gated one. See
[configuration](../control-model/configuration.md).

**commit-msg** runs the trailer and AI-provenance gates plus the package-trust gate.
See [AI provenance trailers](ai-provenance-trailers.md).

**pre-push** parses git's stdin protocol, then:

- **skips branch deletions entirely** — a zero local revision means nothing is being
  added;
- runs the **signing gate only on protected branches**;
- runs the **secret range scan on every branch**.

That split is the right one. Signing is about what may land on a protected branch;
secrets are about what leaves your machine at all.

## Source map

| Concern | Location |
|---|---|
| Hook list, installation, git config | `src/hooks.rs`, `install_hooks` |
| Shim generation | `src/hooks.rs`, `shim_script` |
| Three-state integrity | `src/hooks.rs`, `hook_integrity` |
| Staged materialisation | `src/hooks.rs`, `stage_to_tempdir`, `staged_paths` |
| Secret scanning | `src/hooks.rs`, sentinel exit codes and parsers |
| Hook entry points | `src/hooks.rs`, `hook_pre_commit`, `hook_commit_msg`, `hook_pre_push` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --test integration pre_commit pre_push
```
