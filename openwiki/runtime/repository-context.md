---
type: Architecture Guide
title: Repository context
description: How sscsb finds the repository it is operating on, resolves the slug and default branch, and where it guesses.
tags: [context, discovery, git, slug, default-branch]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Repository context

Everything downstream receives a context: the repository root, the detected platform,
and the configuration if there is one. This module builds it, and it is small enough
that its few judgement calls are worth naming individually.

## Discovery

The root is resolved **through git**, not by walking directories looking for a marker.
Outside a repository the error is the pointed `not inside a git repository`, which
surfaces as [exit 2](../control-model/registry-and-outcomes.md#why-exit-2-is-not-a-finding)
— sscsb could not run, rather than the repository failed something.

**A missing config is not an error here.** It is an absent value, which is what lets
`sscsb status` and `sscsb report` work in any repository. One accessor turns that
absence into the actionable `no .sscsb/config.toml found — run sscsb init first`, and
it is the single place that message exists, so commands requiring configuration all
fail identically.

## Slug resolution

The repository slug comes from the origin remote's URL. **Its error is swallowed**:
no remote and a git failure both yield no answer, indistinguishably.

That is not sloppiness — callers layer their own fallbacks on top, checking
configuration first and reporting a **degraded** verdict when neither source
produces a slug. The absence is handled where it means something, rather than
propagated as an error from a function whose answer is legitimately optional.

Parsing handles only the two conventional remote URL shapes and returns nothing for
anything else, taking the first two path segments and ignoring the rest.

## The default branch is a guess

This is the module's one **silent** degradation, and the most important thing on the
page.

The default branch is read from the remote's recorded head reference. On any failure
— unreadable, unset, no remote at all — it returns a hard-coded `main`, and says
nothing.

The catch is that this reference is populated only by **cloning** or by an explicit
command. A repository initialised locally, with a remote added by hand afterwards,
does **not** have it — so `default_branch` returns the fallback even though the real
default branch may be something else.

That matters because the value is substituted into
[shipped templates](../bootstrap/ci-templates.md) at install time, and rendering
happens **once**. A repository bootstrapped in that state gets workflows triggered on
the wrong branch name, and the federated-credentials trust policy gets a subject
pattern naming the wrong reference. Re-running `init` will not re-render a file it is
keeping.

Current-branch lookup, by contrast, **propagates its git error** rather than
defaulting. The asymmetry is deliberate: there is a conventional answer for "the
default branch", and none for "the branch you are on".

## Source map

| Concern | Location |
|---|---|
| Discovery and the context type | `src/context.rs`, `Ctx::discover` |
| Config gate | `src/context.rs`, `require_config` |
| Slug resolution and parsing | `src/context.rs`, `origin_slug`, `parse_repo_slug` |
| Default branch | `src/context.rs`, `default_branch` |
| Derived paths | `src/context.rs` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib context::
```
