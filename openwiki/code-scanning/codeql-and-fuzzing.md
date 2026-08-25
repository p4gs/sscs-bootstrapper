---
type: Architecture Guide
title: Deep code scanning and fuzzing
description: Two controls whose whole implementation is a shipped template, what each honestly covers out of the box, and what you must add yourself.
tags: [codeql, fuzzing, clusterfuzzlite, templates, scorecard]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Deep code scanning and fuzzing

Two controls for the slower, deeper analysis that belongs in CI rather than at commit
time. Both are implemented **entirely as shipped templates** and declare no tools — so
neither can ever degrade for a missing tool, and the verdict is purely about bytes on
disk.

The fast local layer is [static analysis](sast.md).

## Deep code scanning covers one language out of the box

The shipped workflow analyses **only the workflow language**, and the template says
why in its own header: that is the one language every repository bootstrapped by sscsb
definitely has, and it is the only choice guaranteed to run without knowing anything
about your project.

It also says the part most tools would leave implicit:

> Add your own language. sscsb does not detect them for you, and analysis that does not
> read your source code is not analysing your source code.

So a passing verdict here means a scanning workflow is installed and valid. **It does
not mean your code is being analysed.** Adding your languages to the matrix is the step
that makes this control do the thing its name suggests.

## Why this fuzzing integration specifically

Because it is the integration the **OpenSSF Scorecard fuzzing probe detects** for this
language. That is the whole reason, stated in the template and repeated in the Scorecard
mapping — see [Scorecard](../github/scorecard.md).

Picking a different, equally good fuzzing setup would leave the Scorecard check
unsatisfied, which is a real cost when Scorecard is part of how a project is assessed.

### The scaffold ships the harness, not the targets

You get a build harness, a container definition and a pull-request workflow.
**You do not get fuzz targets**, and the build script says so directly: meaningful
targets are inherently project-specific and cannot be generated for you.

That is the honest division. A scaffold that shipped placeholder targets would produce
a green fuzzing badge over nothing.

The fuzzing control also gates a **scanner waiver file**, so that a repository with
nothing to waive never receives one — a small thing, but it is the same principle as
not installing a release stack in a repository with nothing to release.

### The container, and its two waivers

The base image is pinned **by digest**, not by tag.

Two container-scanner findings are waived, and both are argued as **category errors**
rather than as safe-in-practice exceptions:

- the build toolchain requires root-owned build directories, so there is no root-free
  way to make this language's fuzzing detectable by the probe at all;
- the container **exits after compiling**, so a health check is meaningless for it.

That framing matters. "This is fine in practice" is how waivers accumulate; "the check
does not apply to this kind of thing" is a claim someone can check.

## What verification actually asserts

The workflow template is verified **as a workflow**, so a gutted or job-less file
fails. The container scaffold files are verified as **opaque** — present and non-empty
is the only claim made about them, and the verdict says so.

See [CI hardening](../github/ci-hardening.md#the-shape-machinery) for the full shape
contract.

## Source map

| Concern | Location |
|---|---|
| Control registrations | `src/controls.rs` |
| Artifacts and gating | `src/workflows.rs`, `ARTIFACTS` |
| Code-scanning workflow | `templates/workflows/codeql.yml` |
| Fuzzing workflow | `templates/workflows/cflite-pr.yml` |
| Container scaffold | `templates/clusterfuzzlite/` |
| Waivers | `templates/trivyignore` |

sscsb runs its own fuzzing control, with targets covering its trailer, signer-policy and
dependency parsers — the three places it reads untrusted text. See
[building and testing](../development/building-and-testing.md).
