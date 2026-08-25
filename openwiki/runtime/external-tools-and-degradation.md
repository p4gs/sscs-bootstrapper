---
type: Architecture Guide
title: External tools, detection and degradation
description: How sscsb pins tool versions, what makes a binary count as installed, and why a decoy on PATH no longer satisfies a control.
tags: [tools, pinning, detection, degradation, path]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# External tools, detection and degradation

`sscsb` orchestrates around twenty external tools. This module is where they are
pinned, detected, and — when they are absent — explained.

## One place for pins

The tool registry is the **single place versions are pinned**, and nothing in sscsb
ever fetches "latest". Each entry carries an id, the binary name (which is sometimes
different), the pinned version, how to ask it for its version, a homepage, an optional
package-manager formula, and an install note.

There is a second copy of eleven of those pins, as environment variables in the CI
setup action. A parity test makes the registry **normative** and the CI action a
derived copy, because otherwise CI would test against one version while the degrade
message told users to install another, and both would look correct in isolation. See
[CI and tool pins](../development/ci-and-tool-pins.md).

That test also pins a deliberate **omission**: four tools are intentionally *not*
installed in CI, so their degrade branches stay exercised there. Adding one of them to
the CI action would silently delete a coverage path.

## What "installed" means

Stricter than being on `PATH`. A binary counts as available only if it:

1. is found on `PATH`,
2. is **executable**,
3. spawns successfully,
4. exits zero, and
5. **prints something**.

A parseable version is deliberately **not** required — some tools report versions the
parser cannot read, and calling a genuinely installed tool missing over that would be
a false positive.

### The decoy that satisfied a control

The reason for that strictness is a reproduced defect. Accepting any regular file —
which is what a plain file-exists check does — meant a **non-executable three-line
text file** dropped into a `PATH` directory under a tool's name was reported as that
tool being installed. Combined with a version probe whose failure was swallowed, it
flipped `verify --strict` from exit 1 to exit 0.

That resolution path is shared by **every** orchestrated tool, so the defect was one
bug with many faces.

Symlinks *are* followed, deliberately: `PATH` directories are full of them — package
manager shims, alternatives systems, toolchain wrappers — and it is the target that
gets executed.

### The residual, stated rather than hidden

An **executable** stub that prints anything and exits zero still detects. Telling a
real tool from a convincing impostor needs checksum or signature pinning of the binary
itself, which is a separate control rather than a detection tweak.

That limit is written into the source next to the fix, which is the right place for it.

## Degradation that does not waste your time

When a tool is unusable, the message **re-queries `PATH`** to work out which of two
things went wrong:

- **not found on PATH** — with the pinned known-good version and an install route;
- **found at a path, but the version probe did not succeed** — present, not working.

The reason is practical: telling an operator a binary is missing when it is sitting
right there on their `PATH` is a lie that costs them an hour.

Install hints are **platform-shaped**: a package-manager formula where one exists on
the platform that has that manager, the same formula noted as available through the
Linux port where relevant, and the tool's own install note otherwise.

## Versions are for humans

Version extraction keeps pre-release and build suffixes **verbatim**, and the reason
is a call-site fact rather than a style preference: every consumer only ever
*displays* the version beside the pin for a person to compare. Nothing parses it back
into a version and compares programmatically.

So truncating a release candidate down to its base version would make an `rc` build
look **identical to the pin** in the one place anyone looks. Trailing content that is
not a real version suffix is dropped instead.

## No caching

Availability is not cached. Each query re-runs the version probe, so several controls
asking about the same tool re-spawn it. That keeps answers honest within a run at the
cost of some process spawns.

## Where this shows up

Degradation is the mechanism behind a large share of `DEGRADED` verdicts, and
[the verdict contract](../control-model/registry-and-outcomes.md#degraded-is-not-pass)
explains why those must not read as passing. `sscsb status` uses the same detection to
print `ok` or `missing` per tool — see [phases](../control-model/phases.md).

## Source map

| Concern | Location |
|---|---|
| Registry and pins | `src/tools.rs`, `TOOLS` |
| Detection | `src/tools.rs`, `detect`, `is_available` |
| PATH lookup and executability | `src/exec.rs`, `find_in_path`, `find_in` |
| Degrade messages | `src/tools.rs`, `degrade_message` |
| Version extraction | `src/tools.rs`, `extract_version` |
| Platform hints | `src/platform.rs` |
| Pin parity | `tests/tool_pin_parity.rs` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib tools:: && \
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --test tool_pin_parity
```

One test walks a decoy through four states — non-executable, executable but failing,
executable but silent, and genuinely working — and asserts only the last detects.
