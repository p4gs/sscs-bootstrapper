---
type: Architecture Guide
title: The control registry and the verdict contract
description: How sscsb decides what a control concluded, what each of the five verdicts means, and how verdicts become process exit codes.
tags: [controls, verdicts, exit-codes, verification]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# The control registry and the verdict contract

`sscsb` is a policy engine over other people's tools. It decides which supply-chain
controls apply to a repository, invokes external scanners, parses what comes back,
and turns that into a verdict. This page owns the verdict half of that: what a
control can conclude, what each conclusion means, and how conclusions become an
exit code that CI can gate on.

If you read only one thing here, read [Degraded is not Pass](#degraded-is-not-pass).
It is the distinction most consumers of this tool get wrong.

## The registry

Every control is a `ControlDef` in the `CONTROLS` array in `src/controls.rs`: an
id, a phase, a human name and summary, whether it is on by default, which external
tools it needs, and its configuration options. There are 44 of them. The array is
the single source of truth — the generated config, the compliance map, `sscsb status`
and `sscsb report` are all derived from it rather than maintained beside it. The
[phase model](phases.md) explains how those 44 are banded, and
[adding a control](adding-a-control.md) covers what a new entry has to touch.

`verify_control` is the one dispatch point from a control id to the function that
produces its verdict.

## The five verdicts

A verdict is an `Outcome`, and there are exactly five.

| Verdict | Meaning | What you should do |
|---|---|---|
| `PASS` | The control was checked and the repository satisfies it. | Nothing. |
| `FAIL` | The control was checked and the repository does not satisfy it. | Fix the repository. This is a real finding. |
| `DEGRADED` | The control could not be checked. | Find out why. Do not read this as passing. |
| `INFO` | Context, deliberately not a gate. | Read it. It is neither a pass nor a failure. |
| `disabled` | Turned off in configuration. It did not run. | Nothing, unless turning it on is the task. |

**`disabled` is rendered in lowercase while every other verdict is uppercase.**
That asymmetry is real and it is load-bearing: anything matching on verdict strings
has to special-case it. It is exactly the kind of detail that rots in documentation,
so the agent-facing contract is pinned to the binary by a test rather than
maintained by hand.

### Folding verdicts together

Several controls share a prerequisite — most often hook integrity — and need to
combine that prerequisite's verdict with their own. `Outcome::weakest` does this,
ranking the variants `Fail` < `Degraded` < `Info` < `Pass` < `Disabled`.

Two consequences are easy to get backwards:

- Folding `Info` into a `Pass` produces `Info`. `Info` is a **downgrade** from
  passing, not a neutral annotation.
- Folding `Info` into a `Fail` or `Degraded` changes nothing, because both already
  rank below it.

`Disabled` sits at the strong end by convention, so folding it never weakens
anything. In practice it is never folded at all, for the reason in the next section.

### Where each verdict comes from

`Disabled` has exactly one producer. When a control is off in configuration,
`verify_control` returns `Disabled` with a single message and **stops before
gathering any evidence at all**. No tool is spawned, no file is read. That is what
"off means off" means concretely, and [configuration](configuration.md) covers the
rest of that contract.

`Info` is the interesting one, because it is where the tool declines to manufacture
assurance. Three producers show the pattern:

- **`secure-repo`** is a hard-coded `Info` literal in the dispatch table — the only
  control whose verdict reads no file, no tool and no remote. StepSecurity's
  secure-repo is a hosted web service rather than something checkable from a
  clone, and the verdict says so rather than inventing a check.
- **`scorecard`** returns `Info` rather than `Pass` when live Scorecard findings
  come back non-empty. The reasoning is written into the source: sscsb does not
  re-gate on another scanner's rubric, but reporting `PASS` while printing open
  findings manufactures assurance. Empty findings pass; unreadable findings degrade.
- **`model-signing`** distinguishes a scan that **completed and found no model
  files** (`Info`, genuinely not applicable here) from a scan that **hit its
  directory budget and stopped looking** (`Degraded`). "Found nothing" and "stopped
  looking" are different facts and get different verdicts.

## Degraded is not Pass

`DEGRADED` does not mean "passed with a caveat". It means the check did not happen,
so the repository's posture on that control is **unknown**.

The clearest demonstration is hook integrity, which splits three ways rather than
two:

- **`Pass`** — every hook shim is byte-identical to the one sscsb generates.
- **`Degraded`** — a shim has been edited but still contains its delegation line.
  sscsb can see that the line is present; it cannot prove that an edited shell
  script still *reaches* it. So it refuses to call the control verified.
- **`Fail`** — `core.hooksPath` points somewhere else, a shim is missing, a shim is
  not executable (git silently skips those), or the delegation line is gone.

That middle state is the whole argument. A tool that collapsed it into `Pass` would
report a repository as protected by hooks that may never run.

A common misreading is that `DEGRADED` always means a missing tool. It does not. On
a freshly bootstrapped repository, the controls that degrade typically do so because
there is no GitHub remote configured, because the signer policy is still empty, or
because a setup step has not been completed — with every required tool present. The
agent-facing documentation states this and a test enforces it by bootstrapping a
repository, running `verify commit-signing`, and asserting the verdict is `DEGRADED`
while the missing-tool message is absent.

## Verdicts become exit codes

`sscsb verify` counts only two things across all controls: how many failed, and how
many degraded. Then:

```rust
if failed > 0 || (strict && degraded > 0) { fail(1) } else { ok() }
```

| Verdict | Contribution without `--strict` | With `--strict` |
|---|---|---|
| `FAIL` | exit 1 | exit 1 |
| `DEGRADED` | none | exit 1 |
| `INFO` | none, ever | none, ever |
| `PASS` | none | none |
| `disabled` | none | none |

**`--strict` changes the exit code and nothing else.** It does not change any
control's verdict, does not change which controls run, does not promote `Info`, and
does not change the printed summary line, which reads identically either way. It is
a field on the `verify` command alone; no other subcommand reads it.

### Why exit 2 is not a finding

Exit 2 means sscsb could not run the check, not that the repository failed one. Two
paths converge on it: argument parsing fails before any repository is touched, or an
error propagates out of a command and is caught in `main`, which prints a
`sscsb error:` line to **stderr** and returns 2.

Concretely, exit 2 is what you get when you are not inside a git repository, when
there is no `.sscsb/config.toml` yet, or when the config has a value of the wrong
type. None of those is a statement about supply-chain posture. A CI job that treats
any non-zero exit as "the security gate failed" will report a missing config file as
a security finding.

So the contract for anything automating this tool is: **read the exit code, and
distinguish 2 from 1**. Then read the verdicts on stdout to characterise posture,
because exit 0 means "nothing that ran failed" and not "everything was verified" —
exit 0 coexists with degraded controls unless you passed `--strict`.

## A known gap

`cmd_verify` filters the registry down to the control ids named on the command line.
An id matching nothing simply never enters the loop, so the counters stay at zero
and the command exits 0. A mistyped control id is therefore currently
indistinguishable from a clean run. This is a defect under active repair, not a
design decision, and it is worth knowing about because it is the one place the exit
code affirmatively lies. Note the asymmetry: `sscsb enable` and `sscsb disable`
already reject an unknown id loudly and list every valid one.

## Source map

| Concern | Location |
|---|---|
| Registry and `ControlDef` | `src/controls.rs` |
| `Outcome`, `symbol`, `weakest` | `src/controls.rs` |
| Dispatch and the `Disabled` short-circuit | `src/controls.rs`, `verify_control` |
| Exit-code arithmetic | `src/cli.rs`, `cmd_verify` |
| Error-to-exit-2 mapping | `src/main.rs` |
| Hook integrity's three-way split | `src/hooks.rs`, `hook_integrity` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib controls::
```

Three separate tests, in two crates, assert that every registered control dispatches
to a real verifier and that no control ever reaches the "no verifier wired" arm.
Another disables every control in turn and requires `Disabled` with exactly the one
canonical message, which is what stops a verifier quietly ignoring its own toggle.
