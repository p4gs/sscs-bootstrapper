# Phase 4 — Code analysis

Phases 1–3 care about *where code came from* and *what it depends on*. Phase 4 is
the first one that reads the code.

| Control | What it does | Backing tool | Default |
|---------|--------------|--------------|---------|
| `sast` | Rule-driven SAST in pre-commit and CI | OpenGrep (default), Semgrep | on |
| `codeql` | Deep interprocedural analysis on PRs and default branch | CodeQL | on |
| `workflow-audit-extended` | `pull_request_target` misuse, credential persistence, secret echo, risky actions | (native) | on |
| `secure-repo` | Onboarding accelerator (web service) | StepSecurity | on |
| `sighthound` | Ultra-fast local pre-commit layer | Sighthound | off |
| `wait-for-secrets` | Human-in-the-loop secret injection | StepSecurity | off |

## SAST: OpenGrep by default

**OpenGrep** is the default engine — the open fork of Semgrep, with rules that stay
open. **Semgrep** is a one-line switch if you want the commercial registry:

```toml
[controls.sast]
enabled = true
engine = "opengrep"        # or "semgrep"
rules = ".sscsb/rules"     # or "auto" for the Semgrep registry
```

```sh
sscsb sast
```

`sscsb init` installs a small local ruleset at `.sscsb/rules/`, so scans work
**offline, on a fresh clone, with no registry account** — including the one that
catches `curl … | sh` install steps, which is the shape half of AI-suggested setup
instructions take. `rules = "auto"` opts into the registry instead.

In pre-commit, SAST runs over the **staged** files, and blocking-severity findings
block the commit. `INFO`, `WARNING`, `LOW` and `MEDIUM` are advisory and do not. A
pre-commit hook that blocks on everything gets disabled by the second day; the
severity line is where the control survives contact with actual work.

The blocking half is deliberately **everything else**, rather than a list of
names. Semgrep's rule schema documents `INFO | WARNING | ERROR`, but both engines
accept and echo back a rule that declares `severity: CRITICAL` or `HIGH` — so a
gate written as "block on `ERROR`" waves through the two strictest severities a
rule can carry. And a finding whose severity `sscsb` could not read at all is
recorded as `UNRATED`, which blocks: a severity we cannot place is not a low
severity, the same rule Phase 2 applies to advisories.

**A file the engine could not read is not a clean file.** Both engines report a
file they failed to parse in the results JSON's `errors` array and still exit `0`
with whatever else they found. In pre-commit that is an error rather than an
empty result — the gate's claim is about the files being committed right now, and
it cannot make that claim about a file nobody parsed — so `general.fail_open`
governs it, exactly as it governs a scanner that could not run at all. A
whole-tree `sscsb sast` reports the same thing as a `note:` naming each part of
the tree the run does not cover, without changing the exit code.

`engine` takes `opengrep` or `semgrep`, and nothing else. Anything else is a
configuration error that `sscsb verify` reports as a **FAIL** — not a pass on
some other tool's behalf. `sscsb` orchestrates a registry of tools, so a name
like `trivy` resolves to a real, installed binary; detecting it would say
nothing about whether the SAST control works, and `sscsb sast` would refuse to
run it.

A detail that cost real debugging time and is worth writing down: **OpenGrep exits
0 even when it finds things** (you need `--error` to change that), and it prints
rule-parse errors to **stdout** with an empty stderr. So `sscsb` gates on the parsed
JSON rather than the exit code, and when the tool does fail, it surfaces whichever
stream actually carried the diagnostic. Semgrep, for its part, exits `1` on
findings and `2+` on errors — and a scanner that was *killed* exits with nothing
at all, which is a failed scan and not a low exit code. Three tools, three
conventions — treating them interchangeably is how a scanner ends up reporting
green forever.

## CodeQL

CodeQL runs in CI on pull requests and the default branch. It does the thing local
pattern-matching cannot: interprocedural dataflow, tracing a value from an untrusted
source, through the functions it passes, to a dangerous sink — across files.

It is slow, and that is fine, because it does not live in your pre-commit hook. The
division of labour is: OpenGrep and (optionally) Sighthound run in the seconds you
will tolerate before a commit; CodeQL runs in the minutes you will tolerate on a
PR.

## Extended workflow audit

The [phase-1](phase-1.md) audit covers pinning and permissions. The extended audit
(`sscsb verify workflow-audit-extended`) adds the patterns that turn a workflow into
a foothold:

- **`pull_request_target` with a checkout of the PR head.** This is the classic
  one. `pull_request_target` runs with repository secrets available and *write*
  permissions, in the context of the base repository. Check out the fork's code in
  that context and you have handed an arbitrary stranger your secrets.
- **Credential persistence.** `actions/checkout` leaves a token in `.git/config` by
  default (`persist-credentials`). Any later step — including one inside a
  compromised dependency — can read it.
- **Secret echo.** Interpolating a secret into a `run:` block where it can end up in
  logs or in an error message.
- **Script injection.** `${{ github.event.* }}` interpolated straight into a shell
  command. Issue titles and branch names are attacker-controlled strings; putting
  one inside `run:` is command injection with extra steps.
- **Known-risky actions.** A substitution table pointing at hardened equivalents —
  `tj-actions/changed-files` → `step-security/changed-files`, and others. The
  `tj-actions/changed-files` compromise in 2025 rewrote the action's tags to
  exfiltrate CI secrets from thousands of repositories; the hardened forks exist
  because of it.
- **Self-hosted runners**, which have persistence characteristics a GitHub-hosted
  ephemeral runner does not.

## The StepSecurity two

**`secure-repo`** is an *onboarding accelerator*, not an action: `app.stepsecurity.io`
analyses a repository and opens a PR pinning actions, adding permissions blocks, and
inserting Harden-Runner. It is a **web service** — `sscsb` cannot invoke it, and does
not pretend to. The control reports what it is and points you at it. What it would
have fixed, `sscsb` already enforces locally; it is useful for repositories you
adopt rather than bootstrap.

**`wait-for-secrets`** (off by default) makes a workflow *pause and ask a human* for
a secret, out-of-band, mid-run. No long-lived secret sits in the repository at all.
It is the right answer for a rare, high-sensitivity release step, and completely
wrong for anything that runs often — which is exactly why it is off unless you turn
it on.

## Sighthound (optional)

**Sighthound** (`sscsb enable sighthound`) is a very fast local SAST layer, intended
for the pre-commit path where every second is felt. It is off by default and, if
enabled without being installed, reports `DEGRADED` with the install hint — it does
not silently do nothing while appearing to protect you.
