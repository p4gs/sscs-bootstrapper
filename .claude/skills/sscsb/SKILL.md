---
name: sscsb
description: >-
  Bootstrap and verify software supply chain security in a git repository using
  the `sscsb` CLI — secret scanning, commit signing policy, SBOMs, vulnerability
  scanning, SAST, dependency trust, SLSA provenance, and continuous posture, as
  45 individually toggleable controls across five phases. USE WHEN harden this
  repo, supply chain security, SSCS, secret scanning, commit signing, SBOM,
  vulnerability scan, dependency trust, typosquat, SLSA provenance, sigstore,
  cosign, OpenSSF Scorecard, OpenVEX, SAST, branch protection, pin GitHub
  Actions, is this repo secure, set up security controls, sscsb, security
  baseline for a project. NOT FOR offensive security, pentesting, or exploit
  development; NOT FOR runtime threat detection, SIEM, or EDR; NOT FOR designing
  or implementing cryptographic primitives; NOT FOR general code review.
---

# sscsb — SSCS Bootstrapper

`sscsb` orchestrates best-in-class supply-chain security tools inside a git
repository. It does not reimplement them: TruffleHog and Gitleaks find secrets,
Syft builds SBOMs, Trivy and OSV-Scanner find vulnerabilities, Cosign signs,
slsa-verifier verifies, OpenGrep runs SAST. `sscsb` decides what runs, parses
what comes back, and gates on it.

Full machine contract: [`AGENTS.md`](../../../AGENTS.md) in the repository root.
Read it before driving the tool in anger — this file is the routing summary.

## The invariant you cannot route around

**An AI cannot sign a commit that lands on a protected branch.** Signing
identities are classified `human` / `ci` / `ai`; only `human` may sign on a
protected branch, and `sscsb` refuses to emit an `ai`-class key into
`allowed_signers` at all.

Never reclassify a key, add your own key as `human`, pass `--no-gpg-sign`, or
disable `commit-signing` to get a commit through. Prepare the commit and tell the
human it needs their signature.

## Install

```sh
brew install p4gs/p4gs/sscsb
```

## The loop

```sh
sscsb init      # bootstrap: config, hooks, policies, SHA-pinned CI templates
sscsb status    # every control: enabled? tool installed?
sscsb verify    # prove each enabled control works, here, now
sscsb report    # control → SLSA / SSDF / CRA / Badge coverage
```

`init` is idempotent — safe to re-run; it writes what is missing and keeps what
exists.

## Reading the result

Branch on the **exit code**, never on scraped stdout:

- `0` — success (for `verify`: all enabled controls passed, or degraded without `--strict`)
- `1` — a gate failed; this is a real finding
- `2` — `sscsb` itself errored (bad args, not a git repo). **Not a security verdict.**

Per-control verdicts are `PASS`, `FAIL`, `DEGRADED`, `disabled`, `INFO` — note
that `disabled` is the one the binary prints in lowercase.

**`DEGRADED` is not `PASS`.** It means a required tool was missing and the check
did not happen. Never report a repo as secure on the strength of a `DEGRADED`.
Install the tool `sscsb` names, at the version it pins. In CI, use
`sscsb verify --strict`, which exits non-zero on `DEGRADED` too.

## Common tasks

| Ask | Do |
|-----|-----|
| "Harden this repo" | `sscsb init` then `sscsb deps baseline` then `sscsb verify` |
| "Is this repo secure?" | `sscsb verify --strict`, then read verdicts — report `DEGRADED` honestly |
| "What's turned on?" | `sscsb status` |
| "Which frameworks do we cover?" | `sscsb report` (add `--format json` to parse) |
| "Scan for vulns" | `sscsb scan` (add `--vex <file>` to apply OpenVEX suppression) |
| "Generate an SBOM" | `sscsb sbom` |
| "Are these dependencies trustworthy?" | `sscsb deps check` |
| "Who signed these commits?" | `sscsb signers check` |
| "Turn off X" | `sscsb disable <control>` — off means the code does not run |

## The one command that writes remotely

`sscsb harden` changes GitHub repository settings (branch protection). It prints
a plan and changes nothing **unless** `--apply` is passed.

Do not pass `--apply` without explicit human instruction for that specific
repository. Misapplied branch protection can lock a team out of their own default
branch, and it is not a local revertable edit.

## Working inside this repository

- Never weaken a gate to make a change pass — no `#[allow(...)]`, no scanner
  suppression, no lowered coverage floor, no disabled control. Fix the code.
- Run the suite hermetically, or the host's git identity leaks into the fixtures
  and you get mass bogus failures that look like regressions:

  ```sh
  GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo test
  ```

- Never read an exit code through a pipe (`cargo test | tail` returns `tail`'s
  status). Redirect to a file and check `$?`.
- `AGENTS.md` is pinned to the binary by `tests/agents_md.rs`. Add a subcommand,
  update the doc, or the build fails.
