# AGENTS.md — driving `sscsb`

Instructions for AI coding agents operating `sscsb` (SSCS Bootstrapper) inside a
git repository. Humans want [README.md](README.md); this file is the machine
contract.

`sscsb` orchestrates supply-chain security tools — it does not reimplement them.
TruffleHog and Gitleaks find secrets, Syft builds SBOMs, Trivy and OSV-Scanner
find vulnerabilities, Cosign signs, slsa-verifier verifies. `sscsb` decides what
runs, parses what comes back, and gates on it.

## The one thing you cannot do

**You cannot sign a commit that lands on a protected branch.** Every signing
identity in `.sscsb/policy/signers.toml` is classified `human`, `ci`, or `ai`.
Only `human`-class identities may sign a protected-branch commit.

Be precise about *why*, because there are two separate mechanisms and only one
of them is absolute. When the `agent-signing` control is off (the default), an
`ai`-class key is not written into `allowed_signers` at all. When it is on, the
key *is* written — deliberately, so an agent's commit can verify as a genuine
agent signature on a feature branch. What never changes is the gate: the
protected-branch check keys on the signer's **class**, not on presence in
`allowed_signers`, so an AI signature is rejected there either way.

This is not a lint you can route around. Do not attempt to reclassify a key, add
your own key as `human`, pass `--no-gpg-sign`, or disable `commit-signing` to get
a commit through. If a commit needs to land, prepare it and tell the human it
needs their signature.

You can draft anything. You cannot sign.

## Install

```sh
brew install p4gs/p4gs/sscsb
```

Or from source:

```sh
cargo build --release && install -m 0755 target/release/sscsb /usr/local/bin/sscsb
```

## The core loop

```sh
sscsb init           # bootstrap: config, hooks, policies, SHA-pinned CI templates
sscsb deps baseline  # bless the dependencies already in the manifests
sscsb status         # every control: enabled? tool installed?
sscsb verify         # prove each enabled control actually works, here, now
sscsb report         # control → SLSA / SSDF / CRA / Badge coverage
```

`sscsb deps baseline` is part of the bootstrap, not an optional extra — `init`
prints it as step 2 of its own closing next-steps list. Until it runs, the
approved baseline is empty and the package-trust gate has nothing to compare a
new dependency against. A repo is not bootstrapped until it has run.

### What `init` rewrites

`sscsb init` is idempotent, but idempotent is not "nothing is overwritten". The
rule is *nothing you are meant to edit is overwritten*, and it has three
classes.

**Kept if it exists.** `.sscsb/config.toml`, the policy TOMLs
(`.sscsb/policy/signers.toml`, `.sscsb/policy/packages.toml`,
`.sscsb/policy/signing-model.toml`), every CI workflow, and every generated
config file. Your edits survive indefinitely.

**Rewritten every run — edits here are silently discarded:**

- `.sscsb/hooks/pre-commit`
- `.sscsb/hooks/commit-msg`
- `.sscsb/hooks/pre-push`
- `.sscsb/policy/allowed_signers`

The three shims carry a `DO NOT EDIT` banner and are rewritten so a tampered or
stale shim is repaired. `allowed_signers` is derived from `signers.toml` and is
regenerated on every protected-branch push anyway. Put local logic in a control,
never in a shim: a re-init will eat it, and you will not be told.

**Extended, never rewritten.** The repo's `.gitignore` gains a `.sscsb/out/`
rule, appended, and only when git reports that path is not already ignored. Your
own rules and their order are untouched.

`sscsb init` takes no flags — there is no `--force` and no `--dry-run`, and both
exit `2`. To regenerate a kept file, delete it and re-run; the run log tells you
so, line by line (`keep … (exists — delete to regenerate)`).

## Exit codes

Read these, do not scrape stdout for the word "PASS" — and then read the
per-control verdicts as well. An exit code tells you whether anything *failed*.
It does not tell you whether everything was *checked*.

| Code | Meaning |
|------|---------|
| `0` | Nothing that ran, failed. For `verify`: no enabled control returned `FAIL`. Controls may still have been skipped or left unverified. |
| `1` | A gate failed. A control is on, its tooling is present, and the repo does not satisfy it. |
| `2` | `sscsb` itself errored — bad arguments, unreadable config, not a git repo. Not a security verdict. |

**`0` is not a clean bill of health.** A fresh bootstrap exits `0` with four
controls DEGRADED — four checks that never happened. "Exit 0" means *nothing
that ran, failed*; it never means *everything was verified*. When you need the
stronger claim, ask for it:

```sh
sscsb verify --strict     # DEGRADED becomes a non-zero exit
```

So: branch on the exit code, then report the verdict counts (`verify` prints
`N failed, M degraded` on its last line). Never report a repo as secure on the
strength of an exit code alone.

`2` is never a finding. If you get `2`, the tool could not run; fix the
invocation or the environment before drawing any conclusion about the repo's
security posture.

These three codes apply to the gating commands. `harden` is not a gate and does
not follow them — see [its own section](#sscsb-harden-is-the-one-that-writes-remotely).

## Verdicts

`sscsb verify` reports one of five outcomes per control. Treat them differently:

| Outcome | Meaning | What you should do |
|---------|---------|--------------------|
| `PASS` | Present and demonstrably working. | Nothing. |
| `FAIL` | Control on, tooling present, repo does not satisfy it. | Fix the repo. This is a real finding. |
| `DEGRADED` | Control on, but the check could not be performed. | Read the reason line — it says what was missing. **Do not** report the repo as secure; nothing was checked. |
| `disabled` | Turned off in config. It did not run. | Nothing, unless turning it on is the task. |
| `INFO` | Context, not a gate. | Read it; do not treat as pass or fail. |

**`DEGRADED` is the one agents get wrong.** It is not a pass. It means the check
did not happen — and usually *not* because a tool is missing. A missing tool is
only one of four reasons:

| Reason | The line looks like | What you do |
|--------|---------------------|-------------|
| Tool missing | `witness not found on PATH … Pinned known-good version: 0.12.0` | Install that tool at the pinned version. `sscsb tools` lists every pin. |
| No GitHub repo | `no GitHub repo configured (general.github_repo) and no origin remote` | Set `general.github_repo` in `.sscsb/config.toml`, or add an origin remote. |
| Empty policy | `no approved signers configured` | Add a signer to `.sscsb/policy/signers.toml`. |
| Setup incomplete | `human-local: incomplete — run sscsb signing setup human-local` | Run the command the line names. |

Only the first row names a tool, and only the first row is fixed by installing
anything. In a fresh bootstrap all four DEGRADED controls — `commit-signing`,
`signing-model`, `branch-protection`, `scorecard` — degrade for the *other three*
reasons, with every tool present and healthy. An agent that reads `DEGRADED` as
"install something" goes hunting for binaries that are already on the machine.

Read the reason line. It always says which of the four it is.

Under `--strict`, DEGRADED exits non-zero, which is usually what you want in CI:

```sh
sscsb verify --strict
```

## Command reference

Every command below exists in the binary. Run `sscsb <command> --help` for flags.

### Core

| Command | Purpose |
|---------|---------|
| `sscsb init` | Bootstrap the repo — config, hooks, policies, CI templates. Idempotent, takes no flags; see [What `init` rewrites](#what-init-rewrites). |
| `sscsb status [--format text\|json]` | Every control with enabled state and tool availability. |
| `sscsb verify [controls...] [--strict] [--format text\|json]` | Verify all enabled controls, or only the named ones. An id that is not a real control exits `2` and runs nothing — including when other named ids are valid. JSON output is schema-versioned; exit codes are identical in both formats. |
| `sscsb scan --local [--submit] [--dry-run] [--strict]` | Produce a **local-lane** record for the public directory: a directory `ScanRecord` (the site's own schema — `schema_version` 1, `methodology_version` 1) bound to this repo and commit, written to the **committed** path `.sscsb/scan-record.local.json` and signed with git's own signing key (`gpg.format`, `user.signingkey`, `gpg.ssh.program`) as a detached SSHSIG in the `sscsb-scan-record` namespace at `.sscsb/scan-record.local.json.sig`. Commit and push both — the submission is a pointer, and the directory reads them from the public repository. Refuses — exit `2`, nothing written — when no SSH signing key is configured, when the key is absent from the committed `.sscsb/policy/allowed_signers` or not granted that namespace, when the working tree has tracked changes (the lane's own two output files excepted), or when there is no `origin` remote. Rejected together with `--vex`/`--grype`, which shape the vulnerability scan. `--submit` files the pointer with `gh`; `--dry-run` prints it instead. It proves a repository-approved signer asserted the result at a commit — **not** that CI ran the scan — so a row only counts where either no independent observation is possible, or an independent record agrees with it. The one normative statement of namespace/paths/shape/command is the contract block in [docs/local-scan.md](docs/local-scan.md). |
| `sscsb report [--format text\|json]` | Control → framework coverage map. |
| `sscsb enable <control>` / `sscsb disable <control>` | Toggle a control in `.sscsb/config.toml`. Off means the code does not run. |
| `sscsb tools` | The pinned external-tool registry and where each was detected. |

### Scanning and analysis

| Command | Purpose |
|---------|---------|
| `sscsb sbom [--format cyclonedx-json\|spdx-json]` | Generate an SBOM with Syft. |
| `sscsb scan [--vex <file>] [--grype]` | Vulnerability scan (Trivy + OSV-Scanner), optional OpenVEX suppression. |
| `sscsb sast` | Run SAST (OpenGrep by default; engine configurable). |
| `sscsb deps check` | Validate packages — registry existence plus typosquat heuristics. |
| `sscsb deps approve <pkg>` | Approve one package into the baseline, e.g. `cargo:serde`. |
| `sscsb deps baseline` | Approve everything currently in the manifests. |
| `sscsb deps list` | List the approved baseline. |

`deps check` and `deps baseline` both gate, and their `1` means different
things:

| Invocation | `0` | `1` |
|------------|-----|-----|
| `sscsb deps check` | No problems found. | A package failed a trust check — unknown to its registry, or one edit from a popular name (possible typosquat). A real finding; the offending package is named on stdout as `PROBLEM: …`. |
| `sscsb deps baseline` | Every dependency was approved. | **Partial success.** The clean packages *were* written to `.sscsb/policy/packages.toml`; the suspect ones were skipped and named on stderr. |

`deps baseline` exiting `1` does not mean nothing was baselined — read the
`baselined N package(s)` line on stdout and the skipped names on stderr. Resolve
each skipped package on its merits; approve one deliberately, and only when you
are certain it is the package you meant, with `sscsb deps approve <pkg> --force`.

Both accept `--offline`, which skips the registry-existence lookup and leaves
the local typosquat heuristic running.

### Provenance and signing

| Command | Purpose |
|---------|---------|
| `sscsb provenance verify` | Verify an artifact against SLSA provenance (wraps slsa-verifier). |
| `sscsb provenance inspect <file>` | Inspect a DSSE/in-toto provenance file. |
| `sscsb provenance verify-blob` | Verify a cosign keyless blob signature bundle. |
| `sscsb signers list` | Configured signers with class, backend, expiry, attestation state. |
| `sscsb signers add` | Add a signer to `.sscsb/policy/signers.toml`, validated before writing. |
| `sscsb signers check` | Classify recent commits as human / ci / agent / unsigned. |
| `sscsb signers verify-policy` | Server-side gate: reject policy changes not made by a pre-trusted human. |
| `sscsb signing status` / `setup` / `verify` | The multi-environment commit-signing model. |
| `sscsb agent-key setup --backend <backend>` | Setup guidance for a hardware-backed or remote agent signing key. `--backend` is a flag, not a positional. |
| `sscsb receipt create` / `verify <file>` | AI provenance receipts. |

### Remote and integrations

| Command | Purpose |
|---------|---------|
| `sscsb harden [control] [--apply] [--require-reviews]` | Remediate remote GitHub settings toward Scorecard alignment. **Dry-run unless `--apply`.** |
| `sscsb vex create` | Create an OpenVEX document. |
| `sscsb dtrack upload` | Upload the SBOM to Dependency-Track. |
| `sscsb guac ingest` | Ingest into the GUAC supply-chain graph. |
| `sscsb oras push <ref> <file>` | Push SBOM/attestation files to an OCI registry. |

### Hooks (invoked by git, not by you)

`sscsb hook pre-commit`, `sscsb hook commit-msg <file>`, `sscsb hook pre-push <remote> <url>`.
These are the entry points the installed shims call. Do not invoke them directly
to "test" a repo — run `sscsb verify` instead.

## `sscsb harden` is the one that writes remotely

`sscsb harden` changes GitHub repository settings — branch protection today.
It **prints a plan and changes nothing** unless you pass `--apply`.

Do not pass `--apply` without explicit human instruction for that specific
repository. Changing branch protection can lock a team out of their own default
branch, and it is not a local, revertable edit.

`harden` is not a gate, and the exit-code table above does not describe it:

| Code | Meaning |
|------|---------|
| `0` | harden reached the remote and read it. This says nothing about whether changes are pending — a dry run that printed a plan full of changes still exits `0`. |
| `1` | harden could not do its job: no `general.github_repo` *and* no origin remote, `gh` missing, no branch-protection ruleset targeting any configured branch, or an `--apply` write that failed. |
| `2` | A control `harden` does not support. Only `branch-protection` exists today. |

The plain `sscsb harden` dry run exits `1` in a repo with no GitHub remote
configured. Against the gating table that reads as "a gate failed" — it is not.
It means harden found nothing to inspect. Read the printed line: it names which
of the four `1` conditions you hit.

## Configuration

One file: `.sscsb/config.toml`, generated from the control registry so config and
code cannot drift apart.

```toml
[general]
protected_branches = ["main", "master"]
fail_open = false          # true would let hooks pass when scanners are missing
github_repo = "owner/repo"

[controls.secrets]
enabled = true
trufflehog = true
gitleaks = true
```

Policy lives beside it:

- `.sscsb/policy/signers.toml` — signing identities and their class
- `.sscsb/policy/allowed_signers` — the git-consumable allowed-signers file
- `.sscsb/policy/packages.toml` — the approved dependency baseline
- `.sscsb/rules/` — SAST rules
- `.sscsb/hooks/` — the installed hook shims

`.sscsb/out/` is regenerated output — SBOMs, receipts, VEX documents. `init`
ensures it is ignored: it asks git whether the path is already ignored, and only
if not, appends a `.sscsb/out/` rule to the repo's `.gitignore`. An existing
`.gitignore` is extended, never rewritten, so your own rules and their order
survive. A rule you spelled differently, or one in `.git/info/exclude` or your
global excludes, counts — nothing is appended on top of it.

Everything else under `.sscsb/` is policy and **is** committed. Never commit
anything from `.sscsb/out/`: a regenerated SBOM in policy history buries the
real policy diffs reviewers need to see.

## Rules for agents working in this repository

1. **Never weaken a gate to make a change pass.** No `#[allow(...)]`, no scanner
   suppression, no lowered coverage threshold, no disabled control. If a check
   fails, the code is wrong. Fix the code.
2. **Never claim a control works because it is enabled.** Enabled is not
   verified. Run `sscsb verify` and read the outcome.
3. **`DEGRADED` is not `PASS`.** Say what was missing — the tool, the config,
   the remote, or the policy. Do not assume it was a tool; most of the time it
   is not.
4. **Do not invent surface.** Every command, flag, and control id you reference
   must exist. `tests/agents_md.rs` asserts this file's documented command and
   control sets match the binary — if you add a command, update this file or the
   test fails.
5. **Run tests hermetically.** The suite builds real git repos and verifies real
   signatures, so the host's git identity must not leak in:

   ```sh
   GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo test
   ```

   Mass `status U` / "communication with agent failed" failures under any other
   invocation are the harness leaking, not a regression.
6. **Never read an exit code through a pipe.** `cargo test | tail` returns
   `tail`'s status. Redirect to a file and check `$?`.

## Development

```sh
cargo build --release
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo llvm-cov --ignore-filename-regex '(main\.rs|cli\.rs)'   # gate: 95% lines / 94% functions (see ci.yml)
```

`main.rs` and `cli.rs` are excluded from the coverage floor — they are argument
parsing and printing over library functions that are themselves covered.

## Where to read more

- [README.md](README.md) — the human introduction
- [docs/phase-1.md](docs/phase-1.md) … [docs/phase-5.md](docs/phase-5.md) — what each control does and how it fails
- [docs/signing.md](docs/signing.md) — the human/CI/AI key separation
- [docs/ai-provenance.md](docs/ai-provenance.md) — commit trailers and AI gates
- [docs/example-walkthrough.md](docs/example-walkthrough.md) — a real bootstrap with real output

<!-- OPENWIKI:START -->

## OpenWiki

This repository has a generated `openwiki/` evidence index. It is optional just-in-time context, not required startup reading.

- Treat source code and tests as authoritative. A brief's unknowns and review items are verification gaps, not automatic requirements.
- Prefer the narrowest quiet validation that proves the changed behavior. Preserve complete failure output.

The scheduled OpenWiki GitHub Actions workflow refreshes the repository wiki. Do not hand-edit generated OpenWiki pages unless explicitly asked; prefer updating source code/docs and letting OpenWiki regenerate.

<!-- OPENWIKI:END -->
