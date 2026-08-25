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
sscsb init      # bootstrap: config, hooks, policies, SHA-pinned CI templates
sscsb status    # every control: enabled? tool installed?
sscsb verify    # prove each enabled control actually works, here, now
sscsb report    # control → SLSA / SSDF / CRA / Badge coverage
```

`sscsb init` is idempotent. It writes what is missing and keeps what exists —
safe to re-run after an upgrade, and it will not clobber edits.

## Exit codes

Read these, do not scrape stdout for the word "PASS".

| Code | Meaning |
|------|---------|
| `0` | Success. For `verify`: every enabled control passed (or degraded, without `--strict`). |
| `1` | A gate failed. A control is on, its tooling is present, and the repo does not satisfy it. |
| `2` | `sscsb` itself errored — bad arguments, unreadable config, not a git repo. Not a security verdict. |

`2` is never a finding. If you get `2`, the tool could not run; fix the
invocation or the environment before drawing any conclusion about the repo's
security posture.

## Verdicts

`sscsb verify` reports one of five outcomes per control. Treat them differently:

| Outcome | Meaning | What you should do |
|---------|---------|--------------------|
| `PASS` | Present and demonstrably working. | Nothing. |
| `FAIL` | Control on, tooling present, repo does not satisfy it. | Fix the repo. This is a real finding. |
| `DEGRADED` | Control on, but a required tool is missing. | Install the named tool at the pinned version. **Do not** report the repo as secure — nothing was checked. |
| `disabled` | Turned off in config. It did not run. | Nothing, unless turning it on is the task. |
| `INFO` | Context, not a gate. | Read it; do not treat as pass or fail. |

**`DEGRADED` is the one agents get wrong.** It is not a pass. It means the check
did not happen. Under `--strict` it exits non-zero, which is usually what you
want in CI:

```sh
sscsb verify --strict
```

## Command reference

Every command below exists in the binary. Run `sscsb <command> --help` for flags.

### Core

| Command | Purpose |
|---------|---------|
| `sscsb init` | Bootstrap the repo — config, hooks, policies, CI templates. Idempotent. |
| `sscsb status` | Every control with enabled state and tool availability. |
| `sscsb verify [controls...] [--strict]` | Verify all enabled controls, or only the named ones. An id that is not a real control exits `2` and runs nothing — including when other named ids are valid. |
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

`.sscsb/out/` is regenerated output (SBOMs, receipts) and is gitignored.
Everything else under `.sscsb/` is policy and **is** committed.

## Rules for agents working in this repository

1. **Never weaken a gate to make a change pass.** No `#[allow(...)]`, no scanner
   suppression, no lowered coverage threshold, no disabled control. If a check
   fails, the code is wrong. Fix the code.
2. **Never claim a control works because it is enabled.** Enabled is not
   verified. Run `sscsb verify` and read the outcome.
3. **`DEGRADED` is not `PASS`.** Say the tool was missing.
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
