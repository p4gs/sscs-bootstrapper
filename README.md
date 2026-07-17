# SSCS Bootstrapper (`sscsb`)

[![CI](https://github.com/p4gs/sscs-bootstrapper/actions/workflows/ci.yml/badge.svg)](https://github.com/p4gs/sscs-bootstrapper/actions/workflows/ci.yml)

> `.github/workflows/ci.yml` is this repo's only committed workflow — everything
> else under `.github/workflows/` and `.sscsb/` is `sscsb`'s own *generated
> output* (see `.gitignore`), kept out of version control on purpose so a
> reviewer is never unsure whether a file is hand-authored or tool-produced.
> That means a live CodeQL/SAST/Scorecard/SLSA/Secret-Scan/SBOM badge would be
> unfulfillable — those workflows never actually run in *this* repo's GitHub
> Actions, so the badge would sit permanently blank, which is exactly the kind
> of quiet-false-assurance this tool exists to prevent. The real, live picture
> of what's enforced *here* is `sscsb verify` / `sscsb report`, run against
> this repo, right now — not a static badge.

Software supply chain security for solo developers and small teams who write code
with AI — bootstrapped into a git repository in one command.

`sscsb` **orchestrates** best-in-class tools. It does not reimplement them. It
detects what you have, configures it, invokes it, parses its output, and gates on
the result. TruffleHog and Gitleaks find the secrets. Syft builds the SBOM. Trivy
and OSV-Scanner find the vulnerabilities. Cosign signs. slsa-verifier verifies.
`sscsb` is the policy engine and the glue, and it is honest about which of those
tools are actually present on your machine.

```
sscsb init      # config, hooks, policies, SHA-pinned CI templates
sscsb status    # every control: enabled? tool installed?
sscsb verify    # prove each enabled control actually works, here, now
sscsb report    # control → SLSA / SSDF / CRA coverage
```

## Why this exists

The threat model changed. An AI agent can add a dependency you have never heard
of, paste a credential into a config file, or write a `curl … | sh` install step —
in a commit that looks exactly like every other commit. The controls that catch
this already exist and are excellent. Wiring them together correctly — pinned, least-privilege,
fail-closed, verified — is the part nobody has time for.

That wiring is what this is.

Three ideas run through the whole design:

**Humans, CI, and AI never share a key.** Every signing identity is classified.
Only `human`-class identities may sign a commit that lands on a protected branch,
and `sscsb` refuses to even emit an AI-class key into the `allowed_signers` file —
an AI's signature cannot be made verification-valid, no matter how the policy file
is edited. An AI can draft anything; it cannot sign.

**Every control is toggleable, and off means off.** One `.sscsb/config.toml`,
generated from the control registry itself, so the config and the code cannot
drift apart. Secure defaults on. If you disable a control, its code does not run.

**A missing tool degrades loudly, never silently.** If Trivy isn't installed,
`sscsb verify` says so, tells you the pinned version and how to install it, and
reports `DEGRADED` — it does not quietly pass. Nothing here claims to protect you
with a tool that isn't there.

## Install

```sh
cargo build --release
install -m 0755 target/release/sscsb /usr/local/bin/sscsb
```

Then, in any git repository:

```sh
sscsb init
sscsb deps baseline     # bless the dependencies you already have
sscsb verify
```

`sscsb init` is idempotent: it writes what's missing and keeps what exists. Re-run
it after an upgrade; it will not clobber your edits.

External tools are **pinned** — `sscsb tools` prints the exact version `sscsb`
expects and where each one was found. Nothing installs `latest`, and nothing is
installed behind your back.

## The five phases

Each phase is a coherent layer, and each is independently useful. Full detail —
what each control does, which tool backs it, how it fails, how to turn it off — is
in the per-phase docs.

| Phase | What it gets you | Docs |
|-------|------------------|------|
| **1 — Commit integrity** | Secrets blocked pre-commit and pre-push. Hardware-backed, human-only signing enforced on protected branches. Branch protection checked. Actions audited for mutable refs and over-broad permissions. AI-provenance commit trailers, with extra gates when AI adds a dependency or a shell command. | [docs/phase-1.md](docs/phase-1.md) |
| **2 — Know your dependencies** | CycloneDX SBOMs (Syft). Vulnerability scanning (Trivy + OSV-Scanner V2). Scorecard. Renovate with digest pinning. Package-trust: does this package *exist*, is it one edit away from a popular name, did a human approve it? | [docs/phase-2.md](docs/phase-2.md) |
| **3 — Provenance** | Keyless signing (Cosign/Fulcio/Rekor). SBOM and provenance attestations bound to artifact digests. SLSA Build L3 provenance via the official generator, verified with slsa-verifier before anything is promoted. Short-lived credentials (Octo STS). Harden-Runner on every job. | [docs/phase-3.md](docs/phase-3.md) |
| **4 — Code analysis** | OpenGrep SAST by default (Semgrep selectable), in pre-commit and CI. CodeQL on PRs and the default branch. Extended workflow auditing: `pull_request_target` misuse, credential persistence, secret echo, known-risky actions. | [docs/phase-4.md](docs/phase-4.md) |
| **5 — Continuous posture** | Dependency-Track for continuous SBOM management. GUAC for the supply-chain graph. OpenVEX so "not exploitable" is a first-class, auditable answer instead of a muted alert. A machine-readable control → SLSA/SSDF/CRA map behind `sscsb report`. | [docs/phase-5.md](docs/phase-5.md) |

Two more docs cover the parts people get wrong:

- **[docs/signing.md](docs/signing.md)** — YubiKey / `ed25519-sk` setup, the
  human/CI/AI key separation, and the WSL2 USB problem (and its fixes).
- **[docs/ai-provenance.md](docs/ai-provenance.md)** — commit trailers, the AI
  dependency and shell-command gates, and cryptographic receipts.
- **[docs/example-walkthrough.md](docs/example-walkthrough.md)** — a complete
  bootstrap on a fresh repo, with the real terminal output, including the hooks
  actually blocking a planted secret and an unsigned protected-branch commit.

## Controls

32 controls, each with an id you can `enable`, `disable`, and `verify`:

```sh
sscsb status                      # what's on, what's installed
sscsb disable grype               # off means off — the code will not run
sscsb enable dependency-track
sscsb verify secrets commit-signing
sscsb verify --strict             # DEGRADED (missing tool) also exits non-zero
```

Secure defaults are on. Off by default are the ones that need infrastructure you
may not have (Dependency-Track, GUAC, ORAS), a paid or unreleased tool
(Sighthound, Socket), or that overlap something already on (Grype duplicates
Trivy for most people; Witness overlaps the SLSA generator).

## CI templates

`sscsb init` installs workflow templates into `.github/workflows/`, one per
enabled control that has a CI half. They are **SHA-pinned to 40-character commit
digests**, least-privilege (`permissions:` on every job, `contents: read` by
default), and every job runs Harden-Runner.

There is exactly one action that is *not* SHA-pinned:
`slsa-framework/slsa-github-generator`, which **must** be referenced by tag —
that is a requirement of its own trust model, and slsa-verifier validates the
builder ref. The exception is called out in the template and encoded in the
auditor as a single named exception rather than a general hole.

`sscsb` audits its own templates: a test asserts that **every** shipped workflow
passes `sscsb`'s own Actions audit. The tool that tells you to pin your actions
cannot ship an unpinned one.

## Verification, and what "verified" means here

`sscsb verify` runs each enabled control against the actual repository and reports
one of:

| Outcome | Meaning |
|---------|---------|
| `PASS` | The control is present and demonstrably working. |
| `FAIL` | The control is on, the tooling is there, and the repository does not satisfy it. |
| `DEGRADED` | The control is on but a tool is missing. It tells you which, at which pinned version, and how to get it. Under `--strict` this exits non-zero. |
| `DISABLED` | You turned it off. It did not run. |
| `INFO` | Reported for context; not a gate. |

There are no TODO stubs, no mock integrations, and no control that claims a tool
works without running it. Where a tool is absent, `sscsb` says so.

## Platforms

macOS, Linux, and WSL. The hooks are POSIX shell shims that delegate to the Rust
binary, so they work under git's own shell everywhere, including Git for Windows.
The one genuine platform limitation is hardware-key signing under WSL2, which
cannot reach USB FIDO2 devices directly — [docs/signing.md](docs/signing.md)
covers both workarounds.

## Development

```sh
cargo build --release
cargo test               # unit + integration + library + tool-orchestration suites
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo llvm-cov --ignore-filename-regex '(main\.rs|cli\.rs)'   # 95% line / 95% fn floor
```

The suites run the **real tools** where they are installed (a real `slsa-verifier`
verification against a real signed release artifact, a real OpenGrep scan, real
Gitleaks and TruffleHog runs against a planted secret) and exercise the
degrade paths by masking `PATH` where they are not.

`main.rs` and `cli.rs` are excluded from the coverage floor: they are argument
parsing and printing over library functions that are themselves covered. Every
control's logic lives in the library, including `sscsb init` itself.

No secret-shaped string exists anywhere in this repository's history. The test
that proves the hooks block a planted credential constructs that credential at
runtime, by concatenation. The hooks are run against this repository, by this
repository's CI.
