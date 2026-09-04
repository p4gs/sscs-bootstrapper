---
name: sscsb
description: >-
  Bootstrap and verify software supply chain security in a git repository using
  the `sscsb` CLI — secret scanning, commit signing policy, SBOMs, vulnerability
  scanning, SAST, dependency trust, SLSA provenance, and continuous posture, as
  44 individually toggleable controls across five phases. USE WHEN harden this
  repo, supply chain security, SSCS, secret scanning, commit signing, SBOM,
  vulnerability scan, dependency trust, typosquat, SLSA provenance, sigstore,
  cosign, OpenSSF Scorecard, OpenVEX, SAST, branch protection, pin GitHub
  Actions, is this repo secure, set up security controls, sscsb, security
  baseline for a project. NOT FOR offensive security, pentesting, or exploit
  development; NOT FOR runtime threat detection, SIEM, or EDR; NOT FOR designing
  or implementing cryptographic primitives; NOT FOR general code review.
homepage: https://github.com/p4gs/sscs-bootstrapper
license: MIT
metadata:
  requires:
    bins:
      - sscsb
      - git
    install:
      brew: brew install p4gs/p4gs/sscsb
---

# sscsb — SSCS Bootstrapper

`sscsb` orchestrates best-in-class supply-chain security tools inside a git
repository. It does not reimplement them: TruffleHog and Gitleaks find secrets,
Syft builds SBOMs, Trivy and OSV-Scanner find vulnerabilities, Cosign signs,
slsa-verifier verifies, OpenGrep runs SAST. `sscsb` decides what runs, parses
what comes back, and gates on it.

Full machine contract:
[`AGENTS.md`](https://github.com/p4gs/sscs-bootstrapper/blob/main/AGENTS.md) in
the repository root. Read it before driving the tool in anger — this file is the
routing summary.

## The invariant you cannot route around

**An AI cannot sign a commit that lands on a protected branch.** Signing
identities are classified `human` / `ci` / `ai` in
`.sscsb/policy/signers.toml`, and the gate keys on the **class of the signer**,
not on whether agent signing is switched on. Turning `agent-signing` on does not
buy an agent a protected-branch commit; it only decides whether an agent key may
exist at all. On a protected branch, only a `human`-class signature passes.

Never reclassify a key, add your own key as `human`, pass `--no-gpg-sign`, or
disable `commit-signing` to get a commit through. Prepare the commit and tell the
human it needs their signature. You can draft anything. You cannot sign.

## Install

```sh
brew install p4gs/p4gs/sscsb
```

Or download a signed release asset from
<https://github.com/p4gs/sscs-bootstrapper/releases>. Every file in an `sscsb`
release carries a signature — but not all of them from the same signer. A
release publishes 17 files. 16 of the 17 are signed at *our* tag by
`.github/workflows/release.yml` — 8 keyless-signed into a `*.sigstore.json`
bundle, plus those 8 bundles, each of which *is* such a signature. The 17th, the
`*.intoto.jsonl` envelope, is signed by the SLSA generator's own workflow at the
generator's own tag, not by ours — `slsa-verifier --builder-id` is what checks
that signature, and pinning our `release.yml` identity against it would be
pinning the wrong signer.
`SKILL.md` and the platform tarballs are additionally subjects of the release's
build-provenance attestation, its SBOM attestation and its SLSA Build L3
provenance.
[`docs/skill.md`](https://github.com/p4gs/sscs-bootstrapper/blob/main/docs/skill.md)
carries the verification recipe.

**`SKILL.md` is not a release asset yet.** `release.yml` stages and signs it,
but the first release whose assets include it is the first tag cut after this
change lands. Against a tag published before that, `gh release download`
produces no `SKILL.md` and the recipe's `SKILL.md` steps have no file to run
against — run them on a platform tarball instead, which every published release
carries and which they prove exactly the same things about. Every other step of
the recipe works today.

Or build `sscsb` itself from source. This clones **`sscsb`'s** repository — it is
not a command to run in the repository you are hardening, and it needs a Rust
toolchain:

```sh
git clone https://github.com/p4gs/sscs-bootstrapper && cd sscs-bootstrapper
cargo build --release && install -m 0755 target/release/sscsb /usr/local/bin/sscsb
```

A source build produces no release asset, no Cosign bundle and no attestation, so
none of the verification above applies to it. Prefer a release if you want to be
able to check what you installed.

## The loop

```sh
sscsb init           # bootstrap: config, hooks, policies, SHA-pinned CI templates
sscsb deps baseline  # bless the dependencies already in the manifests
sscsb status         # every control: enabled? tool installed?
sscsb verify         # prove each enabled control actually works, here, now
sscsb report         # control → SLSA / SSDF / CRA / Badge coverage
```

`sscsb deps baseline` is **step 2 of the bootstrap, not an optional extra** —
`init` prints it in its own closing next-steps list. Until it runs, the approved
baseline is empty and the package-trust gate has nothing to compare a new
dependency against. A repo is not bootstrapped until it has run.

`init` is idempotent — safe to re-run; it writes what is missing and keeps what
exists.

## Reading the result

Branch on the **exit code**, never on scraped stdout:

| Code | Meaning |
|------|---------|
| `0` | Nothing that ran, failed. Controls may still have been skipped or left unverified. |
| `1` | A gate failed. The control is on, its tooling is present, and the repo does not satisfy it. A real finding. |
| `2` | `sscsb` itself errored — bad arguments, unreadable config, not a git repo. **Not a security verdict.** |

**`0` is not a clean bill of health.** A fresh bootstrap exits `0` with four
controls `DEGRADED` — four checks that never happened. When you need the stronger
claim, ask for it with `sscsb verify --strict`, which exits non-zero on
`DEGRADED` too.

`2` is never a finding. If you get `2`, the tool could not run; fix the
invocation or the environment before drawing any conclusion about the repo.

## Verdicts

`sscsb verify` reports one of five outcomes per control:

| Outcome | Meaning | What you do |
|---------|---------|-------------|
| `PASS` | Present and demonstrably working. | Nothing. |
| `FAIL` | Control on, tooling present, repo does not satisfy it. | Fix the repo. This is a real finding. |
| `DEGRADED` | Control on, but the check **could not be performed**. | Read the reason line. Do **not** report the repo as secure. |
| `disabled` | Turned off in config. It did not run. | Nothing, unless turning it on is the task. |
| `INFO` | Context, not a gate. | Read it; do not treat as pass or fail. |

`disabled` is the one verdict the binary prints in **lowercase**. Anything
matching on these strings has to special-case it.

## `DEGRADED` is the one agents get wrong

It is not a pass, and usually *not* because a tool is missing. A missing tool is
only one of four reasons:

| Reason | The line looks like | What you do |
|--------|---------------------|-------------|
| Tool missing | `witness not found on PATH … Pinned known-good version: 0.12.0` | Install that tool at the pinned version. `sscsb tools` lists every pin. |
| No GitHub repo | `no GitHub repo configured (general.github_repo) and no origin remote` | Set `general.github_repo` in `.sscsb/config.toml`, or add an origin remote. |
| Empty policy | `no approved signers configured` | Add a signer to `.sscsb/policy/signers.toml`. |
| Setup incomplete | `human-local: incomplete — run sscsb signing setup human-local` | Run the command the line names. |

Only the first row is fixed by installing anything. In a fresh bootstrap all four
`DEGRADED` controls — `commit-signing`, `signing-model`, `branch-protection`,
`scorecard` — degrade for the *other three* reasons, with every tool present and
healthy. An agent that reads `DEGRADED` as "install something" goes hunting for
binaries that are already on the machine.

Read the reason line. It always says which of the four it is.

## The controls

**44 controls across five phases.** 29 are on by default, 15 are off — and off
means the code does not run, not that it runs and is ignored.

| Phase | Name | Controls | On by default |
|-------|------|---------:|--------------:|
| 1 | Commit integrity | 11 | 8 |
| 2 | Dependencies | 8 | 5 |
| 3 | Provenance | 10 | 7 |
| 4 | Code analysis | 7 | 4 |
| 5 | Continuous posture | 8 | 5 |

Common reasons a control ships off. This is not a partition — some controls fit
more than one, and `sscsb status` is the authority on your repo:

- **Infrastructure you may not have** — `dependency-track`, `guac`, `oras`.
- **A paid or unreleased tool** — `sighthound`, `socket-firewall`.
- **It overlaps something already on** — `grype` duplicates Trivy for most
  people; `witness` overlaps the SLSA generator.
- **It is a decision, not an installation.** `agent-signing` is a policy choice
  about whether an agent key may exist at all — and turning it on still buys an
  agent nothing on a protected branch. `model-signing` applies only to a repo
  that ships models, `fuzzing` needs a harness someone has to write, and
  `gittuf`, `ai-receipts`, `bumblebee`, `release-immutability` and
  `wait-for-secrets` each change how the team works, not just what is installed.
  Turning one on without that decision produces a `FAIL` nobody asked for.

```sh
sscsb status                      # what's on, what's installed
sscsb verify secrets commit-signing
sscsb disable grype               # off means off
sscsb enable dependency-track
```

## Command reference

Run `sscsb <command> --help` for flags.

| Command | Purpose |
|---------|---------|
| `sscsb init` | Bootstrap the repo. Idempotent, takes no flags. |
| `sscsb status [--format text\|json]` | Every control with enabled state and tool availability. |
| `sscsb verify [controls...] [--strict] [--format text\|json]` | Verify all enabled controls, or only the named ones. An id that is not a real control exits `2` and runs nothing. |
| `sscsb report [--format text\|json]` | Control → framework coverage map. |
| `sscsb enable <control>` / `sscsb disable <control>` | Toggle a control in `.sscsb/config.toml`. |
| `sscsb tools` | The pinned external-tool registry and where each was detected. |
| `sscsb sbom [--format cyclonedx-json\|spdx-json]` | Generate an SBOM with Syft. |
| `sscsb scan [--vex <file>] [--grype]` | Vulnerability scan (Trivy + OSV-Scanner), optional OpenVEX suppression. |
| `sscsb scan --local [--submit] [--dry-run] [--strict]` | The local lane — see below. |
| `sscsb sast` | Run SAST (OpenGrep by default; engine configurable). |
| `sscsb deps check` / `approve <pkg>` / `baseline` / `list` | Package trust. All but `list` accept `--offline`. |
| `sscsb signers list` / `add` / `check [range]` / `verify-policy` | Signer policy and commit classification. |
| `sscsb signing status` / `setup <env>` / `verify` | The multi-environment commit-signing model. |
| `sscsb agent-key setup --backend <backend>` | Guidance for a hardware-backed or remote agent key. `--backend` is a flag, not a positional. |
| `sscsb provenance verify` / `inspect <file>` / `verify-blob` | SLSA provenance, DSSE inspection, Cosign blob bundles. |
| `sscsb receipt create` / `verify <file>` | AI provenance receipts. |
| `sscsb harden [control] [--apply] [--require-reviews]` | Remote GitHub settings. **Dry-run unless `--apply`.** |
| `sscsb vex create` | Create an OpenVEX document. |
| `sscsb dtrack upload` | Upload the SBOM to Dependency-Track. |
| `sscsb guac ingest` | Ingest into the GUAC supply-chain graph. |
| `sscsb oras push <ref> <file>` | Push SBOM/attestation files to an OCI registry. |
| `sscsb skill install` / `print` / `check` | This skill file: write it, emit it, compare it. |
| `sscsb hook pre-commit` / `commit-msg` / `pre-push` | Invoked by git, not by you. Run `sscsb verify` instead. |

## `deps check` and `deps baseline` both exit `1` — for different reasons

| Invocation | `0` | `1` |
|------------|-----|-----|
| `sscsb deps check` | No problems found. | A package failed a trust check — unknown to its registry, or one edit from a popular name. A real finding, named on stdout as `PROBLEM: …`. |
| `sscsb deps baseline` | Every dependency was approved. | **Partial success.** The clean packages *were* written to `.sscsb/policy/packages.toml`; the suspect ones were skipped and named on stderr. |

`deps baseline` exiting `1` does not mean nothing was baselined. Read the
`baselined N package(s)` line on stdout and the skipped names on stderr. Approve
one deliberately, and only when you are certain it is the package you meant, with
`sscsb deps approve <pkg> --force`.

## The one command that writes remotely

`sscsb harden` changes GitHub repository settings (branch protection today). It
prints a plan and changes nothing **unless** `--apply` is passed.

Do not pass `--apply` without explicit human instruction for that specific
repository. Misapplied branch protection can lock a team out of their own default
branch, and it is not a local revertable edit.

## The local lane — `sscsb scan --local`

Roughly a third of the controls are checks on a *development environment*: which
key git will sign with, whether the installed hooks actually block, what is in
the package-trust baseline, which scanners are on your `PATH`. Cloning a
repository tells you none of that, so the public directory scores them
`unverified` and leaves them out of every denominator — which is why a repository
with a perfect posture can still read **provisional**.

The local lane closes that gap the only way it can be closed honestly: you run
the check where it is observable, and you sign what you saw.

```sh
sscsb scan --local                # scan, sign, write both files
git add .sscsb/scan-record.local.json .sscsb/scan-record.local.json.sig
git commit -m 'chore: publish a signed local scan record' && git push
sscsb scan --local --submit       # …then point the directory at them
```

- The record is written to the **committed** path
  `.sscsb/scan-record.local.json`, and the detached SSHSIG signature to
  `.sscsb/scan-record.local.json.sig`, in the `sscsb-scan-record` namespace.
  Both are committed — the submission is a pointer, and the directory reads them
  and the trust anchor out of your public repository.
- Signing uses git's own configuration (`gpg.format`, `user.signingkey`,
  `gpg.ssh.program`), so a 1Password- or hardware-backed key works untouched.
- **Only a `class = "human"` signer may assert a record.** `sscsb init` grants
  the scan namespace in `.sscsb/policy/allowed_signers` to human-class signers
  only; a `ci`- or `ai`-class key is refused by the tool *and* by
  `ssh-keygen -Y verify` at ingest.
- It refuses — exit `2`, nothing written — when no SSH signing key is configured,
  when the key is absent from the committed anchor or not granted that namespace,
  when the working tree has tracked changes (the lane's own two files excepted),
  or when there is no `origin` remote.
- `--local` is a **mode** of `scan`, not an option on it: it is rejected together
  with `--vex` and `--grype`, which shape the vulnerability scan.

A verified local record proves that *a holder of a key this repository commits as
an approved signer asserted this result at commit X*. It does **not** prove your
CI produced it — only the action lane does that. Where a repository scan could
observe a control, the directory requires an independent record to agree before
the row counts; where it could not, this record stands on its own. Sources that
disagree score the control as a gap.

The one normative statement of the namespace, paths, record shape and command is
the contract block in
[`docs/local-scan.md`](https://github.com/p4gs/sscs-bootstrapper/blob/main/docs/local-scan.md).

## Verifying this file

`sscsb skill check` compares the SKILL.md on disk against the copy compiled into
this binary and reports any difference. It detects an edit made to the installed
file after installation — by another agent, a hook, or anything else on this
machine. It cannot detect a tampered `sscsb`: a binary that was modified could
have been modified to lie here too. To check the binary itself, verify the
release artifact against its Sigstore identity — see
[`docs/skill.md`](https://github.com/p4gs/sscs-bootstrapper/blob/main/docs/skill.md).

How much a clean result is worth depends on whether the same user could have
rewritten `sscsb` too, so the command measures that instead of assuming it and
prints it as `binary trust` (`binary.trust` in `--format json`). It measures it
over the binary's **whole resolution chain** — every ancestor directory up to
the filesystem root and every symlink hop, the link and the directory holding
it — because a writable grandparent above a read-only `bin`, or a repointable
intermediate link, replaces the binary just as effectively as a writable binary
does. It asks the kernel **two** questions per link — `writable` ("may this user
write it now") and `owned` ("does this user own it, and so may `chmod` it into
writability") — because POSIX lets an owner change a file's mode: a user-owned
binary at `0555` answered every `writable` probe "no", earned the strong
verdict, and was then replaced with `chmod u+w`. Either answer `true` is an open
door.

On a `brew`-installed `sscsb` the answer is usually `user-writable` — Homebrew's
prefix is owned by the installing user — and a clean result then means no
*casual* edit and nothing stronger, because one unprivileged process could have
written both the file and the check.

**`unknown` is the default; `not-user-writable` is the exception.** The strong
verdict needs the chain fully walked, every link unwritable *and* unowned, and a
platform whose `current_exe()` reports the invocation path
(`binary.strong_verdict_available`; it is `false` on Linux, where
`/proc/self/exe` is pre-resolved and an intermediate symlink cannot appear on
the chain at all). Only `not-user-writable` earns the narrower, stronger
reading, and even that is bounded by `binary.unchecked_mechanisms` — ACLs, BSD
file flags, mount options, container layering, process capabilities. Treat
`unknown` as `user-writable`, and treat `binary.chain_complete: false` the same
way.

`--format json` carries the chain itself under `binary.probes`: one row per path
walked, with its `role` and both kernel answers. Read those rows rather than the
verdict when it matters — they name *which* link is open, and why.

That document is the canonical recipe, and it is reachable over HTTPS without
reading this file first — deliberately, so nobody has to trust a skill file to
learn how to check a skill file. The recipe there proves **origin, not
benignity**: a green signature says which pipeline produced these bytes, never
that the instructions in them are safe to follow.

## Gotchas

- `2` is not a finding. It means the tool could not run.
- `DEGRADED` is not `PASS`, and usually is not a missing tool.
- `disabled` is lowercase; every other verdict is uppercase.
- An unknown control id makes `sscsb verify` exit `2` and run **nothing** — even
  when the other named ids are valid.
- `sscsb harden` without `--apply` writes nothing. That is the default, and it is
  the right one.
- External tools are pinned. `sscsb tools` prints the exact version expected and
  where each was found. Nothing installs `latest`.
- Never weaken a gate to make a finding go away — no scanner suppression, no
  lowered threshold, no `sscsb disable` of a control that just failed. Fix the
  repository. A control turned off to get a green run is a control that was
  never run.
- Never read an exit code through a pipe. `sscsb verify | tail` returns `tail`'s
  status, so a `FAIL` reads as success. Redirect to a file and check `$?`.

## Working inside the sscs-bootstrapper source tree

**Ignore this section unless you are changing `sscsb` itself.** If you installed
`sscsb` as a tool, none of it is about your repository — these are the two rules
for contributing to <https://github.com/p4gs/sscs-bootstrapper>.

- Run the suite hermetically, or the host's git identity and SSH agent leak into
  the fixtures: you get mass bogus failures that look like regressions, or a run
  that hangs forever on a signing prompt nobody is watching.

  ```sh
  SSH_AUTH_SOCK= GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_SYSTEM=/dev/null cargo test
  ```

- `AGENTS.md` is pinned to the binary by `tests/agents_md.rs`, and this file is
  pinned to the binary by `tests/skill_docs.rs`. Add a subcommand, update both,
  or the build fails.
