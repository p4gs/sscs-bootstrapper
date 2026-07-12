# Phase 1 — Commit integrity

The commit is the boundary. Everything downstream — the SBOM, the scan, the
provenance, the release — describes code that got in through a commit. If a
credential, an unreviewed dependency, or an unattributed AI change can walk
through that boundary, nothing further down the chain can undo it.

Phase 1 puts eight controls on that boundary.

| Control | What it does | Backing tool | Default |
|---------|--------------|--------------|---------|
| `secrets` | Blocks credentials at pre-commit and pre-push | TruffleHog, Gitleaks | on |
| `commit-signing` | Hardware-backed, human-only signing on protected branches | git + OpenSSH | on |
| `branch-protection` | Verifies GitHub's protected-branch rules are actually set | `gh` | on |
| `actions-audit` | Flags mutable action refs and missing/over-broad permissions | (native) | on |
| `ai-trailers` | Validates AI-Assisted / AI-Tool / AI-Model / AI-Role trailers | (native) | on |
| `ai-dep-gate` | Extra gates when an AI commit adds a dependency or a shell command | (native) | on |
| `pr-template` | PR template asking what the AI wrote | (native) | on |
| `ai-receipts` | Cryptographic receipts binding a commit to a tool/model/role | Cosign | off |

## How the hooks work

`sscsb init` writes POSIX shell shims into `.sscsb/hooks/` and points git at them
with `core.hooksPath`. The shims contain no logic. They delegate:

```sh
#!/bin/sh
# This shim only delegates; policy logic lives in the sscsb CLI (Rust).
exec sscsb hook pre-commit "$@"
```

Two consequences worth stating plainly.

**The shims fail closed.** If `sscsb` is not on `PATH`, the hook does not shrug
and let the commit through — it exits non-zero and tells you why. A security
control that silently disappears when its binary is missing is worse than no
control, because you believe you have one.

**`core.hooksPath` is a single switch.** Your hooks live in the repository, are
visible in `git status`, and travel with a clone. There is no `.git/hooks`
tampering to detect, because nothing is installed there.

### pre-commit

Runs against the **staged content**, not your working tree — the thing that is
actually about to be committed. `sscsb` materializes the staged blobs into a
temporary directory and scans that.

- **TruffleHog** in filesystem mode, `--results=verified,unknown`. Verified means
  it called the provider and the credential is live. Unknown means it looks like a
  credential and could not be checked. Both block.
- **Gitleaks** in directory mode against the same staged snapshot.
- **SAST** (if `sast` is enabled) over the staged files; `ERROR`-severity findings
  block. See [phase-4.md](phase-4.md).

If neither scanner is installed, the commit is **blocked**, not allowed. That is
the fail-closed rule again: `sscsb` will not let you believe you are being
scanned when you are not.

### commit-msg

Validates AI provenance trailers, and applies the AI gates. See
[ai-provenance.md](ai-provenance.md) for the full contract. In short:

- If `AI-Assisted: true` is present, `AI-Tool`, `AI-Model`, and `AI-Role` must all
  be present, and the role must be one of `draft`, `review`, `test`, `refactor`.
- If that AI-assisted commit **touches a dependency manifest**, it must also carry
  `AI-Dependency-Review: approved` — and every newly-introduced package must be in
  the approved baseline. A human has to have looked.
- If it **adds a shell script**, it must carry `AI-Command-Review: approved`.

The point is not the trailer. The point is that an AI cannot add a dependency or a
shell command to your repository without a human explicitly saying, in the commit
itself, that they reviewed it.

### pre-push

Reads the refs being pushed on stdin (git's actual pre-push protocol), and for
each one:

- **Range secret scan.** TruffleHog `git --since-commit` and Gitleaks
  `--log-opts` over exactly the commits you are about to publish. Pre-commit only
  ever saw one commit at a time; this sees the range, including anything that
  arrived by rebase, cherry-pick, or `--no-verify`.
- **Signing enforcement**, below.

Branch deletions are never blocked.

## The signing guard

This is the control most worth understanding, because it is the one that encodes
the rule that humans, CI, and AI never share a key.

`.sscsb/policy/signers.toml` classifies every identity:

```toml
[[signer]]
principal = "you@example.com"
class = "human"              # human | ci | ai
hardware_backed = true
ssh_public_key = "sk-ssh-ed25519@openssh.com AAAA…"
```

From that, `sscsb` **generates** `.sscsb/policy/allowed_signers` — the file git
uses to decide whether a signature is valid — and points `gpg.ssh.allowedSignersFile`
at it. The generator has one rule that cannot be configured away:

> **An `ai`-class key is never written to `allowed_signers`.**

Not "is written and then rejected." Not written at all. An AI's signature cannot be
verification-valid in this repository, because the material needed to verify it is
not there. You cannot misconfigure your way into an AI-signed commit, and an AI
with write access to the policy file cannot promote itself, because the class it
would have to claim is the one that gets stripped.

On a **protected branch** (`main` and `master` by default; configurable), pre-push then requires
that every commit in the range is:

1. **Signed** — git reports a good signature;
2. by a key in `allowed_signers`;
3. whose class is **`human`**;
4. and, if `require_hardware_backed = true` (the default), marked as hardware-backed.

Anything else is blocked, with the offending commit named.

CI-class keys exist so that a CI identity can sign artifacts and attestations —
not protected-branch commits. AI-class entries exist so you can *record* that an AI
identity exists and have the system actively refuse it.

### Merge commits

A merge commit whose parents include AI-assisted work is checked for review
evidence, so the merge is not a laundering path for commits that would have been
blocked individually.

## Branch protection

`sscsb verify branch-protection` asks GitHub what the rules on the branch actually
are (`gh api repos/{owner}/{repo}/rules/branches/{branch}` — which covers both
rulesets and classic protection) and reports the gaps: pull requests not required,
force-push allowed, signatures not required, status checks missing.

It reports. It does not silently change your repository's governance. If `gh` is
missing or unauthenticated, or no GitHub repo is configured, the control reports
`DEGRADED` and says which.

## Actions audit

Every workflow in `.github/workflows/` is parsed and checked for:

- **Mutable action refs.** `uses: actions/checkout@v4` is a tag. Tags move. The
  audit requires a 40-character commit SHA.
- **Missing or over-broad `permissions:`.** No block at all means the job inherits
  whatever the repository default is — historically `write-all`. Every job should
  declare least privilege.
- Self-hosted runners, and other patterns extended in [phase-4.md](phase-4.md).

There is one sanctioned exception, `slsa-framework/slsa-github-generator`, which
**must** be tag-referenced: its trust model depends on the builder ref, and
slsa-verifier validates it. That exception is a single named entry in the auditor,
not a general escape hatch.

`sscsb`'s own shipped templates are held to this: a test asserts that every
workflow template it installs passes this very audit.

## Turning things off

```sh
sscsb disable ai-receipts     # already off by default
sscsb disable branch-protection
sscsb verify
```

A disabled control does not run — the hook path short-circuits before the tool is
invoked. This is tested: disabling `secrets` and committing a planted credential
succeeds, which is exactly what "off" has to mean for the toggle to be trustworthy.

## Configuration

```toml
[general]
# Branches where human-only signing and merge policy are enforced.
protected_branches = ["main", "master"]
# fail_open = true would let hooks pass when scanners are missing. Keep false.
fail_open = false
# github_repo = "owner/repo"  # set to enable GitHub API checks

[controls.secrets]
enabled = true
trufflehog = true
gitleaks = true
pre_push_range_scan = true

[controls.commit-signing]
enabled = true
require_hardware_backed = true
require_review_evidence_for_ai_merges = true
```

`.sscsb/config.toml` is generated from the control registry, so a control can
never exist in the code without appearing in your config, or vice versa. Edits
preserve your comments.
