# End-to-end walkthrough

A complete bootstrap on a fresh repository. **Every block below is real terminal
output**, captured from an actual run — including the three places the hooks refuse
to let something through.

The project is a trivial Rust crate with one dependency.

## 1. `sscsb init`

```console
$ sscsb init
write .sscsb/config.toml (37 controls, secure defaults)
write .sscsb/hooks/pre-commit (POSIX shim → `sscsb hook …`, fail-closed)
write .sscsb/hooks/commit-msg (POSIX shim → `sscsb hook …`, fail-closed)
write .sscsb/hooks/pre-push (POSIX shim → `sscsb hook …`, fail-closed)
set core.hooksPath = .sscsb/hooks
write .sscsb/policy/signers.toml (add your hardware-backed key!)
write .sscsb/policy/packages.toml
write .sscsb/policy/allowed_signers (generated from signers.toml)
write .github/workflows/secrets-scan.yml
write .gitleaks.toml
write .trufflehog.yaml
skip .github/workflows/agent-signing-verify.yml (control agent-signing disabled)
write .github/PULL_REQUEST_TEMPLATE.md
write .github/workflows/sbom.yml
write .github/workflows/vuln-scan.yml
write .github/workflows/scorecard.yml
write renovate.json5
write .github/workflows/release-sign.yml
write .github/workflows/release-slsa.yml
write .github/workflows/release-attest.yml
write .github/workflows/release-attest-sbom.yml
write .github/workflows/deploy-gate.yml
skip .github/workflows/release.yml (control release-immutability disabled)
write .github/workflows/octo-sts-example.yml
write .github/chainguard/sscsb-automation.sts.yaml
write .github/workflows/sast-opengrep.yml
write .sscsb/rules/sscsb-default.yaml
write .github/workflows/codeql.yml
skip .github/workflows/cflite-pr.yml (control fuzzing disabled)
skip .github/workflows/wait-for-secrets-example.yml (control wait-for-secrets disabled)
skip .sscsb/templates/dependency-track-compose.yml (control dependency-track disabled)

Bootstrap complete. Next steps:
  1. Add your signing identity: .sscsb/policy/signers.toml (docs/signing.md)
  2. Bless current dependencies: sscsb deps baseline
  3. Check posture:              sscsb verify && sscsb report
```

Note the three `skip` lines. Disabled controls do not install their artifacts — off
means off, all the way down.

## 2. `sscsb status`

```console
$ sscsb status
sscsb status — repo: /tmp/demo-repo (branch: main, platform: macos)
config: .sscsb/config.toml
hooks installed: true

Phase 1
  [on ] secrets                  Secret scanning hooks  (trufflehog:ok, gitleaks:ok)
  [on ] commit-signing           CommitSigningGuard
  [off] agent-signing            AI agent commit signing  (ssh-tpm-agent:missing)
  [on ] branch-protection        Branch protection verification  (gh:ok)
  [on ] actions-audit            Actions pinning & permissions audit
  [on ] ai-trailers              AI commit trailers
  [on ] ai-dep-gate              AI dependency & command gate
  [on ] pr-template              AI-provenance PR template
  [off] ai-receipts              AI provenance receipts  (cosign:ok)
Phase 2
  [on ] sbom                     SBOM generation  (syft:ok)
  [on ] vuln-scan                Vulnerability scanning  (trivy:ok, osv-scanner:ok)
  ...
Phase 3
  ...
  [off] witness                  Witness (optional)  (witness:missing)
Phase 4
  [on ] sast                     SAST (OpenGrep default)  (opengrep:ok, semgrep:ok)
  [off] sighthound               Sighthound (optional)  (sighthound:missing)
  ...
```

Every control, its state, and whether its tools are actually on this machine. A
missing tool is named as missing.

## 3. Bless the dependencies you already have

```console
$ sscsb deps baseline
baselined 1 package(s) into .sscsb/policy/packages.toml
```

Do this before your first commit. Otherwise the package-trust gate sees your existing
dependencies as brand new and unapproved — correctly, if inconveniently — and blocks.

## 4. A normal commit

```console
$ git add -A && git commit -m "chore: initial commit

AI-Assisted: true
AI-Tool: Claude Code
AI-Model: Fable 5
AI-Role: draft
AI-Dependency-Review: approved"

sscsb: secrets — staged changes clean
[main 2036d43] chore: initial commit
```

The hook ran, scanned the staged content, found nothing, and got out of the way.

---

Now the three blocks. This is the part that matters.

## 5. A planted secret is blocked

A GitHub token is written into a config file and staged. (The token below is fake and
authorizes nothing — it was constructed at runtime specifically so that no
secret-shaped string is ever stored in this project's source.)

```console
$ git add leaked.env && git commit -m "chore: add config"

sscsb: BLOCKED — secret scanning found problems:
  ✗ gitleaks: generic-api-key in /tmp/.tmpIn4EdR/leaked.env (line 1)
  ✗ gitleaks: github-pat in /tmp/.tmpIn4EdR/leaked.env (line 1)
sscsb: remove the secret (and rotate it if real), then retry.

$ echo $?
1
```

The path is a temp directory because the scan runs against the **staged blobs**, not
your working tree — what is actually about to be committed.

## 6. An unapproved, typosquatted dependency is blocked

`tokoi` is added to `Cargo.toml` — one transposition away from `tokio` — in an
AI-assisted commit.

```console
$ git add Cargo.toml && git commit -m "feat: add async runtime

AI-Assisted: true
AI-Tool: Claude Code
AI-Model: Fable 5
AI-Role: draft"

sscsb: secrets — staged changes clean
sscsb: BLOCKED — commit message / AI-provenance policy:
  ✗ AI-assisted commit modifies dependency manifests (Cargo.toml) — a human must
    review and add trailer `AI-Dependency-Review: approved` (see docs/ai-provenance.md);
    run `sscsb deps check` to validate the new packages first
  ✗ new dependency `cargo:tokoi` is not in the approved baseline — validate it
    (`sscsb deps check`) then approve it (`sscsb deps approve cargo:tokoi`)

$ echo $?
1
```

Two independent gates fired: the AI-dependency trailer is missing, **and** the package
is unapproved. Adding the trailer alone would not be enough — a human still has to
approve the specific package.

And when you go looking:

```console
$ sscsb deps check --offline
note: checking 1 staged new package(s)
PROBLEM: cargo:tokoi: name is one edit away from popular package `tokio` —
         possible typosquat/slopsquat; verify intent before approving
```

`tokoi` → `tokio` is an *adjacent transposition*. Plain Levenshtein scores that as
distance 2 and would have let it through; the check uses Damerau distance precisely
because transposition is the commonest typosquat shape.

## 7. An unsigned commit is blocked on a protected branch

```console
$ git push origin main

sscsb: PUSH BLOCKED:
  ✗ protected branch `main`: no approved signers configured — add your key to
    .sscsb/policy/signers.toml (see docs/signing.md); refusing unsigned/unapproved push
  ✗ 2036d43511: UNSIGNED commit — protected branch `main` requires signed commits
    (git config commit.gpgSign true; see docs/signing.md)
error: failed to push some refs to '/tmp/demo-remote.git'

$ echo $?
1
```

Note that it fails **closed**: no signers configured does not mean "no policy to
enforce", it means "nothing is allowed to land." That is the difference between a
control and a decoration.

## 8. …but the same push succeeds on a feature branch

```console
$ git checkout -b feature/demo && git push origin feature/demo
$ echo $?
0
```

The gate is the protected branch, not every push. Draft freely; the hardware key is
what says "this ships." Set your signing identity up per
[docs/signing.md](signing.md) and the `main` push above starts working.

## 9. `sscsb verify` — the honest posture

```console
$ sscsb verify
[PASS    ] secrets
           pre-commit + pre-push hooks installed (core.hooksPath=.sscsb/hooks)
           trufflehog: 3.94.3 (/opt/homebrew/bin/trufflehog)
           gitleaks: 8.30.1 (/opt/homebrew/bin/gitleaks)
[DEGRADED] commit-signing
           no approved signers configured — protected-branch pushes will be blocked
           until a human signer is added to .sscsb/policy/signers.toml
           git config `gpg.format` unset — see docs/signing.md for YubiKey ed25519-sk setup
           git config commit.gpgSign = false
           policy: hardware-backed keys required on protected branches
[disabled] agent-signing
           disabled in .sscsb/config.toml
[DEGRADED] branch-protection
           no GitHub repo configured (general.github_repo) and no origin remote —
           cannot verify branch protection
[PASS    ] actions-audit
           [info] .github/workflows/release-slsa.yml: `slsa-framework/slsa-github-generator/…@v2.1.0`
           is tag-pinned by design: slsa-github-generator must be referenced by @vX.Y.Z
           for slsa-verifier to verify the trusted builder
[PASS    ] ai-trailers
           enforced by commit-msg hook (installed)
...
[PASS    ] github-attestations
           .github/workflows/release-attest.yml installed
[PASS    ] sbom-attestation
           .github/workflows/release-attest-sbom.yml installed
[PASS    ] provenance-verify
           slsa-verifier: 2.7.1
           cosign: 3.1.1
           gate: `sscsb provenance verify --artifact <f> --provenance <f>.intoto.jsonl
                  --source-uri github.com/<owner>/<repo> [--source-tag vX.Y.Z]`
           deploy-gate workflow present (verification before publish)
[PASS    ] harden-runner
           codeql.yml: harden-runner present
           deploy-gate.yml: harden-runner present
           ... (every workflow checked individually)
[INFO    ] secure-repo
           StepSecurity secure-repo is a web service (app.stepsecurity.io), not an action
[disabled] witness
           disabled in .sscsb/config.toml
[PASS    ] compliance-map
           map covers all 37 controls across SLSA/SSDF/CRA/Badge

verify: 0 failed, 2 degraded
```

This is what "no fakery" looks like in practice. Two controls are **DEGRADED**, and
the reason is stated: this demo repo has no signing key and no GitHub remote. `sscsb`
does not paper over that. Under `sscsb verify --strict`, those two degrades exit
non-zero.

Note also that the single tag-pinned action is reported as an `[info]`, with the
reason — not hidden, and not silently allowed.

## 10. `sscsb report`

```console
$ sscsb report
SSCS Bootstrapper — control → framework coverage
frameworks: SLSA v1.2 (Build L3 + Source L3) · NIST SSDF v1.2 · EU CRA · OpenSSF Badge

Phase 1
  [ENABLED ] secrets — Secret scanning hooks
      SSDF: PS.1.1; PW.7.2
      CRA : Annex I Part I(2)(d) (protection against unauthorised access);
            Annex I Part II §3 (effective and regular tests and reviews)
      Badge: no_leaked_credentials
  [ENABLED ] commit-signing — CommitSigningGuard
      SLSA: Source L1: Identity Management; Source L2: History
      SSDF: PS.1.1
      CRA : Annex I Part I(2)(f) (integrity of code, commands and configuration)
  ...
  [disabled] ai-receipts — AI provenance receipts
      SLSA: Source L2: Source Provenance
      SSDF: PO.3.3
```

`--format json` for the machine-readable version. Disabled controls are shown as
disabled: the report describes what you have turned on, not what the tool could
theoretically do.

## 11. SBOM and scan

```console
$ sscsb sbom
SBOM written: .sscsb/out/sbom.cdx.json

$ sscsb scan
0 finding(s):
```

## What ended up in the repository

```
.github/PULL_REQUEST_TEMPLATE.md
.github/chainguard/sscsb-automation.sts.yaml
.github/workflows/{codeql,deploy-gate,octo-sts-example,release-attest,release-attest-sbom,
                   release-sign,release-slsa,sast-opengrep,sbom,scorecard,secrets-scan,vuln-scan}.yml
.gitleaks.toml
.trufflehog.yaml
renovate.json5
.sscsb/config.toml            # 37 controls, generated from the registry
.sscsb/hooks/{pre-commit,commit-msg,pre-push}
.sscsb/policy/{signers.toml,packages.toml,allowed_signers}
.sscsb/rules/sscsb-default.yaml
.sscsb/out/                   # generated artifacts (gitignored)
```

Twenty-four files, eleven SHA-pinned workflows, three hooks, and a policy directory —
from one command, on a repository that had none of it a minute earlier.
