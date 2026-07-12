# Software Supply Chain Security (SSCS) Project Plan

**Author:** JAI (PAI) for Justin
**Date:** 2026-02-11
**Framework:** SLSA v1.2 (Build + Source Tracks)
**Status:** Research Complete, Awaiting Implementation Approval

---

## Executive Summary

This plan establishes comprehensive software supply chain security across all of Justin's git repositories, using SLSA v1.2 as the foundational framework and integrating sigstore, in-toto, TUF, and the broader OpenSSF ecosystem. It includes Claude Code hooks and skills as AI-powered enforcement mechanisms that ensure SSCS controls are maintained uniformly and automatically.

**Target SLSA Levels (Solo Developer Ceiling):**
- Build Track: **L3** (unforgeable provenance via GitHub Actions)
- Source Track: **L3** (continuous technical controls; L4 requires two-party review)

---

## Table of Contents

1. [SLSA v1.2 Framework Summary](#1-slsa-v12-framework-summary)
2. [Tool Selection Matrix](#2-tool-selection-matrix)
3. [Implementation Phases](#3-implementation-phases)
4. [Claude Code Integration Architecture](#4-claude-code-integration-architecture)
5. [Hook Specifications](#5-hook-specifications)
6. [Skill Specifications](#6-skill-specifications)
7. [CI/CD Pipeline Templates](#7-cicd-pipeline-templates)
8. [Compliance Tracking](#8-compliance-tracking)
9. [Appendix: Research Sources](#9-appendix-research-sources)

---

## 1. SLSA v1.2 Framework Summary

### Build Track

| Level | Requirements | How We Achieve It |
|-------|-------------|-------------------|
| **L0** | No provenance | (Baseline, not acceptable) |
| **L1** | Provenance exists, identifies output by digest | `actions/attest-build-provenance@v3` in GitHub Actions |
| **L2** | Provenance is authentic (signed, tamper-resistant) | Same action + Sigstore keyless signing via GitHub OIDC |
| **L3** | Provenance is unforgeable (isolated build, signing keys inaccessible to build steps) | `slsa-framework/slsa-github-generator` reusable workflows |

### Source Track (NEW in v1.2)

| Level | Requirements | How We Achieve It |
|-------|-------------|-------------------|
| **L1** | Version controlled, immutable revisions, identity management | Git + GitHub (already met) |
| **L2** | Enforced history, source provenance attestations, no force-push | Branch protection rules, signed commits |
| **L3** | Protected named references, continuous technical controls | GitHub rulesets, required status checks |
| **L4** | Two-party review | NOT feasible for solo developer |

### Provenance Format

SLSA provenance uses **in-toto Statement v1** wrapped in **DSSE envelope**:

```
DSSE Envelope (authentication)
  -> in-toto Statement (subject binding)
    -> SLSA Provenance v1 Predicate (build metadata)
       - buildDefinition: { buildType, externalParameters, resolvedDependencies }
       - runDetails: { builder: { id }, metadata: { invocationId, timestamps } }
```

### Dependencies Track

NOT included in SLSA v1.2. Remains draft/proposal status. We address dependency security through tooling (OSV-Scanner, Socket.dev, Scorecard) rather than a SLSA track.

---

## 2. Tool Selection Matrix

### Tier 1: Core (Implement First)

| Tool | Purpose | Version | Install | Priority |
|------|---------|---------|---------|----------|
| **TruffleHog** | Secret scanning (pre-commit) | 3.93.1 | `brew install trufflehog` | DONE (PreCommitGuard hook) |
| **Gitleaks** | Secret scanning (complementary) | v8.18.0+ | `brew install gitleaks` | Phase 1 |
| **cosign** | Artifact/container signing (keyless) | v3.0.4 | `brew install cosign` | Phase 2 |
| **Syft** | SBOM generation (CycloneDX/SPDX) | v1.41.2 | `brew install syft` | Phase 2 |
| **Trivy** | Vulnerability scanning + SBOM | v0.68.2 | `brew install trivy` | Phase 2 |
| **OSV-Scanner** | Cross-ecosystem vuln scanning | v2.0.0 | `go install github.com/google/osv-scanner/v2/...` | Phase 2 |

### Hardware-Backed Signing (NEW)

| Tool | Purpose | Requirements | Priority |
|------|---------|-------------|----------|
| **YubiKey 5 Series** | Hardware security key for FIDO2 + PIV | Firmware 5.2.3+ (for ed25519-sk) | Phase 1 |
| **OpenSSH 8.3+** | SSH signing with FIDO2 resident keys | `ssh-keygen -t ed25519-sk -O resident` | Phase 1 |
| **cosign `--sk` (PIV)** | Hardware-backed container/artifact signing | cosign built with `pivkey` tag | Phase 3 |
| **libpcsclite** (Linux/WSL) | Smart card daemon for YubiKey PIV | `sudo apt install libpcsclite-dev pcscd` | Phase 3 |
| **windows-fido-bridge** (WSL) | Bridge Windows FIDO2 into WSL2 | Required for WSL2 + YubiKey FIDO2 | Phase 1 |

**Signing Architecture (Full Spectrum):**
```
HUMAN-TRIGGERED (developer workstation)
  ├── Git commits     → YubiKey FIDO2 ed25519-sk resident key (PRIMARY — cross-platform)
  │                     OR Windows Hello/TPM via windows-fido-bridge (ALTERNATIVE — Windows only)
  │                     OR macOS Touch ID via Secretive/1Password (ALTERNATIVE — Mac only)
  ├── Local releases  → cosign --sk via YubiKey PIV slot 9c (ONLY option with hardware backing)
  ├── Local attests   → cosign attest --sk via YubiKey PIV (ONLY option with hardware backing)
  └── OIDC MFA        → YubiKey FIDO2 for GitHub/Google login

SYSTEM-TRIGGERED (CI/CD — GitHub Actions)
  ├── Provenance      → Keyless via GitHub OIDC → Fulcio ephemeral cert (DEFAULT)
  ├── Container sign  → cosign keyless (DEFAULT) or cosign --key awskms:// (OPTIONAL)
  ├── Attestations    → cosign attest keyless (DEFAULT) or KMS-backed (OPTIONAL)
  └── SBOM attestation→ cosign attest --type cyclonedx keyless

HSM/KMS ESCALATION (when keyless is insufficient)
  ├── AWS KMS         → cosign --key awskms://[region]/[alias] (~$1/mo)
  ├── GCP KMS         → cosign --key gcpkms://[project]/[keyring]/[key] (~$0.10/mo)
  ├── Azure Key Vault → cosign --key azurekms://[vault]/[key] (~$1/mo)
  ├── HashiCorp Vault → cosign --key hashivault://[key] (self-hosted)
  └── YubiHSM 2       → cosign via PKCS#11 ($650 one-time, on-prem)
```

**Platform Authenticator Capabilities (What Works vs. What Doesn't):**

| Platform | Git Commits | cosign Artifacts | in-toto Attestations | Key Backup |
|---|:-:|:-:|:-:|:-:|
| **YubiKey FIDO2 (ed25519-sk)** | YES | YES (PIV) | YES (PIV) | NO (2nd key) |
| **Windows Hello/TPM** | YES (via bridge) | NO | NO | NO |
| **macOS Touch ID/Secure Enclave** | YES (native/Secretive) | NO | NO | NO |
| **1Password SSH Agent** | YES (best UX) | NO | NO | YES (1P sync) |
| **iOS Face ID** | NO | NO | NO | N/A |
| **Android Biometrics** | NO | NO | NO | N/A |

*Why platform authenticators can't sign artifacts:* cosign requires PKCS#11 or native KMS backends. Windows CNG has no cosign backend. macOS Secure Enclave has an Apple PKCS#11 callback bug that prevents external tool integration. Mobile lacks the caBLE/hybrid transport in libfido2.*

### Tier 2: CI/CD Integration

| Tool | Purpose | Version | Priority |
|------|---------|---------|----------|
| **actions/attest-build-provenance** | SLSA L2 provenance (GitHub) | v3 | Phase 3 |
| **slsa-framework/slsa-github-generator** | SLSA L3 provenance (reusable WF) | v2.1.0 | Phase 3 |
| **slsa-framework/slsa-verifier** | Provenance verification | v2.x | Phase 3 |
| **GitHub Artifact Attestations** | Native GH attestation | Built-in | Phase 3 |
| **Scorecard Action** | OpenSSF security scoring | v5.1.0 | Phase 3 |

### Tier 3: Advanced

| Tool | Purpose | Version | Priority |
|------|---------|---------|----------|
| **Semgrep** | SAST static analysis | Latest | Phase 4 |
| **Gitsign** | Keyless commit signing (sigstore) | Latest | Phase 4 (awaiting GH verification support) |
| **Socket.dev** | Proactive supply chain attack detection | SaaS | Phase 4 |
| **ORAS** | OCI artifact storage (SBOMs alongside images) | v1.3.0 | Phase 4 |
| **Chainguard Images** | Zero-CVE base images | Latest | Phase 4 |
| **GUAC** | Metadata correlation graph | Pre-1.0 | Phase 5 (when 1.0 ships) |

### SBOM Format Decision

**CycloneDX v1.7** (selected over SPDX 3.0.1):
- Ratified as ECMA-424 (international standard)
- Better tooling support for security use cases (VEX, CBOM)
- Native integration with OWASP Dependency-Track
- Backward compatible with v1.4-v1.6
- Syft, Trivy, and cdxgen all support CycloneDX output

### Dependency Update Strategy

**Renovate** (selected over Dependabot):
- 30+ package managers (vs 14 for Dependabot)
- Docker, K8s manifest, and Dockerfile updates
- Shareable presets across repos
- Dependency dashboard for oversight
- Works on GitHub, GitLab, Bitbucket

### Hardware-Backed Signing Deep Dive

#### Git Commit Signing — YubiKey FIDO2 + SSH (Phase 1)

Every git commit is signed with a `ed25519-sk` resident key stored on a YubiKey. The private key **never leaves the hardware**. Each signature requires physical touch.

**Setup:**
```bash
# Generate FIDO2 resident signing key ON the YubiKey
ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -C "git-signing $(git config user.email)" \
  -f ~/.ssh/id_ed25519_sk_git_signing

# Configure git globally
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_sk_git_signing.pub
git config --global commit.gpgSign true
git config --global tag.forceSignAnnotated true

# Local verification (allowed signers file)
echo "$(git config user.email) namespaces=\"git\" $(cat ~/.ssh/id_ed25519_sk_git_signing.pub)" \
  >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers

# Upload public key to GitHub as "Signing Key"
# Settings → SSH and GPG keys → New SSH key → Key type: "Signing Key"
```

**Backup (second YubiKey):**
```bash
ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -C "git-signing-backup $(git config user.email)" \
  -f ~/.ssh/id_ed25519_sk_git_signing_backup
# Upload this public key to GitHub as well
```

**Portability (new machine):**
```bash
ssh-keygen -K  # Downloads resident key handles from YubiKey — no file transfer needed
```

**GitHub verification:** Shows identical green "Verified" badge. GitHub does not distinguish hardware vs. software keys.

#### WSL2 + YubiKey FIDO2 Bridge

WSL2 cannot directly access USB FIDO2 devices. Bridge options:

| Method | How | Recommended |
|--------|-----|:-----------:|
| **Git for Windows (native)** | Use Windows-side git for signing, WSL git for everything else | For git signing only |
| **windows-fido-bridge** | Bridges Windows FIDO2 API into WSL2 ssh-keygen/ssh-agent | Yes |
| **usbipd-win** | Passes USB device to WSL2 kernel (requires `libfido2`) | For PIV/OpenPGP |
| **wsl2-ssh-agent** | Forwards Windows ssh-agent socket to WSL2 | Alternative |

**Recommended WSL setup:**
```bash
# Option A: Use windows-fido-bridge (for FIDO2 ssh-keygen inside WSL)
# Install: https://github.com/mgbowen/windows-fido-bridge
export SSH_SK_PROVIDER=/usr/lib/windows-fido-bridge/libnativemessaging.so

# Option B: Use Git for Windows for signing, WSL git for daily work
# In WSL, configure git to call Windows ssh for signing:
git config --global gpg.ssh.program "/mnt/c/Windows/System32/OpenSSH/ssh-keygen.exe"
```

#### Artifact Signing — cosign + YubiKey PIV (Phase 3)

For local releases (containers, binaries), cosign signs using a key stored in the YubiKey's PIV slot 9c.

**Setup:**
```bash
# Install cosign with hardware token support
# (Official releases include pivkey support)
brew install cosign  # or: go install -tags=pivkey github.com/sigstore/cosign/v2/cmd/cosign@latest

# On Linux/WSL: install smart card dependencies
sudo apt install libpcsclite-dev pcscd
sudo systemctl enable --now pcscd

# Generate signing key ON the YubiKey PIV slot
cosign piv-tool generate-key --random-management-key=true

# Change default PIN (default: 123456)
cosign piv-tool set-pin

# Export public key for verification
cosign public-key --sk > cosign-yubikey.pub
```

**Per-release signing:**
```bash
# Sign container image (touch + PIN)
cosign sign --sk ghcr.io/p4gs/myimage@sha256:...

# Sign in-toto attestation (SBOM, provenance) with hardware key
cosign attest --predicate sbom.cdx.json --type cyclonedx --sk \
  ghcr.io/p4gs/myimage@sha256:...

# Verify
cosign verify --key cosign-yubikey.pub ghcr.io/p4gs/myimage:latest
```

**CI/CD remains keyless** — GitHub Actions uses OIDC → Fulcio ephemeral certificates. No hardware key needed (or possible) in CI.

#### Platform Authenticator Alternatives for Git Commit Signing

Platform authenticators can sign git commits (but NOT artifacts/attestations):

**Windows Hello/TPM (WSL2):**
```bash
# Install windows-fido-bridge (bridges Windows Hello FIDO2 into WSL2)
sudo apt install windows-fido-bridge
export SSH_SK_PROVIDER=/usr/lib/x86_64-linux-gnu/libwindowsfidobridge.so

# Generate TPM-backed ecdsa-sk key via Windows Hello
ssh-keygen -t ecdsa-sk -O resident
# Windows Hello PIN or biometric prompt appears

# Git config same as YubiKey FIDO2
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ecdsa_sk.pub
```
*Limitation: ecdsa-sk (P-256) only — most TPMs don't support ed25519-sk natively.*

**macOS Touch ID / Secure Enclave (Sequoia+):**
```bash
# Native macOS — no third-party tools needed
ssh-keygen -t ecdsa-sk -O resident -w /usr/lib/ssh-keychain.dylib
# Touch ID prompt appears

# Or via Secretive app (GUI, stores keys in Secure Enclave)
brew install secretive
```
*Limitation: ECDSA P-256 only. Keys cannot be exported or backed up.*

**1Password SSH Agent (cross-platform, best UX):**
```bash
# 1Password manages SSH keys with Touch ID/Windows Hello unlock
# Each git commit triggers biometric prompt
git config --global gpg.format ssh
git config --global gpg.ssh.program "/Applications/1Password.app/Contents/MacOS/op-ssh-sign"
git config --global user.signingkey "ssh-ed25519 AAAA..."
```
*Advantage: Ed25519 support, keys synced across devices via 1Password vault.*
*Limitation: Keys backed by 1Password's encryption, not raw hardware. Trust model differs from FIDO2.*

**Why these CAN'T sign artifacts:** cosign requires PKCS#11 or native KMS backends. Windows CNG has no cosign backend. macOS Secure Enclave has an [Apple PKCS#11 callback bug](https://mjg59.dreamwidth.org/65462.html) preventing external tool integration. For artifact signing, YubiKey PIV remains the only hardware option.

#### HSM/KMS for Automated (System-Triggered) Signing

When GitHub OIDC keyless signing is insufficient (multi-cloud, air-gapped, regulatory), use cloud KMS:

**AWS KMS:**
```bash
# One-time: generate signing key in KMS
cosign generate-key-pair --kms awskms://us-east-1/alias/cosign-signing

# In GitHub Actions (with OIDC federation to AWS):
cosign sign --key awskms://us-east-1/alias/cosign-signing $IMAGE_DIGEST
cosign attest --key awskms://us-east-1/alias/cosign-signing --predicate sbom.json $IMAGE_DIGEST

# Verify
cosign verify --key awskms://us-east-1/alias/cosign-signing $IMAGE
```
*Cost: ~$1/mo (key storage) + $0.03-0.15 per 10K signing ops.*

**GCP KMS:**
```bash
cosign generate-key-pair --kms gcpkms://projects/PROJECT/locations/global/keyRings/RING/cryptoKeys/KEY
cosign sign --key gcpkms://projects/PROJECT/locations/global/keyRings/RING/cryptoKeys/KEY/versions/1 $IMAGE
```
*Cost: ~$0.06/mo (software-backed) or ~$1-2.50/mo (HSM-backed).*

**Azure Key Vault:**
```bash
cosign generate-key-pair --kms azurekms://VAULT.vault.azure.net/KEY
cosign sign --key azurekms://VAULT.vault.azure.net/KEY $IMAGE
```

**HashiCorp Vault Transit:**
```bash
cosign generate-key-pair --kms hashivault://cosign-key
cosign sign --key hashivault://cosign-key $IMAGE
```
*Caveat: [key rotation versioning bug](https://github.com/sigstore/cosign/issues/1351) — Vault's `vault:vN:` prefix not properly handled during verification.*

**When to use KMS over keyless:**

| Scenario | Keyless (OIDC) | KMS |
|---|:-:|:-:|
| Standard GitHub Actions CI/CD | **YES** | Optional |
| Must survive GitHub/Sigstore outage | NO | **YES** |
| Air-gapped / private environments | NO | **YES** |
| Regulatory key ownership requirement | NO | **YES** |
| Multi-CI-platform signing | Complex | **YES** |
| Cost-sensitive solo dev | **YES** (free) | ~$1-2/mo |

**Recommendation for solo dev:** Use keyless as default. Add KMS only if you need signing that doesn't depend on public Sigstore infrastructure.

#### What Hardware-Backed Signing Does NOT Cover

| Scenario | Why Not | Mitigation |
|----------|---------|------------|
| CI/CD builds | No physical touch possible in automation | OIDC keyless via Fulcio (SLSA L3 isolation provides equivalent guarantee) |
| SLSA L3 provenance | Build platform signs, not developer | Reusable workflows + GitHub runner isolation |
| Key compromise via OIDC | If GitHub account is compromised | FIDO2 MFA on GitHub account (same YubiKey) |
| Lost/destroyed YubiKey | Private key is gone forever | Backup key on second YubiKey, both registered on GitHub |
| Artifact signing without YubiKey | Platform authenticators can't do it | Use YubiKey PIV (local) or KMS (CI/CD) |
| Platform authenticator for cosign | No PKCS#11/CNG backends exist | YubiKey PIV or cloud KMS |

---

## 3. Implementation Phases

### Phase 1: Git-Level Security Foundation (Week 1)

**Goal:** Every git repo has secret scanning, hardware-backed commit signing, and basic security gates.

| # | Task | Tool | Claude Code Component |
|---|------|------|-----------------------|
| 1.1 | TruffleHog pre-commit hook on all repos | TruffleHog | `PreCommitGuard.hook.ts` (DONE) |
| 1.2 | Add Gitleaks as complementary scanner | Gitleaks | Extend `PreCommitGuard.hook.ts` |
| 1.3 | Enable branch protection on all repos (main/master) | GitHub | New `BranchProtectionGuard.hook.ts` |
| 1.4 | Pin all GitHub Actions to full SHAs | Manual/Script | New `ActionPinningAudit` skill |
| 1.5 | Set minimum `permissions` in all GH Actions workflows | Manual/Script | Same skill as 1.4 |
| 1.6 | Set up YubiKey FIDO2 `ed25519-sk` resident key for git commit signing | YubiKey + OpenSSH | New `CommitSigningGuard.hook.ts` |
| 1.7 | Enable GitHub Vigilant Mode (flag unsigned commits) | GitHub Settings | Manual (one-time) |
| 1.8 | Generate backup signing key on second YubiKey | YubiKey #2 | Manual (one-time) |
| 1.9 | Configure WSL2 ↔ YubiKey FIDO2 bridge | windows-fido-bridge | Documented in setup guide |
| 1.10 | Require FIDO2 MFA on GitHub account | YubiKey FIDO2 | Manual (one-time) |

### Phase 2: Vulnerability & SBOM Baseline (Week 2-3)

**Goal:** Generate SBOMs, scan for vulnerabilities, establish dependency baselines.

| # | Task | Tool | Claude Code Component |
|---|------|------|-----------------------|
| 2.1 | Install Syft, Trivy, OSV-Scanner locally | All three | `ToolchainVerifier.hook.ts` (SessionStart) |
| 2.2 | Generate CycloneDX SBOM for each project | Syft | New `SBOMGenerator` skill |
| 2.3 | Run Trivy vulnerability scan on each project | Trivy | Same skill, vuln workflow |
| 2.4 | Run OSV-Scanner on all lockfiles | OSV-Scanner | New `DependencyAudit.hook.ts` (SessionStart) |
| 2.5 | Establish dependency baselines (lockfile hashes) | Custom | New `LockFileIntegrity.hook.ts` (PreToolUse) |
| 2.6 | Set up Renovate for automated dependency updates | Renovate | GitHub App install |
| 2.7 | Run cargo-audit, pip-audit, npm audit per project | Language-specific | Integrated into `DependencyAudit` |

### Phase 3: SLSA Provenance & Signing (Week 4-6)

**Goal:** Build L2-L3 provenance, sign all artifacts. Hardware keys for local releases, keyless for CI/CD.

| # | Task | Tool | Claude Code Component |
|---|------|------|-----------------------|
| 3.1 | Add `actions/attest-build-provenance@v3` to release workflows | GitHub Action | New `CIWorkflowAudit` skill |
| 3.2 | Implement `slsa-github-generator` reusable workflows for L3 | SLSA Generator | Template in skill |
| 3.3 | Sign container images with cosign keyless (CI/CD) | cosign + GitHub OIDC | New `ArtifactSigning` skill |
| 3.4 | Sign container images with cosign `--sk` (local releases) | cosign + YubiKey PIV | Same skill, hardware workflow |
| 3.5 | Attest SBOMs with cosign keyless (CI/CD) | cosign + Syft | Same skill |
| 3.6 | Attest SBOMs with cosign `--sk` (local releases) | cosign + YubiKey PIV + Syft | Same skill, hardware workflow |
| 3.7 | Verify provenance with slsa-verifier in CI | slsa-verifier | CI template |
| 3.8 | Store SBOMs/attestations via ORAS in OCI registry | ORAS | Optional enhancement |
| 3.9 | Add OpenSSF Scorecard Action to repos | Scorecard | CI template |
| 3.10 | Apply for OpenSSF Best Practices Badge (public repos) | Web form | Manual + tracking |
| 3.11 | (OPTIONAL) Set up cloud KMS signing for CI/CD resilience | AWS/GCP/Azure KMS | `ArtifactSigning` skill, KMS workflow |

### Phase 4: Advanced Security Controls (Week 7-10)

**Goal:** SAST, advanced signing, proactive attack detection.

| # | Task | Tool | Claude Code Component |
|---|------|------|-----------------------|
| 4.1 | Add Semgrep to pre-commit and CI | Semgrep | Extend `PreCommitGuard.hook.ts` |
| 4.2 | Evaluate Gitsign as Sigstore-native commit signing alternative | Gitsign | Deferred — hardware signing (Phase 1) is superior until GitHub adds Sigstore CA to trust store |
| 4.3 | Evaluate Socket.dev for npm/PyPI projects | Socket.dev | SaaS setup |
| 4.4 | Switch to Chainguard base images for containers | Chainguard | Dockerfile updates |
| 4.5 | Implement cosign verify-attestation policies (Rego/CUE) | cosign + OPA | Policy files per repo |
| 4.6 | Set up Rekor monitoring for identity abuse | rekor-monitor | Background automation |

### Phase 5: Long-Term / Emerging (Ongoing)

| # | Task | Tool | When |
|---|------|------|------|
| 5.1 | Deploy GUAC for cross-project metadata correlation | GUAC | When 1.0 ships |
| 5.2 | Monitor EU CRA compliance deadlines | Policy tracking | Before Sep 2026 |
| 5.3 | Upgrade to Gitsign when GitHub adds verification | Gitsign | When available |
| 5.4 | Track SLSA Dependencies track standardization | SLSA | When published |
| 5.5 | Evaluate sigstore-rs when it stabilizes (for Rust projects) | sigstore-rs | When non-experimental |

---

## 4. Claude Code Integration Architecture

### Hook Lifecycle for SSCS

```
SessionStart
 |
 ├── PreCommitGuard.hook.ts (EXISTING)
 |   └── Ensures TruffleHog + Gitleaks pre-commit hooks installed
 |
 ├── ToolchainVerifier.hook.ts (NEW - Phase 2)
 |   └── Verifies cosign, syft, trivy, osv-scanner, semgrep are installed
 |
 ├── DependencyAudit.hook.ts (NEW - Phase 2)
 |   └── Runs OSV-Scanner on lockfiles, reports known vulns
 |
 ├── BranchProtectionGuard.hook.ts (NEW - Phase 1)
 |   └── Checks GitHub branch protection is enabled
 |
 └── CommitSigningGuard.hook.ts (NEW - Phase 1)
     └── Verifies hardware-backed commit signing is configured (ed25519-sk key)

PreToolUse (Bash)
 |
 ├── SecurityValidator.hook.ts (EXISTING - EXTEND)
 |   └── ADD: Block `npm publish --no-verify`, `docker push` without signing
 |   └── ADD: Alert on `curl | sh`, unverified dependency installs
 |
 └── LockFileIntegrity.hook.ts (NEW - Phase 2)
     └── Detect manual lockfile edits, validate against manifest

PreToolUse (Edit/Write)
 |
 └── DependencyFileGuard.hook.ts (NEW - Phase 2)
     └── Monitor changes to package.json, Cargo.toml, requirements.txt
     └── Flag additions of unknown/unvetted dependencies

PostToolUse (Bash)
 |
 └── ArtifactCapture.hook.ts (NEW - Phase 3)
     └── After build commands: capture output hashes, trigger SBOM generation

Stop (end of response)
 |
 └── SSCSSessionSummary.hook.ts (NEW - Phase 3)
     └── Summarize SSCS actions taken, flag any unresolved issues

SessionEnd
 |
 └── SSCSAuditLog.hook.ts (NEW - Phase 3)
     └── Write session SSCS events to audit trail
```

### Skill Architecture for SSCS

```
SSCSSkill/
├── SKILL.md                    # Trigger: "supply chain", "SBOM", "sign", "provenance"
├── workflows/
│   ├── audit.md               # Full SSCS audit of a repo
│   ├── sign-release.md        # Sign artifacts + generate SBOM + attest provenance
│   ├── verify-deps.md         # Verify all dependencies against OSV, Scorecard
│   ├── generate-sbom.md       # Generate CycloneDX SBOM
│   ├── ci-setup.md            # Configure CI/CD with SLSA provenance
│   └── compliance-check.md    # Check SLSA/CRA/SSDF compliance status
└── templates/
    ├── github-actions/
    │   ├── slsa-l2-provenance.yml
    │   ├── slsa-l3-provenance.yml
    │   ├── sbom-generate.yml
    │   ├── container-sign.yml
    │   └── scorecard.yml
    └── pre-commit/
        └── full-security.yaml  # TruffleHog + Gitleaks + Semgrep
```

### Agent Composition for SSCS

| Agent | Type | Role | When Used |
|-------|------|------|-----------|
| **SSCS Auditor** | Architect | Full repo supply chain audit | `audit` workflow |
| **Dependency Analyst** | Engineer | Analyze dependency trees, flag risks | `verify-deps` workflow |
| **Provenance Engineer** | Engineer | Set up CI/CD provenance generation | `ci-setup` workflow |
| **Threat Modeler** | RedTeam (32 agents) | Supply chain threat analysis | On-demand |
| **Compliance Checker** | Algorithm | Check against SLSA/CRA/SSDF | `compliance-check` workflow |

---

## 5. Hook Specifications

### 5.1 ToolchainVerifier.hook.ts (SessionStart)

**Purpose:** Verify that SSCS toolchain is installed and up-to-date.

**Checks:**
- `cosign` installed and version >= 3.0
- `syft` installed and version >= 1.0
- `trivy` installed
- `osv-scanner` installed and version >= 2.0
- `semgrep` installed (Phase 4)
- `gitleaks` installed

**Behavior:**
- Reports missing tools to stderr with install commands
- Outputs `<system-reminder>` with toolchain status
- Non-blocking (informational)

### 5.2 DependencyAudit.hook.ts (SessionStart)

**Purpose:** Quick vulnerability scan of project dependencies at session start.

**Behavior:**
- Detects lockfiles in git root (package-lock.json, Cargo.lock, requirements.txt, go.sum, etc.)
- Runs `osv-scanner --lockfile=<path>` on each
- Reports critical/high vulns to stderr
- Outputs `<system-reminder>` with vuln summary
- Non-blocking but attention-getting for critical vulns

### 5.3 BranchProtectionGuard.hook.ts (SessionStart)

**Purpose:** Verify GitHub branch protection is configured on default branch.

**Behavior:**
- Uses `gh api repos/{owner}/{repo}/branches/{branch}/protection` to check
- Verifies: require PR reviews, require status checks, prevent force push
- Reports gaps to stderr with `gh` commands to fix
- Non-blocking (advisory)

### 5.4 CommitSigningGuard.hook.ts (SessionStart)

**Purpose:** Verify that hardware-backed commit signing is configured.

**Checks:**
- `git config gpg.format` == `ssh`
- `git config user.signingkey` points to a file ending in `_sk` or `_sk.pub` (FIDO2 resident key indicator)
- `git config commit.gpgSign` == `true`
- `git config tag.forceSignAnnotated` == `true`
- The signing key file exists
- `git config gpg.ssh.allowedSignersFile` is set and file exists
- (Optional) GitHub Vigilant Mode is enabled (via `gh api /user` check)

**Behavior:**
- If `gpg.format` is not `ssh`: warn, suggest migration from GPG to SSH
- If signing key is not `ed25519-sk` type: warn about software key, suggest hardware upgrade
- If signing disabled: warn with exact `git config` commands to enable
- Reports to stderr with remediation commands
- Non-blocking (advisory) — does NOT prevent work, but alerts prominently
- Outputs `<system-reminder>` with signing status

**WSL-Specific Checks:**
- If running in WSL2: verify `SSH_SK_PROVIDER` is set or `gpg.ssh.program` points to Windows OpenSSH
- If neither: warn about WSL2 FIDO2 limitation with bridge setup instructions

### 5.5 LockFileIntegrity.hook.ts (PreToolUse: Edit/Write)

**Purpose:** Detect direct edits to lockfiles (should be auto-generated, not hand-edited).

**Behavior:**
- Matches: `*/package-lock.json`, `*/yarn.lock`, `*/Cargo.lock`, `*/poetry.lock`, etc.
- If Edit/Write targets a lockfile: warn user, suggest using package manager instead
- Decision: `ask` (prompt user to confirm)

### 5.6 DependencyFileGuard.hook.ts (PreToolUse: Edit/Write)

**Purpose:** Monitor dependency manifest changes.

**Behavior:**
- Matches: `*/package.json` (dependencies/devDependencies), `*/Cargo.toml`, `*/requirements.txt`, etc.
- On change: note the dependency being added/removed/changed
- Cross-reference against deps.dev API for Scorecard score
- Decision: `allow` with informational output

### 5.7 ArtifactCapture.hook.ts (PostToolUse: Bash)

**Purpose:** Capture build artifact metadata after build commands.

**Behavior:**
- Matches: commands containing `cargo build --release`, `npm run build`, `docker build`, `go build`
- After successful build: compute SHA256 of output artifacts
- Log artifact hashes to session SSCS audit trail
- Non-blocking (capture only)

### 5.8 SecurityValidator.hook.ts Extensions

**Add to existing patterns:**

```yaml
supply_chain_blocked:
  - pattern: "npm publish.*--no-verify"
    reason: "Publishing without verification bypasses security checks"
  - pattern: "pip install.*--trusted-host"
    reason: "Installing from untrusted host bypasses TLS verification"

supply_chain_confirm:
  - pattern: "npm publish"
    reason: "Publishing package to registry"
  - pattern: "cargo publish"
    reason: "Publishing crate to registry"
  - pattern: "docker push"
    reason: "Pushing container image to registry"
  - pattern: "twine upload"
    reason: "Publishing Python package to PyPI"

supply_chain_alert:
  - pattern: "curl.*\\| sh"
    reason: "Piping remote script to shell without verification"
  - pattern: "wget.*\\| bash"
    reason: "Piping remote script to shell without verification"
```

---

## 6. Skill Specifications

### 6.1 SSCS Skill (Primary)

**Trigger words:** "supply chain", "SBOM", "sign artifact", "provenance", "SLSA", "cosign", "dependency audit"

**Workflows:**

#### `audit` — Full SSCS Audit
1. Spawn SSCS Auditor agent (Architect type)
2. Check SLSA Build Track compliance (L1/L2/L3)
3. Check SLSA Source Track compliance (L1/L2/L3)
4. Generate SBOM with Syft
5. Run Trivy vulnerability scan
6. Run OSV-Scanner on lockfiles
7. Check OpenSSF Scorecard
8. Report findings with remediation steps

#### `sign-release` — Sign and Attest a Release
1. Generate CycloneDX SBOM
2. Sign artifacts with cosign (keyless)
3. Generate SLSA provenance attestation
4. Push attestations to registry (if container) or alongside release
5. Verify attestation roundtrip

#### `verify-deps` — Dependency Verification
1. Parse all lockfiles in project
2. Run OSV-Scanner for known vulns
3. Check deps.dev for Scorecard scores of top-level dependencies
4. Flag dependencies with Scorecard < 5.0
5. Check for typosquatting patterns
6. Report findings

#### `generate-sbom` — SBOM Generation
1. Detect project type (Rust/Node/Python/Go/Container)
2. Run `syft` with CycloneDX output
3. Validate SBOM against CycloneDX v1.7 schema
4. Store SBOM in project directory
5. Optionally attest SBOM with cosign

#### `ci-setup` — Configure CI/CD for SLSA
1. Detect existing CI (GitHub Actions, etc.)
2. Add/update workflow with SLSA provenance generation
3. Add SBOM generation step
4. Add Scorecard Action
5. Pin all Actions to SHAs
6. Set minimum permissions
7. Validate workflow with `actionlint`

#### `compliance-check` — Compliance Status
1. Check SLSA Build L1/L2/L3 requirements
2. Check SLSA Source L1/L2/L3 requirements
3. Check SBOM presence (EU CRA readiness)
4. Check signing (artifacts signed?)
5. Report compliance matrix

### 6.2 ActionPinningAudit Skill

**Trigger:** "pin actions", "audit actions", "GitHub Actions security"

**Behavior:**
1. Glob all `.github/workflows/*.yml`
2. Parse action references
3. Flag any using tag references (e.g., `@v4`) instead of SHA
4. Resolve SHAs for each tagged action
5. Offer to update all to pinned SHAs

---

## 7. CI/CD Pipeline Templates

### 7.1 SLSA L2 Provenance (GitHub Actions)

```yaml
name: Release with SLSA L2 Provenance
on:
  push:
    tags: ['v*']

permissions:
  contents: write
  id-token: write
  attestations: write

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      digest: ${{ steps.hash.outputs.digest }}
    steps:
      - uses: actions/checkout@<SHA>
      - name: Build
        run: # your build steps
      - name: Generate SBOM
        run: syft . -o cyclonedx-json > sbom.cdx.json
      - name: Hash artifacts
        id: hash
        run: sha256sum artifact.tar.gz | base64 -w0 > digest.txt
      - uses: actions/attest-build-provenance@v3
        with:
          subject-path: artifact.tar.gz
      - uses: actions/attest-sbom@v2
        with:
          subject-path: artifact.tar.gz
          sbom-path: sbom.cdx.json
```

### 7.2 Container Build + Sign + Attest

```yaml
name: Container Release
on:
  push:
    tags: ['v*']

permissions:
  contents: read
  packages: write
  id-token: write

jobs:
  build-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>
      - uses: docker/setup-buildx-action@<SHA>
      - uses: docker/login-action@<SHA>
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@<SHA>
        id: build
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}
      - uses: sigstore/cosign-installer@<SHA>
      - name: Sign image
        run: cosign sign ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
      - name: Generate and attest SBOM
        run: |
          syft ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }} -o cyclonedx-json > sbom.cdx.json
          cosign attest --type cyclonedx \
            --predicate sbom.cdx.json \
            ghcr.io/${{ github.repository }}@${{ steps.build.outputs.digest }}
```

### 7.3 Full Pre-Commit Config (All Security Tools)

```yaml
# .pre-commit-config.yaml — Comprehensive SSCS
repos:
  - repo: local
    hooks:
      - id: trufflehog
        name: TruffleHog Secret Scan
        entry: trufflehog git file://. --since-commit HEAD --results=verified,unknown --fail
        language: system
        stages: ["pre-commit", "pre-push"]
        pass_filenames: false

  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

  - repo: https://github.com/semgrep/semgrep
    rev: latest
    hooks:
      - id: semgrep
        args: ['--config', 'auto', '--error']
```

---

## 8. Compliance Tracking

### SLSA Compliance Matrix (Per Repo)

| Requirement | Build L1 | Build L2 | Build L3 | Source L1 | Source L2 | Source L3 |
|-------------|:--------:|:--------:|:--------:|:---------:|:---------:|:---------:|
| Provenance exists | | | | | | |
| Provenance is signed | | | | | | |
| Provenance is unforgeable | | | | | | |
| Hosted build platform | | | | | | |
| Ephemeral build env | | | | | | |
| Version controlled | | | | | | |
| Immutable revisions | | | | | | |
| Branch protection | | | | | | |
| No force push | | | | | | |
| Protected refs | | | | | | |
| Signed commits | | | | | | |
| Hardware-backed signing keys | | | | | | |
| FIDO2 MFA on OIDC identity | | | | | | |

### Regulatory Readiness

| Regulation | Deadline | Requirements | Status |
|-----------|----------|-------------|--------|
| **EU CRA** - Vuln reporting | Sep 11, 2026 | 24hr disclosure to CSIRT | Not started |
| **EU CRA** - Full enforcement | Dec 11, 2027 | SBOM, vuln management | Not started |
| **EO 14028** (US) | Relaxed (M-26-05) | SBOM discretionary | Reduced urgency |
| **NIST SSDF v1.2** | Draft | Secure SDLC practices | Advisory only |
| **OpenSSF Badge** | Voluntary | Best practices certification | Not started |

---

## 9. Appendix: Research Sources

### SLSA & Provenance
- [SLSA v1.2 Specification](https://slsa.dev/spec/v1.2/)
- [SLSA v1.2 Build Requirements](https://slsa.dev/spec/v1.2/build-requirements)
- [SLSA v1.2 Source Requirements](https://slsa.dev/spec/v1.2/source-requirements)
- [SLSA v1.2 Build Provenance Format](https://slsa.dev/spec/v1.2/build-provenance)
- [SLSA GitHub Generator](https://github.com/slsa-framework/slsa-github-generator)
- [SLSA Verifier](https://github.com/slsa-framework/slsa-verifier)
- [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)

### Sigstore Ecosystem
- [Cosign v3.0.4](https://github.com/sigstore/cosign/releases)
- [Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/)
- [Fulcio OIDC Docs](https://docs.sigstore.dev/certificate_authority/oidc-in-fulcio/)
- [Gitsign](https://github.com/sigstore/gitsign)
- [sigstore-rs (experimental)](https://github.com/sigstore/sigstore-rs)

### in-toto & TUF
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
- [TUF Specification](https://theupdateframework.github.io/specification/latest/)
- [python-tuf](https://pypi.org/project/tuf/)

### SBOM & Vulnerability Scanning
- [SPDX 3.0.1](https://spdx.github.io/spdx-spec/v3.0.1/)
- [CycloneDX v1.7](https://cyclonedx.org/news/cyclonedx-v1.7-released/)
- [Syft v1.41.2](https://github.com/anchore/syft)
- [Trivy v0.68.2](https://github.com/aquasecurity/trivy)
- [OSV-Scanner v2.0.0](https://github.com/google/osv-scanner)

### Dependency & Container Security
- [OpenSSF Scorecard v5.1.0](https://scorecard.dev/)
- [GUAC](https://guac.sh/)
- [deps.dev](https://deps.dev/)
- [Socket.dev](https://socket.dev/)
- [ORAS v1.3.0](https://github.com/oras-project/oras)
- [Chainguard Images](https://images.chainguard.dev/)

### Hardware-Backed Signing & Platform Authenticators
- [Yubico — Securing Git with SSH and FIDO2](https://developers.yubico.com/SSH/Securing_git_with_SSH_and_FIDO2.html)
- [Yubico — Securing SSH with FIDO2](https://developers.yubico.com/SSH/Securing_SSH_with_FIDO2.html)
- [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide)
- [Sigstore — Cosign Hardware Tokens (PIV)](https://docs.sigstore.dev/cosign/key_management/hardware-based-tokens/)
- [Sigstore — Cosign PKCS#11 Tokens](https://docs.sigstore.dev/cosign/signing/pkcs11/)
- [Sigstore — Cosign KMS Integrations](https://docs.sigstore.dev/cosign/key_management/overview/)
- [Foxboron/ssh-tpm-agent](https://github.com/Foxboron/ssh-tpm-agent)
- [mgbowen/windows-fido-bridge](https://github.com/mgbowen/windows-fido-bridge)
- [tavrez/openssh-sk-winhello](https://github.com/tavrez/openssh-sk-winhello)
- [maxgoedjen/secretive (macOS Secure Enclave SSH)](https://github.com/maxgoedjen/secretive)
- [1Password — SSH Git Commit Signing](https://developer.1password.com/docs/ssh/git-commit-signing/)
- [GitHub — About Commit Signature Verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
- [Apple PKCS#11 Secure Enclave Limitation](https://mjg59.dreamwidth.org/65462.html)
- [macOS Native Secure Enclave SSH Keys](https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf)

### HSM & KMS
- [AWS KMS Pricing](https://aws.amazon.com/kms/pricing/)
- [Google Cloud KMS Pricing](https://cloud.google.com/kms/pricing)
- [Azure Key Vault Pricing](https://azure.microsoft.com/en-us/pricing/details/key-vault/)
- [Cosign TPM PKCS#11 Signing](https://blog.salrashid.dev/articles/2022/cosign_tpm/)
- [HashiCorp Vault Transit + Cosign Key Rotation Issue](https://github.com/sigstore/cosign/issues/1351)
- [YubiHSM 2 PKCS#11 with OpenSC](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-opensc-pkcs11.html)

### Pre-commit & SAST
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Gitleaks v8.18.0](https://github.com/gitleaks/gitleaks)
- [Semgrep](https://semgrep.dev/)

### Standards & Regulation
- [OpenSSF Best Practices Badge](https://www.bestpractices.dev/)
- [NIST SSDF SP 800-218](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
- [CISA Secure by Design](https://www.cisa.gov/resources-tools/resources/secure-by-design)

---

## Implementation Priority Summary

```
Phase 1 (Week 1)     ████████████░░░░░░░░ Git-level security + branch protection
Phase 2 (Week 2-3)   ████████████████░░░░ SBOM + vuln scanning + dependency baselines
Phase 3 (Week 4-6)   ████████████████████ SLSA provenance + signing + CI/CD
Phase 4 (Week 7-10)  ████████████████████ SAST + advanced signing + attack detection
Phase 5 (Ongoing)    ░░░░░░░░░░░░░░░░░░░░ GUAC, Gitsign, regulatory tracking
```

**Each phase is independently valuable.** Phase 1 alone stops credential leaks AND establishes hardware-backed commit signing. Phase 2 gives you vulnerability visibility. Phase 3 achieves SLSA L3 with hardware-backed local signing + keyless CI/CD. Phase 4 adds defense-in-depth.

---

*This plan was researched using 3 parallel research agents analyzing SLSA v1.2, sigstore/in-toto/TUF ecosystem, SSCS tooling landscape, and PAI infrastructure integration points. Updated 2026-02-12 to add end-to-end hardware-backed signing (YubiKey FIDO2 for commits, YubiKey PIV for cosign artifact signing, WSL2 bridge configuration). Further updated 2026-02-12 to add platform authenticator analysis (Windows Hello, Touch ID, Face ID), HSM/KMS architecture for automated signing (AWS/GCP/Azure KMS, HashiCorp Vault, YubiHSM 2), and full signing spectrum diagram. All tool versions and recommendations reflect the state of the art as of February 2026.*
