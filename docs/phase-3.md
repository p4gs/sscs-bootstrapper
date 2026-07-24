# Phase 3 — Provenance

Phases 1 and 2 protect the repository. Phase 3 protects the *link between the
repository and the artifact you ship* — so that anyone, including you in six
months, can prove that this binary was built from that commit by that workflow,
and nothing intervened.

This is the phase that gets you to **SLSA Build Level 3**.

| Control | What it does | Backing tool | Default |
|---------|--------------|--------------|---------|
| `sigstore-signing` | Keyless signing + attestations bound to digests | Cosign / Fulcio / Rekor | on |
| `slsa-provenance` | SLSA Build L3 provenance from the official generator | slsa-github-generator | on |
| `github-attestations` | GitHub-native attestations in GitHub's own store | actions/attest-build-provenance, gh | on |
| `sbom-attestation` | GitHub-native SBOM attestation bound to the artifact digest | actions/attest (sbom-path), gh | on |
| `provenance-verify` | Verification gate before promote / deploy / publish | slsa-verifier, Cosign | on |
| `octo-sts` | Short-lived, repo-scoped credentials instead of PATs | Octo STS | on |
| `harden-runner` | Egress and tamper monitoring on every job | StepSecurity Harden-Runner | on |
| `witness` | Richer in-toto attestation capture around build steps | Witness | off |
| `model-signing` | Sign & verify ML model artifacts with Sigstore keyless signing (applies when models are present) | OpenSSF Model Signing | off |

## Keyless signing

There is no key to protect, because there is no key.

Cosign requests a short-lived certificate from **Fulcio**, binding the signature to
the OIDC identity of the thing doing the signing — for a GitHub Actions job, that
identity *is* the workflow: repository, ref, and workflow path. The certificate
expires in minutes. The signature is recorded in **Rekor**, a public append-only
transparency log, so the signing event is discoverable after the fact even by
someone who was not watching at the time.

What you verify against is therefore not "a key someone controls" but "this exact
workflow in this exact repository." A stolen key is not a threat model that exists
here. A compromised workflow still is — which is what Harden-Runner and the Actions
audit are for.

```sh
sscsb provenance verify-blob \
  --artifact dist/app \
  --bundle dist/app.sigstore.json \
  --identity 'https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/v1.0.0' \
  --issuer https://token.actions.githubusercontent.com
```

The `--identity` is the point. Verifying that *something* signed the artifact is
close to worthless; verifying that *the release workflow on the tag you expected*
signed it is the actual control. `sscsb` requires the identity — it is not
optional, and there is no "any identity" mode.

## SLSA provenance and the pinning exception

The release workflow calls **`slsa-framework/slsa-github-generator`**, the official
reusable workflow. It produces an in-toto provenance attestation describing the
builder, the source commit, and the artifact digests — generated in an isolated
job that your build cannot reach, which is precisely what makes it Build L3 rather
than a build step politely describing itself.

This is the one action in the entire repository that is **tag-pinned, not
SHA-pinned**:

```yaml
# PINNING EXCEPTION: slsa-github-generator MUST be referenced by tag.
# Its trust model derives the builder identity from the ref, and slsa-verifier
# validates that ref. A SHA pin here breaks verification by design.
uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0
```

That is not a lapse in the pinning discipline; it is a requirement of the
generator's own trust model, and slsa-verifier will reject provenance from a
builder it cannot identify. `sscsb`'s Actions auditor encodes it as a **single
named exception** for exactly that action prefix, so the rule "everything is
SHA-pinned" stays enforceable for everything else — including any *other* reusable
workflow you add.

## GitHub-native attestations (a third trail, not a replacement)

`github-attestations` installs `release-attest.yml`, which runs
[`actions/attest-build-provenance`](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
over the same artifact set the other two release workflows build. It is
**additive by design** — three independent provenance trails over identical
digests, differing in where the evidence lives and what a consumer needs in
order to check it:

| Trail | Evidence lives in | Consumer verifies with |
|-------|-------------------|------------------------|
| `sigstore-signing` | `.sigstore.json` bundles attached to the release | `cosign verify-blob` (or `sscsb provenance verify-blob`) |
| `slsa-provenance` | `.intoto.jsonl` attached to the release | `slsa-verifier` (or `sscsb provenance verify`) |
| `github-attestations` | GitHub's attestation store (queried via API) | `gh attestation verify` — nothing to install beyond the `gh` CLI |

The `gh` path is the lowest-friction one for downstream consumers: no cosign,
no slsa-verifier, no bundle files to locate — the attestation travels with the
repository, not the release assets:

```sh
gh attestation verify dist/app.tar.gz --repo OWNER/REPO \
  --signer-workflow OWNER/REPO/.github/workflows/release-attest.yml
```

The identity rule from keyless signing applies unchanged: the installed
workflow's in-pipeline verify job pins **both** `--repo` and
`--signer-workflow`, because "some workflow somewhere attested this" is not a
control — "this repository's release-attest workflow attested this" is.

Two honesty notes. First, this default-workflow path produces SLSA Build
L1/L2 provenance material; it does **not** claim L3 — the isolated trusted
builder in `release-slsa.yml` keeps that claim, which is why both ship.
Second, availability: attestations work on public repositories on all plans,
but private repositories require GitHub Enterprise Cloud — on a private
free-plan repo this workflow will fail at the attest step, and disabling the
control (`sscsb disable github-attestations`) is the honest configuration
there.

## SBOM attestation (the SBOM, bound to the digest)

`github-attestations` attests *how* the artifact was built. `sbom-attestation`
attests *what is in it*: it installs `release-attest-sbom.yml`, which generates
a CycloneDX SBOM and then binds it to the artifact's digest as a signed
attestation in GitHub's own store — verifiable the same low-friction way:

```sh
gh attestation verify dist/app.tar.gz --repo OWNER/REPO \
  --predicate-type https://cyclonedx.org/bom \
  --signer-workflow OWNER/REPO/.github/workflows/release-attest-sbom.yml
```

The `--predicate-type` is **not optional** here: `gh attestation verify`
defaults to the build-provenance predicate (`https://slsa.dev/provenance/v1`),
so an SBOM attestation is invisible unless you name its predicate type
(`https://cyclonedx.org/bom` for CycloneDX, `https://spdx.dev/Document/v2.3` for
SPDX). The installed verify job passes it for you.

This is a genuine SBOM *attestation*, not just SBOM *generation*: the `sbom`
control produces a CycloneDX file, but only this control cryptographically ties
that SBOM to the exact artifact digest, so a consumer can prove the SBOM they
hold describes the artifact they received. It uses `actions/attest` in SBOM mode
(`sbom-path`) because `actions/attest-sbom` is **deprecated** in favour of the
generic `attest` action; the engine is pinned to the same `v4.1.1` that
`release-attest.yml`'s `attest-build-provenance` wrapper uses internally.

Two honesty notes carry over. It is **not** mapped to SLSA — SLSA Build levels
cover provenance, not the SBOM predicate; the obligations it satisfies are SSDF
**PS.3.2** ("provenance data … in a software bill of materials") and CRA Annex I
Part II(1) (a machine-readable SBOM). And the same availability caveat applies:
public repos on all plans, private repos need GitHub Enterprise Cloud, so
`sscsb disable sbom-attestation` is the honest configuration on a private
free-plan repo.

## Verification before promotion

Provenance you never check is a file. The gate is the control:

```sh
sscsb provenance verify \
  --artifact dist/app-linux-amd64 \
  --provenance dist/multiple.intoto.jsonl \
  --source-uri github.com/OWNER/REPO \
  --source-tag v1.0.0

sscsb provenance inspect dist/multiple.intoto.jsonl   # subjects, builder, predicate
```

`sscsb provenance verify` wraps **slsa-verifier**, which checks that the artifact's
digest appears in the provenance, that the provenance was produced by a trusted
builder, and that it came from the source repository and tag you specify. All three
must hold. The installed release workflow runs this gate **before** promoting or
publishing anything, so an artifact that cannot prove its origin does not ship.

This path is tested against a real, externally-signed artifact — a real
slsa-verifier binary release with its real provenance — and the test asserts both
that a genuine artifact passes *and* that a tampered one is rejected. A verifier
that says yes to everything is the failure mode worth testing for.

## Short-lived credentials (Octo STS)

A long-lived Personal Access Token is a credential with no expiry, broad scope, and
a habit of ending up in an environment variable. **Octo STS** replaces it: a
workflow exchanges its OIDC identity for a repository-scoped token that lives for
minutes, governed by a policy file that says which identity may get what.

`sscsb init` installs a starter `.github/chainguard/*.sts.yaml` policy. The
credential is issued to *the workflow*, not to *you*, and it cannot outlive the
job. There is nothing to rotate and nothing to leak.

## Harden-Runner on every job

**Harden-Runner** monitors the build at runtime: outbound network egress, file
tampering in the workspace, suspicious process behavior. It is what would have made
the `tj-actions/changed-files` compromise visible while it was happening rather
than afterwards — the exfiltration was network egress from a build step to a place
that build step had no reason to talk to.

Every workflow template `sscsb` ships runs it, and `sscsb verify harden-runner`
checks that **every** workflow in your repository still does. Start in `audit`
mode, learn your legitimate egress, then move to `block`.

## Witness (optional)

**Witness** (`sscsb enable witness`) wraps individual build commands and attests to
what happened inside them — materials in, products out, environment, command line.
It is a finer-grained, more configurable in-toto story than the SLSA generator's
single build-level attestation.

It is off by default because for most projects it overlaps what the SLSA generator
already provides, at real complexity cost. Turn it on when you need per-step
attestation, not because more attestation sounds better.
