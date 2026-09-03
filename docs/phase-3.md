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

## Consolidated evidence (when the step lives in `release.yml`)

The modular workflows above are one shape, not the only one. A repository on
the draft-then-publish `release-immutability` path cannot use them —
`release-sign.yml` uploads signatures *after* publish, which an immutable
release forbids; `release-attest.yml` would attest a separately rebuilt
archive whose digest is not the one shipped; `release-slsa.yml` attaches the
generator's provenance to the release after publish — so it signs, attests
and generates provenance inside `release.yml` instead, over the exact
artifacts it uploads to the draft, and publishes once. That repository has
implemented `sigstore-signing`, `github-attestations`, `sbom-attestation` and
`slsa-provenance`; it has simply not installed the templates.

`sscsb verify` grades the evidence, not the filename. When, and only when, a
control's modular workflow is **absent**, it looks for the control's real
step in the repository's workflows. Exactly what it checks, and nothing more:

1. **Committed (HEAD).** Candidates are `git ls-tree -r --name-only HEAD --
   .github/workflows`, and each one is read with `git show HEAD:<path>` — the
   content a fresh clone of the repository carries. A file that only exists
   on disk, or was only `git add`ed to the index, or holds the step only as
   a working-tree edit, is never evidence; the verdict names the uncommitted
   file, and says when the working tree differs from what it examined. Only
   outside a git repository does `sscsb` fall back to reading the directory,
   and the message then states that committed-ness was not established.
2. **Shape-sound.** The file holds exactly one YAML document (a trailing
   `---` is not a second one), declares at least one job, no job is inert
   (neither `steps:` nor `uses:`), and every `needs:` names a job in the same
   file — a second document or a ghost `needs:` is a hard error GitHub raises
   for the whole file.
3. **Fires unattended.** `on:` includes `push`, `release`, `schedule`,
   `pull_request` or `workflow_run` — or it is `workflow_call` and a
   committed workflow with one of those triggers calls it via `uses: ./<path>`
   from a job that is not switched off, where that caller is itself
   shape-sound (a caller with a ghost `needs:` or two YAML documents calls
   nothing; it is skipped and the note says why) and the calling job's
   *effective* `permissions:` already grant every scope the called proving
   job needs (GitHub refuses a called workflow's job that asks for more than
   its caller holds; the defect names the caller, its job and the scope). A
   `workflow_dispatch`-only workflow, or one with no `on:` at all, is a
   procedure a human runs, not a control. A trigger's `branches` / `tags` /
   `paths` (and `-ignore`), `types` and `workflows` filters are **not
   evaluated** — the message says `on \`push\` (tags filter not evaluated)`
   rather than claiming the workflow fires — with one shape `sscsb` can judge
   without a glob engine or a cron parser: an **empty** list under
   `branches:`, `tags:`, `types:` or `workflows:`, or a `schedule:` with no
   cron entries, matches nothing, and fails.
4. **Not switched off.** Neither the proving job nor the proving step carries
   a constant-false `if:` — `false`, `'false'`, `"false"` or `${{ false }}` —
   or `continue-on-error: true` (YAML `true` or the string `'true'`; the
   installer step is held to the same). A signing command is not negated
   with `!`, not followed by `|| true` / `|| :`, and not preceded in its
   `run:` body by a function or alias named `cosign` (`cosign()`, `function
   cosign`, `alias cosign=`). And a `run:` body is judged only under a POSIX
   shell — no `shell:` at all, `bash`, `sh`, or GitHub's `bash … {0}` /
   `sh … {0}` template, resolved step → job `defaults.run.shell` → workflow
   `defaults.run.shell`; under `pwsh`, `python`, `cmd` or a custom template
   such as `true {0}` the step is reported as "not judged as a POSIX signing
   command" and fails. Any other expression is left alone; the gate models
   the switch left off, not the expression language.
5. **Pinned.** The action is pinned to a 40-hex commit SHA, through the same
   helpers `actions-audit` uses. The one exception is the slsa-github-generator,
   which must be at a `vX.Y.Z` tag — and **only** a tag: slsa-verifier
   identifies the trusted builder by its tag ref, so a SHA-pinned generator
   is refused with the tag requirement named, exactly as the shipped
   `release.yml` header warns. Only the generic generator,
   `generator_generic_slsa3.yml` — the one every template calls and the one
   `provenance-verify`'s `builder_id` names — is judged; a job calling the
   container generator or a language builder fails with that narrowing
   stated, because those are different trusted builders with different
   subjects and are out of scope.
6. **Bound to an artifact, in the right order.** The step names what it
   binds to, and for Cosign the installer precedes the signer.
7. **Granted.** The job's *effective* `permissions:` — the job-level block if
   there is one, else the workflow level, exactly as GitHub resolves them —
   include the scopes the step needs. An **empty** job-level block
   (`permissions: {}`, or a bare `permissions:`) is a declaration that grants
   nothing, never an omission that inherits the workflow level.

| Control | Evidence looked for (steps parsed from YAML, never grepped from text) | Job must be granted |
|---------|---------------------|---------------------|
| `sigstore-signing` | a `run:` body tokenised as shell (quotes, `\` escapes and continuations, `#` comments outside quotes, heredoc bodies — `<<WORD`, `<< 'WORD'`, `<<-WORD` — skipped up to the closing line, commands split on newline / `;` / `&&` / `\|\|` / `\|` / `&`) in which a command's **command word** — after leading `VAR=…` assignments, `sudo` / `env` / `time` and compound openers such as `do` — is `cosign`, its next word is `sign-blob` or `sign`, and `--bundle` (or `--bundle=…`) is a word of **that** command, and that command is not negated, not followed by `\|\|` and any word other than `exit` / `return` / `false` / `kill` / `{` / `(`, not piped (`\|`) into another command unless a `set -o pipefail` precedes it in the body or the shell sets it (the built-in `bash` does; `sh` and no `shell:` do not), and not shadowed by a `cosign` function or alias; run under a POSIX shell (`bash` / `sh`, bare or in GitHub's custom-shell shape — options and exactly one `{0}`); preceded in the same job by a SHA-pinned `sigstore/cosign-installer`; every cosign-bearing step is judged and any defective one fails the job | `id-token: write` |
| `github-attestations` | SHA-pinned `actions/attest-build-provenance` with `subject-path` / `subject-digest` / `subject-checksums` | `attestations: write` + `id-token: write` |
| `sbom-attestation` | SHA-pinned `actions/attest` (or `actions/attest-sbom`) with `sbom-path` **and** a `subject-*` input | `attestations: write` + `id-token: write` |
| `slsa-provenance` | a job `uses:` the `slsa-framework/slsa-github-generator` **generic** generator (`generator_generic_slsa3.yml`, no other) at a `vX.Y.Z` tag — a SHA pin is refused — with a non-empty `base64-subjects` or `base64-subjects-as-file` | `actions: read` (read or write) + `id-token: write` + `contents: write` |

A step that falls short of any gate **fails** with the precise defect: the
mutable ref is named, the missing scope is named, the manual-only trigger is
quoted, the empty filter is named, the constant-false `if:` is quoted, the
`continue-on-error` (on the proving job, its step, its installer, or the
calling job of a `workflow_call`), the `!`, the word after `||` that
swallows the failure, the `|` with no `pipefail` and the shadowing `cosign`
definition are each named, the non-POSIX shell is quoted, the out-of-order
installer names both step positions, the generator call without subjects is
told its provenance is bound to nothing, the SHA-pinned generator is told
which tag shape it needs, the short caller is told which scope it lacks.
`cosign verify-blob` in a deploy gate is verification, not signing; `echo
"cosign sign-blob … --bundle"` prints a command and runs none; a
`#`-commented command — whole-line or trailing — runs nothing; a heredoc
body is data to the tokeniser, never a command — a signing line inside one
is not counted, even when the heredoc is piped into a shell; and the
consolidated path never rescues a modular file that is present but broken —
it answers "the template is absent", nothing else.

### What this does not prove

Static analysis of committed configuration cannot prove execution. That is
the class-A stance of the scan methodology, not a gap to be closed by one
more gate, so after the gates above no further ones are added — what
remains is written down here, exactly:

- **Whether the workflow has ever run, succeeded, or produced a release** is
  not proven. Class-A evidence is committed configuration, and the directory
  methodology says so; whether a release carries the resulting bundles and
  attestations is a property of releases, which `provenance-verify` (the
  deploy gate) checks per release.
- **`with:` inputs and `run:` text are taken as written.** Expressions inside
  them — `${{ '' }}` as a subject path, `${{ env.X }}` as a flag — are not
  evaluated; a value that expands to nothing at runtime passes as the text it
  is in the file.
- **Command substitution, control flow and path-invoked binaries are not
  modelled.** `$(…)` is a word; an `exit 0` before the signing line, an
  `if`/`else` branch the signing line sits in, and `/usr/bin/cosign` (a
  command word that is not `cosign`) are not followed. A body that
  tokenises to a sound signing command is judged sound whatever runs around
  it.
- **Which `cosign` binary the command word resolves to is not followed
  across steps** — a shim placed on `$GITHUB_PATH` by an earlier step is not
  seen. Only a function or alias named `cosign` in the signing step's own
  body, and an installer that runs after the signing step, are caught.
- **Branch, tag, path, `types` and `workflows` filters are named, not
  evaluated.** No glob engine, no ref to match against: a workflow filtered
  to a branch that never receives a tag passes these gates and is reported
  with the filter left unevaluated. Only an empty list is judged.
- **Non-literal `if:` expressions are not evaluated.** Only the literal
  `false` spellings are recognised; a job gated on an expression that is
  always false at runtime, or a `continue-on-error: ${{ … }}` that is always
  true, passes, and the verdict does not mention the expression at all.
- **The runner's operating system is not consulted.** A step with no
  `shell:` is judged as POSIX shell; on a Windows runner GitHub's default is
  `pwsh`, and `runs-on:` is not read.

That list is the boundary. Everything inside it fails with a named defect;
everything outside it is disclosed here and in the verdict's wording, never
claimed.

`init` and `verify` agree. `sscsb init` consults the same recognizer before
writing a modular template: when a control in this set is already proven by
committed (HEAD) evidence, the template is skipped and the log says which
file proved it (`skip .github/workflows/release-sign.yml (sigstore-signing
proven by .github/workflows/release.yml)`). Without evidence, the template is
written as before. This matters because the scan pipeline runs `init` before
`verify` on a fresh clone, where HEAD is all there is.

The `--format json` row for a control proven this way reports the file the
verdict examined in `artifacts` (for example `.github/workflows/release.yml`)
rather than the template that was never installed. The text output says the
same: `release-sign.yml not installed — verified by consolidated evidence in
.github/workflows/release.yml instead`. What any downstream directory makes of
that is the directory's own classification; it reflects this scanner's rows
once its action scans with `sscsb` 0.3.1 or later.

## Verification before promotion

Provenance you never check is a file. The gate is the control:

```sh
sscsb provenance inspect dist/multiple.intoto.jsonl   # subjects, builder, predicate

sscsb provenance verify \
  --artifact dist/app-linux-amd64 \
  --provenance dist/multiple.intoto.jsonl \
  --source-uri github.com/OWNER/REPO \
  --source-tag v1.0.0 \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0
```

`sscsb provenance verify` wraps **slsa-verifier**, which checks that the artifact's
digest appears in the provenance, that the provenance was produced by the builder
you pin, and that it came from the source repository (and tag) you specify. All of
them must hold. The installed release workflow runs this gate **before** promoting
or publishing anything, so an artifact that cannot prove its origin does not ship.

**The builder must be pinned.** `--builder-id` is optional to slsa-verifier itself,
and leaving it off makes the verdict "*some* builder slsa-verifier trusts produced
this, for this source URI" — anyone who can get any trusted builder to run in that
repository clears the gate. `sscsb` therefore refuses to run unpinned: pass
`--builder-id`, or set `builder_id` once under `[controls.provenance-verify]` in
`.sscsb/config.toml`. Look the value up with `sscsb provenance inspect` **once**,
from a build you trust — never from the file you are currently verifying, which is
the untrusted input.

`--source-tag` stays optional, because verifying an artifact built from a branch, or
before any tag exists, is legitimate. When you leave it off the verdict says so
explicitly (`source tag NOT pinned`), rather than letting the word "verified" carry
more weight than it earned.

This path is tested against a real, externally-signed artifact — a real
slsa-verifier binary release with its real provenance — and the test asserts that a
genuine artifact passes, that a tampered one is rejected, and that the *same
genuine* artifact is rejected when pinned to a different trusted builder. A verifier
that says yes to everything is the failure mode worth testing for.

## Short-lived credentials (Octo STS)

A long-lived Personal Access Token is a credential with no expiry, broad scope, and
a habit of ending up in an environment variable. **Octo STS** replaces it: a
workflow exchanges its OIDC identity for a repository-scoped token that lives for
minutes, governed by a policy file that says which identity may get what.

`sscsb init` installs a starter `.github/chainguard/*.sts.yaml` policy. The
credential is issued to *the workflow*, not to *you*, and it cannot outlive the
job. There is nothing to rotate and nothing to leak.

The policy's `subject_pattern` must match GitHub's OIDC `sub` claim as GitHub
actually issues it, which is **id-decorated**:
`repo:OWNER@<owner_id>/REPO@<repo_id>:ref:refs/heads/main`. A pattern spelled
from names alone is refused. The installed policy therefore reads
`repo:OWNER(@<owner_id>)?/REPO(@<repo_id>)?:ref:refs/heads/<branch>` (with `.`
in the repository name escaped — it is a regular expression); `init` fills the
ids in from `gh api repos/<slug> --jq .id` and `gh api users/<owner> --jq .id`
when `gh` is available, and otherwise renders `[0-9]+` for each and logs a
`note` naming those two commands. Pin them: the ids are what survive a rename,
and what a re-created repository of the same name does not share.

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
