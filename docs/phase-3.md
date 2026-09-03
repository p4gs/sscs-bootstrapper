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
   with `!` **outside a condition**, not sitting in a compound command's
   **condition** — `if cosign …; then`, `elif cosign …; then`,
   `while`/`until cosign …; do` — whose failure path leaves the step
   passing. A conditional that CHECKS the signing is the canonical "check
   and fail" idiom, not a suppression, so the gate asks what the shell runs
   when the signing fails, and it asks the **arm** first: the `else` arm, or
   the `then` arm when the test is negated. If that arm **propagates** —
   `exit` / `return` with a literal non-zero status or none at all, `false`,
   or `kill`, the same vocabulary the `||`-branch gate uses — the step still
   fails on a failed signing and nothing is reported, so
   `if cosign …; then echo signed; else exit 1; fi` and
   `if ! cosign …; then exit 1; fi` both pass. The command immediately after
   the compound's terminator is consulted **only when that arm falls
   through** — runs off its end without deciding anything. An arm that ENDS
   the shell without propagating makes everything after the terminator
   unreachable, and nothing unreachable may stand in for it: in
   `if cosign …; then echo signed; exit 0; else echo warn; exit 0; fi`
   followed by `exit 1`, the step exits 0 on both paths and that `exit 1`
   never runs, so the shape keeps failing — while
   `if cosign …; then echo signed; fi` followed by `exit 1`, whose arm truly
   falls through, passes.
   For a **loop** the same question has a different answer, and which arm is
   read depends on the opener. A plain `while cosign …; do …; done` ENDS on
   a failing condition, so its failure arm is the command after `done` and
   its body is never read. An `until cosign …; do …; done` — and its
   `while ! cosign …; do …; done` twin — runs its BODY on a failing
   condition, so the body is the failure arm, and the loop is left on that
   path only by a `break` or by an `exit` / `return` that does not
   propagate. A body that propagates before anything in it escapes fails the
   step outright, and a body holding neither cannot let the step pass with a
   failed signing either, because it retries until the signing succeeds: the
   bounded retry
   `n=0; until cosign …; do n=$((n+1)); if [ "$n" -ge 3 ]; then exit 1; fi;
   sleep 2; done` passes. A body holding an `exit 0` fails outright, since
   nothing after `done` can undo an ended shell; a body holding a `break`
   hands the verdict to the command after `done`, so
   `until cosign …; do break; done` fails and
   `until cosign …; do break; done` followed by `exit 1` passes. A `break`
   ends that reading exactly as an `exit` does — `do break; exit 1; done`
   never reaches its `exit 1` — and is looked for at any depth inside the
   loop, since one nested in an `if` escapes it exactly as a bare one does.
   The `!` in `if ! cosign …; then exit 1; fi` is the conditional's own
   **test**, not a status inversion: in
   condition position a `!` inverts nothing the step ever sees, so the
   negation message — which would be factually wrong there — is never
   emitted, and a condition that does not propagate is reported as a
   condition defect instead. `if cosign …; then echo signed; fi`,
   `while cosign …; do break; done`, `if ! cosign …; then echo failed; fi`
   and `if cosign …; then :; else FAILED=1; fi` all keep failing.
   Those are the only propagating shapes; everything the walk cannot pin
   down structurally fails closed — an `elif` chain (a second condition it
   does not model), a compound never
   closed or closed by the wrong terminator, an arm whose propagating
   command is reached only through `&&` / `||` / `|` / `&`, and an arm where
   an `exit 0` / `exit $?` comes first. A compound NESTED inside an arm is
   read at its opener and no deeper: its own commands belong to it and not to
   the arm, but **an arm that can end the shell from inside a nested
   compound ends the arm**, so
   `else if [ -f skip ]; then exit 0; fi; fi` is an escape and the `exit 1`
   after `fi` may not stand in for it. What is looked for in there is the
   abandoning `exit` / `return` at any depth — the same word a loop's retry
   path is searched for — plus `break`, and only inside a loop.
   Not followed by a `||` branch that
   leaves the step passing, either immediately or at the end of the AND-OR
   list it opens with `&&`, since `&&` short-circuits to that branch
   (`cosign … && echo ok || true` swallows the signing failure exactly as
   `cosign … || true` does; `cosign … && echo ok || exit 1` does not, and a
   list ended by a newline, `;`, `&` or `|` has no such branch), not
   backgrounded with a single unpaired `&` (which detaches it from `-e`
   exactly as `||` does, so its status is never the step's) unless a bare
   `wait $!` — `wait "$!"` too — is the very next command, which collects
   that job's status and hands it back to `-e`; a bare `wait` (which yields
   0), a `wait $PID`, and a `wait $!` that is itself negated, piped,
   backgrounded or followed by a `||` branch all leave the backgrounding
   defect standing, not reached
   with `errexit` turned off by an earlier `set +e` / `set +o errexit` /
   `shopt -o -u errexit` in the same body (a later `set -e` /
   `shopt -o -s errexit` turns it back on; order is honoured, as
   it is for `pipefail`) **without a later command that propagates the
   status the body captured** — the status-capture idiom (`set +e`, sign,
   `rc=$?`, `set -e`, then check `$rc`) turns fail-fast off on purpose and
   re-raises the failure by hand. WHICH parameter carries that status is
   established first, and one spelling establishes it: an assignment from
   `$?` in the command **immediately after** the signing command, reached
   unconditionally — `rc=$?`, `RC=$?`, and the `local` / `declare` /
   `typeset` / `export` / `readonly` spellings of the same. `$?` holds the
   signing's status only until the next command runs, so a capture written
   any later reads some other command's status, and a name so bound is lost
   the moment anything else is assigned to it, `rc=0` included. A parameter
   that cannot be traced to `$?` of the signing command does not count: that
   is what fails `set +e`, sign, `rc=$?`, `set -e`, `other=$?`,
   `exit "$other"`, and what fails a `RC=0` … `exit "$RC"` wrapped around a
   signing loop whose own `|| { …; exit 1; }` guard has been dropped —
   which reports PASS while swallowing every signing failure if the
   parameter is taken on faith. Given that parameter, exactly three shapes
   are recognised as doing so: `exit "$rc"` / `return $rc`, an `exit` or
   `return` whose status is **that captured parameter** (a literal says
   nothing about the signing, so `exit 0`
   and `exit 1` do not count); a test on that parameter whose
   branch fails the step — `[ "$rc" -eq 0 ] || exit 1`,
   `[ "$rc" -ne 0 ] && exit 1`, since which way the test reads is not
   evaluated and either operator counts, and the branch may equally
   **re-raise the captured parameter itself**, `[ "$rc" -eq 0 ] || exit
   "$rc"`, which propagates by construction even though `$rc` is no literal;
   and that same parameter test in a
   condition whose arm fails the step, `if [ "$rc" -ne 0 ]; then exit 1;
   fi`. A guard written the idiomatic way is the same guard, so the test may
   be spelled `[ … ]`, `test …`, `[[ … ]]` — which must close with its own
   `]]` — or the arithmetic `(( rc != 0 ))`, with its own `))`, and
   `let "rc != 0"`: inside arithmetic a parameter is named bare as often as
   with a `$` and `((rc!=0))` needs no spaces, so each word is split into the
   identifiers it holds. `( ( echo $rc ) )` is a nested subshell and not
   arithmetic at all — bash tells the two apart by whether the parens are
   adjacent, and so does the tokeniser.
   **A consultation counts only where the shell reaches it**, at the
   signing's own depth: one inside a nested compound's arm
   (`if [ -f marker ]; then [ "$rc" -ne 0 ] && exit 1; fi`), one written
   after an unconditional `exit` that has already ended the shell, and one
   reached only through `&&` / `||` / `|` / `&` are each no consultation at
   all — the same reachability model the condition gate grades an arm with.
   **That skip is one-directional.** A conditionally reached command proves
   nothing about the path that did not run it, so it never COUNTS — as a
   consultation, or as an arm's verdict — but one that can END the shell
   stops the walk there all the same, because on the path that DID run it
   nothing written afterwards is reached. So `set +e`, sign, `rc=$?`,
   `[ -f dist/skip ] && exit 0`, `exit "$rc"` keeps the defect, and so do its
   `||`, `&& return 0`, `&& exit $?` and
   `[ "${DRY_RUN:-}" = "1" ] && exit 0` spellings, the same one-liner as an
   `else` arm, and the same one-liner as an `until` retry's body.
   **A BARE `exit` / `return` after `&&` abandons the shell too**, and this is
   where the "no status at all" rule above stops holding. An argument-less
   `exit` re-raises `$?`, which is the FAILURE only where the command is
   reached because something failed — a `||` branch, or the arm a compound
   takes on a failing condition. After `&&` the inheritance is inverted: the
   branch runs only because the test SUCCEEDED, so the status re-raised is 0.
   `[ -f dist/skip ] && exit` therefore leaves the step green with the
   signing failed — bash and sh both exit 0 with the marker present — and it
   keeps the defect exactly as `&& exit 0` does, in its `&& return` spelling,
   as an `else` arm, and as an `until` retry's body. The `||` twin is
   untouched, because it is genuinely sound: `[ "$rc" -eq 0 ] || exit`
   inherits the test's failure and re-raises it, and it PASSES.

   The rule holds wherever an argument-less `exit` decides a verdict, which
   includes the branch of the captured-status test itself: `[ "$rc" -eq 0 ]
   && exit` and `[ "$rc" -ne 0 ] && exit` both keep the defect. This one is
   decided rather than disclosed, because unlike the direction a test reads —
   which this walk does not evaluate — a bare `exit` after `&&` is unsound in
   BOTH readings: `-eq 0` exits 0 when the signing succeeded and falls
   through when it failed, and `-ne 0` re-raises the test's success and so
   exits 0 even on failure. `&& exit "$rc"` and `&& exit 1` are unaffected;
   only the argument-less spelling is.
   Only an abandoning `exit` / `return` ends the walk that way: a
   conditionally reached `exit 1` fails the step on the path that takes it,
   so the walk runs on past `[ -f dist/skip ] && exit 1` and still credits
   the re-raise after it, and a conditionally reached `break` is one of the
   residuals disclosed below.
   A nested compound is stepped over whole **only when the shell is certain
   to come back out of it**: one that can END the shell instead — an
   abandoning `exit` / `return` anywhere in its span, at any depth — ends the
   walk, because everything written after its terminator is written on the
   assumption that the arm which exits was not taken. So `set +e`, sign,
   `rc=$?`, `if [ "${SKIP_SIGNING:-}" = "true" ]; then exit 0; fi`,
   `exit "$rc"` keeps the defect, and so does its `while` / `for` /
   `until` / `case` twin and the same arm nested two deep. A compound whose
   extent cannot be pinned down ends the walk for the other reason — the walk
   no longer knows where this depth resumes — rather than letting what
   follows speak. The other half of the walk is the mirror image: an assignment that
   REBINDS the captured name counts wherever it is written, reached or not,
   because a rebinding that cannot be ruled out has to be assumed.
   A status captured and never consulted (`set +e`, sign, `echo done`),
   a check whose failing path still leaves the step passing
   (`[ "$rc" -eq 0 ] || echo warn`), and a test of anything but the captured
   parameter (`[ -f dist/x.sigstore.json ] || exit 1`) each keep the defect. And not
   preceded in its
   `run:` body by a function or alias named `cosign` (`cosign()`, `function
   cosign`, `alias cosign=`). A `||` branch fails the step only when it is
   `exit` / `return` with a **literal non-zero** status (or with no status at
   all, which re-raises `$?` — and in `||` position that `$?` is the failure
   that sent the shell down this branch), `false`, or `kill` — so `|| exit 0`,
   `|| return 0`, `|| exit 256` and `|| exit $?` all swallow — and a
   `{ …; }` / `( … )` group is judged by the status its **last** command
   leaves, so `|| { echo warn; }` swallows while `|| { echo warn; exit 1; }`
   does not. A branch of nothing but `NAME=VALUE` assignments —
   `|| FAILED=1`, `|| RC=$?` — runs them and exits 0, so it swallows too,
   and the defect names the branch as it was written. A group that is never
   closed, or whose last command cannot be read, is treated as swallowing:
   unknown fails closed. That last rule has a cost worth stating: a branch
   that **retries** the signing — `cosign … || cosign …` — is read as
   swallowing too, because a second `cosign` is not `exit`/`return` non-zero,
   `false` or `kill`. The retry is genuinely sound and `sscsb` still fails
   it; that is the fail-closed side of the trade, not an oversight. Express a
   retry that passes as a loop whose **exhaustion** fails the step — each
   attempt `cosign sign-blob "$f" --bundle "$f.sigstore.json" && signed=1 &&
   break`, then `[ -n "${signed:-}" ] || exit 1` after the loop (or a bare
   `false` on the exhausted path) — which every gate above accepts.
   And a `run:` body is judged only under a POSIX
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
| `sigstore-signing` | a `run:` body tokenised as shell (quotes, `\` escapes and continuations, `#` comments outside quotes, heredoc bodies — `<<WORD`, `<< 'WORD'`, `<<-WORD` — skipped up to the closing line, commands split on newline / `;` / `&&` / `\|\|` / `\|` / `&`) in which a command's **command word** — after leading `VAR=…` assignments, `sudo` / `env` / `time` and compound openers such as `do` — is `cosign`, its next word is `sign-blob` or `sign`, and `--bundle` (or `--bundle=…`) is a word of **that** command, and that command is not negated outside a condition, not in the condition of an `if` / `elif` / `while` / `until` whose failure path leaves the step passing (the arm taken on failure must `exit`/`return` non-zero, `false` or `kill` — the `else` arm, the `then` arm when the test is negated, an `until` / negated-`while` body — and only where that arm falls through does the command after the terminator stand in for it; an `until` body that can be left by a `break` or a non-propagating `exit` is one that gives up), not followed by a `\|\|` branch that leaves the step passing — immediately or at the end of the AND-OR list it opens with `&&` (only `exit` / `return` with a literal non-zero status or none at all, `false`, `kill`, and a `{ …; }` / `( … )` group whose LAST command is one of those, still fail it; a retrying `\|\| cosign …` swallows, fail-closed) — not backgrounded by a single unpaired `&` with no immediately following `wait $!` (the `&` of `2>&1` / `>&2` / `&>log` is part of its word, and `&&` is not backgrounding), not reached with `errexit` turned off by an earlier `set +e` / `set +o errexit` in the body (a later `set -e` turns it back on) unless a later command propagates the captured status, where the parameter must be one assigned from `$?` in the command immediately after the signing and the consultation must be one the shell reaches unconditionally at the signing's own depth — a nested compound is stepped over only when the shell must come back out of it, and one that can `exit 0` — or a bare `exit` reached through `&&`, which re-raises the test's success — ends the walk — (`exit "$rc"`, a `[ … ]` / `test …` / `[[ … ]]` / `(( … ))` / `let` on it whose branch fails the step or re-raises that parameter, or that test in a condition), not piped (`\|`) into another command unless a `set -o pipefail` precedes it in the body or the shell sets it (the built-in `bash` does; `sh` and no `shell:` do not), and not shadowed by a `cosign` function or alias; run under a POSIX shell (`bash` / `sh`, bare or in GitHub's custom-shell shape — options and exactly one `{0}`); preceded in the same job by a SHA-pinned `sigstore/cosign-installer`; every cosign-bearing step is judged and any defective one fails the job | `id-token: write` |
| `github-attestations` | SHA-pinned `actions/attest-build-provenance` with `subject-path` / `subject-digest` / `subject-checksums` | `attestations: write` + `id-token: write` |
| `sbom-attestation` | SHA-pinned `actions/attest` (or `actions/attest-sbom`) with `sbom-path` **and** a `subject-*` input | `attestations: write` + `id-token: write` |
| `slsa-provenance` | a job `uses:` the `slsa-framework/slsa-github-generator` **generic** generator (`generator_generic_slsa3.yml`, no other) at a `vX.Y.Z` tag — a SHA pin is refused — with a non-empty `base64-subjects` or `base64-subjects-as-file` | `actions: read` (read or write) + `id-token: write` + `contents: write` |

A step that falls short of any gate **fails** with the precise defect: the
mutable ref is named, the missing scope is named, the manual-only trigger is
quoted, the empty filter is named, the constant-false `if:` is quoted, the
`continue-on-error` (on the proving job, its step, its installer, or the
calling job of a `workflow_call`), the `!` outside a condition, the
condition position whose failure path fails nothing, the `||`
branch that swallows
the failure (quoted as written — `|| echo`, `|| exit 0`, `|| {`), the
backgrounding `&`, the `set +e` whose captured status is never
propagated, the `|` with no
`pipefail` and the shadowing `cosign`
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
  `if`/`else` **body** or a `case` **arm** the signing line sits in, and
  `/usr/bin/cosign` (a
  command word that is not `cosign`) are not followed. A body that
  tokenises to a sound signing command is judged sound whatever runs around
  it — so `case "$MODE" in release) cosign … ;; esac` passes on the strength
  of the signing command itself, and whether `$MODE` is ever `release` is not
  asked. (The signing there IS seen: the arm's `release)` pattern, which the
  tokeniser emits as the words `release` and `)`, is skipped so the command
  word is `cosign` and every gate applies to it.) The one piece of control
  flow that IS followed is the compound whose
  CONDITION holds the signing: its failure arm, the command after its
  terminator when that arm falls through, and — for an `until` / negated
  `while` — whether the loop can be left at all with the signing still
  failing, exactly as far as the gate-4 clause above says and no
  further. The condition gate reads only the command that CARRIES the `if` /
  `elif` / `while` / `until` keyword, so a signing command reached later in
  the same condition list — `if other && cosign …; then` — is not caught.
- **The `errexit` exemption for `&&` / `||` lists is not modelled.** A
  command inside such a list is exempt from fail-fast unless it follows the
  final operator, so `cosign … && echo ok` loses the signing failure when
  further commands follow it in the body and one of them succeeds. Only the
  `||` branch that TERMINATES the list is attributed to the signing command
  (`&& echo ok || true` is caught); a list terminated by `&` or `|` — the
  whole list backgrounded or piped, `cosign … && echo ok &` — is a
  construct this walk stops at and does not grade.
- **`wait` is followed only in its one unambiguous spelling.** A bare
  `wait $!` / `wait "$!"` immediately after the backgrounded signing command
  is recognised as collecting its status. A PID captured first
  (`pid=$!; wait "$pid"`), a `wait` on a job spec, and a `wait $!` reached
  after another command are not: the recognizer does not track variables or
  job tables, so those keep the backgrounding defect.
- **Which `cosign` binary the command word resolves to is not followed
  across steps** — a shim placed on `$GITHUB_PATH`, or a `cosign` function
  exported into the step through `$BASH_ENV`, by an earlier step is not
  seen. Only a function or alias named `cosign` in the signing step's own
  body, and an installer that runs after the signing step, are caught.
- **Fail-fast is assumed on for every POSIX `shell:`, and only a literal
  option word in the body turns it off.** GitHub's default (`bash -e {0}`),
  the built-in `bash` (`-eo pipefail`) and the built-in `sh` (`sh -e {0}`)
  all set `-e`. A `set +e` / `set +o errexit`, and a `shopt -o -u errexit`
  (`shopt -o` addresses the `set -o` namespace, so it is `set +o errexit`
  under another name — in either flag order, and as one cluster), are each
  caught, and a later `set -e` / `shopt -o -s errexit` puts fail-fast back;
  `set --` ends the option list, so `set -- +e` sets `$1` and is not read as
  a toggle. But the option word must be literal: `OPTS=+e; set $OPTS` is not
  followed, since the value is text the recognizer does not evaluate. Nor is
  a **custom** `shell:` template that omits `-e`, `bash {0}` or `sh {0}`,
  which runs the body with no fail-fast at all: the template is
  POSIX-shaped, so the step is graded as if `-e` were on. So is a `trap`
  that rewrites the step's status (`trap 'exit 0' EXIT`).
- **A suppression that wraps the signing command from the outside is not
  attributed to it.** The recognizer reads the separator that ends the
  signing command itself — and, when that separator is `&&`, walks the
  AND-OR list forward to the branch that terminates it — so
  `cosign sign-blob … &`, `cosign sign-blob … || true` and
  `cosign sign-blob … && echo ok || true` are all caught. A `{ …; }` or
  `( … )` **group** is never read from the outside in: `( … ) &`,
  `{ …; } || true` and `( … ) | tee log` are judged by the signing line's
  own separator, not the group's, whether the group is written on one line
  or across many.
- **A conditional and a captured status are followed only in the shapes
  enumerated above.** The failure path of a compound is read one level deep
  — the arm the shell takes when the signing fails, and the command after the
  terminator only when that arm falls through — with exactly one thing read
  deeper: whether a compound nested in that arm can END the shell, which is
  looked for at any depth and closes the arm. Nothing else inside a nested
  compound is graded, so an arm that re-raises the failure from inside one
  (`else if [ -f x ]; then exit 1; fi; fi`) is read as falling through and
  hands the verdict to the command after the terminator. A command in that arm
  reached only through `&&` / `||` / `|` / `&` is never the arm's verdict
  either — but one that can END the shell
  (`else [ -f dist/skip ] && exit 0; fi`) ends the arm, so the command after
  the terminator may not stand in for it. A captured status is
  followed only through a parameter bound from `$?` in the command
  immediately after the signing, then consulted, where the shell reaches it
  at the signing's own depth, as
  `exit "$rc"`, as a `[ … ]` / `test …` / `[[ … ]]` / `(( … ))` / `let` whose
  branch fails the step or re-raises that same parameter, or as that
  test in a condition. A body that is genuinely sound and re-raises the
  failure some other way — a `trap`, a flag summed across a loop and checked
  in a later STEP, a helper function that exits, an `elif` chain — fails
  with the condition or `set +e` defect named. So does a **`case` on the
  captured status**: `case "$rc" in 0) ;; *) exit 1 ;; esac` re-raises the
  failure correctly and is failed anyway, because judging it would mean
  deciding which arm a non-zero status takes, and an arm's pattern is only
  ever SKIPPED so the command behind it can be read, never matched against a
  value — a `case` is stepped over whole, exactly as any other nested
  compound the shell is certain to come back out of, and in **either
  spelling**: the multi-line one, and the one-liner
  `case "$MODE" in skip) echo s ;; esac`, whose `case` keyword and first arm
  the tokeniser emits as a single command (one whose arm can `exit 0` ends
  the walk instead, and the defect stands for that reason too).
  So does a status relayed
  through a second variable (`rc=$?; status=$rc; exit "$status"`): the walk
  does not follow a captured status from one name to another, only its loss.
  So does a consultation the reachability model cannot place — one whose
  enclosing compound has an `elif`, or a missing or mismatched terminator —
  since the walk ends there rather than crediting what follows. And so does
  one written OUTSIDE the compound the signing itself sits in: the walk ends
  at that compound's own terminator, because what follows a loop is reached
  under the loop's terms and not the signing's, so `set +e`, a `for` loop
  that signs and captures `rc=$?` per file, `done`, `exit "$rc"` keeps the
  defect — the last iteration's status is not every iteration's.
  That is the same fail-closed
  trade as the retrying `|| cosign …` branch, and the reason the passing
  shapes are enumerated rather than described: a maintainer who is failed
  here can read off a shape that passes and write it.
  Where this walk errs the OTHER way is a CLASS, not one case: **a command
  that ends or diverts the shell without being an `exit` / `return` this walk
  can see.** Only an abandoning `exit` / `return` ends the walk, so every
  member of the class is stepped past and whatever is written after it is
  credited. The class has four members, each disclosed rather than closed:
  - **A `trap` that rewrites the step's status.** `trap 'exit 0' EXIT`
    replaces the status of every path out of the body, the re-raise the gate
    credited included. It is named in the fail-fast bullet above as well.
  - **A `break` the shell does not reach unconditionally.** A bare `break`
    before the re-raise ends the walk (the re-raise is not credited) while
    `if [ -f dist/skip ]; then break; fi` before it does not, and neither
    does `[ -f dist/skip ] && break`. The whole body that shows it, in
    order: `set +e`; `for f in dist/*; do`; the signing; `rc=$?`;
    `if [ -f dist/skip ]; then break; fi`; `exit "$rc"`; `done`; `echo done`.
    The re-raise is INSIDE the loop and `echo done` is what the `break` path
    falls into, and that body passes although the `break` path leaves the
    loop unsigned — `$rc` is never re-raised, control runs off `done` into
    `echo done`, and the step ends green with the signing failed. Closing it
    would mean grading what follows `done` under the loop's terms, the thing
    the bullet above says this walk does not do: a `break` says where control
    goes, not whether the step ends up failing.
  - **`exec CMD`, which REPLACES the shell process** — the step's status
    becomes `CMD`'s, and nothing written after it ever runs. This walk reads
    `exec` as an ordinary command word, so it neither ends the walk nor
    propagates: `set +e`, sign, `rc=$?`, `[ -f dist/skip ] && exec true`,
    `exit "$rc"` PASSES, and so does `exec true` as an `else` arm with an
    `exit 1` after `fi`, while both exit 0 with the signing failed. An `exec`
    reached UNCONDITIONALLY is failed, but for the other reason — nothing
    then re-raises the captured status — not because the `exec` was read.
  - **`eval STRING`, whose string is shell code this walk never parses.**
    `set +e`, sign, `rc=$?`, `eval "exit 0"`, `exit "$rc"` PASSES and exits 0
    with the signing failed, and `eval "exit 0"` as an `else` arm passes the
    same way; the sound mirror image, `eval "exit \$rc"`, is failed for the
    same blindness. A string assembled at runtime is further still from what
    is read.

  All four are the one instrument pointed the wrong way: the walk grades the
  `exit` / `return` words it can see, and a construct that leaves the shell
  by another route is outside what it claims.
- **An `until` retry that can only loop is read as sound, not as a hang.**
  When the body of an `until cosign …; do …; done` holds no `break` and no
  non-propagating `exit`, the gate concludes that a failed signing never
  reaches a passing step — which is true, but the way it is true may be that
  the loop runs until the job's timeout kills it rather than that the step
  exits non-zero. `sscsb` grades whether an unsigned artifact can reach a
  green step, not whether the body terminates; an unbounded retry passes.
  The `break` that would change that answer is counted at any depth, so a
  `break` that only leaves an INNER loop is over-counted and the outer loop
  is judged as escapable — fail-closed, and the reason a bounded retry
  should exit rather than break.
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
