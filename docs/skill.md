# The bundled agent skill — `sscsb skill`

`sscsb` ships the instructions an AI agent needs in order to drive `sscsb`. The
canonical copy lives in this repository at `templates/skills/sscsb/SKILL.md`, is
compiled into the binary with `include_str!`, is installed into a repository at
`.claude/skills/sscsb/SKILL.md`, and is published as an asset on every release.

Those four copies are the same bytes, and this document is about how you can
know that.

---

## THE CONTRACT

Everything below this line is an explanation of these nine lines. **They are the
only normative text.** `tests/skill_docs.rs` asserts every one of them against
the constant the binary actually uses, and computes a digest over the block so an
edit here that is not mirrored in the code fails a test rather than shipping a
document that describes a tool nobody built.

```contract
sscsb skill contract v1
command                   sscsb skill install
template-path             templates/skills/sscsb/SKILL.md
installed-path            .claude/skills/sscsb/SKILL.md
asset-path                SKILL.md
bundle-path               SKILL.md.sigstore.json
certificate-identity      https://github.com/p4gs/sscs-bootstrapper/.github/workflows/release.yml@refs/tags/vX.Y.Z
certificate-oidc-issuer   https://token.actions.githubusercontent.com
attestation-predicate     https://slsa.dev/provenance/v1
embedded-check-scope      detects modification of the installed file by anything other than this binary; cannot detect a tampered sscsb
```

Read line by line:

- **`command`** — the one invocation that installs the skill. `--dry-run` prints
  the plan and touches nothing, in **all four** states — including the one where
  a real run would refuse, which it describes rather than performs; refusing
  inside a dry run would be the wet-run behaviour. `--force` replaces a file that
  differs, `--path` writes elsewhere.
- **`template-path`** — the source of truth in this repository. Editing the
  installed copy instead is how the two drift; a test holds them byte-identical.
- **`installed-path`** — where `sscsb skill install` writes, relative to the
  repository root. Note that this is a path *inside a repository you already
  work in*, writable by every other tool on the machine. That fact is the whole
  reason `sscsb skill check` exists.
- **`asset-path`** — the file's name among the release assets.
- **`bundle-path`** — its Cosign bundle: certificate, signature and Rekor
  inclusion proof. `release.yml`'s signing loop covers every file staged in
  `dist/` at that moment, skipping only the bundles it is in the middle of
  writing; `deploy-gate.yml` then refuses to publish a set in which any asset
  lacks a bundle or any bundle lacks its asset. The `*.intoto.jsonl` envelope is
  the one *asset* that legitimately carries no bundle — see
  [the 9 files that carry no Cosign bundle](#the-9-files-that-carry-no-cosign-bundle).
- **`certificate-identity`** — what `cosign verify-blob` must be told to expect.
  `vX.Y.Z` is a placeholder, and it is deliberately not filled in for you: see
  [The tag has to come from somewhere else](#the-tag-has-to-come-from-somewhere-else).
- **`certificate-oidc-issuer`** — the issuer that minted that certificate. Pin it
  alongside the identity. An identity string on its own can be matched by a
  certificate from an issuer you never trusted.
- **`attestation-predicate`** — the predicate type of the build-provenance
  attestation covering the release. `gh attestation verify` defaults to this one;
  state it anyway, because the same command with a different predicate is a
  different check.
- **`embedded-check-scope`** — the exact limit of what `sscsb skill check`
  establishes, quoted from the constant the binary prints.

---

## The two claims, stated exactly

There are two different checks here, and they prove different things. Conflating
them is the failure mode this document exists to prevent.

### 1. `sscsb skill check` — the installed copy

> `sscsb skill check` compares the SKILL.md on disk against the copy compiled
> into this binary and reports any difference. It detects an edit made to the
> installed file after installation — by another agent, a hook, or anything else
> on this machine. It cannot detect a tampered `sscsb`: a binary that was
> modified could have been modified to lie here too. To check the binary itself,
> verify the release artifact against its Sigstore identity — see docs/skill.md.

That is a narrow claim, and it is narrow on purpose. In-binary verification of an
`include_str!`'d file proves nothing against an attacker who can modify the
binary: the check, the bytes and any pinned digest all live in the same artifact.
Shipping that as "tamper-evidence" would contradict this repository's own
doctrine, stated for the local lane in
[docs/local-scan.md](local-scan.md#three-properties-are-load-bearing): a digest a
record supplies about itself authorizes nothing.

What it *does* buy depends on where your `sscsb` is installed — and the tool
works that out at run time instead of asking you to assume it.
`.claude/skills/sscsb/SKILL.md` sits in a working repository, writable by every
other agent, hook, postinstall script and prompt-injected tool call on the
machine. Whether any of those could *also* have rewritten `sscsb` itself is the
question that decides what a clean result is worth, and it has two answers:

- **Into a root-owned prefix** — `/usr/local/bin` on macOS is `root:wheel`, mode
  `0755`, and `/usr/bin` on a distribution is root-owned too. Nothing running as
  you replaces that binary without `sudo`, and the narrow claim holds exactly as
  stated: whatever edited the skill could not have edited the check. This is the
  *only* shape that can still earn `not-user-writable`, and even then only on a
  platform that qualifies — see
  [§1.1](#11-why-the-strong-verdict-is-hard-to-earn); on Linux the verdict reads
  `unknown` from `/usr/bin` and the reason is stated in the output.
- **By Homebrew** — the install this repository's README recommends *first* —
  it does not hold. `brew install` writes into a prefix owned by the installing
  user: `/opt/homebrew/bin` is `drwxrwxr-x` owned by you, and
  `/opt/homebrew/bin/sscsb` is a symlink into `../Cellar/…` you can repoint with
  no elevation whatsoever. There the binary is *exactly* as writable as the file
  it checks, one attacker holds both, and a clean result is evidence of no
  **casual** edit and nothing stronger.

`sscsb skill check` does not guess which of those you have. It walks its own
executable's **entire resolution chain** — every ancestor directory up to the
filesystem root, and every symlink hop individually, the link and the directory
holding it — and asks the kernel two questions about each one:

- **`writable`** — `faccessat(…, W_OK, AT_EACCESS)`, not the mode bits, so
  supplementary groups and ACLs count. "May I write this right now."
- **`owned`** — does the effective uid own this path. "May I *make myself able*
  to write it." POSIX gives a file's owner `chmod`, so a path you own at mode
  `0555` is one command from open, and asking only the first question missed
  that: a real `sscsb` binary, user-owned at `0555` in a user-owned `0555`
  directory under a root-owned prefix, answered `writable: false` on every link,
  printed `not-user-writable`, and was then replaced twice by an unprivileged
  `chmod u+w` — once on the file, once on the directory followed by
  unlink-and-recreate. Root owns everything and is reported as owning
  everything.

**Either answer `true`, anywhere on the chain, is a replaceable binary.** It
prints the verdict as `binary trust`:

| `binary trust` | What a clean `check` means |
|---|---|
| `not-user-writable` | the narrow claim above, at full strength — subject to *[what nothing here checks](#what-nothing-here-checks)* |
| `user-writable` | no *casual* edit to the installed file, and nothing stronger |
| `unknown` | read as `user-writable` — an unanswerable probe, an abandoned walk, or a platform that disqualifies the strong verdict is never rounded up into an assurance |

**`unknown` is the default, and `not-user-writable` is the exception.** That is
deliberate, and [§1.1](#11-why-the-strong-verdict-is-hard-to-earn) is the
argument for it. The strong verdict requires four things at once: the chain
fully walked, every link *not owned* by you, every link *not writable* by you,
and a platform whose `current_exe()` is known to report the path the executable
was invoked by. Anything else is `unknown`.

```sh
sscsb skill check                 # 0 identical, 1 differs or missing, 2 could not look
sscsb skill check --format json   # same exit codes; `state` is the field to read
```

The JSON form carries the same thing under `binary`: `trust`, a boolean
`narrow_claim_holds`, the resolved path, a boolean `chain_complete`, the
platform gate as `chain_start` (`invocation-path` or `pre-resolved`) and
`strong_verdict_available`, the `unchecked_mechanisms` list, and the chain
itself under `probes` — every path walked, in order, with its role and both
kernel answers (`writable`, `owned`). Read the chain rather than the verdict
when it matters: it names *which* link is open, and why.

**Why the whole chain, and not four points.** An earlier version of this check
probed exactly four paths — the executable, its directory, the canonicalized
file, and that file's directory — and reported `not-user-writable` for two
layouts where an unprivileged user can replace the binary. Both were
demonstrated by doing it:

- **A writable grandparent.** `prefix/bin` and the binary inside it can both be
  mode `0555` while `prefix` itself is yours. `mv bin bin.orig && mkdir bin`
  swaps the binary without touching any of the four.
- **A repointed intermediate symlink.** `bin/sscsb -> ../opt/sscsb/bin/sscsb`
  and `opt/sscsb -> ../Cellar/sscsb/<version>` — Homebrew's own shape.
  `canonicalize` jumps straight from one end to the other, so `opt/` never
  appears in a four-point probe, and repointing that middle link swaps the
  binary with nothing elevated.

A hedge that is merely vague misleads; a green verdict that is checkable and
wrong gets trusted. The chain walk guards against symlink loops and pathological
depth by stopping and saying so: `chain_complete` goes `false`, and a walk that
did not finish can never earn `not-user-writable`.

### 1.1 Why the strong verdict is hard to earn

Four rounds of hardening have each closed one door on this check and found
another open:

| Round | The door | How it was found |
|---|---|---|
| 1 | the binary and its own directory only | Homebrew's prefix is owned by the installing user |
| 2 | a writable **grandparent** above a read-only `bin` | takeover: `mv bin bin.orig && mkdir bin` |
| 3 | a repointed **intermediate symlink** invisible to `canonicalize` | takeover: repointing `opt/sscsb` |
| 4 | **ownership** — `W_OK` says "no" to a `0555` file you own | takeover: `chmod u+w`, twice, two ways |

Every one of those corrections was right, and none of them finished the job.
The pattern is the finding: this probe is trying to prove a **negative about a
filesystem**, and it cannot do that portably.

**What the chain still cannot see.** A walk can only begin where the operating
system says the running executable is, and that answer is platform-dependent:
some platforms report the symlink an executable was invoked through, others
report its target. macOS reports the link, so a `bin/sscsb -> ../opt/…/sscsb`
install puts the middle link *and* the directory holding it on the chain — the
Homebrew shape above is caught there. Linux reports the already-resolved
`/proc/self/exe`, so a link the kernel traversed before the process started
cannot appear on the chain at all, and a layout whose only open door is such an
intermediate link would look exactly like a shut one. A process cannot portably
recover the path it was invoked by — `argv[0]` is supplied by the caller, so
trusting it would let a caller pick the verdict — so this is stated rather than
guessed at, and it **disqualifies** the strong verdict rather than being papered
over: where `binary.chain_start` reads `pre-resolved`,
`binary.strong_verdict_available` is `false` and `trust` is never
`not-user-writable`, however shut the chain looks. On Linux, `sscsb skill check`
therefore reports `unknown` even from `/usr/bin`.

#### What nothing here checks

The strong verdict included. The JSON carries this list verbatim as
`binary.unchecked_mechanisms`, because the reader most likely to act on
`narrow_claim_holds: true` is a machine:

- **POSIX ACLs** — an entry granting another principal, or a default ACL on a
  parent, can change who may write after this answer was taken.
- **BSD file flags** — `chflags uchg`/`schg` can mask a path this answer calls
  shut.
- **Mount options** — a read-only mount can be remounted read-write by whoever
  may mount it.
- **Container image layering** — a copy-on-write layer can present different
  bytes to a different process.
- **Process capabilities** — `CAP_DAC_OVERRIDE` and `CAP_FOWNER` let a non-root
  process write regardless of mode or owner.

That list is not itself provably complete, which is the honest end of the
argument. `not-user-writable` is the **floor of what an attacker must beat**, not
a proof — and it is one more reason the only trust root here that does not
depend on this binary is [§2](#2-the-release-asset--the-claim-that-does-not-depend-on-us).

Exit `2` is not a verdict. An unreadable file is "we could not look", which is a
different claim from "it was changed", and the tool keeps them apart — including
the case where it could not even *look for* the file, which
`Path::exists()` cannot express, since that returns `false` for a directory you
may not traverse just as readily as for a path that is not there.

None of this reaches a tampered binary. For that there is exactly one trust root
in this document that is not this binary — the release asset's Sigstore
identity, [§2](#2-the-release-asset--the-claim-that-does-not-depend-on-us).
Where `binary trust` reads `user-writable`, that is not a nice-to-have; it is the
only check left that means anything.

### 2. The release asset — the claim that does not depend on us

> **Read this whole section in the future tense.** `SKILL.md` is not a release
> asset yet — `release.yml` stages and signs it, but no tag published so far was
> cut from a tree that did, so every count below describes what a release *of
> this repository's current shape* publishes, not what you will find attached to
> the newest tag today. The gap, and when it closes, is
> [spelled out before the recipe](#before-you-start-skillmd-is-not-a-release-asset-yet);
> nothing here is worth reading as a promise about an existing download.
>
> Every file in an `sscsb` release carries a signature, `SKILL.md` included —
> but not all of them are signed by the same identity, and the difference is
> the whole point of `--certificate-identity`. A release of this repository's
> current shape publishes 17 files. 16 of the 17 are signed at *our* tag by
> `.github/workflows/release.yml` — 8 keyless-signed into a `*.sigstore.json`
> bundle, plus those 8 bundles, each of which *is* such a signature. The 17th,
> the `*.intoto.jsonl` envelope, is signed by the SLSA generator's own workflow
> at the generator's own tag, not by ours — `slsa-verifier --builder-id` is what
> checks that signature, and pinning our `release.yml` identity against it would
> be pinning the wrong signer.
> `SKILL.md` and the platform
> tarballs are also subjects of that release's build-provenance attestation, of
> its CycloneDX SBOM attestation, and of its SLSA Build L3 provenance. Using
> tools you obtained independently of `sscsb`, you can verify that a copy is
> byte-for-byte what that workflow published at that tag, and that no asset was
> altered or added afterwards. That is a proof of origin, not a judgement of
> content: it establishes which pipeline produced these bytes, not that the
> instructions in them are safe to follow.

Read that last sentence again before acting on any green check mark. **Provenance
is not benignity.** A compromised repository cutting a release produces a
perfectly verifiable malicious skill: the signature would be valid, the
attestation would verify, the identity would match, and the instructions inside
would still be an attacker's. Signature verification answers *who built this*. It
does not answer *should I run this*, and nothing in this document claims it does.

### What a release actually contains

Three of the statements in this document are statements about *counts*, and a
reader running the closure check in step 4 sees every one of these files. For
this repository's current build fan-out — three platform targets — a release
publishes **17** assets. Future tense again, for the same reason as above:
`SKILL.md` is one of the 17, and
[`SKILL.md` is not a release asset yet](#before-you-start-skillmd-is-not-a-release-asset-yet).
A tag cut before that change lands attaches 15 — the same table without the
`SKILL.md` row and without its bundle.

| What | How many | Cosign bundle | Attested |
|------|---------:|---------------|----------|
| platform tarballs (`*.tar.gz`) | 3 | yes | yes |
| checksum sidecars (`*.sha256`) | 3 | yes | no |
| `sbom.cdx.json` | 1 | yes | no |
| `SKILL.md` | 1 | yes | yes |
| Cosign bundles (`*.sigstore.json`) | 8 | it **is** one | no |
| SLSA envelope (`*.intoto.jsonl`) | 1 | no — DSSE instead | no |

So **8** files carry a Cosign bundle, **9** carry none, **4** are signed *and*
attested, and **4** are signed but not attested. Change the build fan-out and
every number here moves with it, which is why `tests/skill_docs.rs` recomputes
them by replaying `release.yml`'s own rules and fails this document rather than
letting it drift.

### The 9 files that carry no Cosign bundle

The signing loop in `release.yml` runs over everything staged in `dist/` and
skips exactly one shape — `*.sigstore.json`, the bundles it is writing as it
goes. Signing a bundle would be signing a signature. That accounts for 8 of the
9.

The `*.intoto.jsonl` SLSA envelope is the ninth, and it is an exception of
*sequence*, not of policy: the SLSA generator produces it in a separate job
after that loop has finished, and `publish` collects it alongside the signed set.
It is not unsigned — a DSSE envelope carries the generator's own signature over
its payload, and step 6 below is where `slsa-verifier` checks that signature,
the pinned builder identity, and this source repository at this tag. What it does
**not** carry is a Cosign bundle, so a recipe that demands one for every file
would flag the envelope and be wrong; and a recipe that merely *skips* the
envelope's name shape would let an attacker add a file called
`anything.intoto.jsonl` and walk past the check. Step 4 does neither: it counts
them, because a release has exactly one, and so does the gate.

### The 4 files that are signed but not attested

Exactly 4 files in a release are signed but **not** attested: the 3 `.sha256`
sidecars and `sbom.cdx.json`. That is deliberate, and it is stated here rather
than papered over — each of them *describes* a subject instead of being one, and an
SBOM listed among its own subjects would be a claim about nothing. They are
covered by the signature gate like everything else, and step 4 below is where
you check that for yourself.

Read what the SBOM attestation says with the same care. It binds *this
release's* CycloneDX SBOM — generated from the source tree the tarballs were
built from — to each subject's digest. For a tarball that is a components list.
For `SKILL.md` it is a statement that the document shipped with that build, not
that a Markdown file has dependencies.

---

## The skeptic's recipe

Every step below uses a tool you obtain from somewhere that is not us. That is
the point: a verification performed entirely with software the publisher shipped
you is a publisher telling you about itself.

### Before you start: `SKILL.md` is not a release asset yet

`release.yml` stages `SKILL.md` into `dist/` and the signing loop covers it, so
the pipeline described above is real — but it is newer than every tag published
so far. **The first release whose assets include `SKILL.md` and
`SKILL.md.sigstore.json` is the first tag cut after this change lands.** Any tag
published before that carries those two files fewer than the counts above, and
`gh release download` will simply not produce a `SKILL.md` for it.

This matters because everything *around* the gap works. Real Cosign verifies the
real published tarballs, and the closure loop in step 4 prints `closed` over a
real release. A reader who runs step 3 verbatim against a published tag gets
`no such file or directory` from an otherwise-working recipe and reasonably
concludes the mistake is theirs. It is not.

What you can run **today**, against any published tag:

| Step | Against a published tag |
|------|-------------------------|
| 0, 1, 2 | yes |
| 3 — `cosign verify-blob` | yes, with a platform tarball substituted for `SKILL.md` |
| 4 — the closure loop | yes, over the whole published set |
| 5 — `gh attestation verify` | yes, with a platform tarball substituted |
| 6 — `slsa-verifier verify-artifact` | yes, with a platform tarball substituted |
| any step naming `SKILL.md` | from the next release onward |

The steps are written against `SKILL.md` because that is what this document is
about. Substituting a tarball changes nothing about what each step proves — the
signature, the attestations and the provenance cover both the same way.

### 0. Get the tools from an independent source

```sh
brew install cosign gh slsa-verifier   # or: apt / dnf / the projects' own signed releases
cosign version && gh --version && slsa-verifier version
```

Do not use `sscsb` to install, fetch, or check any of these.

### 1. Decide which tag you mean — out of band

Pick the version from a changelog, a release announcement, or the pin in your own
dependency manifest. Write it down before you download anything.

```sh
TAG=v0.3.1                      # ← the version you MEANT to install
REPO=p4gs/sscs-bootstrapper
```

### 2. Download the release assets

```sh
gh release download "$TAG" --repo "$REPO" --dir sscsb-release
cd sscsb-release
ls -1
```

You should see the platform tarballs, their `.sha256` sidecars, `sbom.cdx.json`,
one `*.intoto.jsonl` provenance envelope, `SKILL.md`, and a `*.sigstore.json`
bundle beside every one of those except the provenance envelope itself — 17
files for a release of this repository's current shape, broken down in
[what a release actually contains](#what-a-release-actually-contains). On a tag
published before this change, `SKILL.md` and its bundle are the two that are not
there; see
[`SKILL.md` is not a release asset yet](#before-you-start-skillmd-is-not-a-release-asset-yet).

### 3. Verify the signature on `SKILL.md`

```sh
cosign verify-blob SKILL.md \
  --bundle SKILL.md.sigstore.json \
  --certificate-identity "https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`--certificate-identity` takes the **exact** string — not
`--certificate-identity-regexp`. The deploy gate inside this repository uses the
regexp form only because it assembles the identity in shell and must escape it;
you are typing a literal, so pin a literal. A regexp that is not anchored, or
whose dots are not escaped, will happily match a host or a repository that is not
the one you meant.

### 4. Check that the set is closed — every asset signed, every bundle matched

Step 3 proved one file. This is the step that proves the *set*: it is the same
bidirectional loop `deploy-gate.yml` runs over the run's artifacts before
publish, run again by you over what was actually published.

```sh
IDENTITY="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${TAG}"
# zsh aborts a script outright when a glob matches nothing, and "nothing
# matched" is an ANSWER here — a set with no envelope is exactly what the third
# check is looking for. `nullglob` makes zsh agree with sh/bash/dash; the
# `[ -e ]` guards make those three agree with zsh, which would otherwise let
# them iterate once over the unexpanded pattern itself.
[ -n "${ZSH_VERSION-}" ] && setopt nullglob
fail=0
for f in *; do
  [ -e "$f" ] || continue
  case "$f" in *.sigstore.json | *.intoto.jsonl) continue ;; esac
  [ -f "$f.sigstore.json" ] || { echo "UNSIGNED: $f"; fail=1; continue; }
  cosign verify-blob "$f" \
    --bundle "$f.sigstore.json" \
    --certificate-identity "$IDENTITY" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    || { echo "BAD SIGNATURE: $f"; fail=1; }
done
for b in *.sigstore.json; do
  [ -e "$b" ] || continue
  [ -f "${b%.sigstore.json}" ] || { echo "ORPHAN BUNDLE: $b"; fail=1; }
done
envelopes=0
for p in *.intoto.jsonl; do [ -f "$p" ] && envelopes=$((envelopes + 1)); done
[ "$envelopes" -eq 1 ] || { echo "PROVENANCE ENVELOPES: expected 1, found $envelopes"; fail=1; }
[ "$fail" -eq 0 ] && echo "closed: every asset signed by that identity, every bundle matched"
```

All three checks are load-bearing, and each one covers a name shape the others
skip. The first loop catches an asset **added** after the fact — it would have no
bundle, and nothing that is not that workflow at that tag can mint one — but it
deliberately skips the two suffixes that carry their own signature, so an
addition *named* `*.sigstore.json` or `*.intoto.jsonl` walks straight past it.
The second loop catches both of the first suffix at once: a bundle whose file was
**removed**, and a file added under a bundle's name, since neither has a matching
artifact. The third catches an addition named `*.intoto.jsonl`, by counting: a
release has exactly one SLSA envelope, and `deploy-gate.yml` refuses to publish a
set with any other number. A **modified** asset fails its own `verify-blob`, and
a **substituted** envelope fails `slsa-verifier` in step 6.

The `nullglob` line at the top is load-bearing for exactly one of those, and it
is the one the count exists for. Without it, zsh — the default login shell on
macOS — treats a glob that matches nothing as a fatal error and *aborts the
script*, so a release with its envelope **removed** never reaches the count at
all: instead of `PROVENANCE ENVELOPES: expected 1, found 0` you get
`no matches found: *.intoto.jsonl` and a shell that stopped, which is a
diagnostic about your shell rather than about the release. All five cases —
closed, an added asset, an orphan bundle, a removed envelope, a second envelope
— now produce identical output under `sh`, `bash`, `dash` and `zsh`.

Read the skip list as a claim about signatures, not about scrutiny: the two
suffixes are skipped by the `verify-blob` loop because a bundle *is* a signature
and the envelope carries a DSSE one, and each is picked up by a later check
rather than waved through.

### 5. Verify the store attestations over `SKILL.md`

```sh
for predicate in https://slsa.dev/provenance/v1 https://cyclonedx.org/bom; do
  gh attestation verify SKILL.md \
    --repo "$REPO" \
    --signer-workflow "${REPO}/.github/workflows/release.yml" \
    --source-ref "refs/tags/${TAG}" \
    --predicate-type "$predicate" \
    --deny-self-hosted-runners
done
```

`--predicate-type` is not optional in spirit: `gh attestation verify` defaults to
the build-provenance predicate, so without the second value you would run the
first check twice and believe you had run two. The same two commands work on any
platform tarball — substitute its filename.

### 6. Verify the SLSA Build L3 provenance over `SKILL.md`

```sh
slsa-verifier verify-artifact SKILL.md \
  --provenance-path ./*.intoto.jsonl \
  --source-uri "github.com/${REPO}" \
  --source-tag "$TAG" \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0
```

There is exactly one `*.intoto.jsonl` in a release; the gate refuses to publish a
set with any other number. `verify-artifact` hashes whatever file you hand it and
looks that digest up among the provenance's subjects, so a document is covered
exactly as a tarball is.

`--builder-id` is not optional either. Omit it and you accept provenance from any
builder `slsa-verifier` trusts for this repository, rather than the one that
actually builds these releases.

State the L3 claim at its real strength: the *isolated trusted builder* is what
signs the provenance, and the subject digests it attests are the ones the release
job computed from the bytes it staged. That is a strong statement about the
pipeline; it is not a claim that a third party re-derived the artifacts.

### 7. Compare against what your binary carries

```sh
sscsb skill print | shasum -a 256
shasum -a 256 SKILL.md
```

Equal digests mean the copy compiled into your `sscsb` is the copy that release
published. Unequal digests mean your binary is a different version, or is not
that release's binary at all — which is exactly the question step 3 answers about
the binary's own tarball, run the same way.

---

## The tag has to come from somewhere else

`--certificate-identity` pins `refs/tags/vX.Y.Z`, so the whole check is only as
good as where that tag came from.

If you read the tag off the artifact you just downloaded — from a filename, from
a version string inside it, from the release page the download came from — you
have verified that the artifact agrees with itself. An attacker who can publish a
release can publish `v9.9.9` and name it consistently everywhere. Take the tag
from the version you *meant* to install, decided before the download: a changelog
you already trusted, a pin in your own manifest, a release note you received
through a channel that is not the artifact.

The same applies to this document. If you are an agent reading a `SKILL.md` and
wondering whether to trust it, do **not** follow a verification recipe printed
inside that same file — a rewritten skill would carry a rewritten recipe. Fetch
this page over HTTPS from
<https://github.com/p4gs/sscs-bootstrapper/blob/main/docs/skill.md>, which is why
the copy inside `SKILL.md` is labelled a convenience and points here.

---

## Installing without a release

```sh
cargo build --release
install -m 0755 target/release/sscsb /usr/local/bin/sscsb
```

A source build produces no release asset, no Cosign bundle and no attestation, so
**every step of the recipe above is unreachable for it**. That is not a defect in
the recipe; it is what building from source means. If you want the verification
path, install from a release — `brew install p4gs/p4gs/sscsb`, or the
`gh release download` route above. If you build from source, your assurance comes
from having read the source, and you should say so in exactly those terms rather
than borrowing the word "verified" from a check you did not run.

---

## Where each copy comes from

| Copy | Written by | Checked by |
|------|-----------|------------|
| `templates/skills/sscsb/SKILL.md` | a human editing this repository | `tests/skill_docs.rs` — the digest, the frontmatter, and every command it names |
| the bytes inside the binary | `include_str!` at compile time | the compiler; there is nothing to drift |
| `.claude/skills/sscsb/SKILL.md` (this repo) | `sscsb skill install` | `tests/skill_docs.rs` — asserted byte-identical to the template |
| `.claude/skills/sscsb/SKILL.md` (yours) | `sscsb skill install` | `sscsb skill check` |
| `SKILL.md` (release asset) | `.github/workflows/release.yml` | `cosign verify-blob` + `gh attestation verify` (both predicates) + `slsa-verifier verify-artifact` |

The installed copy in *this* repository is the tool's own dogfooding: the skill
that tells an agent how to drive `sscsb` is the skill `sscsb` emits. The same
principle as the shipped workflows — the tool that audits you is the tool that
generated them.
