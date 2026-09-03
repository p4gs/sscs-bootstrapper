# The local lane — `sscsb scan --local`

Some controls cannot be seen from outside your machine.

`commit-signing`, `ai-trailers`, `ai-dep-gate`, `ai-receipts`, `package-trust`,
`bumblebee`, `grype`, `socket-firewall`, `signing-model` and the rest of the
**local-environment** controls are checks on a *development environment*: which
key git will sign with, whether the installed hooks actually block, what is in
the package-trust baseline, which scanners are on your `PATH`. Cloning your
repository tells you none of that. The public directory calls these **class C**
and scores them `unverified` — deliberately, because an unperformed check is
never a verdict.

That honesty has a cost. `unverified` sits outside every denominator, so a
repository with a perfect posture can still read **provisional**: it is graded
on the two-thirds of its controls a repo scan could observe, and the directory
says so out loud rather than pretending.

The local lane closes that gap the only way it can be closed honestly: you run
the check where it is observable, and you sign what you saw.

---

## THE CONTRACT

Everything below this line in this document — and everything in the directory's
`/methodology` page, its ingest workflow, and its site build — is an
explanation of these twelve lines. **They are the only normative text.** The
tool asserts them in `tests/local_scan_docs.rs`; the directory asserts a
verbatim mirror of the same block in `site/test/local.test.ts`. Both sides
compute a digest over it and pin the same hex, so an edit on one side that is
not mirrored on the other fails a test rather than shipping a lane that does
not work end to end.

```contract
sscsb local-lane contract v1
command              sscsb scan --local --submit
sshsig-namespace     sscsb-scan-record
record-path          .sscsb/scan-record.local.json
signature-path       .sscsb/scan-record.local.json.sig
anchor-path          .sscsb/policy/allowed_signers
anchor-namespaces    git,sscsb-scan-record
signed-bytes         the bytes of .sscsb/scan-record.local.json, verbatim
record-shape         ScanRecord
schema-version       1
methodology-version  1
record-fields        schema_version methodology_version repo scanned_at scanner request_issue controls score
repo-fields          owner name url default_branch commit description
control-fields       id phase in_scope raw_outcome scan_outcome reclassified reason messages
score-fields         grade provisional overall_percent evidence_coverage_percent phases
submission-label     local-scan-result
```

Read line by line:

- **`command`** — the one invocation. It is what the directory prints on every
  provisional listing, what the issue form names, and what this tool
  implements. There is no `verify --local`; there is no second spelling.
- **`sshsig-namespace`** — the SSHSIG namespace the detached signature is
  minted in, and the namespace `ssh-keygen -Y verify` is given at ingest.
  Distinct from git's own `git` namespace so a commit signature can never be
  replayed as a scan record, or the reverse.
- **`record-path` / `signature-path`** — **committed** paths. `sscsb init` adds
  exactly one ignore rule, `.sscsb/out/`, so neither of these is ignored; the
  record and its signature are meant to live in your history. The submission is
  therefore a *pointer*: the directory reads both files out of your public
  repository and nothing you type reaches the bytes it verifies.
- **`anchor-path` / `anchor-namespaces`** — the trust anchor, generated from
  `.sscsb/policy/signers.toml` by `sscsb init` and already the anchor for the
  `commit-signing` control. Its lines grant both namespaces explicitly.
- **`signed-bytes`** — the signature covers the record file *as written*, byte
  for byte. Nothing re-serializes it: not this tool, not ingest, not the site
  build, which republishes it with a byte-identical copy.
- **`record-shape` … `score-fields`** — the record **is** a directory
  `ScanRecord`, the same shape `site/src/schema.ts` validates for every other
  lane, with every required field present including `methodology_version`.
  Because the signature makes the bytes unreshapeable afterwards, the shape has
  to be right at signing time; the tool emits the final shape and signs that.
- **`submission-label`** — the label `--submit` applies, and the label the
  directory's `ingest_local` job keys on.

The record carries one **additive** block the directory ignores for validation
and uses for display: `local` (`record_version`, `lane`, `namespace`, `repo`,
`worktree`, `signer`, `allowed_signers`). Additive means a consumer that does
not know it reads the record exactly as it reads any other.

---

## What a local record proves, exactly

A workstation has no OIDC identity. There is no Sigstore certificate to bind
to, because there is no workflow and no issuer — that is what makes CI evidence
strong and what a laptop cannot borrow.

So the anchor is something your repository already **commits**:
`.sscsb/policy/allowed_signers`.

1. `sscsb scan --local` runs the full control set and writes the record to
   `.sscsb/scan-record.local.json`.
2. It signs those exact bytes with **the key git signs your commits with** —
   read from `gpg.format`, `user.signingkey` and `gpg.ssh.program`, so a
   1Password-, Secure-Enclave- or YubiKey-backed key signs untouched —
   producing a detached SSHSIG at `.sscsb/scan-record.local.json.sig`.
3. You commit and push both files.
4. The directory fetches both from your public repository, fetches
   `allowed_signers` **at the commit the record names**, and runs
   `ssh-keygen -Y verify`.

A verified local record therefore proves precisely this:

> a holder of a key this repository commits as an approved signer asserted this
> result at commit X.

That is attributable and auditable, and anyone can re-check it. This recipe is
executed verbatim in `tests/local_scan_docs.rs` against a real signed record,
so it cannot rot into an example that does not run:

```sh
gh api -H 'Accept: application/vnd.github.raw' \
  "repos/OWNER/REPO/contents/.sscsb/policy/allowed_signers?ref=COMMIT" \
  > allowed_signers
ssh-keygen -Y verify -f allowed_signers -I PRINCIPAL \
  -n sscsb-scan-record \
  -s .sscsb/scan-record.local.json.sig \
  < .sscsb/scan-record.local.json
```

`OWNER`, `REPO`, `COMMIT` and `PRINCIPAL` all come out of the record itself:

```sh
jq -r '.repo.owner, .repo.name, .repo.commit, .local.signer.principal' \
  .sscsb/scan-record.local.json
```

### What it does **not** prove

It does not prove your CI produced the result. Only the `action` lane does
that, by keyless-signing in a workflow whose identity the directory pins to
your repository's canonical `sscsb-scan.yml` on its live default branch.

It does not prove the machine was clean, that the tools were the ones claimed,
or that the working tree matched the commit. Nobody can inspect a workstation.

## How the directory scores it

This is the part that changed, and it is worth stating precisely because the
old rule ("local may only fill class-C rows") was too blunt in one direction
and the naive fix ("just union the lanes") is unsafe in the other.

For every control id, the directory collects a verdict from **every evidence
source** it holds for that repository: the newest action-lane record whose
signature verified, the newest local-lane record whose signature verified, and
the external record the directory produced itself. Then:

1. **Two or more sources give different countable verdicts** (pass / fail /
   gap) → the control scores **gap**, and carries a contradiction flag naming
   each source and the verdict it gave. The flag appears on the record, on the
   listing row and on the detail page.
2. **Exactly one distinct countable verdict** across sources → that verdict,
   whichever lane produced it. A local `pass` on a class-C row counts; so does
   a local `fail`.
3. **No countable verdict** → `unverified` / `info`, outside every denominator,
   exactly as before.

A contradiction therefore **costs** the repository: a gap sits in the
denominator without passing. That is the "err on the side of caution" rule, and
it is what removes any incentive to submit a flattering local scan.

### The observability requirement

One refinement makes the union safe, and it is not "local counts less":

> **Where someone else could have checked, we require that someone else.**

Classes A, A′ and B are *by definition* observable from a repository scan — a
committed artifact, a committed workflow, a live GitHub API setting. For those
rows a maintainer's self-report **alone** is not countable: with no independent
source the row stays `unverified` and outside the denominator, and it becomes
countable the moment a CI or external record exists to agree or disagree with
it.

Class C is *by definition* not independently observable — it lives on the
workstation and nowhere else. There, the maintainer's signed word is the best
evidence that can exist, and it counts on its own.

The practical consequence: a repository whose only evidence is a local record
publishes with its class-C rows scored and everything else `unverified`. Its
evidence coverage is low, so it reads `NA — insufficient evidence`, not `A+`. A
local record raises a real score only alongside a scan somebody else could run.

## The guard rails

Each refusal names the exact thing to change. None can be overridden by a flag,
because every one exists to stop a record that would be a lie.

| Refusal | Why | Fix |
|---------|-----|-----|
| `gpg.format` is not `ssh` | The anchor is an `allowed_signers` file; only SSH signatures verify against one. | `git config --global gpg.format ssh` |
| `user.signingkey` unset | There is nothing to sign with. | `git config --global user.signingkey ~/.ssh/id_ed25519.pub` |
| The key does not resolve to a public key | The value is neither a key, a file holding one, a `.pub` sibling, nor a private key `ssh-keygen` can derive from. | Point it at your real key — see [signing.md](signing.md). |
| No `.sscsb/policy/allowed_signers` | Without the committed anchor there is nothing for a verifier to check against. | `sscsb init`, then commit the file. |
| Your key is not in the anchor | The record would be signed by someone the repository has not approved. | Add it to `signers.toml`, `sscsb init`, commit both files. |
| The anchor does not grant `sscsb-scan-record` | The signature would not verify. | `sscsb init`, commit the anchor. |
| The working tree has tracked changes | See below. | `git commit` or `git stash` |
| No `origin` remote | The directory identifies a repository by its GitHub slug and fetches the anchor from it. | `git remote add origin https://github.com/owner/repo` |

### Why a dirty tree is refused rather than recorded

Both are defensible; this one is deliberate.

The record's commit is not decoration — it is the whole binding. The directory
fetches `allowed_signers` from your public repository *at that commit*, and the
class-C controls the record exists to resolve are read out of your **working
tree**. If the tree differs from the commit, the record describes files that
are not at the commit it names, and nothing downstream can tell which rows are
affected.

**Untracked files are ignored.** Build output, `.sscsb/out/`, an editor scratch
file — none of them are part of the commit, and refusing on them would make the
command unusable for exactly the maintainers it exists to serve.

The record and its signature are themselves written *before* they are
committed, so the tree is dirty the moment the command finishes. That is
expected: the next run is checked against the commit you make from them.

## What gets written

```
.sscsb/scan-record.local.json          the record (the signed bytes) — COMMIT THIS
.sscsb/scan-record.local.json.sig      the detached SSHSIG            — COMMIT THIS
.sscsb/out/scan-local-submission.md    the submission body (--submit only; gitignored)
```

The record is a directory `ScanRecord` — the same shape the site validates for
every lane — plus the additive `local` block:

```jsonc
{
  "schema_version": 1,
  "methodology_version": 1,
  "repo": {
    "owner": "p4gs",
    "name": "sscs-bootstrapper",
    "url": "https://github.com/p4gs/sscs-bootstrapper",
    "default_branch": "main",
    "commit": "<40-hex sha the result describes>",
    "description": ""
  },
  "scanned_at": "2026-09-03T12:00:00Z",
  "scanner": {
    "sscsb_version": "0.3.1",
    "workflow_run_id": 0,
    "workflow_run_url": ""
  },
  "request_issue": null,
  "controls": [
    {
      "id": "commit-signing",
      "phase": 1,
      "in_scope": true,
      "raw_outcome": "pass",
      "scan_outcome": "pass",
      "reclassified": false,
      "reason": null,
      "messages": ["…"]
    }
  ],
  "score": {
    "grade": "A",
    "provisional": false,
    "overall_percent": 92.3,
    "evidence_coverage_percent": 88.9,
    "phases": [ /* one entry per phase 1-5 */ ]
  },
  "local": {
    "record_version": 1,
    "lane": "local",
    "namespace": "sscsb-scan-record",
    "generated_at": "2026-09-03T12:00:00Z",
    "sscsb_version": "0.3.1",
    "repo": { "branch": "main", "…": "…" },
    "worktree": { "clean": true, "tracked_changes": [] },
    "signer": {
      "principal": "you@example.com",
      "key": "ssh-ed25519 AAAA…",
      "fingerprint": "SHA256:…",
      "program": "op-ssh-sign"
    },
    "allowed_signers": {
      "path": ".sscsb/policy/allowed_signers",
      "sha256": "<digest of the anchor as read here>"
    }
  }
}
```

Three properties are load-bearing:

- **The score in the record is the tool's own arithmetic over the tool's own
  rows.** The directory recomputes it from the merged evidence and never
  displays this copy as the listing's grade. It exists so the record is a
  complete, self-describing, independently checkable `ScanRecord`.
- **`scanner.workflow_run_id` is `0` and `workflow_run_url` is empty.** A
  workstation has no workflow run. The fields exist because the shape requires
  them; the lane is established by the verified sidecar the directory writes,
  never by a URL a submitter chose.
- **`allowed_signers.sha256` authorizes nothing.** It is a drift signal. A
  verifier uses the anchor it fetches from the repository, never a digest the
  record supplies about itself.

## The namespace, and why your anchor has to say so

SSHSIG signatures are namespaced so a signature minted for one protocol cannot
be replayed as another. Git signs commits in the `git` namespace; local scan
records are signed in `sscsb-scan-record`.

`sscsb init` therefore generates anchor lines that grant both — **to a
`class = "human"` signer**:

```
you@example.com namespaces="git,sscsb-scan-record" ssh-ed25519 AAAA… comment
```

A repository anchored before this lane existed carries `namespaces="git"` only,
and `sscsb scan --local` refuses rather than producing a record that will not
verify. The fix is one regeneration and one commit:

```sh
sscsb init
git add .sscsb/policy/allowed_signers
git commit -m 'policy: permit the sscsb-scan-record namespace'
```

The grant is a **positive statement** the repository makes. Dropping
`namespaces=` entirely would work too, and would silently permit every
namespace OpenSSH ever defines — which is not what your repository means to
say.

### Only a human-class approved signer may assert a local record

`ci`- and `ai`-class signers keep `namespaces="git"` and nothing else. Only
`class = "human"` entries in `.sscsb/policy/signers.toml` are granted
`sscsb-scan-record`.

Three reasons, and none of them is tidiness:

1. **A local record is a person's attested word.** It is the one lane whose
   local-environment verdicts count with no independent corroboration,
   precisely because nobody else can observe the machine. The thing that makes
   that acceptable is that a named human put their key behind it. An unattended
   process signing it removes the only property the lane rests on.
2. **CI does not need it.** A repository's own CI has the action lane, which
   proves strictly more: GitHub's OIDC issuer burns the repository, the workflow
   path and the branch into the certificate. Granting CI the weaker lane as
   well buys nothing and adds a second, softer way to assert the same claims.
3. **An `ai` signer must never sign.** `.sscsb/policy/signers.toml` states that
   invariant in its own header, and `sscsb` enforces it on `class`. A grant that
   let an agent key mint a record the directory accepts would contradict it in
   the one file the whole model hangs on.

The refusal is **structural, not advisory**. Because the namespace is simply
absent from the line, `ssh-keygen -Y verify -n sscsb-scan-record` fails against
the committed anchor — so `sscsb scan --local` refuses locally *and* the
directory's ingest refuses independently, without either one having to
re-implement the rule.

## Submitting

```sh
sscsb scan --local                     # scan, sign, write both files
git add .sscsb/scan-record.local.json .sscsb/scan-record.local.json.sig
git commit -m 'chore: publish a signed local scan record'
git push
sscsb scan --local --submit --dry-run  # see the submission first
sscsb scan --local --submit            # file it
```

`--submit` files a pointer — the repository URL — to the directory's queue with
the `gh` CLI, under the `local-scan-result` label. Nothing in the body is
trusted: the directory re-reads the record, the signature and the anchor from
your public repository, and a signature that does not verify is refused.

Because the submission is a pointer, **the files must already be pushed**. The
command says so, and prints the body it filed.

## Exit codes

`scan --local` keeps `verify`'s contract. Producing a record does not launder a
failing posture into a success code:

- `0` — every control passed (or only DEGRADED rows exist and `--strict` was
  not given)
- `1` — at least one control FAILed, or `--strict` and at least one DEGRADED
- `2` — an operational error, including every guard rail above

A failing record is still produced and still submittable. The directory records
fails; hiding them is the opposite of the point.

## Why `scan --local` and not `verify --local`

`sscsb scan` without `--local` is the vulnerability scan (Trivy and
OSV-Scanner, with `--vex` and `--grype`), and `--local` is a different mode of
it rather than an extra option on it: `--local` is rejected together with
`--vex` or `--grype` rather than quietly ignoring them.

The deciding argument is not taxonomy, it is that **one string has to be
right**. The directory prints a command on every provisional listing, the issue
form repeats it, and the peer-pressure nudge sends it to maintainers who have
never used this tool. A command that is one word different from the one that
exists is worse than an imperfect verb, and there is exactly one place — the
contract block above — where that string is written down.

## See also

- [signing.md](signing.md) — the five-environment signing model, and how to get
  a signing key configured in the first place
- [phase-1.md](phase-1.md) — the commit-integrity controls, several of which
  are class C
- [phase-2.md](phase-2.md) — package trust and the local scanner controls
