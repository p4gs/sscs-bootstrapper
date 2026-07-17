# AI provenance

Git already answers *who committed this*. In an AI-heavy workflow that is no longer
the interesting question. The interesting questions are:

- Was this written by a model, and which one?
- Was the human *driving*, or *reviewing*, or neither?
- Did an AI add that dependency? Did anyone look at it?

`sscsb` answers all three, at the commit boundary, with a mechanism you can grep.

## Commit trailers

```
feat(scan): parse Trivy misconfiguration findings

AI-Assisted: true
AI-Tool: Claude Code
AI-Model: Fable 5
AI-Role: draft
```

If `AI-Assisted: true` is present, the `commit-msg` hook requires **all** of
`AI-Tool`, `AI-Model`, and `AI-Role`, and the role must be one of:

| Role | Means |
|------|-------|
| `draft` | The AI wrote it; a human reviewed and owns it. |
| `review` | A human wrote it; the AI reviewed. |
| `test` | The AI wrote the tests. |
| `refactor` | The AI restructured existing, working code. |

Four roles, not an open string, because "AI-Role: helped" is not information. The
distinction that matters at review time is *who produced the logic and who checked
it* — a `draft` commit deserves a different kind of attention than a `refactor` of
code that already had tests.

Trailers are cheap, honest metadata. They are also the input to the gates below,
which is where they stop being merely descriptive.

## The two gates

An AI-assisted commit is held to a higher standard in exactly two places — the two
places where a wrong suggestion becomes code execution.

### Dependencies

If an AI-assisted commit touches a dependency manifest (`Cargo.toml`,
`package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, `Gemfile`, …), it
must carry:

```
AI-Dependency-Review: approved
```

**and** every package it newly introduces must already be in the approved baseline
(`sscsb deps approve npm:some-package`). Both. The trailer says a human looked; the
baseline records what they approved. A trailer alone would be a checkbox, and the
package-trust checks from [phase 2](phase-2.md) — does this package exist, is it one
edit away from a popular name — run against the new packages regardless.

The failure mode this exists for: a model suggests `pip install reqeusts`, that name
is registered by someone who was waiting for exactly this, and the install script
runs as you. The gate makes a human name the package out loud before it lands.

### Shell commands

If an AI-assisted commit adds a shell script, it must carry:

```
AI-Command-Review: approved
```

Shell is the sharpest edge in the repository — it is the code that runs *before* your
tests, on your machine, with your credentials. `curl … | sh` is a normal-looking
suggestion and a full compromise. The SAST ruleset in [phase 4](phase-4.md) flags
that specific shape at `ERROR` severity and blocks the commit outright; this gate
covers everything else shell can do.

## What an AI may never do

Two hard stops, from [signing.md](signing.md):

- **An AI may not sign.** An `ai`-class key is never emitted into
  `allowed_signers`, so an AI's signature cannot be verification-valid — no matter
  how the policy file is edited.
- **An AI may not land on a protected branch.** Pre-push requires every commit on a
  protected branch to be signed by a `human`-class key.

An AI can therefore write anything and land nothing. That is the intended shape of
the collaboration: the agent drafts at full speed on a feature branch, and a human's
hardware key is the thing that says "this ships."

## Receipts (optional)

Trailers are assertions in a commit message. Anyone can write one. If you need the
attribution to be **cryptographic** rather than merely stated:

```sh
sscsb enable ai-receipts
sscsb receipt create HEAD           # → .sscsb/out/receipts/<sha>.json
sscsb receipt create HEAD --sign    # + cosign keyless signature (needs OIDC)
sscsb receipt verify .sscsb/out/receipts/<sha>.json
```

A receipt is an **in-toto statement** binding:

- the commit SHA,
- the **sha256 of the patch itself**,
- the AI tool, model, and role from the trailers,
- the author and timestamp.

`sscsb receipt verify` recomputes the patch digest from the repository and compares.
If the commit was amended, rebased, or otherwise altered after the receipt was
issued, the digest no longer matches and verification **fails loudly** with
`DIGEST MISMATCH`. The receipt attests to a specific patch, not to a commit message
that claims things about a patch.

Signed with `--sign`, the receipt carries a Sigstore keyless signature bound to your
OIDC identity — the same trust model as [phase 3](phase-3.md), no key to steal.

Off by default: for most teams the trailers plus the gates are the useful 90%, and
receipts are the answer when someone downstream needs to *verify* AI attribution
rather than *read* it — a regulator, an auditor, or a future maintainer trying to
work out which parts of a codebase were generated.

## Reading it back

```sh
git log --grep='AI-Assisted: true' --oneline           # everything AI touched
git log --grep='AI-Role: draft' --format='%h %s %an'   # what the AI drafted
```

Which is the real payoff. When something breaks in six months, "was this written by a
model, and did anyone actually review it?" is answerable in one command instead of
being a matter of recollection.
