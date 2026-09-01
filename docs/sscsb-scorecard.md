# The SSCSB Scorecard

`sscsb verify` tells *you* whether your repo is healthy. The SSCSB Scorecard
tells *everyone else* — as one signed, verifiable JSON document that a site
can list, a badge can summarize, and a stranger comparing two dependencies
can actually trust.

The architecture is OpenSSF Scorecard's, deliberately. Their problem is our
problem: the checks that matter most (branch protection, Actions token
permissions, security-feature enablement) are **repository settings**, and
settings are readable only with repository credentials. No outside scanner
can see them. The only place a complete scan can run is the repository's own
CI — which immediately raises the question the rest of this document
answers: *when a repo hands you its own report card, why believe it?*

## The three components

| Component | OpenSSF analog | Where |
|-----------|----------------|-------|
| `sscsb score` (this repo) | `scorecard` CLI | emits and verifies the result document |
| SSCSB Scorecard Action + `sscsb-scorecard.yml` | `scorecard-action` | runs the complete scan in the repo's own CI, signs, publishes |
| SSCSB Directory | `scorecard-webapp` / api.scorecard.dev | queues outside scans, verifies published results, serves listings + badges |

## The result document

```sh
sscsb score emit            # → .sscsb/out/score/sscsb-scorecard.json
sscsb score emit --stdout   # → stdout
```

One run of every registered control, folded into:

- **`controls`** — every control's id, phase, outcome, and messages.
- **`score`** — 0–10 over the *determinate* outcomes (PASS/FAIL) only.
- **`completeness`** — the count of controls that could not be evaluated
  (DEGRADED), and the tier that falls out of it: `complete` or `partial`.
- **`config`** — `repo` when `.sscsb/config.toml` was present, or
  `registry-defaults` when the repo never ran `sscsb init` and was scored
  against the defaults `init` would have written.

Two doctrinal choices, both inherited from `sscsb verify`:

1. **Unknown is not failure.** A control whose check *did not happen* — tool
   missing, no credentials, no GitHub remote — is excluded from the score and
   charged to completeness instead. Averaging absences into the number would
   let an unreadable repo score differently from a read one on evidence
   nobody has.
2. **The score never hides the tier.** A `partial` 9.8 and a `complete` 9.8
   are different claims, and the document keeps them apart. OpenSSF Scorecard
   encodes the same idea as a score ceiling for non-admin scans; we encode it
   as an explicit label because a label survives aggregation.

## The two tiers, and why they are the funnel

**Partial (outside-in).** Anyone — the SSCSB Directory's queue, a curious
human — can clone a public repo and run `sscsb score emit` in it. Everything
observable from the working tree and public API surfaces gets a real verdict:
hooks, workflow pinning and permissions, checked-in policy, SECURITY.md,
rulesets on public repos. Settings-gated checks degrade honestly. The result
is labeled `partial`.

**Complete (inside-out).** The same command, run by the repo's own CI, where
`GITHUB_TOKEN` reads what outsiders cannot. Every enabled control gets
evaluated; the result earns `complete` — and is worth signing.

The Directory shows the partial result to every visitor **with the gap
spelled out**: "N controls could not be evaluated without repository
credentials — install the publish workflow for a complete scorecard," next
to a one-click *Create PR* (GitHub's prefilled-file-editor URL, which
auto-forks for non-maintainers) and *Create Issue*. The partial listing is
the invitation; the complete, signed listing is the product.

## The publish pipeline

`sscsb enable sscsb-scorecard` + `sscsb init` installs
`.github/workflows/sscsb-scorecard.yml` (the same file the Directory's
one-click PR proposes):

1. **Install sscsb, verified.** The release tarball is checked against its
   `.sha256` and its Sigstore bundle, pinned to this repo's own
   `release.yml@refs/tags/<version>` signing identity — the scanner proves
   its own provenance before it is allowed to assess anyone else's.
2. **Score.** `sscsb score emit` with the workflow's `GITHUB_TOKEN` in the
   environment: the complete tier.
3. **Sign.** `--sign` runs `cosign sign-blob` keylessly. The job has
   `id-token: write`, so Fulcio issues a short-lived certificate whose
   identity *is* this workflow: repository, workflow path, and branch ref
   are burned into the certificate by GitHub's OIDC issuer — not asserted
   by the document.
4. **Publish.** Result + bundle upload as the `sscsb-scorecard` artifact,
   where the Directory's collector fetches them.

## Verification — why a self-reported scorecard is believable

```sh
sscsb score verify sscsb-scorecard.json --repo owner/name
```

Fail-closed, in order:

1. The document parses, is a scorecard result, and has a known schema major.
2. It claims the repository the caller expects — a result is only evidence
   about the repo whose workflow signed it.
3. A Sigstore bundle exists beside it. **Unsigned is a FAIL, not a shrug**:
   an unsigned result is a claim, and the Directory lists only evidence.
4. cosign verifies the bundle against the pinned identity:
   `https://github.com/<owner>/<repo>/.github/workflows/sscsb-scorecard.yml@refs/heads/<default branch>`,
   issued by `https://token.actions.githubusercontent.com`. The default
   branch is fetched **live from GitHub**, never read from the document — a
   document that named its own trusted branch would let a signature minted
   on any branch nominate itself.

What this proves: the result was produced and signed by *that repository's
canonical publish workflow on its default branch*. A third party cannot
forge it (they cannot obtain that OIDC identity), and a maintainer cannot
launder a feature-branch or renamed-workflow signature into the canonical
identity.

What it deliberately does not yet prove: a repository owner who **edits the
canonical workflow itself** can make it sign whatever it emits. OpenSSF
Scorecard closes this by fetching the producing workflow at the
certificate's commit SHA and rule-checking it (allowlisted steps only, no
env redirection, `id-token` confined to the scanner job, hosted runners
only). That check belongs in the Directory's ingestion — it needs the
certificate's commit claims and a GitHub fetch, not a local file — and is
the Directory's hardening milestone. Until then the trust level equals
`gh attestation verify --signer-workflow`: the same bar this repo's own
`release-attest.yml` sets for its artifacts, stated here so nobody mistakes
it for more.

## The SSCSB Directory

The Directory is OpenSSF's `scorecard-webapp` translated to GitHub-native
infrastructure — no standing servers:

- **Submission queue**: an issue form ("scan this repo"). A workflow
  validates the target (public GitHub repo, deduplicated, rate-limited),
  clones it, runs the partial scan with no credentials, commits the result
  to the site's data, and answers the issue with the listing link.
- **Verified ingestion**: a scheduled collector walks the repos that
  publish, downloads each `sscsb-scorecard` artifact, and runs
  `sscsb score verify` — the exact command above, same binary, same
  fail-closed rules — before a result may replace the partial listing.
  Complete-and-verified beats partial wherever both exist, mirroring
  Scorecard's publisher-results-over-cron precedence.
- **Serving**: static pages per repo (score, tier, per-control detail, the
  install funnel), a search index, and a per-repo
  [shields.io endpoint-JSON](https://shields.io/badges/endpoint-badge)
  badge.

One asymmetry with OpenSSF worth stating: their API accepts pushed results;
the Directory *pulls* artifacts. Pull costs nothing to operate and — because
trust comes from the signature, not the transport — verifies identically.
Repos never hold Directory credentials, and the Directory holds nobody's.

## Privacy and disclosure

The `sscsb-scorecard` control is **off by default**. Publishing a scorecard
is a disclosure decision: the signed result names every failing control in
public, and keyless signing writes an entry to Rekor's public transparency
log. sscsb does not make that choice for a repository owner; it makes the
choice one `enable` away and the consequences legible.
