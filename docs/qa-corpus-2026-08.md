# Cross-repository QA run — August 2026

`sscsb` had never been run against a repository other than its own. This is the
record of running it against twenty, what that surfaced, and what the fixes
measurably changed.

## The corpus

Twenty repositories from the `p4gs` and `grcengineering` organisations, cloned
locally and **never written back to**. Chosen to span the ecosystems `sscsb`
detects and both repository shapes — already-hardened and never-touched.

| Ecosystem | Repositories |
|---|---|
| Rust | `grcengineering/nthpartyfinder`, `grcengineering/OCEAN`, `p4gs/ADE-Bootstrapper` |
| TypeScript | `grcengineering/bootcamp`, `grcengineering/daily-findings` |
| Python | `p4gs/GrantGuard`, `p4gs/ghosttype`, `grcengineering/companion`, `grcengineering/conduit`, `p4gs/flask-webgoat` |
| Go | `grcengineering/security-grc-tools` |
| Ruby | `grcengineering/homebrew-grcengineering` |
| Shell | `grcengineering/how-to-harden`, `p4gs/linux-scripts` |
| JS / HTML | `grcengineering/cheatsheet`, `p4gs/twofactorauth`, `p4gs/how-to-rotate` |
| PHP | `p4gs/magento2-klaviyo` |
| Docs-only | `grcengineering/awesome-grcengineering`, `p4gs/autociso` |

Fifteen invocations per repository — `status`, `verify`, `verify --strict`,
`report`, `report --format json`, `deps check`, `sast`, `signers list`,
`signers check`, `signing status`, `harden` (dry-run), `tools`, and `init` with
`status`/`verify` either side of it — for **300 invocations** per pass.

## What it found

**No panics and no hangs**, in either pass. Empty repositories, docs-only
repositories, repositories with no remote, and a deliberately-vulnerable Flask
app all produced verdicts rather than crashes.

The verdicts themselves were a different story. The run fed directly into an
independent code review, and between them they produced four CRITICAL and eleven
HIGH findings. Two are worth recording here because the corpus is what exposed
them:

- **`init` installs a five-workflow release stack into repositories with nothing
  to release** — including `awesome-grcengineering`, whose entire tracked
  contents are a `README.md`. Seventeen of twenty repositories received
  `release-sign.yml`, `release-slsa.yml`, `release-attest.yml`,
  `release-attest-sbom.yml` and `deploy-gate.yml`. Still open; see
  `Plans/phase-6-distribution-publishing.md`, which names the rule this
  violates.
- **Path dependencies were resolved against the public registry by name.** On
  `grcengineering/OCEAN`, whose `grc-controls-*` crates are sibling-repo path
  dependencies, `deps check` reported them as *"NOT FOUND on its public registry
  — likely hallucinated (slopsquatting target)"* and exited 1. The inverse was
  worse: an in-repo path dependency whose name collides with an unrelated public
  crate was reported as *"exists on registry"*, a validation that never
  happened. Fixed.

## What the fixes changed, measured

The corpus was re-run against a binary built from `main` after the CRITICAL and
HIGH remediation, with every clone reset to pristine first so the two passes are
comparable.

| Verdict | Before | After | Δ |
|---|---:|---:|---:|
| PASS | 446 | 408 | **−38** |
| DEGRADED | 29 | 52 | +23 |
| INFO | 40 | 64 | +24 |
| FAIL | 47 | 47 | **0** |

Every one of the 38 verdict changes left `PASS`:

```
19x  openvex     PASS -> INFO        a control that could not fail, now honest
14x  scorecard   PASS -> DEGRADED    gh absent: could not check, said fine
 5x  scorecard   PASS -> INFO
```

**Zero new failures were introduced.** That is the number that matters most: a
remediation pass that removes false assurance is only useful if it does not
replace it with false alarm. Across twenty real repositories, nothing that
legitimately passed before started failing.

## What this does not claim

The run exercises the paths reachable on a developer machine with the tool set
installed here. Controls needing infrastructure that was not present —
Dependency-Track, GUAC, ORAS — were exercised only on their degrade paths, which
is a real contract but a narrower one.

Findings from the paired code review that were reported but did not survive
verification are recorded as rebuttals in the pull requests that fixed their
neighbours, rather than being quietly dropped. Two are worth knowing about: a
reported secret-scanning bypass used AWS's *published documentation* key pair,
which gitleaks allowlists and which therefore never discriminated between
working and neutered hooks; and a reported homoglyph package-name attack cannot
reach a build, because PyPI's name grammar is ASCII-only and pip fails to parse
such a requirement rather than installing it.
