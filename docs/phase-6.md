# Phase 6 — Distribution & publishing

Phases 1 to 5 stop at the registry door. They harden the repository, the
dependencies it consumes, the CI that builds it, and the artifacts a GitHub
Release carries. None of them covers the moment the artifact leaves for
crates.io, npm, PyPI, Homebrew, Chocolatey or WinGet — and none of them covers
the credential that lets it.

That gap has a name and a body count. Phish a maintainer, steal a long-lived
publish token, push malware under a name a million projects already trust. The
Shai-Hulud npm worm, the chalk/debug compromise, the `ua-parser-js` and
`event-stream` takeovers: no commit was involved in any of them, so every
control in phases 1 to 5 was looking the other way.

| Control | What it does | Class | Default |
|---------|--------------|-------|---------|
| `publish-targets` | Detects which registries this repository publishes to, and names the manifest that proved it | A | on |
| `trusted-publishing` | Publish workflows authenticate by OIDC with a gated `release` environment, never a stored registry token | A′ | on |
| `maintainer-mfa` | The publishing account's second factor — GitHub 2FA, npm `tfa.mode`, and a dated phishing-resistance claim | C | on |
| `publish-tokens` | No committed credential files, no long-lived registry secrets where OIDC exists, declared tokens scoped and unexpired | A′ | on |
| `publish-provenance` | Probes the live registry for provenance on what was **actually published** | B | on |
| `dist-manifests` | Formula `sha256`, Chocolatey `checksum` + `checksumType`, WinGet `InstallerSha256`, Authenticode claim | A | on |

All six are on by default and every one of them goes quiet on its own when its
target is not there. A repository with no `package.json` is not a repository
failing its npm posture, and saying so would be exactly the false positive this
tool exists to avoid. That is why phase 6 adds no off-by-default control: the
gate is detection, not configuration.

## What "publish target" means, and how it is found

`deps::Ecosystem` is what this repository **consumes**. `PublishTarget` is what
it **ships**. A Rust project that vendors npm dependencies consumes npm and
publishes to crates.io, and conflating the two would point every control here
at the wrong registry.

Detection is file-based and offline:

| Target | Trigger |
|--------|---------|
| crates.io | `Cargo.toml` with a `[package]` section — a pure `[workspace]` manifest publishes nothing |
| npm | `package.json` without `"private": true` (bun publishes to the same registry) |
| PyPI | `pyproject.toml` with a `[project]` table — a `[build-system]`-only file configures tooling and ships nothing |
| Homebrew | `Formula/*.rb`, `Casks/*.rb`, or a repository directory named `homebrew-*` |
| Chocolatey | a `*.nuspec` |
| WinGet | a `*.installer.yaml` manifest |

The scan reaches the repository root and **two directory levels** below it,
which is what `packages/<name>/package.json` and `crates/<name>/Cargo.toml`
actually need — the container directory holds no manifest of its own, so
stopping at one level reads the conventional monorepo as publishing nothing.
`node_modules/`, `target/`, `dist/`, `vendor/` and friends are never searched:
a dependency's manifest says nothing about what you publish, and without that
exclusion a single `npm install` would make every repository on earth look like
an npm publisher.

Anything detection gets wrong, you correct in `.sscsb/policy/distribution.toml`:

```toml
[targets]
homebrew = "on"    # the tap's formulae live in another repository
npm      = "off"   # that package.json is an example, not a product
```

## Trusted Publishing — delete the credential

The strongest available move is not to rotate the publish token. It is to not
have one.

Trusted Publishing is GA on all three code registries that support it, and it
works the same way in each: the registry is configured to trust *this
repository's* *this workflow's* GitHub OIDC identity, and the workflow proves
who it is at publish time instead of presenting a secret. There is then nothing
in the repository for a phished maintainer, a compromised action, or a
malicious transitive dependency to exfiltrate.

`sscsb init` installs the publish workflow for each **detected** target:

| Target | Template | Mechanism |
|--------|----------|-----------|
| crates.io | `.github/workflows/publish-crates.yml` | `rust-lang/crates-io-auth-action` exchanges OIDC for a 30-minute scoped token |
| npm | `.github/workflows/publish-npm.yml` | `npm publish --provenance --access public`, no `NODE_AUTH_TOKEN` |
| PyPI | `.github/workflows/publish-pypi.yml` | `pypa/gh-action-pypi-publish` with `attestations: true` |

These live in their own `DIST_ARTIFACTS` table with a detection-gated
installer, deliberately **not** in the control-gated table the other templates
use. That table installs an artifact whenever its control is enabled, and
`trusted-publishing` is on by default — so registering `publish-npm.yml` there
would drop it into every repository sscsb ever touched. A publish workflow you
do not publish with is not a harmless extra file; it is a `workflow_dispatch`
button wired to somebody else's namespace.

Each template needs a one-time setup on the registry, which the workflow cannot
do for you, and each **fails closed** until you do it. Do not add a token to
make the error go away — that is the state this phase exists to end.

### The environment is half the control

An OIDC identity is only as strong as the gate in front of it. Without a
protected environment, anyone who can dispatch the workflow can publish, and
the fact that no token was involved buys you nothing. So `trusted-publishing`
also reads `repos/{slug}/environments/release` and checks for real protection
rules — required reviewers, a wait timer, a deployment-branch policy.

That read degrades rather than failing whenever it could not be performed: `gh`
absent, no remote, no auth. GitHub also answers **404 for both** "no such
environment" and "your token cannot see environments", and those are opposite
verdicts — so the ambiguous case degrades and says which two things it might
be. Telling a maintainer to create an environment that already exists is how a
tool teaches people to stop reading it.

## maintainer-mfa — the far-left link

Everything else in this phase assumes the attacker has to get past a workflow.
This control is about the case where they just log in.

Each target resolves to the identity that actually gates publishing, and sscsb
asks the API that can answer:

- **crates.io, Homebrew, WinGet** → a GitHub identity. `gh api user` →
  `two_factor_authentication`.
- **npm** → `npm profile get --json` → `tfa.mode`.
- **PyPI** → 2FA is mandatory for every uploader. That is a registry-enforced
  fact, reported as one, not a check that could fail.
- **Chocolatey** → the community repository offers no account 2FA at all.

Three deliberate calls in there:

**`auth-only` fails, it does not degrade.** npm's `tfa.mode` has two settings
that both look like "2FA is on". Only `auth-and-writes` requires a second
factor for the *publish itself*; `auth-only` gates the login and leaves the
publish open to a stolen session or token — which is the exact gap the worms
walked through. A control that called that "enabled" would be worse than no
control.

**A missing `two_factor_authentication` field degrades, it does not fail.**
GitHub omits the field entirely for a token without `read:user`, rather than
erroring. Reading that absence as `false` would accuse a maintainer who has a
passkey of having no second factor. The message says `gh auth refresh -s
read:user` and says, in as many words, that this is unverified rather than a
confirmed absence.

**The GitHub read is gated on a resolvable remote.** With no GitHub remote and
no `general.github_repo`, the account `gh` happens to be logged in as is a
*guess* — it is whoever owns the laptop, not whoever owns the package. Grading
a repository on that is precisely the false positive this project refuses to
ship, so it degrades with `no-remote` instead.

**Chocolatey's missing 2FA is `Info`, not a failure.** It is a real gap and it
is reported as one, but no maintainer can fix it, and a `--strict` run that is
permanently red for something nobody can act on is a run people learn to
ignore.

### The part no API will tell you

No registry exposes whether a second factor is *phishing-resistant* — whether
it is a passkey with no TOTP fallback, or a TOTP code that can be relayed
through a convincing login page. That is the distinction CISA and OpenSSF's
*Principles for Package Repository Security* put at its upper maturity levels,
and it is the one nobody can query.

So it is a dated claim:

```toml
[[account]]
target   = "npm"
identity = "your-npm-username"
mfa      = "webauthn-only"     # webauthn-only | webauthn | totp | none
attested = "2026-01-15"        # the day a human last confirmed it
```

A claim documents; it never upgrades an outcome. That is the ISC-A6 invariant
from `signers.rs`, and this module reuses that module's `evaluate_expiry` and
`evaluate_attestation` rather than keeping a second copy of the rule. A fresh
claim is reported. A claim older than `max_attestation_age_days` (180 by
default) **fails**, for the same reason an expired agent key fails: a stale
assertion about who can publish is exactly as actionable as a stale key, and
the only thing worse than not knowing is a year-old note saying you checked.

## publish-tokens — the credentials that are left

Three distinct findings, with three distinct severities.

**A committed credential file is a hard failure**, whether or not this
repository publishes anything. A `.npmrc` with `_authToken`, a `.pypirc` with a
password, a `.cargo/credentials.toml` — the token is live the moment the file
is pushed, and "we do not publish from here" has never stopped anyone reading
it. The remediation says revoke first: rewriting history does not un-leak a
secret that has already been fetched.

Only files **tracked at HEAD** count. An untracked `.npmrc` in a working tree
is the maintainer's own business.

**A long-lived secret on a path where OIDC exists is a failure.** If a workflow
publishes to crates.io, npm or PyPI using `secrets.CARGO_REGISTRY_TOKEN`,
`secrets.NPM_TOKEN` or `secrets.PYPI_API_TOKEN`, the credential is avoidable
entirely — and a `[[token]]` entry explaining why it is kept does not make a
removable credential necessary.

This check looks at **every** workflow in the repository, not only the template
sscsb installs. The interesting case is the `release.yml` that was already
there doing `npm publish` with a stored token; a check that graded only its own
output would call that repository clean.

It also keys on the literal `secrets.` prefix, because Trusted Publishing and
the anti-pattern use the *same environment variable name*. `CARGO_REGISTRY_TOKEN:
${{ steps.auth.outputs.token }}` is a 30-minute token that did not exist a
second ago; `CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}` is a
credential sitting in repository settings. Whole comment lines are stripped
first, so a template that *documents* the anti-pattern is not accused of
committing it.

**A credential with no OIDC alternative is reported, and then graded on its
expiry.** Chocolatey's push key is the honest case: there is no trusted-publishing
path, so a token is unavoidable. Declare it, and sscsb evaluates what it can:

```toml
[[token]]
target         = "chocolatey"
purpose        = "push key — Chocolatey has no OIDC path"
scoped         = true
cidr_allowlist = false
expires        = "2026-04-01"
stored_in      = "1Password / GitHub environment `release`"
```

`max_token_age_days` defaults to **90**, which is npm's own ceiling for a
granular write token — the rest of the ecosystem gets held to the strictest
published standard rather than to nothing.

## publish-provenance — measure the artifact, not the intent

Whether a trusted publisher is *configured* is not anonymously queryable on any
registry. Whether the artifact people actually downloaded carries provenance
is. So the probe asks about the published package:

| Target | Probe | Verdict |
|--------|-------|---------|
| npm | `registry.npmjs.org/-/npm/v1/attestations/<pkg>` | attestation bundles present → Pass |
| PyPI | `pypi.org/simple/<pkg>/` (PEP 691 JSON) | distributions carrying PEP 740 `provenance` → Pass |
| crates.io | — | `Info`: no artifact-level provenance exists in the ecosystem yet; Trusted Publishing is the strongest available claim |
| Homebrew | local | every `url` has a `sha256` → Pass |
| Chocolatey, WinGet | local | deferred to `dist-manifests` |

This measures the outcome rather than the intent, which is the right trade even
though it is an imperfect proxy: a package configured for trusted publishing
but last shipped by hand still has an unprovenanced tarball in front of
everyone who installs it.

Never-published is a **skip**, not a failure — an unshipped package is not a
failing one. A network error is `Degraded` naming the endpoint, never `Fail`:
an unreachable registry is not evidence of absent provenance, the same rule
`deps::registry_exists` already follows. Probes use the same bounded, anonymous
`ureq` shape with a 10-second ceiling, so a hung registry cannot hang
`sscsb verify`.

For an air-gapped lane:

```toml
[controls.publish-provenance]
probe_registry = false
```

which makes the control hermetic and reports that the claim was **narrowed**,
not that it passed. Declining a check must never read like clearing it.

## dist-manifests — the checksum is the whole boundary

For Homebrew, Chocolatey and WinGet the manifest digest is what the consumer's
machine actually verifies, and it is checkable entirely offline.

- **Homebrew** — every `url` needs a `sha256`. A formula with one and not the
  other installs whatever that URL serves at install time.
- **Chocolatey** — the `.nuspec` is metadata; the digest lives in
  `tools/chocolateyinstall.ps1`, which is the file that downloads anything. A
  script with `checksum` but no `checksumType` makes Chocolatey *guess* the
  algorithm, and a guess is not a verification. A nuspec with no install script
  beside it fails rather than passing vacuously.
- **WinGet** — `InstallerSha256`. microsoft/winget-pkgs requires it and the
  client checks it.

An unpinned download is the shape of the Polyfill.io hijack: a URL that served
a good file for years and then did not.

Authenticode is what Windows genuinely checks before it runs your installer,
and sscsb cannot verify a certificate chain off Windows. So it is recorded as a
claim with an evaluated expiry, and the message says plainly that no chain was
verified:

```toml
[signing]
authenticode = true
subject      = "CN=Your Org, O=Your Org, C=US"
expires      = "2027-06-30"
```

## `sscsb dist` — and why there is no `sscsb publish`

```sh
sscsb dist status          # targets, templates, declared claims
sscsb dist check [--strict]  # every phase-6 verifier, probes included
```

`dist check` is a break-glass preflight for the moment you are about to publish
by hand and want the phase-6 verdict without running everything else.

A `sscsb publish` wrapper was considered and **rejected**, for three reasons
worth writing down so nobody re-proposes it:

1. **It could not be enforced.** sscsb's gates are git hooks, and git hooks fire
   on git events. Nothing intercepts `npm publish`. A wrapper you have to
   remember to use is advisory theater — it protects the maintainer who was
   never the problem and does nothing about the one who typed the raw command.
2. **It points the wrong way.** The entire doctrine of this phase is to move
   publishing *into CI behind an OIDC identity*. A convenient local publish
   command makes the thing we are trying to eliminate easier.
3. **It is a support tarpit.** OTP prompts, workspace ordering, dist-tags,
   pre-release channels, per-registry auth quirks — reimplementing six
   registries' publish clients to add no security property is a large amount of
   surface for nothing.

## Known limits

- Detection reaches two directory levels. Deeper monorepos declare their
  targets under `[targets]`.
- npm's trusted-publisher *configuration* is not anonymously queryable; the
  published artifact's provenance is the observable proxy, and the control's
  messages say so.
- `gh api user` needs `read:user` for the MFA field. A token without it
  degrades with the exact `gh auth refresh` command, never a guess.
- Chocolatey's ecosystem-level absence of account 2FA cannot be fixed by a
  maintainer and is reported rather than failed.
- Authenticode is a declared claim off Windows. sscsb does not verify the
  chain and does not pretend to.
