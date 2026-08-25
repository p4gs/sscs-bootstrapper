---
type: Architecture Guide
title: What sscsb writes to your repository
description: The per-path on-disk contract — which files are kept, which are regenerated every run, and which are extended.
tags: [init, bootstrap, gitignore, hooks, artifacts]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# What sscsb writes to your repository

`sscsb init` is safe to re-run. That claim needs a precise form, because the honest
version is not "nothing is overwritten" — it is **nothing you are meant to edit is
overwritten**. Three classes of file, three different rules.

## Class 1 — kept if present

Everything you are expected to edit. If the file exists, `init` leaves it alone and
logs that it kept it.

| Path | Content when created |
|---|---|
| `.sscsb/config.toml` | Generated from the control registry |
| `.sscsb/policy/signers.toml` | Signer policy template |
| `.sscsb/policy/packages.toml` | Approved-package baseline template |
| `.sscsb/policy/signing-model.toml` | Signing-environment attestation template |
| every registered artifact | The rendered template |

Artifacts log `keep <dest> (exists — delete to regenerate)`. That message is the
whole upgrade story: to pick up a newer template, delete the file and re-run. There
is no `--force`, and `sscsb init` takes no flags at all.

The measurable form of this contract is that a second `init` writes **strictly
fewer** files than the first. Not zero — class 2 exists — and the source says so
explicitly, because "zero" would be a false claim.

## Class 2 — regenerated every run

Exactly four files, and edits to them are discarded by design:

- `.sscsb/hooks/pre-commit`
- `.sscsb/hooks/commit-msg`
- `.sscsb/hooks/pre-push`
- `.sscsb/policy/allowed_signers`

The three hook shims are pure delegation. Each carries a `DO NOT EDIT — regenerate
with sscsb init` banner, hands off to `sscsb hook <event>`, and — this is the part
that matters — **exits 1 with an explanatory message if the binary cannot be
found**. A broken install blocks commits instead of silently skipping the gate.
Policy lives in Rust; the shell is only a doorway. See
[git hooks](../commit-integrity/git-hooks.md).

`allowed_signers` is regenerated because it is *derived*: it is a projection of
`signers.toml` through the `agent-signing` control's setting. Editing it directly is
meaningless, and it is rewritten again on every protected-branch push.
[Signer policy](../commit-integrity/signer-policy.md) covers why.

## Class 3 — extended, never rewritten

`.gitignore`, and only `.gitignore`.

`.sscsb/` holds two different kinds of thing: **policy**, which belongs in history,
and **generated output** under `.sscsb/out/`, which does not. Nothing enforced that
boundary, so a `git add .` after `sscsb sbom` committed a regenerated SBOM into the
same tree as signed policy, burying real policy diffs in review noise.

The fix is unusual and worth understanding, because it does not parse `.gitignore`
at all. **git decides.** `init` runs a `check-ignore` probe and reacts to the status:
already ignored, do nothing; not ignored, append; anything else, refuse and error
out rather than guess.

Two details in that probe are deliberate:

- **The probe path is a neutral placeholder, not a real artifact name.** If it
  probed `sbom.cdx.json`, a narrow pre-existing rule like `.sscsb/out/*.json` would
  answer "already covered" — and receipts and VEX documents would stay exposed.
- **Appending never glues onto an unterminated final line.** Without that, a
  `.gitignore` whose last line lacks a newline would become
  `target/# sscsb: generated output…`, silently destroying the user's own rule.

One limit, stated plainly because it surprises people: **adding an ignore rule
cannot untrack anything.** A repository that has already committed files under
`.sscsb/out/` keeps tracking them. You have to `git rm --cached` those yourself.

## Repository state that is not a file

`init` also rewrites two git config values every run:

- `core.hooksPath` → `.sscsb/hooks`
- `gpg.ssh.allowedSignersFile` → the **absolute** path of `.sscsb/policy/allowed_signers`

Absolute is deliberate: git resolves relative paths from the current working
directory, which is not reliable inside a hook.

## Rendering happens once

Templates substitute the repository slug, the default branch and the project name at
**write time**. The slug resolves from config, then the origin remote, then the
literal `OWNER/REPO`.

Combine that with class 1 and you get a sharp edge: **a repository bootstrapped
before it had a remote bakes the literal `OWNER/REPO` into its workflows
permanently.** Re-running `init` will not re-render a file it is keeping. There is no
repair path in the source; deleting the file and re-running is the only route.

## What a fresh bootstrap produces

On a repository with default configuration: the config file, three hook shims, three
policy TOMLs, `allowed_signers`, and the subset of registered artifacts whose owning
control is on by default. Artifacts belonging to default-off controls are skipped
with a log line naming the control.

That skipping is a small piece of judgement worth noticing. The fuzzing scaffold
gates its `.trivyignore` too, on the stated grounds of never dropping a waiver on a
repository that has nothing to waive.

Not everything lands under `.sscsb/` and `.github/` — `renovate.json5`,
`security-insights.yml`, `.gitleaks.toml`, `.trufflehog.yaml`, `.trivyignore` and
the ClusterFuzzLite scaffold all sit at the repository root. See
[CI templates](../bootstrap/ci-templates.md).

## Generated output

Everything written by a command rather than by `init` lands under `.sscsb/out/`,
which is the ignored half:

- `.sscsb/out/sbom.cdx.json` or `sbom.spdx.json` — see [SBOM generation](../dependencies/sbom-generation.md)
- `.sscsb/out/receipts/receipt-<sha>.json`, optionally with a signature bundle beside it — see [AI receipts](../provenance/ai-receipts.md)
- `.sscsb/out/<vuln>.vex.json` — see [OpenVEX](../dependencies/openvex.md)

## How this contract is defended

The strongest guard appends a marker to **every** file sscsb writes, re-runs `init`,
collects the files that lost their marker, and asserts that set equals the documented
"rewritten every run" list **exactly, in both directions**. A file that starts being
regenerated fails the build, and so does one that stops. It also asserts the set is
non-empty, so the guard cannot quietly go vacuous.

A companion asks *git* — not the file text — whether generated output is ignored and
policy is not.

## Source map

| Concern | Location |
|---|---|
| The three-class contract | `src/init.rs` module doc |
| Keep-if-present | `src/init.rs`; `src/workflows.rs`, `write_if_absent` |
| Hook shim generation | `src/hooks.rs`, `install_hooks`, `shim_script` |
| `.gitignore` extension | `src/init.rs`, `ensure_out_ignored` |
| Artifact registry and rendering | `src/workflows.rs`, `ARTIFACTS`, `render` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib init:: && \
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --test agents_md
```
