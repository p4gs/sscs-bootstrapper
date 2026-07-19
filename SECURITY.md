# Security Policy

## Reporting a vulnerability

Please report vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/p4gs/sscs-bootstrapper/security/advisories/new)
— it keeps the report private while it is triaged and fixed, and it credits you
in the advisory when it is published.

Please do **not** open a public issue for a security report, and do not include
proof-of-concept secrets or live credentials in a report.

What to expect:

- **Acknowledgement** within 72 hours.
- **Triage verdict** (accepted / not a vulnerability / needs more info) within 7 days.
- **Fix or mitigation** for accepted reports targeted within 30 days, with a
  published GitHub Security Advisory and a patched release. Coordinated
  disclosure is the default; if a fix needs longer, you'll get a status update
  and a revised timeline rather than silence.

## Scope

`sscsb` is a local CLI and CI-template generator. Reports of particular
interest, roughly in order of blast radius:

- A way to make a **blocking control pass when it should fail** (fail-open):
  secret-scan bypass in the pre-commit/pre-push hooks, signing-policy bypass on
  protected branches, package-trust approval bypass.
- **Generated CI templates** that grant more privilege than documented, unpin a
  dependency, or expose secrets in logs.
- Parser crashes or hangs on attacker-supplied input (workflow YAML, policy
  TOML, dependency manifests, commit messages) — these are fuzzed continuously,
  but reports beat fuzzers regularly.
- Anything that makes `sscsb verify` report PASS for a control that is not
  actually enforcing.

## Supported versions

| Version | Supported |
|---------|-----------|
| latest release + `main` | ✔ |
| anything older | ✘ — upgrade first, then re-test |

## Verifying what you run

Release artifacts are signed and attested by three independent CI trails:
Cosign keyless bundles, SLSA Build L3 provenance, and GitHub artifact
attestations. Verify before you trust:

```sh
gh attestation verify <asset> --repo p4gs/sscs-bootstrapper
slsa-verifier verify-artifact <asset> --provenance-path <asset>.intoto.jsonl \
  --source-uri github.com/p4gs/sscs-bootstrapper
```
