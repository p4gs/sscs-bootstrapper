# Phase 5 — Continuous posture

The first four phases are events: a commit is checked, a build is signed, a PR is
scanned. Phase 5 is the standing state — *what is true about this project right
now*, and *can I show someone*.

| Control | What it does | Backing tool | Default |
|---------|--------------|--------------|---------|
| `openvex` | Exploitability-aware triage: "not affected", auditably | (native) + vexctl | on |
| `security-insights` | Machine-readable `security-insights.yml` (OpenSSF Security Insights) declaring security practices + reporting channels | (native) | on |
| `best-practices-badge` | Worksheet pre-filling the OpenSSF Best Practices passing criteria from installed controls | (native) | on |
| `osps-baseline` | Maps enabled controls to OpenSSF Project Security Baseline families; adds an OSPS column to `sscsb report` | (native) | on |
| `compliance-map` | Control → SLSA / SSDF / CRA / OSPS / Badge map behind `sscsb report` | (native) | on |
| `dependency-track` | Continuous SBOM management platform | Dependency-Track | off |
| `guac` | Supply-chain knowledge graph | GUAC | off |
| `oras` | Push SBOMs/attestations to an OCI registry | ORAS | off |
| `sscsb-scorecard` | Score the repo in its own CI, keyless-sign the result, publish for the SSCSB Directory | (native) + cosign | off |

## OpenVEX — the one that saves your sanity

A scanner finds a critical CVE in a library you ship. You investigate. The
vulnerable function is never called; the code path does not exist in your build.
You are, in fact, not affected.

Now what? The industry's usual answer is to add the CVE to an ignore list, where the
*reason* is lost, the ignore never expires, and six months later nobody remembers
whether it was analysed or just muted. Ignore lists are where security knowledge
goes to die.

**VEX** — Vulnerability Exploitability eXchange — makes "not affected" a real,
structured, signed-off answer, with a justification the standard defines:

```sh
sscsb vex create \
  --vuln CVE-2024-12345 \
  --product 'pkg:cargo/some-lib@1.2.3' \
  --status not_affected \
  --justification vulnerable_code_not_present

sscsb scan --vex .sscsb/out/vex/CVE-2024-12345.json
```

`status = not_affected` **requires** a justification — the OpenVEX spec says so, and
`sscsb` enforces it rather than accepting a bare assertion. The valid statuses are
`not_affected`, `affected`, `fixed`, and `under_investigation`; anything else is an
error, not a shrug.

When a VEX document suppresses a finding, `sscsb scan` **says that it did**. The
finding does not vanish; it is reported as suppressed, with the document that
suppressed it. A suppression you cannot see is an ignore list wearing a better
schema.

## `sscsb report` — the compliance map

```sh
sscsb report                # human-readable
sscsb report --format json  # machine-readable
```

Every control is mapped to the frameworks it contributes to — **SLSA v1.2**, **NIST
SSDF v1.2**, the **EU Cyber Resilience Act**, and the OpenSSF Best Practices Badge —
and the report merges that static map with your *live* configuration, so it tells
you what you have actually enabled, not what the tool could theoretically do.

The map is a checked-in JSON file, and a test asserts that every control in the
registry appears in it, mapped to at least one framework, with no orphaned entries
pointing at controls that no longer exist. The map cannot rot away from the code,
because the build fails if it does.

This is the artifact you hand to someone who asks "what do you do about supply chain
security?" — with the honest caveat that it describes *controls*, not an audit.
`DEGRADED` controls appear as degraded. A tool you have not installed does not
quietly become a compliance checkmark.

## Dependency-Track (optional)

```sh
sscsb enable dependency-track
export DTRACK_API_KEY=…            # environment only — never the config file
sscsb sbom && sscsb dtrack upload
```

An SBOM is a photograph. **Dependency-Track** is the film: upload each build's BOM
and it tracks your components over time, re-evaluating every one of them against new
advisories as they land. The CVE published tomorrow against a library you shipped
last month finds *you*, instead of waiting for someone to re-run a scan.

The API key is read **from the environment only** — never from `.sscsb/config.toml`,
never from a file in the repository, and never as a URL query parameter (tokens in
URLs leak into access logs, proxy logs, and browser history). It travels in an
`X-Api-Key` header, and nowhere else. The HTTP contract — `PUT /api/v1/bom`, header
auth, base64 BOM, `autoCreate` — is verified in the test suite against a stub server,
so the request shape cannot drift without a test failing.

Dependency-Track is off by default because it is a service you have to run.
`sscsb init` ships a Docker Compose file to make that a five-minute job.

## GUAC (optional)

```sh
sscsb enable guac
sscsb guac ingest              # ingests .sscsb/out — SBOMs, attestations, VEX
```

**GUAC** turns your artifacts into a **graph** and answers the questions a flat SBOM
cannot:

> *A CVE just dropped in a transitive dependency four levels down. Which of my
> released artifacts contain it, which builds produced them, and were those builds
> signed?*

That is a graph traversal, not a text search. GUAC ingests SBOMs, attestations, and
VEX documents from `.sscsb/out/` — which is precisely why phases 2, 3, and 5 all
write their artifacts to the same place. Off by default: it is another service.

## ORAS (optional)

```sh
sscsb enable oras
sscsb oras push ghcr.io/owner/repo:sbom .sscsb/out/sbom.cdx.json
```

**ORAS** stores the SBOM and attestations *next to the image they describe*, in the
OCI registry, as referrer artifacts. The provenance travels with the artifact
instead of living in a CI run's expiring storage. Anyone who can pull the image can
pull its SBOM.

## SSCSB Scorecard (optional)

```sh
sscsb score emit                 # the whole posture as one JSON document
sscsb enable sscsb-scorecard     # + sscsb init: install the publish workflow
```

`sscsb score emit` runs every control and folds the outcomes into a single
result document: per-control verdicts, an aggregate 0–10 score over the
*determinate* outcomes only, and a completeness tier. DEGRADED controls —
tool missing, no credentials, no GitHub repo configured — are excluded from
the score and counted against completeness instead, so a scan that could not
read something is labeled `partial` rather than quietly scored as if it had.
A repo scanned from the outside (the SSCSB Directory's queue does this) is
almost always `partial`; the same repo scored by its own CI — where
`GITHUB_TOKEN` can read settings nobody else can — earns `complete`. That
gap is the honest pitch for installing the publish workflow.

The `sscsb-scorecard` control installs `.github/workflows/sscsb-scorecard.yml`:
score in CI, keyless-sign the result (cosign, GitHub OIDC), publish it as a
workflow artifact. `sscsb score verify` is the consuming side — it pins the
signature to that exact repository's canonical workflow on its live default
branch before believing a word of the document. The full architecture,
including what the Directory checks before listing a result, is in
[sscsb-scorecard.md](sscsb-scorecard.md).

Off by default for a different reason than the infrastructure controls:
publishing a scorecard is a *disclosure* decision — the signed result names
every failing control in public — and sscsb does not make that choice for a
repository owner.

## What "off by default" means here

Phase 5's infrastructure controls — Dependency-Track, GUAC, ORAS — are off.
That is a deliberate reading of who this is for: a solo developer does not
need a knowledge graph, and shipping one that sits unconfigured and
permanently `DEGRADED` would be noise pretending to be posture.

The two that are **on** — OpenVEX and the compliance map — need no infrastructure at
all, and are the two that make the other four phases legible: *here is what is
covered, here is what we decided about the thing that was flagged, and here is why*.
