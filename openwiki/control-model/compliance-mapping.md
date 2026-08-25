---
type: Architecture Guide
title: Compliance mapping and sscsb report
description: How controls map onto SLSA, SSDF, CRA and the OpenSSF frameworks, and precisely what the report does and does not assert.
tags: [compliance, report, slsa, ssdf, cra, openssf]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Compliance mapping and `sscsb report`

`sscsb report` answers "which framework requirements do my enabled controls touch?"
It is a mapping exercise, not an assessment, and the distinction is the most
important thing on this page.

## The map is embedded

`templates/compliance/map.json` is compiled into the binary. The stated reason is
that the report never depends on the network or the working directory — you get the
same answer on a laptop, in CI, and on a machine with no internet.

It names five frameworks:

| Key | Framework |
|---|---|
| `slsa` | SLSA v1.2 (target: Build L3 + Source L3) |
| `ssdf` | NIST SSDF v1.2 (SP 800-218) |
| `cra` | EU Cyber Resilience Act (Regulation (EU) 2024/2847) |
| `badge` | OpenSSF Best Practices Badge (passing level) |
| `osps` | OpenSSF Project Security Baseline |

All five must be present; a test enforces it.

## Coverage is uneven, and that is information

Framework mappings are not uniform across the 44 controls:

| Framework | Controls with a mapping |
|---|---:|
| SSDF | 44 |
| CRA | 40 |
| OSPS | 20 |
| Badge | 19 |
| SLSA | 18 |

So **an absent framework line means that control has no mapping to that framework**,
not that it failed one. SSDF is broad enough to touch everything sscsb does; SLSA is
specifically about build and source integrity and legitimately says nothing about,
say, a pull-request template.

## What the report shows

`sscsb report` groups by [phase](phases.md), lists each control with its
`ENABLED`/`disabled` state, and indents one line per framework the control maps to.
It runs **without a config** — with none loaded, every control renders at its
registry default.

`--format json` returns the static embedded map with exactly one thing added: an
`enabled` boolean per control. The `version` and `frameworks` blocks pass through
untouched.

That shape is the honest summary of the whole feature:

> **The framework mappings are static data. The only live part is whether each
> control is enabled.**

The report tells you which requirements your configuration *addresses*. It does not
tell you whether those controls passed — that is `sscsb verify`, and the two are
deliberately separate commands. A control can be `ENABLED` here and `FAIL` there.

One detail with a practical consequence: the text report renders each control's
**name from the registry**, not from the map. The map's own `name` and `notes`
fields are reachable only through the JSON output, so tooling that wants the map's
richer text has to ask for JSON.

## The `compliance-map` control checks the map, not you

`verify_compliance_control` parses the embedded map and asserts every registered
control appears in it. It reads **nothing about your repository** — it does not even
use the repository context it is handed.

It can therefore only fail if a control were added to the registry without a map
entry, which the test suite already blocks at build time. In a shipped binary it is
effectively always `Pass`. That is the honest reading, and it is worth stating so
nobody treats a green `compliance-map` as evidence about their project.

## Two summaries that overstate

Worth knowing when reading `sscsb status`, because these strings are user-visible:

- The `osps-baseline` control's summary says it "adds an OSPS column to
  `sscsb report`". The OSPS lines are emitted unconditionally; nothing consults
  whether that control is enabled. Its real deliverable is the installed worksheet.
- The `best-practices-badge` summary says the worksheet is pre-filled from installed
  controls. The template is a hand-authored table whose marks are literals — only
  the repository slug and branch are substituted. A repository with SAST disabled
  still receives a worksheet ticking SAST.

Both worksheets are `.md` files and are therefore verified as opaque: present and
non-empty, with no machine-checkable structure. The verdict says as much, because
their substance is a human judgement sscsb does not assert. See
[project declarations](../governance/project-declarations.md).

## Source map

| Concern | Location |
|---|---|
| The map itself | `templates/compliance/map.json` |
| Embedding and parsing | `src/compliance.rs` |
| Text rendering | `src/compliance.rs`, `render_report` |
| JSON rendering | `src/compliance.rs`, `render_report_json` |
| The self-consistency control | `src/compliance.rs`, `verify_compliance_control` |
| Command entry point | `src/cli.rs`, `cmd_report` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib compliance::
```
