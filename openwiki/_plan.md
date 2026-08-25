# OpenWiki plan — sscs-bootstrapper

Revision 2. Incorporates skeleton-critic requests RQ-01 … RQ-10.

## Information architecture

`sscsb` is a policy engine and glue layer: it decides which supply-chain
controls run, invokes external tools, parses their output, and gates on the
result. The taxonomy follows **what a control does at runtime and which forge or
subsystem owns it**, never `src/`.

The five phases are the product's user-facing vocabulary — `ControlDef.phase` is
a validated struct field, generated config carries phase banners, and
`sscsb status` groups by phase — but they are **not** the directory axis, because
several phases mix independently owned subsystems. `control-model/phases.md`
owns the phase model and maps phases onto these domains (RQ-08).

```
openwiki/
  quickstart.md
  control-model/
    registry-and-outcomes.md
    phases.md
    configuration.md
    repository-state.md
    adding-a-control.md
    compliance-mapping.md
  commit-integrity/
    git-hooks.md
    signer-policy.md
    signing-environments.md
    ai-provenance-trailers.md
    gittuf-ref-policy.md
    sast.md
  dependencies/
    manifests-and-package-trust.md
    vulnerability-scanning.md
    sbom-generation.md
    openvex.md
    endpoint-exposure.md
  provenance/
    artifact-signing.md
    ai-receipts.md
    model-signing.md
  github/
    workflow-auditing.md
    branch-protection.md
    scorecard.md
  governance/
    project-declarations.md
    external-services.md
  runtime/
    process-execution.md
    repository-context.md
    external-tools-and-degradation.md
  bootstrap/
    initialization.md
    ci-templates.md
  operations/
    cli-surface.md
    network-and-credentials.md
  development/
    building-and-testing.md
    release-pipeline.md
    ci-and-tool-pins.md
```

Taxonomy decisions, and what changed:

- **`posture/` dissolved** (RQ-04). It was a catch-all over four unrelated
  subsystems, and it mis-filed a phase-2 control. `bumblebee.rs` is
  `phase: 2` — verified — and moves to `dependencies/endpoint-exposure.md`;
  `openssf.rs`'s three verifiers split by what they actually govern (gittuf → git
  ref policy, model-signing → provenance, security-insights → governance);
  Dependency-Track/GUAC/ORAS become `governance/external-services.md`.
- **`code-analysis/` replaced by `github/`** (RQ-05). Grouping by source flavor
  split a declared read/write pair across two top-level directories:
  `harden.rs`'s own module doc calls it "the write-side counterpart to the
  read-only `verify` controls", and both halves route the same
  `branch-protection` control id. `github/branch-protection.md` owns both.
  `sast.rs` moves to `commit-integrity/` because its real coupling is
  `hooks::stage_to_tempdir`, the shared staged-materialization mechanism.
- **`development/` added** (RQ-01). The plan documented the security product but
  not the project. The highest-frequency maintenance questions live here.
- **Factual correction** (RQ-04): `openssf.rs` contains exactly three verifiers.
  `best-practices-badge` and `osps-baseline` dispatch to
  `workflows::verify_template_control`, not to `openssf.rs`. Verified at
  `src/controls.rs:519-521`.
- `runtime/` is the documented exception to the no-umbrella rule: process
  execution, repository discovery, and tool detection are genuinely cross-domain
  infrastructure every control sits on.

## Page map

| Page | Primary sources | Focused tests | Owns |
|---|---|---|---|
| `quickstart.md` | `README.md`, `AGENTS.md` | — | Written last; task-routing map matching the physical tree |
| `control-model/registry-and-outcomes.md` | `controls.rs`, `cli.rs::cmd_verify`, `main.rs` | `library.rs` verifier wiring | **The verdict contract** (RQ-07): all five outcomes, which code path produces each, `Outcome`→exit-code incl. `--strict`, exit-2-is-not-a-finding, DEGRADED-is-not-PASS |
| `control-model/phases.md` | `controls.rs`, `config.rs::default_config_toml`, `cli.rs::cmd_status` | `registry_ids_unique_and_phases_valid`, `every_phase_has_controls` | **NEW** (RQ-08) phase model + phase→domain map |
| `control-model/configuration.md` | `config.rs` | config tests | `.sscsb/config.toml`, off-means-off |
| `control-model/repository-state.md` | `init.rs`, `workflows.rs::ARTIFACTS`, `.gitignore` | `bootstrap_is_idempotent_and_never_clobbers_local_edits` | **NEW** (RQ-02) per-path on-disk contract: writer, generated vs authored, committed vs ignored, clobber semantics |
| `control-model/adding-a-control.md` | `controls.rs`, `tools.rs`, `workflows.rs`, `compliance.rs` | the 4 enforcing tests | **NEW** (RQ-03) the six-file extension contract |
| `control-model/compliance-mapping.md` | `compliance.rs`, `templates/compliance/map.json` | map coverage | `sscsb report` |
| `commit-integrity/git-hooks.md` | `hooks.rs` | `integration.rs` pre_commit_*/pre_push_* | Hook engine, POSIX shims, fail-closed, `stage_to_tempdir` |
| `commit-integrity/signer-policy.md` | `hooks.rs` (`Signer`, `SignerClass`, `parse_signers`, `regenerate_allowed_signers`), `signers.rs` | signer + signing tests | **Canonical owner of the AI-cannot-sign invariant** (RQ-06) end to end |
| `commit-integrity/signing-environments.md` | `signing_setup.rs` | its tests | Five-lane probe/converge/verify |
| `commit-integrity/ai-provenance-trailers.md` | `hooks.rs` trailers, AI dep/shell gate, `review_evidence_problems` | `commit_msg_gates_*` | Trailers + **the AI-assisted-commit end-to-end flow** (RQ-10) |
| `commit-integrity/gittuf-ref-policy.md` | `openssf.rs::verify_gittuf` | openssf tests | **NEW** (RQ-04) git ref policy |
| `commit-integrity/sast.md` | `sast.rs` | `tool_orchestration.rs` sast_* | **MOVED** (RQ-05); names `hooks::stage_to_tempdir` as shared |
| `dependencies/manifests-and-package-trust.md` | `deps.rs` | deps tests | Ecosystems, typosquat, baseline, registry probing |
| `dependencies/vulnerability-scanning.md` | `scan.rs` | scan tests | Trivy, OSV, severity gating |
| `dependencies/sbom-generation.md` | `sbom.rs` | sbom tests | Syft, Grype |
| `dependencies/openvex.md` | `observability.rs::vex_create`, `scan.rs::apply_vex` | `vex_create_produces_valid_openvex_and_scan_can_ingest_shape` | **NEW** (RQ-09) full VEX lifecycle across the generate/consume seam |
| `dependencies/endpoint-exposure.md` | `bumblebee.rs` | bumblebee tests | **MOVED** (RQ-04) phase-2 control; machine, not repo |
| `provenance/artifact-signing.md` | `provenance.rs` | cosign/slsa tests | cosign keyless, slsa-verifier, DSSE + **the deploy-gate flow** (RQ-10) |
| `provenance/ai-receipts.md` | `provenance.rs` receipts | `receipts_bind_commits_*`, `forged_receipt_naming_a_git_option_is_refused_*` | Receipt shape, untrusted-input boundary |
| `provenance/model-signing.md` | `openssf.rs::verify_model_signing` | openssf tests | **NEW** (RQ-04) |
| `github/workflow-auditing.md` | `audit.rs` | `every_workflow_template_passes_own_audit` | Pinning, permissions, extended audit, slsa tag-pin exception |
| `github/branch-protection.md` | `audit.rs::verify_branch_protection` + `harden.rs` | audit + harden tests | **BOTH HALVES** (RQ-05): read and plan/apply, dry-run-unless-`--apply` |
| `github/scorecard.md` | `scorecard.rs` | scorecard tests | **MOVED** (RQ-04) |
| `governance/project-declarations.md` | `openssf.rs::verify_security_insights`, `workflows::verify_template_control` | openssf + workflows tests | **NEW** (RQ-04); states badge/OSPS are template-verified |
| `governance/external-services.md` | `observability.rs` minus VEX | `guac_and_oras_*` | **MOVED + SCOPED** (RQ-04/09) DT, GUAC, ORAS only |
| `runtime/process-execution.md` | `exec.rs` | exec tests | argv-only; **git argument safety** (`is_object_name`, `--end-of-options` not `--`) |
| `runtime/repository-context.md` | `context.rs` only | context tests | **SCOPED** (RQ-07): `Ctx::discover`, slug, default branch |
| `runtime/external-tools-and-degradation.md` | `tools.rs` + `platform.rs` | `is_available_*` | **RENAMED/MERGED** (RQ-07): pins, detection, `degrade_message`, platform install hints, `signing_note` |
| `bootstrap/initialization.md` | `init.rs` | idempotence test | Bootstrap + **re-init/upgrade flow** (RQ-10) |
| `bootstrap/ci-templates.md` | `workflows.rs`, `templates/` | self-audit test | SHA pinning, self-audit invariant |
| `operations/cli-surface.md` | `cli.rs`, `AGENTS.md`, `.claude/skills/sscsb/SKILL.md` | `agents_md.rs` | Subcommands; shipped agent surface, noting **only `AGENTS.md` is test-pinned** (RQ-01) |
| `operations/network-and-credentials.md` | `observability.rs`, `deps.rs`, `audit.rs`, `harden.rs`, `scorecard.rs`, `signing_setup.rs`, `provenance.rs` | — | **NEW** (RQ-09) every egress: method, read/write, credential source, offline behavior |
| `development/building-and-testing.md` | `CLAUDE.md`, `tests/*`, `ci.yml`, `fuzz/` | — | **NEW** (RQ-01) hermetic invocation + why, the 4 suites, runtime-constructed secret fixtures, coverage gate rationale |
| `development/release-pipeline.md` | `.github/workflows/release.yml` | — | **NEW** (RQ-01) draft-then-publish immutability, 3-target matrix, central checksums, Homebrew tap |
| `development/ci-and-tool-pins.md` | `ci.yml`, `.github/actions/setup-sscsb-tools` | — | **NEW** (RQ-01) job graph, Trivy-cache concurrency constraint, the `tools.rs` ↔ action.yml pin duplication |

## Cross-system workflows to cover

Each has a home page carrying the end-to-end narrative (RQ-10).

1. **`sscsb init` → what lands on disk** → `bootstrap/initialization.md`.
2. **Re-init / upgrade** — idempotent by contract; second run writes strictly
   less and preserves local edits → `bootstrap/initialization.md`.
3. **A commit blocked** → `commit-integrity/git-hooks.md`.
4. **A push blocked** → `commit-integrity/signer-policy.md`.
5. **AI-assisted commit, end to end** — trailers → AI dep/shell gate → new-package
   approval → `ai`-class valid on a feature branch only → human-signed merge
   carrying review evidence → `commit-integrity/ai-provenance-trailers.md`.
6. **`sscsb verify` → a verdict** → `control-model/registry-and-outcomes.md`.
7. **Tool absent → DEGRADED** → `runtime/external-tools-and-degradation.md`.
8. **Release/deploy provenance gate** — `deploy-gate.yml`, `verify_artifact`,
   `cosign_verify_blob` → `provenance/artifact-signing.md`.
9. **VEX suppression** — generate in `observability.rs`, consume in `scan.rs`
   → `dependencies/openvex.md`.

## Deferred

Nothing deferred. `testutil.rs` is covered in
`development/building-and-testing.md`; `main.rs` in
`control-model/registry-and-outcomes.md` (it owns the exit-2 mapping).
