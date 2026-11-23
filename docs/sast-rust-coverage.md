# Rust SAST coverage and Aikido crosswalk

The default OpenGrep workflow still runs the four generic SSCSB supply-chain
rules. The expanded pack is a separate, **report-only** analysis. A finding is
a review candidate, not a merge blocker or a confirmed vulnerability. A
successful scan also does not certify a repository: check the rules, files
and exclusions actually exercised, scanner diagnostics, and SARIF upload.

The comparison starts from SSCSB `main` at
[`8f8429e`](https://github.com/p4gs/sscs-bootstrapper/tree/8f8429eb1ac05858bbd8caf4b8dd1c5b6074046c).
[Its default OpenGrep run](https://github.com/p4gs/sscs-bootstrapper/actions/runs/45109392147)
reported four rules, 226 tracked files, and no results. It did not run a Rust
semantic pack. CodeQL, dependency scanning, secrets scanning, and Aikido are
separate evidence.

With SAST enabled, `sscsb init` installs the expanded rules alongside the
baseline. Run `sscsb sast --expanded` for a local report with the selected
engine. The [expanded CI workflow](../.github/workflows/sast-opengrep-expanded.yml)
runs OpenGrep and uploads a separate SARIF category (`opengrep-expanded`).
It does not pass `--error`: matches do not block, but a broken scanner or
upload is still an operational problem. Neither the default workflow nor
pre-commit gating uses the expanded rules.

## Source inventory and deduplication

These source pins identify what was reviewed, not what CI fetches. The local
rules implement independently written checks for the normalized intents; no
upstream rule YAML, messages, or fixtures are vendored. Rule syntax support
and fixture outputs are tested locally; this table does not claim byte-for-byte
or behavioral equivalence with the source packs.

- **Semgrep Community `p/rust` (11):** registry configuration
  [response URL](https://semgrep.dev/c/p/rust), observed 2026-11-23, SHA256
  `3d3edde1eca1467780e2eb41c780a22382a27ad35226dea9bdf602ae57f15366`.
  This pins the observed registry bytes, not a Git commit. The related
  [Semgrep rules source](https://github.com/semgrep/semgrep-rules/tree/a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2/rust/lang/security)
  is a separate upstream reference.
- **Archived OpenGrep Rust directory (10):**
  [`f1d2b562b414783763fd02a6ed2736eaed622efa`](https://github.com/opengrep/opengrep-rules/tree/f1d2b562b414783763fd02a6ed2736eaed622efa/rust/lang/security).
  All ten have equivalent top-level intents in the registry's Rust entries.
- **RTK Rust configuration (10):**
  [`e5e7c55ac13aebf5d39c1ddf8e027c46ad2cdef4`](https://github.com/rtk-ai/rtk/blob/e5e7c55ac13aebf5d39c1ddf8e027c46ad2cdef4/.semgrep.yml).
  Several rules encode RTK's own network and file policy. Their normalized
  SSCSB form is advisory and does not copy RTK-specific allowed modules.

In the first table, Rust registry suffix `X` expands to
`rust.lang.security.X.X`. OpenGrep names are filenames without `.yml`.
SSCSB rule IDs begin with `sscsb-rust-`.

| Semgrep Community entry | Archived OpenGrep entry | Normalized SSCSB rule | What to review |
| --- | --- | --- | --- |
| `args-os`, `args` | `args-os`, `args` | `process-arguments` | Argument reads, particularly treating argv as identity or authorization. Ordinary CLI parsing is expected. |
| `current-exe` | `current-exe` | `current-executable` | Reliance on the path of the running executable as a security boundary. |
| `insecure-hashes` | `insecure-hashes` | `legacy-digest` | Recognized legacy digest calls; compatibility checks are not necessarily cryptographic trust decisions. |
| `reqwest-accept-invalid`, `rustls-dangerous`, `ssl-verify-none` | Same three | `tls-verification-disabled`, `custom-certificate-verifier` | Recognized reqwest and OpenSSL disabling behavior, and a separate review signal for replacing Rustls verification. A custom verifier need not be insecure. |
| `reqwest-set-sensitive` | `reqwest-set-sensitive` | `http-sensitive-header` | Sensitive header values and optional log-safety marking. Does not prove that a header is logged or fail to recognize every marking path. |
| `temp-dir` | `temp-dir` | `shared-temp-directory` | Shared temp path and whether creation is race-safe and uniquely named. |
| `unsafe-usage` | `unsafe-usage` | `unsafe-code` | Review the invariants of unsafe constructs; unsafe code is not necessarily incorrect. |
| `generic.unicode.security.bidi.contains-bidirectional-characters` | Not present | `bidi-control` | Hidden control characters in Rust source; the source registry's generic rule has wider target scope. |

| RTK entry | Normalized SSCSB rule | What to review |
| --- | --- | --- |
| `dynamic-command-execution` | `dynamic-executable` | Nonliteral executable selection, including legitimate wrappers. |
| `unsafe-block` | `unsafe-code` | Same family as registry and archived OpenGrep; emitted once by the local rule. |
| `ld-preload-manipulation` | `child-loader-env` | Process loader environment changes; determine value trust and inheritance. |
| `raw-socket-usage` | `raw-socket` | Recognized low-level TCP/UDP APIs; not a claim of prohibited traffic. |
| `reqwest-forbidden`, `ureq-outside-telemetry` | `http-egress` | Recognized HTTP call sites; network access is not categorically forbidden. |
| `interpreter-execution` | `interpreter-process` | Explicit shell, runtime or downloader launch; check need and inputs. |
| `path-env-manipulation` | `command-search-path` | Changing executable search order in process or child environment. |
| `sensitive-path-reference` | `credential-path` | Recognizable sensitive filenames or directories; a reference alone is not a leak. |
| `filesystem-deletion` | `file-deletion` | Direct file and tree deletion; check containment, symlinks, and operator intent. |

There are **31 upstream entries and 17 normalized Rust-pack rules**.
Overlapping check families are grouped; two different review questions can
still flag the same code. The expanded scan also has six Aikido-gap heuristics
listed below. The checks target known spellings and local context.
Aliases, wrappers, reexports, macro expansion, control flow, feature
selection and cross-file value flow can all limit matches. Separate runtime
evidence is needed for filesystem races, process environment, and actual
network destinations.

## Aikido: ten-group baseline crosswalk

Issue IDs refer to the historical inventory for this repository. This is a
scope map, not a live Aikido status, a rescan, or an instruction to dismiss
any finding. Counts are issue groups, not underlying occurrences or CVEs.

| Aikido issue group | Appropriate local signal | Gap or disposition |
| --- | --- | --- |
| `62018405`, Rustls advisories | Cargo lockfile and OSV/Trivy/Socket. | Historical 0.23.45 was updated to 0.23.46 on checked `main`; source SAST is the wrong layer. |
| `62018409`, rustls-webpki | Cargo lockfile and OSV/Trivy/Socket. | Alerted against 0.103.15, remediation threshold 0.103.16; checked `main` locks 0.103.17. |
| `62018414`, webpki-roots | Cargo lockfile and OSV/Trivy/Socket. | Alerted against 1.0.8, remediation threshold 1.0.10; checked `main` locks 1.0.12 on the 1.x line. Repository, published archive, and dashboard age are different evidence. |
| `62018418`, zerovec | Cargo lockfile, advisory `GHSA-7fx9-626j-vqph`. | Baseline locked 0.11.6; candidate raises it to 0.11.8. Aikido surfaced this at comparison time; older successful SCA runs do not rule it out. |
| `62018419`, zerovec-derive | Cargo lockfile, same grouped advisory. | Baseline locked 0.11.3; candidate raises it to 0.11.5. Do not count this and the previous row as separate CVEs or assume equal scanner feeds. |
| `62018523`, repository path handling | `sscsb-aikido-repo-path-direct-io` plus caller review. | Seventeen reported instances included different trust boundaries. The local rules review direct shapes, not all aliases, normalization, symlink behavior, or multi-file paths. Explicit operator-selected input is not equivalent to an untrusted repository-controlled path. |
| `62018525`, generic process spawning | `sscsb-rust-dynamic-executable`, with the separate `sscsb-aikido-git-variable-operand` heuristic for the neighboring Git option-boundary risk. | Direct argv does not mean shell injection. Review executable provenance, option parsing and environment separately. The signed local-scan lane deliberately honors trusted Git signer configuration; do not scan arbitrary supplied Git metadata as if it were trusted. |
| `62018506`, workflow permissions | `sscsb-aikido-workflow-read-all`, `sscsb-aikido-workflow-write-all`, and inspection of the job permission block. | Top-level read-all was redundant for the existing Scorecard job's explicit scopes. Keep results publishing and SARIF permissions narrowly scoped; a textual match does not model the effective token. |
| `62018481`, remote CI tools | `sscsb-aikido-archive-verification-review` identifies a narrow literal curl-to-tar sequence without a recognized same-file pinned digest before extraction. | Same-release checksum data is weaker than independently authenticated or in-repository pinned digests. Exact Semgrep package version does not lock transitive wheel hashes. The matcher does not check pip, arbitrary shell or helper semantics, or attestations. |
| `62018471`, root Docker image | `sscsb-aikido-docker-user-review`: single-stage absent USER, or an explicit root USER in the default final stage. It does not infer inherited users or alternative build targets. | The ClusterFuzzLite image is an ephemeral digest-pinned build fixture, with a documented mount/toolchain rationale. Flagging a missing USER does not imply root in a production deployment or that changing USER would preserve the fuzz build. |

### Repository-path group: 17 baseline anchors

Line numbers refer to the baseline, not to the fix candidate. This groups
reported locations by actual path ownership and operation. It does not label
every anchor a vulnerability or claim that the new heuristic reproduces them.

| Group | Baseline anchors in `src/` | Disposition |
| --- | --- | --- |
| Narrowed in the separate remediation candidate (4) | `observability.rs:37`, `signers.rs:92`, `signing_setup.rs:757`, `signing_setup.rs:1542` | Bound the implicit Dependency-Track SBOM, repository-relative signer attestation, signing lane policy and repo-local Claude settings. Preserve an explicitly selected SBOM path. The expanded lint does not verify the containment helper or attribute a path to the caller. |
| Caller-supplied instead of implicit repo paths (3) | `hooks.rs:804`, `provenance.rs:437`, `scan.rs:126` | Git supplies the commit-message file to the hook. The operator supplies the provenance receipt and VEX file to their CLI commands. A blanket repo-root restriction would change these interfaces. Assess the operation and input validation separately. |
| Config-selected catalog (1) | `bumblebee.rs:351` | Catalog file/directory selection is a configuration trust decision. Review selection and enumeration together; this anchor alone does not show exfiltration or demonstrate containment. |
| Other repo-relative or repo-discovered reads (9) | `distribution.rs:510`, `hooks.rs:160`, `context.rs:23`, `deps.rs:905`, `deps.rs:1104`, `pinning.rs:531`, `sbom.rs:87`, `artifacts.rs:80`, `audit.rs:1018` | Keep for manual review by boundary and effect: policy/config loads, discovered manifest/tracked-file reads, SBOM counting, binary-header inspection and local action discovery. Some have lexical or metadata guards; the pack neither revalidates those guards nor models ancestor links, races or cross-file dataflow. Not part of the narrowed fix unless explicitly listed above. |

Use the existing [Vulnerability Scan workflow](../.github/workflows/vuln-scan.yml)
for dependency and filesystem scanning and check Socket's exact-ref dependency
report separately. On `8f8429e`, the
[earlier OSV job](https://github.com/p4gs/sscs-bootstrapper/actions/runs/45109392385/job/137478016100)
reported 147 Cargo lockfile packages and no issues. That result is bound to
its scan date, advisory feed, and ref, not the newer Aikido snapshot or the
unpublished fix candidate. Do not add an advisory-ID regex to Rust source to
simulate dependency analysis. When Aikido and Cargo scanners disagree, check
the lock entries, source/advisory timeline, platform/feature applicability,
and a fresh exact-ref scan rather than treating an absence as clearance.
