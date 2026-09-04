# Changelog

All notable changes to `sscsb` are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) and is pre-1.0 — the
CLI surface and `.sscsb/config.toml` schema may still change between minor
versions.

## [Unreleased]

### Added

- **`sscsb scan --local` — the local lane.** About a third of the controls
  are checks on a *development environment* — `commit-signing`,
  `agent-signing`, `signing-model`, `ai-trailers`, `ai-dep-gate`, `ai-receipts`,
  `package-trust`, `bumblebee`, `grype`, `socket-firewall`, `witness`,
  `sighthound`, `guac`, `openvex` and `oras`, of which ten or eleven are in
  scope for a typical repository — so a repository scan can only score them
  `unverified`, which is why a repository with a perfect posture reads
  *provisional* in the public directory.

  `--local` runs the full control set where those checks are observable and
  writes a **directory `ScanRecord`** — the public directory's own schema,
  `schema_version` 1 and `methodology_version` 1, every required field present
  — to the **committed** path `.sscsb/scan-record.local.json`, with one added
  `local` block binding it to the repository, the commit and the signer. It
  signs those exact bytes with the key git already signs commits with —
  `gpg.format`, `user.signingkey`, `gpg.ssh.program`, so a 1Password-,
  Secure-Enclave- or YubiKey-backed key signs untouched. The detached SSHSIG
  lands at `.sscsb/scan-record.local.json.sig` and is re-verified before the
  command reports success. Both files are meant to be committed and pushed:
  the submission is a *pointer*, and the directory reads the record, the
  signature and the anchor out of the public repository, so nothing typed into
  an issue reaches the bytes it verifies.

  The trust anchor is `.sscsb/policy/allowed_signers` **as committed in the
  public repository at the recorded commit** — content the submitter does not
  supply. A verified local record therefore proves exactly that *a holder of a
  key this repository commits as an approved signer asserted this result at
  commit X*. It does **not** prove CI produced the result; only the action lane
  does that. The directory therefore requires an independent record to agree
  with a local row wherever a repository scan could have observed the control
  (evidence classes A, A′ and B), and lets a local row stand alone only where
  no independent observation is possible (class C). Sources that disagree score
  the control as a **gap** with a contradiction flag, so a flattering local
  scan costs the repository rather than helping it. `--submit` files the
  pointer with `gh`; `--dry-run` prints it instead.

  **The lane now has one written contract**: the fenced ```contract block in
  `docs/local-scan.md` pins the command, the SSHSIG namespace, the committed
  paths, the record shape and every required field. The tool asserts each line
  against its own constants and the directory asserts a verbatim mirror, both
  over the same digest — so the namespace/shape/path/command mismatches that
  made the first cut of this lane unusable end to end now fail a test instead.

- **`sscsb skill install | print | check` — the bundled agent skill.** The
  instructions an AI agent needs in order to drive `sscsb` now ship *with*
  `sscsb`. The canonical copy is `templates/skills/sscsb/SKILL.md`, compiled
  into the binary with `include_str!`; `install` writes it to
  `.claude/skills/sscsb/SKILL.md` (refusing — exit `2`, nothing written — to
  clobber a file that differs, unless `--force`), `print` emits the bundled
  bytes verbatim for a digest or a diff, and `check` compares the installed copy
  against the bundled one: exit `0` identical, `1` differs or missing, `2` could
  not look. `--dry-run` prints the plan and touches nothing in **all four**
  states — including the one where a real run would refuse, which it now
  describes rather than performs. This repository installs its own copy and a
  test holds the two byte-identical — the tool that audits you is the tool that
  wrote the instructions your agent reads.

  **The two claims are kept apart, deliberately — and the strength of the first
  is measured, not asserted.** `skill check` detects an edit made to the
  *installed file* by another agent, a hook, or anything else on the machine.
  Whether that is worth much depends on something no document can know for you:
  whether the same unprivileged process could have rewritten `sscsb` itself.
  Into a root-owned prefix (`/usr/local/bin`, `root:wheel`) it could not. By
  Homebrew — the install path the README recommends first — it usually could:
  `/opt/homebrew/bin` is owned by the installing user and the binary there is a
  symlink you can repoint without `sudo`, so the binary is exactly as writable
  as the file it checks. `skill check` therefore walks its own executable's
  **entire resolution chain** — every ancestor directory up to the filesystem
  root and every symlink hop individually, the link and the directory holding
  it — and asks the *kernel* about each (not the mode bits, so groups and ACLs
  count), reporting the answer as `binary trust` —
  `not-user-writable` / `user-writable` / `unknown`, with `unknown` read as the
  weak case — in the text output and under `binary` in `--format json`,
  alongside a boolean `narrow_claim_holds`, a boolean `chain_complete`, and the
  chain itself as `binary.probes`, one row per path walked, so a reader can see
  *which* link is writable rather than trusting the verdict over it. Where it is
  `user-writable`, the tool says outright that a clean result is evidence of no
  *casual* edit and nothing stronger. It **cannot** detect a tampered `sscsb` in
  any case: the check, the bytes and the digest all ship in one artifact.

  Walking the whole chain is a **correction**, not a flourish. A probe of four
  points — the executable, its directory, the canonicalized file, that file's
  directory — printed `not-user-writable` for two layouts an unprivileged user
  can take over, and both were taken over to prove it: a **writable
  grandparent** above a `0555` `bin` (`mv bin bin.orig && mkdir bin`), and a
  **repointed intermediate symlink**, which is exactly Homebrew's
  `opt/<formula> -> ../Cellar/<formula>/<version>` shape, where `canonicalize`
  jumps from one end of the chain to the other and never sees `opt/`. A vague
  hedge misleads; a green verdict that is checkable and wrong gets trusted.
  Symlink loops and pathological depth stop the walk and set
  `chain_complete: false`, which can never earn the strong verdict. The
  Homebrew sentence in the output is now printed only for chains that actually
  run through a Homebrew prefix — it used to be appended to every
  `user-writable` verdict, including for a binary in `/tmp`.

  **Ownership is capability, and the default verdict is now the weak one.**
  `faccessat(W_OK)` answers "may I write this right now", not "may I make
  myself able to write it", and POSIX lets a file's owner `chmod` it. A real
  `sscsb` binary, user-owned at mode `0555` inside a user-owned `0555`
  directory under a root-owned prefix, probed `writable: false` on every link
  of its chain, printed `not-user-writable` with `narrow_claim_holds: true`,
  and was then replaced twice with no elevation — `chmod u+w` on the file, and
  `chmod u+w` on the directory followed by unlink-and-recreate. Every probe row
  now carries an `owned` answer beside `writable`, and either one `true` is an
  open door.

  That was the third consecutive round in which this check produced a
  checkable-but-wrong "not-user-writable", so the **default is inverted**. The
  probe is trying to prove a negative about a filesystem and cannot do that
  portably, so `not-user-writable` is now the narrow, hard-to-earn case:
  it requires the chain fully walked, every link both unwritable *and*
  unowned, **and** a platform whose `current_exe()` is known to report the path
  the executable was invoked by. Anything else — one unreadable link, one
  unanswered probe, one abandoned walk — is `unknown`, read as the weak case.
  The platform gate is reported as `binary.chain_start`
  (`invocation-path` / `pre-resolved`) and `binary.strong_verdict_available`:
  on Linux `/proc/self/exe` is already resolved, so an intermediate symlink
  cannot appear on the chain at all, and the strong verdict is simply
  unavailable there rather than being awarded to a chain that may be missing a
  door. What no verdict checks even at full strength — POSIX ACLs, BSD file
  flags, mount options, container image layering, process capabilities — now
  ships as data in `binary.unchecked_mechanisms` and in the printed statement,
  not only in prose: `narrow_claim_holds: true` is the floor of what an
  attacker must beat, never a proof.

  The claim that does not depend on us is the release asset, signed at its tag
  by `release.yml` and a subject of the release's build-provenance attestation,
  its CycloneDX SBOM attestation and its SLSA Build L3 provenance, verifiable
  with `cosign`, `gh` and `slsa-verifier` obtained independently. Two honest
  qualifications ship with it. First, **`SKILL.md` is not a release asset yet**:
  `release.yml` stages and signs it, but the first release whose assets include
  it is the first tag cut after this change lands, so every `SKILL.md` step of
  the recipe must be run against a platform tarball until then — stated on
  `docs/skill.md`, `README.md`, the skill and `AGENTS.md`, and pinned by a test
  that says when it may be deleted. Second, a release's 17 files do **not** all
  carry one signer: 16 are minted at our tag by `release.yml`, while the
  `*.intoto.jsonl` envelope is signed by the SLSA generator's own workflow at
  the generator's own tag, and pinning our `--certificate-identity` against it
  pins the wrong signer. That is a proof of origin, not a judgement of content.
  `docs/skill.md` carries the fenced ```contract block pinning all of it, the
  full verification recipe — including the three-way closure check that is what
  actually establishes "no asset was altered *or added* afterwards": every asset
  has a bundle that verifies, every bundle has its asset, and there is exactly
  one SLSA envelope, which is what closes the two name shapes the verify loop
  skips. That closure check is now **`nullglob`-guarded**: under `zsh`, macOS's
  default login shell, an unmatched glob aborts the script, so the
  removed-envelope case never reached the count it exists for and printed
  `no matches found: *.intoto.jsonl` instead of a verdict. All five cases now
  produce identical output under `sh`, `bash`, `dash` and `zsh`, executed by a
  test rather than claimed. `docs/skill.md` also carries
  the reasons the tag must come from out of band and the recipe must not be read
  out of the file it verifies.

- **The release subject set is computed once, and the deploy gate verifies all
  of it.** `release.yml` previously scoped every subject glob to
  `dist/*.tar.gz` — `actions/attest-build-provenance`, the SBOM `actions/attest`
  and the SLSA generator's `base64-subjects` alike — so any non-tarball asset a
  release staged was signed by the all-files Cosign loop and covered by nothing
  else, silently. The `release` job now stages extra assets FIRST, computes one
  `subjects.sha256` over everything in `dist/` except the `.sha256` sidecars,
  and hands that same list to both attestations (`subject-checksums`) and to the
  generator. `deploy-gate.yml` derives the same set from the published assets —
  everything except the sidecars, bundles, SLSA envelope and SBOM — and runs its
  provenance, SBOM and SLSA gates over it instead of over `*.tar.gz`, so an
  asset that is attested is an asset that is checked. The shipped
  `templates/workflows/` copies carry the identical wiring, with the
  extra-assets slot left empty: the bug is fixed for every repository `sscsb`
  bootstraps, not only for this one.

### Changed

- **Generated `allowed_signers` lines now grant two namespaces to `human`-class
  signers**, `namespaces="git,sscsb-scan-record"` rather than
  `namespaces="git"`. SSHSIG namespaces stop a signature minted for one protocol
  being replayed as another, and the second name is the one local scan records
  are signed in. The grant is additive — commit-signature verification is
  unchanged — and it is written as a positive statement rather than by dropping
  the restriction, which would silently permit every namespace OpenSSH ever
  defines. A repository anchored before this release carries `namespaces="git"`
  alone and `--local` refuses with the one-line fix (`sscsb init`, commit the
  anchor) rather than producing a record that will not verify.

  **`ci`- and `ai`-class signers keep `namespaces="git"` and nothing else.** A
  local scan record is a maintainer's attested word about a machine nobody else
  can inspect, and it is the one lane whose local-environment verdicts count
  without independent corroboration — so only a `class = "human"` signer may
  assert one. CI does not need the grant (the action lane proves strictly more),
  and granting it to an `ai` key would contradict this policy's own invariant
  that an AI-class signer never signs. The refusal is structural: the namespace
  is simply absent from the line, so `ssh-keygen -Y verify -n sscsb-scan-record`
  fails against the committed anchor and both `sscsb` and the public directory
  refuse independently.

### Fixed

- **A test read `PATH` without the environment lock and failed as if the code
  had regressed.** `scan::tests::run_scan_surfaces_a_clear_error_when_the_vex_path_does_not_exist`
  resolved `trivy`/`osv-scanner` by bare name in its skip guard and again inside
  `run_scan`, holding no lock across the two. A sibling test stripping `PATH`
  between them flipped the guard's answer, and `run_scan` reported "no
  vulnerability scanner available" instead of the VEX read error — surfacing as
  an unrelated assertion failure under parallel execution. It now holds the lock
  the `testutil` module docs require of every `PATH`-dependent read.

## [0.3.1] - 2026-09-02

### Fixed

- **Four provenance controls were graded by filename, not by evidence.**
  `sigstore-signing`, `slsa-provenance`, `github-attestations` and
  `sbom-attestation` verified by asking whether the modular workflow `sscsb
  init` installs (`release-sign.yml`, `release-slsa.yml`, `release-attest.yml`,
  `release-attest-sbom.yml`) existed and parsed. A repository on the
  draft-then-publish `release-immutability` path performs the Cosign signing,
  the build-provenance attestation, the SBOM attestation and the
  slsa-github-generator call **inside `release.yml`**, over the exact artifact
  it ships — the modular workflows cannot coexist with an immutable release.
  Such a repository was told to run `sscsb init`, and the only way to silence
  that was to disable the controls, which every downstream consumer then read
  as "not implemented".

  When — and only when — the modular artifact is **absent**, `verify` now
  looks for the control's real step in the repository's workflows. Exactly
  what it checks (see `docs/phase-3.md` § Consolidated evidence):
  the candidate files are the ones **committed at HEAD** (`git ls-tree -r
  --name-only HEAD -- .github/workflows`, each read with `git show
  HEAD:<path>` — a file that is only on disk, only `git add`ed, or edited in
  the working tree is never evidence and is named as such, and a working
  tree that differs from HEAD is reported; only outside a git repository
  does it read the directory, and the message then says committed-ness was
  not established); the file is shape-sound (one YAML document, at least one
  job, no inert job, every `needs:` resolvable); its `on:` carries an
  automatic trigger (`push`, `release`, `schedule`, `pull_request`,
  `workflow_run`) or is `workflow_call` reached from a committed workflow
  that has one — a trigger's `branches`/`tags`/`paths` filters are **not
  evaluated** and the message says so (`on \`push\` (tags filter not
  evaluated)`), except that an empty `branches:`/`tags:` list fails; neither
  the proving job nor the proving step has a constant-false `if:` (`false`,
  `'false'`, `"false"`, `${{ false }}`; no other expression is evaluated);
  the action is pinned to a 40-hex commit SHA (the slsa-github-generator's
  `vX.Y.Z` tag pin excepted); the step is bound to an artifact (`subject-*`
  for both attestation actions, plus `sbom-path` for the SBOM; a non-empty
  `base64-subjects` / `base64-subjects-as-file` for the generator; for
  Cosign the `run:` body is **tokenised as shell** and the command word —
  after `VAR=…`, `sudo`/`env`/`time`, `do` and the like — must be `cosign`
  followed by `sign-blob`/`sign` with `--bundle` a word of that same
  command, so an `echo` that prints the command, a trailing `#` comment, or
  a `--bundle` on the next command of a chain is not signing; with the
  `sigstore/cosign-installer` step **preceding** the signing step, every
  cosign-bearing step judged); and the job's effective `permissions:` (job
  level replaces workflow level, as GitHub applies them) grant what the step
  needs — `id-token: write` for signing, `attestations: write` + `id-token:
  write` for the attestations, `actions: read` + `id-token: write` +
  `contents: write` for the generator. Every shortfall **fails** with the
  precise defect named. Nothing here claims the workflow has run; that
  remains the release's, and `provenance-verify`'s, business.
- **`init` and `verify` now agree.** `sscsb init` consults the same
  recognizer before writing a modular template: a control already proven by
  consolidated evidence committed at HEAD is skipped with a log line naming
  the proving file (`skip .github/workflows/release-sign.yml
  (sigstore-signing proven by .github/workflows/release.yml)`). Previously, a
  pipeline that runs `init` before `verify` had the template written into the
  clone first, so `verify` graded an init-created file and never reached the
  committed evidence.
- **The shipped `release.yml` / `deploy-gate.yml` templates carried the old
  design** — no generator job, a `workflow_dispatch`-only gate, and a header
  claiming the slsa-github-generator is incompatible with release
  immutability. They are now the pipeline this repository runs (below),
  verbatim outside two marked `sscsb:customize-*` regions (the build job and
  the tarball count it yields — `git archive` and `1` in the template, a Rust
  matrix and `3` here), and a test holds the two in byte parity outside
  those regions; `deploy-gate.yml` has no region and is byte-identical. The
  `release-slsa.yml` header and the compliance map now say what is actually
  true: only that workflow's after-publish attachment conflicts with
  immutability, not the generator.
- **`verify --format json` rows now report the file the verdict actually rests
  on.** `artifacts` used to be the registered template paths unconditionally,
  so a control proven by consolidated evidence pointed reclassifiers at a file
  the repository never contained. When consolidated evidence proved the
  control, the row carries that file (e.g. `.github/workflows/release.yml`);
  otherwise it is the registry parity it always was. Additive within
  `schema_version: 1` — the field's shape and meaning, "the committed evidence
  for this verdict", are unchanged. Any downstream directory reflects these
  rows once its action scans with this version.
- **The consolidated-evidence gates close the cheap structural evasions, and
  `docs/phase-3.md` § "What this does not prove" now states every remaining
  one.** Heredoc bodies are data; a signing step under a non-POSIX `shell:`
  (step → job → workflow `defaults.run.shell`) is "not judged"; `continue-on-error:
  true` on the proving job/step/installer (and on the calling job of a
  `workflow_call`), a `!`-negated signing command **outside a condition**, a
  signing command in a compound command's CONDITION (`if cosign …; then`,
  `elif`, `while`/`until cosign …; do`) **whose failure path leaves the step
  passing** — a conditional that CHECKS the signing is the canonical "check
  and fail" idiom, not a suppression, so `if cosign …; then echo signed;
  else exit 1; fi` and `if ! cosign …; then exit 1; fi` both PASS: the gate
  reads the arm the shell takes when the signing fails FIRST (the `else`
  arm, or the `then` arm when the test is negated) and stays quiet when it
  propagates (`exit`/`return` with a literal non-zero status or none,
  `false`, `kill`); the command after the compound's terminator is consulted
  only when that arm FALLS THROUGH, because an arm that ends the shell
  without propagating makes everything after the terminator unreachable, so
  `if cosign …; then echo signed; exit 0; else echo warn; exit 0; fi`
  followed by `exit 1` keeps FAILING while
  `if cosign …; then echo signed; fi` followed by `exit 1` passes. For a
  loop the failure arm depends on the opener: a plain
  `while cosign …; do …; done` ENDS on a failing condition, so only the
  command after `done` speaks; an `until cosign …; do …; done` (and its
  `while ! cosign …` twin) runs its BODY on a failing condition, so the body
  is the failure arm and the loop is left on that path only by a `break` or
  a non-propagating `exit` — which is why the bounded retry
  `n=0; until cosign …; do n=$((n+1)); if [ "$n" -ge 3 ]; then exit 1; fi;
  sleep 2; done` PASSES while `until cosign …; do break; done` fails.
  In condition position the `!` is the conditional's own test, not a status
  inversion, so the negation message — which would be factually wrong there
  — is never emitted and the condition defect is reported instead;
  `if cosign …; then echo signed; fi`, `while cosign …; do break; done` and
  `if ! cosign …; then echo failed; fi` all still fail, and an `elif` chain,
  an unclosed compound, an arm whose propagating command is reached
  only through `&&`/`||`/`|`/`&`, an arm where an `exit 0` comes first, and
  a compound nested inside an arm all fail closed (a `break` is the one word
  read deeper, and only inside a loop) —, a `||` branch after it
  that leaves the step passing — immediately or at the end of the AND-OR
  list it opens with `&&`, since `&&` short-circuits to that branch, so
  `cosign … && echo ok || true` swallows exactly as `cosign … || true` does
  while `… && echo ok || exit 1` does not; only `exit` / `return` with a literal
  non-zero status (or none at all, which re-raises `$?` — in `||` position
  the failure that sent the shell down the branch), `false`,
  `kill`, and a `{ …; }` / `( … )` group whose LAST command is one of those
  still fail it, so `|| true`, `|| :`, `|| echo warn`, `|| continue`,
  `|| exit 0`, `|| return 0`, `|| exit $?`, `|| { echo warn; }` and
  `|| ( echo warn )` all swallow, as does a branch of nothing but
  `NAME=VALUE` assignments (`|| FAILED=1`, `|| RC=$?`, named as written),
  and an unreadable or unclosed group fails
  closed — so a branch that RETRIES the signing (`cosign … || cosign …`) is
  read as swallowing too, deliberately: a sound retry has to be written as a
  loop whose exhaustion fails the step (`cosign … && signed=1 && break` per
  attempt, then `[ -n "${signed:-}" ] || exit 1`), which these gates accept —
  a single unpaired `&` after it (which detaches it from `-e`
  exactly as `||` does; `&&` and the `&` of `2>&1` / `>&2` / `&>log` are
  not backgrounding) unless a bare `wait $!` / `wait "$!"` is the very next
  command, which collects that job's status (a bare `wait`, a `wait $PID`,
  and a `wait $!` that is itself negated, piped, backgrounded or `||`-ed
  still fail), a `set +e` / `set +o errexit` / `shopt -o -u errexit`
  before it in the body (`shopt -o` addresses the `set -o` namespace, in
  either flag order and as one cluster; a later `set -e` /
  `shopt -o -s errexit` turns fail-fast back on, order is honoured as it is
  for `pipefail`, and `set --` ends the option list so `set -- +e` is an
  operand, not a toggle) **with no later command that propagates the
  captured status** — the status-capture idiom (`set +e`, sign, `rc=$?`,
  `set -e`, `[ "$rc" -eq 0 ] || exit 1`) turns fail-fast off on purpose and
  re-raises the failure by hand, so it PASSES; the parameter that carries
  the status must be one assigned from `$?` in the command IMMEDIATELY after
  the signing, reached unconditionally (`rc=$?`, `RC=$?`, and the `local` /
  `declare` / `typeset` / `export` / `readonly` spellings), and it is lost
  the moment anything else is assigned to that name — a parameter that
  cannot be traced to the signing's own `$?` does not count, so
  `set +e`, sign, `rc=$?`, `set -e`, `other=$?`, `exit "$other"` and a
  `RC=0` … `exit "$RC"` wrapped around an unguarded signing loop both keep
  FAILING; the recognised shapes are then
  `exit "$rc"` / `return $rc` (that **captured parameter**, never a literal
  — `exit 1` says nothing about the signing), a test on it whose
  `||`
  or `&&` branch fails the step (which way the test reads is not evaluated,
  so either operator counts, and the branch may equally re-raise the captured
  parameter itself — `[ "$rc" -eq 0 ] || exit "$rc"` propagates by
  construction and now PASSES, where before only the literal `|| exit 1`
  did), and that test in a condition whose arm fails
  the step (`if [ "$rc" -ne 0 ]; then exit 1; fi`) — the test may be spelled
  `[ … ]`, `test …`, `[[ … ]]` (its own `]]` required), `(( rc != 0 ))` (its
  own `))`) or `let`, since an idiomatic guard is the same guard, and a
  SEPARATED `( ( … ) )` is a nested subshell rather than arithmetic, told
  apart exactly as bash tells them apart; **and the consultation counts only
  where the shell reaches it**, at the signing's own depth — one inside a
  nested compound's arm, one after an unconditional `exit` that already
  ended the shell, and one behind `&&` / `||` / `|` / `&` are each no
  consultation at all, on the same reachability model the condition gate
  grades an arm with (a rebinding of the captured name, by contrast, counts
  wherever it is written: unknown fails closed on both sides). **That skip is
  one-directional**: a conditionally reached command never COUNTS, but one
  that can END the shell stops the walk there anyway, so the one-liner
  `set +e`, sign, `rc=$?`, `[ -f dist/skip ] && exit 0`, `exit "$rc"` keeps
  FAILING — with its `||`, `&& return 0`, `&& exit $?` and
  `[ "${DRY_RUN:-}" = "1" ] && exit 0` spellings, and the same one-liner in
  an `else` arm or an `until` retry's body — while
  `[ -f dist/skip ] && exit 1`, which fails the step on the path that takes
  it, leaves the walk running. **A BARE `exit` / `return` after `&&` abandons
  the shell too**: an argument-less `exit` re-raises `$?`, which is the
  FAILURE only where the command is reached because something failed (a `||`
  branch, or the arm a compound takes on a failing condition), and after `&&`
  the branch runs only because the test SUCCEEDED, so the status re-raised is
  0 — `set +e`, sign, `rc=$?`, `[ -f dist/skip ] && exit`, `exit "$rc"` now
  keeps FAILING (with its `&& return` spelling, and the same one-liner in an
  `else` arm or an `until` retry's body), while the sound `||` twin
  `[ "$rc" -eq 0 ] || exit` keeps PASSING, since there the inherited status
  is the failing one. The rule holds wherever an argument-less `exit` decides
  a verdict, including the branch of the captured-status test itself:
  `[ "$rc" -eq 0 ] && exit` and `[ "$rc" -ne 0 ] && exit` both keep the
  defect. That one is decided rather than disclosed because, unlike the
  direction a test reads, a bare `exit` after `&&` is unsound in BOTH
  readings; `&& exit "$rc"` and `&& exit 1` are unaffected. **A nested
  compound is stepped over only when the shell must come back out of it** —
  one that can END the shell instead, an abandoning `exit` / `return`
  anywhere in its span at any depth, ends the walk, so `set +e`, sign,
  `rc=$?`, `if [ "${SKIP_SIGNING:-}" = "true" ]; then exit 0; fi`,
  `exit "$rc"` keeps FAILING (with its `while` / `for` / `until` / `case`
  twins and the same arm nested two deep); and the arm index lists now carry
  a nested compound at its opener, so the same rule closes an `else` arm that
  ends the shell from inside one; a status
  captured and
  never consulted (`set +e`, sign, `echo done`), a check whose failing path
  still passes (`|| echo warn`), a `case` on the captured status
  (`case "$rc" in 0) ;; *) exit 1 ;; esac` — sound, and failed anyway,
  because an arm's pattern is only skipped so the command behind it can be
  read, never matched against a value), which now grades identically in
  **either `case` spelling** — a one-liner
  `case "$MODE" in skip) echo s ;; esac` carries its keyword and its first
  arm as one command, and used to open no compound at all, so the walk read
  it as a simple command and then stopped at the `esac` behind it — and a
  test of anything but
  the captured
  parameter each
  keep the defect, a `|`
  after it with no `set -o pipefail` before it in the body and a shell that
  does not set it (the built-in `bash` does; `sh` and no `shell:` do not),
  and a `cosign` function/alias in the body are each named; a `shell:` is
  POSIX only as `bash` / `sh`, bare or in GitHub's custom-shell shape —
  options and exactly one `{0}` — so `bash -c 'exit 0; {0}'` and an extra
  bare word are "not judged"; a `workflow_call` caller must be shape-sound
  and its job must already hold the called job's scopes; `types` / `workflows` are named as
  unevaluated and an empty `types:`/`workflows:`/`schedule:` fails; an empty
  job-level `permissions:` grants nothing; only `generator_generic_slsa3.yml`
  at a `vX.Y.Z` tag (a SHA pin is refused) is the generator; a test holds the
  generator tag identical across `.sscsb/config.toml`, both `release.yml`s,
  `release-slsa.yml`, both `deploy-gate.yml`s and the docs. Beyond these, no
  further gates: `with:`/`run:` text as written, `$(…)`, control flow beyond
  the failure path of the compound whose CONDITION holds the signing —
  including an `if`/`else` BODY or a `case` ARM the signing line sits in
  (the signing there IS seen — the arm's `release)` pattern is skipped so the
  command word is `cosign` and every gate applies — but whether the arm is
  ever taken is not asked), a signing command
  reached later in the same condition list (`if other && cosign …; then`),
  and the `errexit` exemption for `&&` / `||` lists, which loses a
  `cosign … && echo ok` failure when further commands follow it —
  `/usr/bin/cosign`, a `cosign` shim placed on `$GITHUB_PATH` (or a `cosign`
  function exported through `$BASH_ENV`) by an earlier step, a non-literal
  option word (`OPTS=+e; set $OPTS` — the value is text, not a toggle), a
  custom `shell:` template that omits `-e` (`bash {0}`, `sh {0}` — the body
  is graded as if fail-fast were on) and a `trap` that rewrites the step's
  status, a suppression applied to a `{ …; }` / `( … )` group from the
  outside (`( … ) &`, `{ …; } || true` — the recognizer reads the separator
  that ends the signing command itself, and walks a `&&` list forward to its
  terminating branch, but never the group's, on one line or across many), a
  sound body that re-raises a failed signing outside the enumerated
  condition and captured-status shapes (a `trap`, a flag checked in a later
  STEP, a helper function that exits, a status relayed through a second
  variable — `rc=$?; status=$rc; exit "$status"` — since the walk follows a
  captured status' loss but never its copy: fail-closed, as with the retry),
  an `until` retry whose body can only loop, which is graded sound because a
  failed signing never reaches a green step even though the way it never
  does may be the job's timeout rather than an exit, and whose `break` is
  counted at any depth so a `break` that leaves only an INNER loop is
  over-counted, the rest of the class that `break` belongs to — a command
  that ends or diverts the shell without being an `exit` / `return` this walk
  can see: a `trap` that rewrites the status, `exec CMD` (which REPLACES the
  shell process, so `[ -f dist/skip ] && exec true` before the re-raise, and
  `exec true` as an `else` arm, both PASS while exiting 0 with the signing
  failed), and `eval STRING` (whose string is never parsed, so
  `eval "exit 0"` passes and the sound `eval "exit \$rc"` is failed) — an
  AND-OR list backgrounded or
  piped as a whole (`cosign … && echo ok &`), a `wait` on anything but a
  literal `$!` immediately after (`pid=$!; wait "$pid"`),
  filter globs, non-literal `if:`, whether the workflow ever ran, and
  the runner OS (`runs-on:` is not read — a step with no `shell:` is judged
  as POSIX) are disclosed, not claimed.
- **The Octo STS trust policy `sscsb init` installs never matched GitHub's
  OIDC subject.** GitHub decorates the `sub` claim with ids —
  `repo:OWNER@<owner_id>/REPO@<repo_id>:ref:refs/heads/main` — and the
  template's `subject_pattern` was spelled from names alone, so Octo STS
  refused every exchange (observed live: `subject "repo:p4gs@10093271/
  p4gs.github.io@1354031532:ref:refs/heads/main" did not match
  "repo:p4gs/p4gs.github.io:ref:refs/heads/main"`). The template now renders
  `repo:OWNER(@<owner_id>)?/REPO(@<repo_id>)?:ref:refs/heads/<branch>` with
  `.` in the repository name escaped; the ids are resolved through `gh api
  repos/<slug>` / `users/<owner>` when `gh` is available, and otherwise
  rendered as `[0-9]+` with a `note` line in the `init` log naming the two
  commands that pin them.

### Changed (this repository's own release pipeline)

- The `publish` job's already-published re-run guard is decided **once**, in
  a first step that records `published=true|false` to `GITHUB_OUTPUT`; every
  later step (collect, refuse-incomplete, create-draft-and-upload, confirm,
  publish) is gated on `steps.published.outputs.published != 'true'`. Before,
  the guard lived inside the upload and publish steps only, so a re-run of a
  published tag still downloaded the set, re-checked it, and re-downloaded
  the draft's assets before finding nothing to do. Same change in the shipped
  `templates/workflows/release.yml`; the parity test holds the two together.
- `.github/chainguard/sscsb-automation.sts.yaml` pins this repository's own
  ids: `repo:p4gs(@10093271)?/sscs-bootstrapper(@1156341487)?:ref:refs/heads/main`.

- `.github/workflows/release.yml` now generates **SLSA Build L3 provenance**
  via `slsa-framework/slsa-github-generator` (`generator_generic_slsa3.yml@v2.1.0`,
  `upload-assets: false`) over the sha256 subjects of the shipped tarballs,
  and uploads the resulting `*.intoto.jsonl` to the **draft** release with the
  other assets before the single publish. The earlier premise that the
  generator is incompatible with release immutability was wrong; the
  `slsa-provenance` control is re-enabled in `.sscsb/config.toml`.
- `.github/workflows/deploy-gate.yml` is now a `workflow_call` reusable gate
  that `release.yml` runs between provenance and publish (`publish` `needs:`
  it): checksum sidecars, every Cosign bundle against an anchored,
  regex-escaped identity of `release.yml@refs/tags/<tag>`, `gh attestation
  verify` for `https://slsa.dev/provenance/v1` and `https://cyclonedx.org/bom`
  with `--signer-workflow` and `--source-ref`, and `slsa-verifier
  verify-artifact` with `--source-uri`, `--source-tag` and the pinned
  `--builder-id`. `workflow_dispatch` with a tag remains as a manual
  re-verify of a published release. The first tag pushed after this change is
  the pipeline's first real run; every gate is fail-closed.
- `.sscsb/config.toml` pins `builder_id` under `[controls.provenance-verify]`
  to the same `generator_generic_slsa3.yml@refs/tags/v2.1.0` that
  `release.yml` calls and `deploy-gate.yml` verifies against, so `sscsb
  provenance verify` needs no `--builder-id` here and the three cannot drift
  silently.

## [0.3.0] - 2026-09-01

### Added

- **`sscsb verify --format json` and `sscsb status --format json`.** Machine-
  readable output for the two commands whose results external consumers (CI
  pipelines, the upcoming public scan directory) need to parse. The document is
  schema-versioned (`schema_version: 1`); outcome strings are the five pinned
  lowercase literals `pass|fail|degraded|disabled|info`; each verify row also
  carries the control's registered `artifacts` paths so a consumer's
  artifact→control map can never drift from the binary that scanned. Exit-code
  semantics are identical in both formats, and an unknown `--format` is a usage
  error (exit `2`) before any control runs — not a silent fallthrough to text.
  All JSON assembly lives in the new `src/machine.rs`, inside the coverage
  gate; `report --format json` (the static control dictionary) is unchanged.

## [0.2.1] - 2026-08-25

### Fixed

- **The identity-blur check compared path strings, not keys.** The agent lane's
  guard tested `user.signingkey` **paths** for equality. Git accepts the
  private-key path and its `.pub` sibling interchangeably, so an agent pointed at
  `~/.ssh/key` while the human's global config said `~/.ssh/key.pub` was using
  **the same key** and no blur was reported: the lane read CONFIGURED, `verify
  signing-model` returned no failure, and the agent signed with the human's
  registered key. Symlinks and `~`-versus-absolute spelling evaded it
  identically. This defeated the module's central invariant — the agent never
  signs as the human — in shipped code. The comparison is now on key
  **material**: paths are expanded and canonicalised, a private path resolves to
  its public half, and the decoded key blob is compared with the comment
  dropped.
- **The same defect was encoded in the test suite.** The `fully_configured_machine`
  fixture gave the human and the agent the same key blob under two filenames, so
  the fixture asserting the control's PASS verdict was describing a genuinely
  blurred machine. A path comparison could never notice, which is why the suite
  could not have caught the source defect.
- **An agent email differing only in case passed both the probe and the setup
  refusal.** Comparisons were byte-exact; email attribution is not. Both sites
  now case-fold.
- **`signing setup --confirm` destroyed the attestation store** when the policy
  file failed to parse: the read fell through to a blank document, which was
  written back containing only the lane just confirmed. Every other lane's
  attestation was lost and the command reported success. An existing, unparseable
  file is now a hard error, matching the contract the JSON settings merge in the
  same module already followed.
- **`attribution: null` read as a configured cloud lane**, because the check
  tested presence rather than shape. That also defeated the guard preventing an
  attestation from papering over a probeable gap. A real, non-empty object is now
  required.
- **The `git sign` alias broke for any name or email containing an apostrophe**,
  silently, after reporting success. That alias is the documented protection
  against a bare `git commit` signing as the agent, so its breakage pushed the
  user onto the exact footgun it prevents. Values are now shell-escaped.
- **A `~`-prefixed `user.signingkey` read as a missing file.** Git expands `~`;
  a string comparison does not. A working configuration was reported broken.
- **A personal key basename was hard-coded into the public binary.** The agent
  key basename is now derived from the agent's own identity. The old name is
  retained solely so a machine already carrying that key reuses it rather than
  silently rotating and orphaning the key its past commits were signed with; it
  never names a new key.
- **A corrupt global gitconfig silently disabled the blur refusal.** An
  unreadable value was indistinguishable from an unset one, so a security guard
  failed open. The two are now distinguished.

## [0.2.0] - 2026-08-25

### Fixed

- **A typo'd control id read as a clean run.** `sscsb verify not-a-real-control`
  filtered the registry down to nothing, ran zero controls, printed
  `verify: 0 failed, 0 degraded` and exited `0` — so a typo in a CI invocation
  was indistinguishable from a genuine clean verification of a control that
  never existed. An unknown id is now a usage error and exits `2`, naming the
  id and listing the valid ones. The check runs before any control does, so a
  partially-valid invocation (`sscsb verify secrets not-a-real-control`) also
  exits `2` and verifies nothing rather than passing `secrets` and never
  mentioning the typo. `enable`/`disable` already behaved this way; both routes
  now share one rule. This is a behaviour change for anyone whose CI passes a
  control id that was silently ignored — such a run was never verifying what it
  claimed.

- **A bare TOML key in a `pyproject.toml` was read as a dependency.** A manifest
  whose entire contents were `name = "throwaway"` made `sscsb deps check`
  report `pypi:name` as `NOT FOUND on its public registry — likely hallucinated
  (slopsquatting target)` and exit `1`. The parser decided TOML-vs-line-scan by
  sniffing content — a document counted as a pyproject only if it contained
  `[build-system]`, `[project]`, `[dependency-groups]` or `[tool]` — so a
  manifest announcing none of them fell through to the requirements.txt line
  scanner. The filename now decides: anything named `pyproject.toml` is parsed
  as TOML and never line-scanned, which also covers a malformed pyproject (no
  content sniff can classify a file it cannot parse, and that case invented the
  same phantom package). A false "hallucinated package" verdict is worse than a
  miss — it trains users to run `deps approve` on noise.

- **The pre-commit SAST gate could not be made to hold.** Its arm degraded open
  unconditionally — a missing engine, or a mistyped `[controls.sast] engine`
  name, printed a notice and let the commit through — while the secret-scan arm
  beside it respected `general.fail_open`. That setting is documented as the
  one opt-out for every hook ("would let hooks pass when scanners are missing.
  Keep false"), and a comment in this same file already described the SAST arm
  as using that shape. It does now: `fail_open = false` (the default) blocks
  when the gate you switched on could not run, and `fail_open = true` warns.
  Being opt-in was the argument *for* the switch applying, not against it — a
  user who turns a gate on should be able to make it hold.
- **`sscsb verify` reported PASS for a SAST engine `sscsb sast` refuses to
  run.** The verifier detected the configured engine by falling back to the
  OpenGrep tool spec for any name it did not recognise — and the tool registry
  holds every tool `sscsb` orchestrates, so `[controls.sast] engine = "trivy"`
  found a real, installed Trivy and reported the control as passing, printing
  `trivy: 0.74.0` as its evidence, while `sscsb sast` errored with `unknown sast
  engine`. The supported engines are now one list consulted by both the runner
  and the verifier, and an engine outside it is a **FAIL** naming the valid
  choices, with no version line borrowed from another tool.
- **SAST severity handling lost findings three ways.** All three ended with the
  gate saying "clean" about something it had not cleared:
  - the results JSON's `errors` array was dropped entirely. Both engines report
    a file they could not parse there and still exit `0` with results —
    measured on opengrep 1.25.0 and semgrep 1.169.0, which both emit a
    `PartialParsing` entry for a file whose bytes are not the language it was
    read as. A staged file nobody parsed was reported as a staged file with
    nothing wrong in it. Those entries are now carried on the scan: in
    pre-commit an unreadable staged file is an error governed by
    `general.fail_open`, and `sscsb sast` names each uncovered part of the tree.
    An `errors` entry at a level that is not a warning fails the scan outright.
  - a finding whose severity could not be read defaulted to `WARNING`, i.e.
    advisory, i.e. it stopped gating. One renamed or moved field in the engine's
    schema would have quietly demoted every finding in the scan. It is now
    `UNRATED`, which blocks — the rule H6 set for advisories, applied here.
  - only the literal `ERROR` gated. Both engines accept and echo back a rule
    declaring `severity: CRITICAL` or `HIGH` (measured), so the two strictest
    severities a rule can carry passed straight through the gate that exists to
    stop them. The advisory set (`INFO`, `WARNING`, `LOW`, `MEDIUM`) is now what
    is enumerated, and everything else blocks.
- **A SAST scanner that was killed reported a clean scan.** `run_sast` gated
  the Semgrep engine on `exit status > 1`. A process killed by a signal — the
  OOM killer, a CI timeout's SIGKILL, a segfault — has no exit code at all,
  and the execution layer recorded that as `-1`, which is not greater than 1.
  So an abnormal death ranked *below both success codes*: whatever the scanner
  had managed to print was parsed, and a scanner killed after emitting
  `{"results":[]}` reported zero findings, cleanly. `CmdOutput` now carries the
  terminating signal alongside the code, `exit_code()` returns `None` when
  there was no exit, and both engines accept only the exit codes their
  contracts document (OpenGrep 0; Semgrep 0 or 1). Everything else — including
  no exit at all — is a failed scan, and the diagnostic names the signal
  instead of printing a fabricated exit code.
- **Every staged binary file was corrupted before it was scanned.**
  `stage_to_tempdir` materialises each staged blob by running `git show
  :<file>` and writing the result out, and the process-execution layer decoded
  that stdout with `String::from_utf8_lossy` — which replaces every byte
  sequence that is not valid UTF-8 with U+FFFD, three bytes of `EF BF BD`.
  Measured: a 264-byte staged PNG arrived in the scan directory as 522 bytes,
  and a staged, valid zip failed its own CRC — the reported "zipfile corrupt"
  symptom. This cost twice over: the secret scanners and the pre-commit SAST
  scanner both read bytes that were never in the repository, and so did
  anything else that opened that directory. Staged blobs are now carried as
  bytes end to end, through a new `exec::run_bytes`/`RawOutput` path that
  exists precisely to keep file content out of the lossy `String` channel.
- **A bumblebee scan reported PASS while silently dropping what it could not
  read.** The control read the tool's stderr only when the exit code was
  non-zero — and a successful run is the only place that stream carries
  anything. Measured against v0.1.2 on a real machine: a `baseline` scan over
  464,986 files emitted
  `{"record_type":"diagnostic","level":"warn","path":"…/mcp_config.json",
  "message":"parse MCP config: unexpected end of JSON input"}` on stderr, exited
  `0` with a `status:"complete"` summary, and the control reported PASS with one
  message. That MCP config was never matched against the catalog. Diagnostics are
  now parsed on every run: non-`info` levels print verbatim with the path they
  name and a clean verdict drops to `DEGRADED` (the rung `package-trust` already
  uses for input it cannot read, and the one `--strict` gates on). `info` is
  per-run bookkeeping and is counted, not reprinted; non-record stderr lines
  (bumblebee's fatal errors are bare text) are surfaced verbatim.
- **The bumblebee inventory guard could not tell "scanned the endpoint" from
  "counted the Cellar".** Its "no subjects" refusal read one aggregate counter.
  On a real machine that counter was 16,912 — all Homebrew receipts — while every
  class the control exists for went unopened: MCP configs, editor extensions,
  browser extensions, agent skills. `--findings-only` suppresses the per-package
  records, so the summary's `roots[].kind` list is the only per-class signal
  there is. A clean run now states which endpoint classes it covered, and one
  that reached none of them is not a PASS: `DEGRADED` under
  `profile = "project"`, which cannot reach those roots by construction and is
  fixable from config, and `INFO` under `baseline`, where their absence means the
  endpoint genuinely has none.
- **`[controls.bumblebee] profile` had two different defaults.** The registry
  declared `"baseline"` and the code fell back to `"project"`, so the control
  scanned a different surface depending on whether the config key happened to be
  present — and `project` inventories nothing at all on a Rust repository. The
  runtime default is now read from the registry rather than repeated as a
  literal. An absent key means the registry default; a NAMED but unrecognised
  profile (including an attempt at the `$HOME`-walking `deep`) still narrows to
  `project` and is still reported as a coercion. The `INFO` hint printed when no
  catalog is configured was telling users to set `profile = "project"` — the
  value that produces the zero-subject FAIL — and now prints the real default.
- **The pre-commit hook and the report disagreed about whether SAST was on.** The
  registry declares `sast` enabled by default; the hook read that state with a
  hard-coded `false` fallback. Measured against a config of
  `[controls.sast]` carrying `pre_commit = true` and no `enabled` key: the hook
  saw `enabled=false` while `status` and `verify` saw `enabled=true` — the user
  has explicitly asked for the commit gate, the report says the control is
  installed, and every commit goes through unscanned. The fallback now lives once in
  `Config::control_enabled_or_default`, reading `ControlDef.default_enabled`, and
  a source-scanning test bans any call site from carrying its own copy.
  (`[controls.sast] pre_commit = false` is a separate key, is deliberately false
  in both places, and is now asserted rather than assumed.)
- **Five keys in the generated config did nothing.** `.sscsb/config.toml` is
  generated from the control registry, so every key in it reads as a control the
  user has set. `signing-model.agent`, `signing-model.human_backend`,
  `package-trust.typosquat_check` and `harden-runner.egress_policy` had no reader
  at all, and `package-trust.registry_check` changed only the sentence `verify`
  printed while the lookup ran regardless. The two `package-trust` keys are now
  real, gating all three places their checks run — `deps check`, approval-time
  warnings, and the commit-msg gate that actually blocks — with `verify`
  reporting `INFO` when either is off and `deps check` saying so once per run.
  Neither key can re-enable resolving a `path`/`git`/`url` dependency by name:
  that source guard is correctness rather than policy, so it runs first and
  unconditionally, and suppressing an annotation never unblocks the dependency.
  The other three were removed: honouring `agent`/`human_backend` means
  implementing multi-backend signing support, and
  `egress_policy`'s only non-default value is `block`, which harden-runner
  enforces against an `allowed-endpoints` allowlist sscsb cannot synthesise —
  a generated `block` would break the first `actions/checkout` in every workflow.
  A test now asserts every `default_options` key has a reader in production code.
  Note that `sscsb init` never overwrites an existing config, so removed keys
  linger in configs already written; they are ignored, exactly as before.

- **A file committed to the repository silently muted the scanners.** Trivy
  reads `trivy.yaml` and `.trivyignore` from the directory it scans;
  OSV-Scanner reads `osv-scanner.toml` from the tree. None of it is asked
  for — committing the file is the entire install step. Measured on one
  fixture: a `trivy.yaml` of `severity: [CRITICAL]` took a scan from 3 findings
  to 1, and one `[[IgnoredVulns]]` entry took OSV-Scanner from 8 to 6, with not
  one `note:` or `suppressed:` line to show for it.
  The fix **inherits the waiver and reports it**, rather than overriding it —
  these files are legitimate, and this repository's own `.trivyignore` is the
  example (two container rules that genuinely cannot model an OSS-Fuzz build
  image, with per-ID rationale in the file). Overriding them would break that
  class of documented waiver, and would push anyone who needs one into turning
  the control off. So suppression is honoured and *named*, the way `apply_vex`
  already did it, in two layers:
  - the scanners' own suppression channels — Trivy's `--show-suppressed` and
    OSV-Scanner's stderr — now yield one `suppressed:` row per muted finding,
    carrying the source (`.trivyignore`, a VEX document) and the reason its
    author wrote. OSV-Scanner states this on stderr and nowhere in its JSON,
    not even under `--all-vulns`; discarding stderr on success was what made
    an `osv-scanner.toml` invisible.
  - `sscsb` names every scanner-config file it finds and what that file does.
    This is the only signal there is for `trivy.yaml` narrowing, which Trivy
    reports nothing about even under `--show-suppressed` (measured on 0.72.0),
    and it is the backstop if a scanner's output shape changes underneath the
    first layer. `sscsb verify` states the same inventory without changing the
    verdict: a documented waiver is a decision, not a failure.
- **A severity we could not determine ranked below `low`, so real advisories
  could not breach the gate.** `severity_rank` ended in `.unwrap_or(0)`: every
  string that was not one of `low|medium|high|critical` ranked *beneath the
  weakest severity*, and therefore could not breach any threshold. Three
  consequences, all measured against live tools:
  - `parse_osv` read severity only from `/database_specific/severity`, a field
    RUSTSEC and PYSEC records do not carry — 13 of 25 findings in an
    `osv-scanner 2.4.0` run landed as `unknown` and could not breach
    `fail_on = "high"`. Severity is now recovered from the fields those records
    *do* populate: the OSV `severity` array's CVSS vectors (scored with the
    CVSS v3.0/v3.1 base-score formula) and `affected[].database_specific.cvss`.
    Where a record states a rating more than one way, the highest wins.
  - GHSA's `MODERATE` ranked 0 because it is not the literal string `medium`.
    The two vocabularies are now bridged.
  - What remains genuinely unrated breaches *every* threshold rather than
    passing as `low`, and is reported as a note with its count. The way to
    waive one is a VEX statement — visibly, like every other suppression.
  A CVSS v4.0 vector is left undetermined rather than guessed at; scoring it
  needs the v4 macro-vector tables, and inventing a band is how a gate starts
  lying.
- **A typo'd `fail_on` silently became the strictest setting.** `fail_on =
  "error"` ranked 0, i.e. `low`, i.e. everything breaches — a broken gate that
  looks like a working one. A `fail_on` that is not a severity is now an error
  naming the valid values. Case and stray whitespace (`"HIGH "`) are still
  accepted as the threshold their author meant.
- **Five controls reported `PASS` for checks that never ran.** `sscsb`'s value
  rests on a green `verify --strict` meaning the named controls actually work,
  and `--strict` only escalates `DEGRADED` — so a false `PASS` sailed straight
  through CI. Each of these now reports `DEGRADED`, with the reason:
  - `branch-protection` passed when the GitHub rules API answered for **no**
    configured branch (e.g. a slug that does not exist): the failing-query arm
    pushed a message and `continue`d without touching the verdict.
  - `scorecard` passed when `gh` was absent, when no repo slug could be
    resolved, and when the code-scanning query failed — while every other
    gh-dependent control in the same run correctly degraded.
  - `package-trust` reported an unparseable `.sscsb/policy/packages.toml` as
    `approved baseline present (0 package(s))` and passed.
  - `dependency-track` passed on a non-empty `url` string plus `DTRACK_API_KEY`
    merely being *set*; `verify` now probes `GET /api/version` (5s bound, key in
    the header) so an unreachable server or a rejected key degrades instead of
    passing and then failing at upload time.
  - `model-signing` and `gittuf` passed with the declared tool absent, while
    `sscsb status` said `…:missing` in the same session. An installed workflow is
    not a signature, and a `refs/gittuf/*` ref is a name anyone can create with
    `git update-ref`.
- **The new-package commit gate failed OPEN on a corrupt policy file.** Deleting
  `.sscsb/policy/packages.toml` already failed closed (every dependency reads as
  unapproved), but corrupting it printed "package-trust check skipped" and
  returned `0` — one appended line switched the gate off. It now fails closed,
  with `fail_open = true` as the single explicit opt-out, matching the
  secret-scan and SAST arms of the same hook.
- **A file on `PATH` counted as an installed tool.** `find_in_path` accepted any
  regular file and `detect` swallowed the version probe's failure, so a
  three-line shell script nobody made executable, named `guacone`, took
  `sscsb verify --strict guac` from exit 1 (DEGRADED) to exit 0 (PASS,
  "guacone ? available"). Reproduced end to end. A candidate must now be
  executable, and the probe must run, exit 0, and say something: a present but
  broken install is not a working tool. This is the root of the class — every
  orchestrated tool resolves through the same lookup, so cosign, slsa-verifier,
  guacone, oras and witness are all covered by it. Unparseable versions are
  still accepted (`sighthound` reports two components), because calling a
  genuinely installed tool missing would be the opposite error; an *executable*
  stub that prints anything still detects, and telling a real tool from an
  impostor needs binary checksum pinning, which is a separate control. The
  degrade message now distinguishes "not found on PATH" from "found at <path>
  but its version probe did not succeed".
- **`sscsb receipt create -- --raw` exited 101.** `git rev-parse` echoes an
  unrecognised option back at exit 0 when `--verify` is absent, so the resolved
  "sha" was `--raw` and the receipt filename's twelve-character slice ran off
  the end of it. `--verify --end-of-options` (added the same day for an
  unrelated injection fix) already stopped that particular input; the slice
  itself is now behind a full-object-name check, because `is_object_name`
  admits abbreviations from seven characters and any resolver answer between
  seven and eleven still aborted the process. A CLI must not panic on its own
  argument.
- **A receipt's actual claim was never verified.** `receipt verify` recomputed
  the patch digest and stopped. The AI trailers live in the commit *message*,
  which `git show --format=` does not print, so the digest covers none of them:
  a receipt whose `aiTool` disagreed with the commit it named verified at exit
  0, and deleting the declaration outright — laundering AI-assisted work into
  apparently unassisted work — was equally invisible. The commit's trailers are
  now re-read and diffed field by field (`CLAIM MISMATCH`). Separately,
  `receipt create --sign` wrote a cosign bundle that nothing ever read, so a
  signed receipt and an unsigned one verified identically; any bundle beside a
  receipt is now put to `cosign verify-blob` against an expected identity, from
  `--identity` or the new `cosign_identity`/`cosign_issuer` options. A bundle
  that is present but *unverifiable* — no identity, or no cosign — is an error,
  not a footnote: "receipt verified" must not be printable next to a signature
  nobody looked at.
- **`provenance verify` pinned the source repository and nothing else.**
  `--builder-id` is optional to slsa-verifier, so an unpinned run asserted only
  that *some* builder slsa-verifier trusts produced the provenance for that
  source URI — anyone able to get any trusted builder to run in the repository
  cleared the gate. A trusted builder is now required, from `--builder-id` or
  `builder_id` under `[controls.provenance-verify]`, and resolved before the
  tool-availability check, because an unpinned builder is a policy gap whether
  or not slsa-verifier is installed. Not defaulted: a default has to name one
  generator, and one that is wrong for a repo narrows the gate silently or gets
  copied without thought. `--source-tag` stays optional — branch builds are
  legitimate — but the verdict now states `source tag NOT pinned` rather than
  letting "verified" carry more weight than it earned. The shipped
  `deploy-gate.yml` and `release-slsa.yml` workflows had the same gap and now
  pass a `BUILDER_ID` tied to the generator they pin.

### Changed

- `scorecard` reports `INFO` rather than `PASS` when the live scan returns open
  Scorecard findings. sscsb does not re-gate on another scanner's rubric — each
  finding is routed to the sscsb control that owns it — but printing open
  findings under a `PASS` verdict manufactured assurance.

## [0.2.0] — 2026-08-24

The distribution release: `sscsb` becomes installable by someone who is not its
author, and drivable by an AI agent that has never seen it.

### Added

- **Homebrew install.** `brew install p4gs/p4gs/sscsb`. The release now builds
  real binaries for `aarch64-apple-darwin`, `x86_64-apple-darwin`, and
  `x86_64-unknown-linux-gnu`; v0.1.0 shipped a single Linux target.
- **`AGENTS.md`** — the machine-facing contract: every subcommand, the exit-code
  semantics (`0` pass / `1` gate failed / `2` tool error), the five verdicts and
  why `DEGRADED` is not `PASS`, the config model, and the AI-cannot-sign
  invariant. Pinned to the binary by `tests/agents_md.rs`, so a renamed
  subcommand breaks the build rather than silently misleading an agent.
- **Claude Code skill** at `.claude/skills/sscsb/SKILL.md`, routing
  supply-chain-security asks to the right subcommand.
- **`sscsb signing`** (`status` / `setup` / `verify`) — the multi-environment
  commit-signing model. Verifies and converges the *developer's environment*,
  where signing actually breaks, rather than only the repository's policy.
- **Five OpenSSF controls**: OSPS Baseline, Security Insights, Model Signing,
  gittuf, and the Best-Practices Badge.
- **`bumblebee`** — endpoint exposure scanning, as a phase-2 control.
- **Threat & Control Model** diagram and table in the README.

### Changed

- Release pipeline builds a full platform matrix and refuses to publish an
  incomplete set — a partial platform set is a failed release, not a small one,
  because a formula pinned to a missing asset installs nothing. Checksums are
  computed centrally so every digest comes from one implementation.
- The 1Password SSH key is registered as an approved human signer.
- Control count: 37 → 44.

### Fixed

- **VEX suppression was too broad.** A `not_affected` statement suppressed
  matching findings regardless of which product or ecosystem it was scoped to,
  so a suppression written for one component could silently hide a real finding
  in another.
- **AI-merge review gating checked for the wrong thing.** The hook validated
  that a review-evidence trailer *key was present* rather than that the evidence
  it named was real, which a well-formed but empty trailer satisfied.

### Documentation

- The hermetic test invocation is documented, because the suite builds real git
  repos and verifies real signatures — the host's git identity leaking in
  produces mass failures that look exactly like regressions and are not:

  ```sh
  GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null cargo test
  ```

## [0.1.0] — 2026-07-21

Initial release. Five phases, 37 controls, orchestrating TruffleHog, Gitleaks,
Syft, Trivy, OSV-Scanner, Cosign, slsa-verifier, OpenGrep, Scorecard, Octo STS,
Harden-Runner, Dependency-Track, and GUAC behind one policy engine.

- Phase 1 — commit integrity: secret scanning at pre-commit and pre-push,
  human-only signing on protected branches, branch-protection verification,
  Actions auditing, AI-provenance commit trailers.
- Phase 2 — dependencies: CycloneDX SBOMs, vulnerability scanning, Scorecard,
  Renovate with digest pinning, package-trust and typosquat heuristics.
- Phase 3 — provenance: keyless signing, SBOM and provenance attestations bound
  to artifact digests, SLSA Build L3, short-lived credentials, Harden-Runner.
- Phase 4 — code analysis: OpenGrep SAST, CodeQL, extended workflow auditing.
- Phase 5 — continuous posture: Dependency-Track, GUAC, OpenVEX, and a
  machine-readable control → SLSA/SSDF/CRA map behind `sscsb report`.

[0.2.1]: https://github.com/p4gs/sscs-bootstrapper/releases/tag/v0.2.1
[0.2.0]: https://github.com/p4gs/sscs-bootstrapper/releases/tag/v0.2.0
[0.1.0]: https://github.com/p4gs/sscs-bootstrapper/releases/tag/v0.1.0
