# Release package rehearsal

Use the **Release package rehearsal** workflow against the approved candidate
ref. Verify the run identifies the intended commit before relying on it. This
dispatch does not need a tag. It calls the same build workflow as production:
native macOS ARM, macOS Intel and Linux x64 runners build with the committed lock,
extract the actual packages, and verify their version and contents. Download the
three packages and `rehearsal-sha256s` from the same run. Recheck their checksums
together before using any package as rehearsal evidence.

The rehearsal grants GitHub repository read permissions only. It does not run
the SLSA reusable workflow, write attestations, sign packages, or create a
release. GitHub stores the workflow artifacts temporarily. Treat these as
unpublished test artifacts, not as production release assets.

## Gates before a production tag

- Merge the reviewed candidate; confirm locked CI and applicable security checks
  on the exact revision. Check that the Cargo package/lock and changelog name the
  intended version.
- Rehearse all three packages against that revision. Check that every native
  smoke run and the checksum job passed. Do not reuse test artifacts as uploads.
- Where available, exercise signing, attestations and the deploy gate in an
  eligible **isolated** repository whose workflow cannot publish production
  releases. A non-production repository has its own signer identity and cannot
  prove the production tag binding. The tag-bound SLSA generator is not called
  by the package rehearsal; it needs an independently approved, exact-version
  test path. Its upload switch does not remove the workflow's permission ceiling.
- A matching numeric tag can **publish automatically**. Do not push one for a
  test. Only push the approved production tag; verify the release run's commit,
  runs/attempt, checked builder revision, verified SBOM/provenance and signatures,
  and exact draft-asset read-back before relying on the public result.
- If a rehearsal fails, leave the production tag untouched, investigate and
  repeat on the corrected, reviewed revision. If an immutable release already
  published, do not rewrite its tag or assets; make a corrective release instead.
