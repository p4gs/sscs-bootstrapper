#![no_main]
//! Fuzz sscsb's GitHub Actions workflow/action YAML auditor (untrusted
//! `.github/workflows/*.yml` and local composite `action.yml` content — a
//! pull request from someone sscsb has never trusted can shape both).
//!
//! This target existed as an orphaned corpus directory with no matching
//! target (issue #43) before the corpus was ever seeded with a real one.
//! Building it is what actually found the bug the corpus's existence
//! implied someone once suspected: `audit_workflow`/`audit_action_file`
//! parse content with `yaml-rust2`, which applies no bound to YAML
//! alias/anchor expansion through at least its 0.13.0 release — a
//! "billion laughs" document under 600 bytes ran past three minutes before
//! being killed in manual measurement. `audit.rs::parse_workflow_yaml` now
//! bounds that parse on a wall-clock budget rather than trusting the
//! library to bound itself, so a corpus entry shaped like that no longer
//! hangs this fuzzer (or, in production, `sscsb verify` / `sscsb audit`) —
//! it is refused in the two seconds `YAML_PARSE_BUDGET` allows, which is
//! exactly the property this target exists to keep proven under fuzzing
//! rather than only under the one hand-written regression test.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    // `extended: true` exercises every analysis path audit_workflow can
    // reach, not just the basic SHA-pin/permissions check.
    let _ = sscsb::audit::audit_workflow("fuzz.yml", s, true);
    let _ = sscsb::audit::audit_action_file("fuzz-action.yml", s);
});
