//! The two disclosures that live only in prose must stay written down.
//!
//! `src/workflows.rs` can hold itself honest with a test; a limitation that
//! is *deliberate* and can only be disclosed cannot. Two of those arrived
//! together:
//!
//! - Gate 4 reads a `||` branch that RETRIES the signing
//!   (`cosign … || cosign …`) as swallowing, because `command_propagates`
//!   accepts only `exit`/`return` non-zero, `false` and `kill`. That is
//!   fail-closed and correct, but it means a sound retry cannot be written
//!   as an `||` pair — and a reader who is not told that will read the
//!   verdict as a bug. `docs/phase-3.md` says so, and the CHANGELOG mirrors
//!   it.
//! - The condition gate and the `set +e` gate were narrowed so that sound
//!   "check and fail" bodies stop failing. What they still refuse is
//!   fail-closed, so the shapes they ACCEPT have to be enumerated in prose —
//!   a maintainer the gate fails needs a shape to write. `docs/phase-3.md`
//!   lists them and the CHANGELOG mirrors it. The enumeration is pinned
//!   word for word because a LOOSE description of it is what let two
//!   evasions through: prose that ORed the failure arm with the command
//!   after the terminator, and prose that called the captured status "a
//!   parameter" rather than the signing's own `$?`. The stale spellings are
//!   asserted absent, not just the corrected ones present.
//! - `SSH_AUTH_SOCK` is the third way the host's identity leaks into the
//!   suite, and the only one whose symptom is a hang rather than a failure.
//!   `CLAUDE.md` prescribes unsetting it in the command it tells every agent
//!   shell to run.
//!
//! Same shape as `tests/readme.rs` and `tests/agents_md.rs`: a doc that
//! lies costs more than one that is merely thin.

const PHASE_3_MD: &str = include_str!("../docs/phase-3.md");
const CHANGELOG_MD: &str = include_str!("../CHANGELOG.md");
const CLAUDE_MD: &str = include_str!("../CLAUDE.md");

/// The document with every run of whitespace collapsed to one space, so a
/// claim can be asserted as the sentence it is rather than as the lines the
/// author happened to wrap it into.
fn unwrapped(doc: &str) -> String {
    doc.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_states(doc_name: &str, doc: &str, claim: &str) {
    assert!(
        unwrapped(doc).contains(claim),
        "{doc_name} must state {claim:?}"
    );
}

/// Gate 4's retry clause: the defect is named as deliberate, and the shape
/// that expresses a retry the gate accepts is spelled out.
#[test]
fn phase_3_discloses_that_a_retrying_or_branch_is_read_as_swallowing() {
    for claim in [
        "a branch that **retries** the signing — `cosign … || cosign …` — is read as swallowing",
        "because a second `cosign` is not `exit`/`return` non-zero, `false` or `kill`",
        "that is the fail-closed side of the trade, not an oversight",
        // The way out, so the clause is actionable and not just an apology.
        "Express a retry that passes as a loop whose **exhaustion** fails the step",
        "`[ -n \"${signed:-}\" ] || exit 1`",
    ] {
        assert_states("docs/phase-3.md", PHASE_3_MD, claim);
    }
}

/// The CHANGELOG carries the same clause, in the sentence that enumerates
/// what the suppression gate catches.
#[test]
fn the_changelog_mirrors_the_retry_clause() {
    for claim in [
        "a branch that RETRIES the signing (`cosign … || cosign …`) is read as swallowing too, \
         deliberately",
        "a sound retry has to be written as a loop whose exhaustion fails the step",
    ] {
        assert_states("CHANGELOG.md", CHANGELOG_MD, claim);
    }
}

/// The two narrowed gates are only honest if the shapes they accept are
/// written down: a maintainer failed by the condition gate or the `set +e`
/// gate has to be able to read off a shape that passes. Both lists are
/// enumerations, not descriptions, so they are pinned here.
#[test]
fn phase_3_enumerates_the_shapes_a_narrowed_gate_accepts() {
    for claim in [
        // The condition gate: the ARM is asked first, and the command after
        // the terminator only when that arm falls through. Pinned in that
        // order, because the ORed version of this sentence is exactly the
        // wording the code had to stop matching.
        "the gate asks what the shell runs when the signing fails, and it asks the **arm** \
         first: the `else` arm, or the `then` arm when the test is negated",
        "`exit` / `return` with a literal non-zero status or none at all, `false`, or `kill`",
        "so `if cosign …; then echo signed; else exit 1; fi` and `if ! cosign …; then exit 1; \
         fi` both pass",
        "The command immediately after the compound's terminator is consulted **only when that \
         arm falls through**",
        "An arm that ENDS the shell without propagating makes everything after the terminator \
         unreachable, and nothing unreachable may stand in for it",
        // Loops: which arm is read, per opener.
        "A plain `while cosign …; do …; done` ENDS on a failing condition, so its failure arm \
         is the command after `done` and its body is never read",
        "An `until cosign …; do …; done` — and its `while ! cosign …; do …; done` twin — runs \
         its BODY on a failing condition, so the body is the failure arm",
        "the loop is left on that path only by a `break` or by an `exit` / `return` that does \
         not propagate",
        // The `!`-in-a-condition correction, stated as the reason.
        "in condition position a `!` inverts nothing the step ever sees",
        "Those are the only propagating shapes; everything the walk cannot pin down \
         structurally fails closed",
        // The captured-status gate: WHICH parameter, then the three shapes.
        "an assignment from `$?` in the command **immediately after** the signing command, \
         reached unconditionally",
        "A parameter that cannot be traced to `$?` of the signing command does not count",
        "exactly three shapes are recognised as doing so",
        "`exit \"$rc\"` / `return $rc`, an `exit` or `return` whose status is **that captured \
         parameter**",
        "`[ \"$rc\" -eq 0 ] || exit 1`, `[ \"$rc\" -ne 0 ] && exit 1`",
        // The branch may re-raise the captured parameter, which is how the
        // guard is most often written and which used to FAIL.
        "the branch may equally **re-raise the captured parameter itself**, `[ \"$rc\" -eq 0 ] \
         || exit \"$rc\"`, which propagates by construction even though `$rc` is no literal",
        "`if [ \"$rc\" -ne 0 ]; then exit 1; fi`",
        // Every test spelling the gate accepts, and the one that looks like
        // arithmetic and is not.
        "be spelled `[ … ]`, `test …`, `[[ … ]]` — which must close with its own `]]` — or the \
         arithmetic `(( rc != 0 ))`, with its own `))`, and `let \"rc != 0\"`",
        "`( ( echo $rc ) )` is a nested subshell and not arithmetic at all",
        // Reachability: the half of the captured-status gate that was flat.
        "**A consultation counts only where the shell reaches it**, at the signing's own depth",
        "one inside a nested compound's arm (`if [ -f marker ]; then [ \"$rc\" -ne 0 ] && exit 1; \
         fi`), one written after an unconditional `exit` that has already ended the shell, and \
         one reached only through `&&` / `||` / `|` / `&` are each no consultation at all",
        "an assignment that REBINDS the captured name counts wherever it is written, reached or \
         not, because a rebinding that cannot be ruled out has to be assumed",
        // The fail-open the walk used to have: a compound was stepped over
        // as if it ALWAYS fell through, so an arm that ended the shell was
        // invisible and the re-raise after it was credited.
        "A nested compound is stepped over whole **only when the shell is certain to come back \
         out of it**: one that can END the shell instead — an abandoning `exit` / `return` \
         anywhere in its span, at any depth — ends the walk",
        "everything written after its terminator is written on the assumption that the arm which \
         exits was not taken",
        "`if [ \"${SKIP_SIGNING:-}\" = \"true\" ]; then exit 0; fi`, `exit \"$rc\"` keeps the \
         defect, and so does its `while` / `for` / `until` / `case` twin and the same arm nested \
         two deep",
        // The condition gate's half of the same rule: the arm index lists
        // now carry a nested compound at its opener.
        "**an arm that can end the shell from inside a nested compound ends the arm**",
        "`else if [ -f skip ]; then exit 0; fi; fi` is an escape and the `exit 1` after `fi` may \
         not stand in for it",
        // The one-liner spelling of the skip path, closed this round: the
        // reachability skip credits nothing, but it no longer walks PAST a
        // conditionally reached command that leaves the shell.
        "**That skip is one-directional.** A conditionally reached command proves nothing about \
         the path that did not run it, so it never COUNTS — as a consultation, or as an arm's \
         verdict — but one that can END the shell stops the walk there all the same",
        "`[ -f dist/skip ] && exit 0`, `exit \"$rc\"` keeps the defect, and so do its `||`, `&& \
         return 0`, `&& exit $?` and `[ \"${DRY_RUN:-}\" = \"1\" ] && exit 0` spellings, the same \
         one-liner as an `else` arm, and the same one-liner as an `until` retry's body",
        "a conditionally reached `exit 1` fails the step on the path that takes it, so the walk \
         runs on past `[ -f dist/skip ] && exit 1` and still credits the re-raise after it",
        "A command in that arm reached only through `&&` / `||` / `|` / `&` is never the arm's \
         verdict either — but one that can END the shell (`else [ -f dist/skip ] && exit 0; \
         fi`) ends the arm, so the command after the terminator may not stand in for it",
        // And the boundary that is still disclosed rather than closed.
        "Nothing else inside a nested compound is graded, so an arm that re-raises the failure \
         from inside one (`else if [ -f x ]; then exit 1; fi; fi`) is read as falling through \
         and hands the verdict to the command after the terminator",
        // And the disclosure that everything else keeps failing.
        "A body that is genuinely sound and re-raises the failure some other way",
        "a status relayed through a second variable (`rc=$?; status=$rc; exit \"$status\"`)",
        // The `case` shapes: one failed on purpose, one seen but ungraded.
        "`case \"$rc\" in 0) ;; *) exit 1 ;; esac` re-raises the failure correctly and is failed \
         anyway, because judging it would mean deciding which arm a non-zero status takes, and \
         an arm's pattern is only ever SKIPPED so the command behind it can be read, never \
         matched against a value",
        // The `case` claim is only true of BOTH spellings now that a one-line
        // `case` opens a compound at all.
        "a `case` is stepped over whole, exactly as any other nested compound the shell is \
         certain to come back out of, and in **either spelling**: the multi-line one, and the \
         one-liner `case \"$MODE\" in skip) echo s ;; esac`, whose `case` keyword and first arm \
         the tokeniser emits as a single command",
        "one written OUTSIDE the compound the signing itself sits in: the walk ends at that \
         compound's own terminator",
        "the last iteration's status is not every iteration's",
        "a `case` **arm** the signing line sits in",
        "The signing there IS seen: the arm's `release)` pattern, which the tokeniser emits as \
         the words `release` and `)`, is skipped so the command word is `cosign` and every gate \
         applies to it.",
        "whether `$MODE` is ever `release` is not asked",
        "a consultation the reachability model cannot place",
        "An `until` retry that can only loop is read as sound, not as a hang",
        "the reason the passing shapes are enumerated rather than described",
        // The `&&` half of the bare-`exit` rule, and the `||` half that must
        // stay sound. The JUSTIFICATION is pinned alongside the verdict,
        // because the sentence this replaced asserted a false one — that an
        // argument-less `exit` inherits "the failing one" wherever it is
        // written, which is exactly what does not hold after `&&`.
        "**A BARE `exit` / `return` after `&&` abandons the shell too**, and this is where the \
         \"no status at all\" rule above stops holding",
        "An argument-less `exit` re-raises `$?`, which is the FAILURE only where the command is \
         reached because something failed — a `||` branch, or the arm a compound takes on a \
         failing condition. After `&&` the inheritance is inverted: the branch runs only because \
         the test SUCCEEDED, so the status re-raised is 0",
        "`[ -f dist/skip ] && exit` therefore leaves the step green with the signing failed — \
         bash and sh both exit 0 with the marker present",
        "in its `&& return` spelling, as an `else` arm, and as an `until` retry's body",
        "The `||` twin is untouched, because it is genuinely sound: `[ \"$rc\" -eq 0 ] || exit` \
         inherits the test's failure and re-raises it, and it PASSES",
        // The `||` branch rule may no longer assert the general inheritance
        // claim either; it holds because of the POSITION, and says so.
        "(or with no status at all, which re-raises `$?` — and in `||` position that `$?` is the \
         failure that sent the shell down this branch)",
        // The residuals this round did NOT close, disclosed rather than
        // gated, now headed as the CLASS they belong to rather than as one
        // case — the old head was contradicted by the `trap` disclosure sixty
        // lines above it and by `exec` / `eval` below it.
        "Where this walk errs the OTHER way is a CLASS, not one case: **a command that ends or \
         diverts the shell without being an `exit` / `return` this walk can see.**",
        "The class has four members, each disclosed rather than closed:",
        // Member 1: the `trap` the old head contradicted.
        "**A `trap` that rewrites the step's status.** `trap 'exit 0' EXIT` replaces the status \
         of every path out of the body, the re-raise the gate credited included.",
        // Member 2: the `break`, whose worked example is pinned whole,
        // because the version that named only its pieces did not say where
        // the re-raise sat and so did not reproduce as written.
        "**A `break` the shell does not reach unconditionally.**",
        "A bare `break` before the re-raise ends the walk (the re-raise is not credited) while \
         `if [ -f dist/skip ]; then break; fi` before it does not, and neither does `[ -f \
         dist/skip ] && break`",
        // Members 3 and 4: the two fail-opens that were undisclosed.
        "**`exec CMD`, which REPLACES the shell process** — the step's status becomes `CMD`'s, \
         and nothing written after it ever runs",
        "`set +e`, sign, `rc=$?`, `[ -f dist/skip ] && exec true`, `exit \"$rc\"` PASSES, and so \
         does `exec true` as an `else` arm with an `exit 1` after `fi`, while both exit 0 with \
         the signing failed",
        "An `exec` reached UNCONDITIONALLY is failed, but for the other reason — nothing then \
         re-raises the captured status — not because the `exec` was read",
        "**`eval STRING`, whose string is shell code this walk never parses.**",
        "`set +e`, sign, `rc=$?`, `eval \"exit 0\"`, `exit \"$rc\"` PASSES and exits 0 with the \
         signing failed, and `eval \"exit 0\"` as an `else` arm passes the same way; the sound \
         mirror image, `eval \"exit \\$rc\"`, is failed for the same blindness",
        "All four are the one instrument pointed the wrong way",
        "The whole body that shows it, in order: `set +e`; `for f in dist/*; do`; the signing; \
         `rc=$?`; `if [ -f dist/skip ]; then break; fi`; `exit \"$rc\"`; `done`; `echo done`.",
        "The re-raise is INSIDE the loop and `echo done` is what the `break` path falls into, \
         and that body passes although the `break` path leaves the loop unsigned",
    ] {
        assert_states("docs/phase-3.md", PHASE_3_MD, claim);
    }
    // The inaccurate wording must not survive anywhere: it read as an OR of
    // the arm with the follow-on, which is the defect this round closed.
    for stale in [
        "the `else` arm, or the `then` arm when the test is negated, and the command \
         immediately after the compound's terminator",
        "a loop (no arm is taken on failure)",
        "an `exit` or `return` whose status is a **parameter**",
        // The captured-status walk was FLAT before this round: any later
        // command, at any depth, behind any operator, could clear the defect.
        // Neither doc may describe it that way again.
        "a `[ … ]` / `test` on that parameter whose branch fails the step — `[ \"$rc\" -eq 0 ] \
         || exit 1`, `[ \"$rc\" -ne 0 ] && exit 1`, since which way the test reads is not \
         evaluated and either operator counts; and that same parameter test in a condition whose \
         arm fails the step, `if [ \"$rc\" -ne 0 ]; then exit 1; fi`. A status captured",
        // The wording that made the fail-open sound intentional: a compound
        // stepped over UNCONDITIONALLY, and an arm read no deeper than its
        // own commands.
        "so a nested compound is stepped over whole and a compound whose extent cannot be pinned \
         down ends the walk",
        "a `case` is stepped over whole, exactly as any other nested compound is",
        "The failure path of a compound is read exactly one level deep",
        "and a compound nested inside an arm, whose commands belong to the inner compound and \
         not to the arm — a `break` is the one word read deeper than that",
        // The `case` claim as it stood was true only of the MULTI-LINE
        // spelling: a one-line `case … ;; esac` opened no compound, so it
        // was not stepped over at all.
        "exactly as any other nested compound the shell is certain to come back out of (one \
         whose arm can `exit 0` ends the walk instead",
        // The `break` disclosure as it stood named the pieces of a body
        // without saying where the re-raise sat, and the shape a reader
        // most naturally assembled from it — the re-raise after `done` —
        // keeps the defect, so the example did not reproduce the residual.
        "The one place this walk still errs the OTHER way is a `break` inside a nested compound",
        "Inside a loop that reaches the enclosing `done` with the signing still failed, so \
         `set +e`, a `for` loop that signs, captures `rc=$?`, then `if [ -f skip ]; then break; \
         fi` and `exit \"$rc\"`, passes",
        // The head that called the `break` the ONE place this walk errs the
        // other way. It was contradicted by the `trap` disclosure sixty lines
        // above it before `exec` and `eval` were ever named, and the class it
        // now heads has four members.
        "The one place this walk still errs the OTHER way is a `break` the shell does not reach \
         unconditionally",
        "It is disclosed rather than closed: a `break` says where control goes",
        // The false justification: an argument-less `exit` does NOT inherit
        // the failing status wherever it is written. After `&&` it inherits
        // the test's success, which is the fail-open this round closed.
        "which inherits the failing one",
    ] {
        assert!(
            !unwrapped(PHASE_3_MD).contains(stale),
            "docs/phase-3.md must not still say {stale:?}"
        );
    }
}

/// The group-wrap disclosure blamed a MULTI-LINE group; the rule is that a
/// group escapes attribution at all, however it is written.
#[test]
fn phase_3_blames_the_group_not_its_line_count() {
    assert_states(
        "docs/phase-3.md",
        PHASE_3_MD,
        "are judged by the signing line's own separator, not the group's, whether the group is \
         written on one line or across many",
    );
    assert!(
        !unwrapped(PHASE_3_MD).contains("but a multi-line"),
        "docs/phase-3.md must not blame the group's line count"
    );
}

/// The CHANGELOG carries both narrowings, in the sentence that enumerates
/// what the suppression gate catches.
#[test]
fn the_changelog_mirrors_the_narrowed_gates() {
    for claim in [
        "a `!`-negated signing command **outside a condition**",
        "so `if cosign …; then echo signed; else exit 1; fi` and `if ! cosign …; then exit 1; \
         fi` both PASS",
        "the negation message — which would be factually wrong there — is never emitted",
        "the status-capture idiom (`set +e`, sign, `rc=$?`, `set -e`, `[ \"$rc\" -eq 0 ] || \
         exit 1`) turns fail-fast off on purpose and re-raises the failure by hand, so it PASSES",
        "a suppression applied to a `{ …; }` / `( … )` group from the outside",
        "but never the group's, on one line or across many",
        // The arm-first reading, the loop arms, and the parameter that has
        // to be the signing's own status.
        "the command after the compound's terminator is consulted only when that arm FALLS \
         THROUGH",
        "an `until cosign …; do …; done` (and its `while ! cosign …` twin) runs its BODY on a \
         failing condition, so the body is the failure arm",
        "the parameter that carries the status must be one assigned from `$?` in the command \
         IMMEDIATELY after the signing, reached unconditionally",
        "a parameter that cannot be traced to the signing's own `$?` does not count",
        // The three closings of this round, each in the CHANGELOG's own voice.
        "**and the consultation counts only where the shell reaches it**, at the signing's own \
         depth",
        "the test may be spelled `[ … ]`, `test …`, `[[ … ]]` (its own `]]` required), \
         `(( rc != 0 ))` (its own `))`) or `let`",
        "a `case` on the captured status (`case \"$rc\" in 0) ;; *) exit 1 ;; esac` — sound, and \
         failed anyway, because an arm's pattern is only skipped so the command behind it can be \
         read, never matched against a value)",
        "an `if`/`else` BODY or a `case` ARM the signing line sits in (the signing there IS seen \
         — the arm's `release)` pattern is skipped so the command word is `cosign` and every \
         gate applies — but whether the arm is ever taken is not asked)",
        // This round: the stepped-over compound that can end the shell, and
        // the branch that re-raises the captured parameter.
        "**A nested compound is stepped over only when the shell must come back out of it**",
        "`exit \"$rc\"` keeps FAILING (with its `while` / `for` / `until` / `case` twins and the \
         same arm nested two deep)",
        "the arm index lists now carry a nested compound at its opener, so the same rule closes \
         an `else` arm that ends the shell from inside one",
        "the branch may equally re-raise the captured parameter itself — `[ \"$rc\" -eq 0 ] || \
         exit \"$rc\"` propagates by construction and now PASSES, where before only the literal \
         `|| exit 1` did",
        // This round: the one-liner spelling of the skip path, and the
        // one-line `case` that used to open no compound at all.
        "**That skip is one-directional**: a conditionally reached command never COUNTS, but one \
         that can END the shell stops the walk there anyway",
        "the one-liner `set +e`, sign, `rc=$?`, `[ -f dist/skip ] && exit 0`, `exit \"$rc\"` \
         keeps FAILING",
        "while `[ -f dist/skip ] && exit 1`, which fails the step on the path that takes it, \
         leaves the walk running",
        "which now grades identically in **either `case` spelling** — a one-liner `case \
         \"$MODE\" in skip) echo s ;; esac` carries its keyword and its first arm as one \
         command, and used to open no compound at all",
        // This round: the bare `exit` after `&&`, with the reason it is
        // scoped to `&&` and not to `||`.
        "**A BARE `exit` / `return` after `&&` abandons the shell too**",
        "after `&&` the branch runs only because the test SUCCEEDED, so the status re-raised is 0",
        "`set +e`, sign, `rc=$?`, `[ -f dist/skip ] && exit`, `exit \"$rc\"` now keeps FAILING",
        "while the sound `||` twin `[ \"$rc\" -eq 0 ] || exit` keeps PASSING, since there the \
         inherited status is the failing one",
        // And the two fail-opens that were undisclosed until this round.
        "the rest of the class that `break` belongs to — a command that ends or diverts the \
         shell without being an `exit` / `return` this walk can see: a `trap` that rewrites the \
         status, `exec CMD` (which REPLACES the shell process, so `[ -f dist/skip ] && exec \
         true` before the re-raise, and `exec true` as an `else` arm, both PASS while exiting 0 \
         with the signing failed), and `eval STRING` (whose string is never parsed, so `eval \
         \"exit 0\"` passes and the sound `eval \"exit \\$rc\"` is failed)",
    ] {
        assert_states("CHANGELOG.md", CHANGELOG_MD, claim);
    }
    // The same false justification must not survive in the CHANGELOG either.
    assert!(
        !unwrapped(CHANGELOG_MD).contains("which inherits the failing one"),
        "CHANGELOG.md must not still say \"which inherits the failing one\""
    );
}

/// `CLAUDE.md` names `SSH_AUTH_SOCK` as a leak in its own right, says why its
/// symptom is a hang, and puts the unset into the command it prescribes.
#[test]
fn claude_md_names_ssh_auth_sock_as_the_third_leak() {
    let doc = unwrapped(CLAUDE_MD);
    assert!(
        doc.contains("Three leaks"),
        "CLAUDE.md still counts two leaks"
    );
    for claim in [
        "`SSH_AUTH_SOCK` points at that same Secure-Enclave / 1Password agent",
        "answers a signature request only after a physical tap",
        // The symptom, which is what makes this leak hard to recognise.
        "the run does not fail, it hangs",
        "40+ minutes",
    ] {
        assert_states("CLAUDE.md", CLAUDE_MD, claim);
    }
    assert!(
        doc.contains(
            "SSH_AUTH_SOCK= GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null \
             GIT_CONFIG_SYSTEM=/dev/null cargo test"
        ),
        "CLAUDE.md must prescribe the unset in the command it tells agents to run"
    );
    // The two pre-existing leaks keep their wording; this section was
    // extended, not rewritten.
    for claim in [
        "The agent harness injects `GIT_CONFIG_KEY_n/VALUE_n`",
        "With that neutralized, the global `~/.gitconfig`",
        "Follow-up worth doing properly: have the test helpers",
    ] {
        assert_states("CLAUDE.md", CLAUDE_MD, claim);
    }
}
