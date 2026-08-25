---
type: Architecture Guide
title: gittuf ref policy
description: A signed, forge-independent policy over who may change which refs, and why this control is careful about what Pass means.
tags: [gittuf, refs, policy, forge-independence]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# gittuf ref policy

Branch protection is a rule your forge enforces and your forge can change. gittuf is
a signed policy over who may change which refs, verifiable **without trusting the
forge as a single point of trust**. This control wires it up.

It is off by default and marked advanced, because gittuf requires a local
initialisation step that only a maintainer can perform.

## Detection reads refs, not the tree

gittuf policy lives in `refs/gittuf/*`, not in the working tree, so sscsb asks git
for the refs rather than probing a directory. That choice is also robust to
worktrees, where a directory probe would give the wrong answer.

## Four verdicts, and the reasoning behind the middle two

| Condition | Verdict |
|---|---|
| Verification workflow missing | `FAIL` |
| Workflow present, no policy refs yet | `INFO` |
| Policy refs present, `gittuf` binary absent | `DEGRADED` |
| Policy refs present and `gittuf` available | `PASS` |

**Only the missing workflow fails.** The workflow's presence is the single thing the
control requires of you, because it is the only part sscsb can install.

**No policy refs is `INFO`, not `FAIL`.** Initialising gittuf trust and policy is an
advanced, local, maintainer-only step. Its absence is guidance rather than a finding,
and the messages carry the bootstrap instructions.

**Refs without the binary is `DEGRADED`, and the reasoning is the sharpest statement
of this codebase's honesty rule anywhere in the tree:**

> A ref under `refs/gittuf/` is just a ref name — anyone can create one with
> `git update-ref`. Only gittuf itself can say whether the RSL and policy actually
> verify, so without the binary this control has checked a name, not a guarantee.

That is the general form of [DEGRADED is not PASS](../control-model/registry-and-outcomes.md#degraded-is-not-pass):
seeing the *shape* of a protection is not the same as verifying it.

## What Pass does not mean

**sscsb does not run gittuf's verification itself.** A `PASS` here means the workflow
is installed, policy refs exist, and the binary is available to verify them. The
message tells the operator to run `gittuf verify-ref`.

Read `PASS` as "the machinery is in place and could verify", not "the policy
verified". The control is honest about this in its own output, and this page repeats
it because it is the single most likely misreading.

## The installed workflow

It fetches the gittuf refs, exits non-zero if the reference-state log is absent, and
runs verification against the default branch. It **verifies and never mutates
policy** — a workflow that could rewrite the policy it checks would defeat the point.

One property to know: **it is triggered manually only.** So "verified in CI" here
means "verifiable in CI on request", not "verified on every push". If you want it on
every push, that is a change you make in your own copy, with the usual caution that
a verification failure would then block merges.

The workflow pins its actions by SHA, checks out full history so policy is readable,
and runs without persisted credentials — the same posture as every other shipped
template. See [CI templates](../bootstrap/ci-templates.md).

## Relationship to the rest of the model

gittuf complements rather than replaces two things this wiki covers elsewhere:

- [Branch protection](../github/branch-protection.md) is the forge's rule. gittuf is
  a policy the forge does not own.
- [Signer policy](signer-policy.md) governs who may sign a commit. gittuf governs who
  may move a ref.

Together they mean an attacker who compromises the forge's settings still cannot
rewrite history that a gittuf policy covers, provided someone actually runs the
verification.

## Source map

| Concern | Location |
|---|---|
| Detection | `src/openssf.rs`, `gittuf_policy_present` |
| Verdicts | `src/openssf.rs`, `verify_gittuf` |
| Registry entry and tool pin | `src/controls.rs`, `src/tools.rs` |
| Workflow | `templates/workflows/gittuf-verify.yml` |

Focused validation:

```sh
GIT_CONFIG_COUNT=0 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
  cargo test --lib openssf::
```

Four tests cover the four verdicts.
