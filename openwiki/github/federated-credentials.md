---
type: Architecture Guide
title: Federated credentials
description: Replacing long-lived tokens with short-lived, scope-limited ones exchanged from a workflow's own identity — and the limit of what sscsb verifies about the policy.
tags: [octo-sts, oidc, credentials, federation, least-privilege]
generated: {by: "claude-code", at: "2026-08-25T03:42:40.117Z"}
---

# Federated credentials

A long-lived access token is a secret that has to live somewhere, be rotated by
someone, and can do everything it was granted for as long as it exists. This control
replaces that pattern with an exchange: a workflow proves **who it is** using the
forge's OIDC identity, and receives a short-lived token carrying exactly the
permissions a policy grants it.

**No token is stored anywhere**, and the one it receives expires in about an hour.

## The trust policy

The policy lives in the repository that **grants** access, and declares three things:

**The issuer** is pinned to the forge's own OIDC provider. Nothing else can mint a
token this policy will accept.

**The subject pattern** names the repository and the exact reference — so a workflow on
a different branch, or in a different repository, does not match. This is the part
worth tightening first in your own copy.

**The permissions** are the whole grant. The shipped template ships least privilege:
read access only, with the write scopes present but commented out, so widening is a
deliberate edit rather than the default.

## The consuming workflow

It adds exactly **one** permission scope: the ability to mint an identity token. That
single scope is the entire federation mechanism — everything else the job can do comes
from the exchanged token, which is bounded by the policy above.

The exchanging action is **pinned to a release digest**, even though upstream
documentation shows a mutable reference. That is sscsb applying its own
[pinning rule](workflow-auditing.md) to a template it ships rather than copying
upstream's example.

The workflow is also a clean worked example of the placement rule: the top-level
permissions block stays read-only and the identity scope is granted at **job** level,
so it does not sit as a default for jobs added later.

## What sscsb actually verifies

This is the honest limit, and it matters more here than for most controls.

The trust policy is verified only as **parsing to a non-empty YAML mapping**. sscsb
never checks that the issuer is present, that the subject pattern is scoped, or that
the permissions are least-privilege. **A policy granting broad write access to a
wildcard subject passes this control.**

Read a passing verdict as "a policy file is installed and is valid YAML". Reviewing
what it grants is a human job, and the shipped template is written to make the
least-privilege starting point the easy one.

## One rendering caveat

The subject pattern is rendered at install time from the resolved default branch. As
[repository context](../runtime/repository-context.md) explains, that resolution
falls back to a hard-coded name silently when the remote's recorded head is unset —
which is the normal state for a repository initialised locally with a remote added
afterwards.

In that situation the generated policy names the **wrong reference**, and because
installation never re-renders a file it is keeping, re-running `init` will not fix it.
Check the pattern after bootstrapping.

## Source map

| Concern | Location |
|---|---|
| Control registration | `src/controls.rs` |
| Artifacts | `src/workflows.rs`, `ARTIFACTS` |
| Shape verification | `src/workflows.rs`, `check_yaml` |
| Trust policy template | `templates/configs/octo-sts-policy.sts.yaml` |
| Consuming workflow | `templates/workflows/octo-sts-example.yml` |

This repository runs its own control: the rendered policy is committed and is the
worked example.
