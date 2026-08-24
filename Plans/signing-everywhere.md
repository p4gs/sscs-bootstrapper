# Plan — `sscsb signing`: programmatic five-environment commit-signing implementation

## Context

Owner directive (2026-07-19, /goal): sscsb should be the tool that *implements* the
gold-standard signing model we derived from research — not just audit it. Scope v1:
the owner's actual stack (macOS laptop + Secretive Secure Enclave + Claude Code as
the AI agent + GitHub), architected so other platforms/agents slot in later.
Done-condition: running sscsb ON THIS MACHINE implements/verifies code-commit
signing across all five environments + actors below. Steps that technically cannot
be automated (Secure-Enclave key creation lives in Secretive's UI; GitHub web
toggles have no API) must surface as numbered, re-probeable step-by-step
instructions — sscsb converges the gap, never silently skips it.

## The model being implemented (from the 2026-07-19 research session)

| Env | Actor | Signer | GitHub badge | Anchor |
|---|---|---|---|---|
| E1 laptop | human | Secure-Enclave key, tap required | Verified | hardware + biometric |
| E2 laptop | AI agent (Claude Code) | agent's OWN key, distinct identity, UNREGISTERED on GitHub | Unverified **by design** | key file / enclave-no-tap; policy class=ai |
| E3 Claude cloud | bot | GitHub App server-side (or unsigned drafts) | Verified-as-bot / Unverified | App installation; human gate moves to merge |
| E4 GitHub web/mobile | human | GitHub web-flow key | Verified | GitHub account (⇒ phishing-resistant MFA is the control) |
| E5 Codespaces | human | GitHub-managed signing (opt-in, trusted repos) | Verified | GitHub account |

Doctrinal invariants sscsb must encode (all derived from the kernel/OpenSSF
"Assisted-by" line + owner's rules): the agent NEVER signs as the human; the agent
key is NEVER registered on the human's GitHub account; "GitHub-Unverified" on a
properly-signed agent commit is CORRECT, an UNSIGNED commit is the failure; the
human's tap (or account-anchored web-flow) is the only source of Verified-as-human;
protected-branch landing is human-gated.

## Architecture

**New module `src/signing_setup.rs`** + **new phase-1 control `signing-model`**
(default ON) + **CLI family `sscsb signing <status|setup <env>|verify>`**.

- `Environment` enum: `HumanLocal, AgentClaudeCode, CloudClaude, GithubWeb, Codespaces`
  — each implements probe → converge(programmatic) → guide(manual residue) → verify.
- **Guided-step engine**: `Step { id, title, why, actions: Vec<String>, probe: StepProbe }`
  where `StepProbe ∈ { Command(..), FileState(..), GhApi(..), Attested(policy-key) }`.
  Non-probeable browser/UI steps use the signers.rs attestation pattern
  (`evaluate_expiry`/`evaluate_attestation`, both already `pub`) recorded in a new
  `.sscsb/policy/signing-model.toml`.
- **Generalization seams** (v1 ships macOS+Secretive+Claude Code implementations
  behind them): `HumanBackend` (secretive | yubikey-sk | software…), `AgentKind`
  (claude-code | …), platform paths via existing `src/platform.rs`. Nothing
  owner-specific in source — names/emails/key paths come from config with prompts,
  so any user can run it.

### Per-environment behavior

**E1 `setup human-local`** — probe: Secretive app + socket, git globals, alias.
Programmatic: `gpg.format=ssh`, `user.signingkey`, `commit.gpgsign`,
`gpg.ssh.allowedSignersFile` (+ generate/merge `~/.ssh/allowed_signers`), create the
env-proof **`git sign` alias** (`-c` overrides beat agent session env — the
laptop footgun we proved 2026-07-19). Guided: create the enclave key in Secretive's
UI (numbered steps; app cannot be driven programmatically), register pubkey as a
GitHub **signing key** (`gh auth refresh -s admin:ssh_signing_key` is a browser
step → guided, then `gh api user/ssh_signing_keys` POST is programmatic),
tap-verified probe commit (prompts the human, waits).

**E2 `setup agent-claude-code`** — programmatic: generate agent keypair (0600,
distinct comment) OR detect an existing one; **merge** `GIT_CONFIG_*` env
(signingkey + gpgsign + user.name + user.email) into `~/.claude/settings.json`
(JSON-merge, never clobber; back up first); `allowed_signers` entry mapping the
agent email (never the human's); `signers.toml` `class="ai"` entry; scripted probe
commit in a temp repo asserting author=agent + Good signature for agent principal.
Guarded invariant: warn-and-refuse if the agent email matches any human identity;
verify the agent key is NOT among the account's GitHub signing keys (API if scope
present, else attested + instructions). Optional guided upgrade: Secretive no-tap
enclave key for the agent.

**E3 `setup cloud-claude`** — programmatic: repo-level `.claude/settings.json`
attribution block (syncs to cloud), doc of merge-gate discipline; probe: Claude
GitHub App installation visible via `gh api user/installations` (best-effort).
Guided: install/authorize the Claude GitHub App (URL + steps), choose App-signed
vs unsigned-drafts mode, protected-branch rule requiring human-landed merges.

**E4 `setup github-web`** — probe: `gh api user` → `two_factor_authentication`;
signing-key inventory when scope allows. Guided (no APIs exist): enable **vigilant
mode** (exact settings URL), enroll **passkey/WebAuthn** (URL), each recorded as a
dated attestation in signing-model.toml after the user confirms.

**E5 `setup codespaces`** — guided (setting not API-exposed): enable Codespaces
**GPG verification** for a *selected trusted-repo list* (never "all"), never mount
private keys into a codespace; attested. Probe where possible: recent codespace
commits' `verification.verified` via commits API.

**`sscsb signing verify`** — the report card: one row per environment with
PASS / GUIDED-PENDING(step ids) / ATTESTED(date, stale⇒Fail) / DEGRADED(named
tool) — plus **live history evidence**: sample recent commits via
`gh api repos/{slug}/commits` and classify each `verification.reason` against the
model (web-flow ⇒ E4 verified; agent email + unsigned/unknown_key ⇒ E2 as-designed;
human key ⇒ E1). Wired into `sscsb verify` via the `signing-model` control.

## Slices (each lands compilable + tested; owner taps to commit per signing rule)

1. **Skeleton + status**: module, `Environment`/`Step` types, all E1-E5 probes
   (read-only), `sscsb signing status`, control registered (registry + dispatch +
   compliance map + BOTH tool_orchestration lists + default-on list + init policy
   template — the full D-17 checklist), unit tests w/ fixture dirs.
2. **E1+E2 converge**: setup human-local + agent-claude-code programmatic paths +
   guided steps + probe commits. settings.json merge logic gets heavy tests
   (never-clobber, idempotent).
3. **Policy + attestations**: `signing-model.toml` template/parse (reuse
   evaluate_expiry/evaluate_attestation), E4/E5 guided flows recording attestations.
4. **E3 + verify report card** incl. live-history classification probes.
5. **Docs** (`docs/signing.md` gains the five-environment model + per-env guides),
   README, walkthrough re-capture; dogfood END-TO-END ON THIS MACHINE — the
   done-condition probe: `sscsb signing status|setup|verify` here, every row
   PASS/ATTESTED/GUIDED-with-owner-confirmation.

## Verification (done-condition mapping)

Done = on this machine: E1 verify PASS (existing Secretive setup detected,
`git sign` alias present, GitHub key registered¹); E2 PASS (Jai identity detected
in settings.json, probe commit Good-signature-as-agent, key absent from GitHub¹);
E3 configured-or-guided with attribution block written; E4/E5 attested current
(owner confirms vigilant/passkey/Codespaces toggles through the guided flow).
¹ where the gh scope isn't granted, the flow guides the grant then verifies — or
records a dated attestation if the owner declines the scope.

## Risks / notes

- `~/.claude/settings.json` merge is the highest-blast-radius write on the machine
  → mandatory timestamped backup + JSON-validate + read-back before/after.
- gh scopes (`admin:ssh_signing_key`, `read:user`) require browser OAuth → always
  guided, never assumed; absence degrades to attestation, never blocks.
- Existing 16-test signing-env hermeticity gap (GIT_CONFIG_* leakage) must not
  worsen: new tests explicitly scrub the env (documented gotcha).
- Owner's commit rule: every code commit staged + message prepared, then his
  Secretive tap via `git sign` — the build itself dogfoods E1/E2 continuously.
