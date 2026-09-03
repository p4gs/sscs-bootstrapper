# Signing

The rule this whole system is built around:

> **Humans, CI, and AI never share a key.**

## The five-environment model (`sscsb signing`)

Commits originate from more than one place, and each place has a different
*actor* and a different *signer*. `sscsb signing` implements and verifies the
whole map from one command — programmatically where it can, with numbered
step-by-step guidance where a native app or a web toggle technically can't be
scripted.

| Environment | Actor | Signer | Forge badge |
|-------------|-------|--------|-------------|
| `human-local` | you | OS-keystore / Secure-Enclave key, **tap-gated** | Verified (strongest) |
| `agent-claude-code` | AI agent | the agent's **own** key, **distinct identity**, unregistered | **Unverified by design** |
| `cloud-claude` | bot | forge App server-side, or unsigned drafts | Verified-as-bot / Unverified |
| `github-web` | you | forge web-flow key (account-anchored) | Verified |
| `codespaces` | you | forge-managed signing (opt-in, trusted repos) | Verified |

Invariants sscsb enforces: the agent **never** signs or authors as the human;
the agent key is **never** registered on the human's forge account (its commits
honestly show *Unverified* — that is the correct state, an *unsigned* commit is
the failure); *Verified-as-human* always traces to a real human action (a
hardware tap locally; an authenticated account for web/Codespaces). This mirrors
the Linux-kernel rule that only a human certifies (DCO), and CISA/OpenSSF's
phishing-resistant-MFA guidance for the account-anchored lanes.

### Commands

```sh
sscsb signing status                         # probe every lane, show its state
sscsb signing setup human-local              # converge your enclave lane + `git sign` alias
sscsb signing setup agent-claude-code \
  --agent-name '<name>' --agent-email '<email>'   # give the agent its own identity+key
sscsb signing setup github-web --confirm     # do the guided steps, then record you did them
sscsb signing verify                         # report card + recent-history classification
```

`setup` on the two **local** lanes is fully programmatic (git config, the
env-proof `git sign` alias, an SSH keypair for the agent, the `allowed_signers`
entries, a JSON-merge into the agent harness's settings — backed up and
validated, never clobbered). It **refuses** to proceed if the agent identity
would collide with yours (identity blur) — comparing signing keys by **key
material**, not by the path string git happens to have been given, and comparing
emails case-insensitively, because git accepts a private-key path and its `.pub`
interchangeably and forges attribute `Human@Example.Invalid` and
`human@example.invalid` to one person. It also refuses when your global git
config cannot be read at all, rather than treating an unreadable identity as an
absent one. The **cloud/web/Codespaces** lanes are
guided — sscsb prints the exact numbered steps (enroll a passkey, enable
vigilant mode, authorize the App, turn on Codespaces GPG verification) and, once
you confirm with `--confirm`, records a dated attestation in
`.sscsb/policy/signing-model.toml` that `verify` re-checks for staleness (180d).

The **`git sign` alias** deserves a callout: inside an AI-agent session a bare
`git commit` signs as the *agent* (the session's `GIT_CONFIG_*` env wins). `git
sign` forces your human key via `-c` overrides — which outrank that env — so it
signs as *you* whether you run it in your own terminal or the agent runs it for
your review. It is the seam where a human tap ships code. Because it is that
seam, sscsb POSIX-quotes the identity it embeds and parses the finished alias
with `sh -n` before storing it: an apostrophe in your name (`Pat O'Brien`) used
to produce an unmatched quote that git stored happily and only failed at the
moment you reached for `git sign` — pushing you back onto the bare `git commit`
this alias exists to protect you from.


A signature is a claim about *who*. The moment a human's signing key is reachable by
a CI job — or by an agent running on the human's laptop — the signature stops
answering the question it exists to answer. So `sscsb` classifies every identity,
and enforces the classification where it matters: the protected branch.

## The three classes

`.sscsb/policy/signers.toml` is the source of truth:

```toml
[[signer]]
principal = "you@example.com"
class = "human"
hardware_backed = true
ssh_public_key = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t…"

[[signer]]
principal = "ci@example.com"
class = "ci"
hardware_backed = false
ssh_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5…"
```

| Class | May sign | May land on a protected branch |
|-------|----------|-------------------------------|
| `human` | commits, tags, artifacts | **yes** (this is the only class that may) |
| `ci` | artifacts, attestations | no |
| `ai` | nothing by default; feature-branch commits only when the `agent-signing` control is enabled | **no** (never, either way) |

From `signers.toml`, `sscsb` **generates** `.sscsb/policy/allowed_signers` — the file
git consults to decide whether a signature verifies — and points
`gpg.ssh.allowedSignersFile` at it. The generator has one rule that no configuration
option can turn off:

> **By default, an `ai`-class key is never written into `allowed_signers`.**

Not written and then rejected downstream. **Not written.** The material git would need
in order to verify an AI's signature is not present, so an AI-signed commit cannot be
verification-valid in this repository — regardless of how the policy file is edited,
and regardless of what an agent with write access to that file tries to claim about
itself. The one class it could name to grant itself signing power is the one class
that gets stripped on the way out.

An AI may draft any change. By default it may not sign at all, and it may **never**
push to a protected branch. That is the boundary, and it is enforced in code, not in
a guideline.

### Two namespaces, both named

Generated lines carry `namespaces="git,sscsb-scan-record"` — for `human`-class
signers. SSHSIG signatures are namespaced so a signature minted for one protocol
cannot be replayed as another: `git` is the namespace commit signatures are
minted in, and `sscsb-scan-record` is the one
[`sscsb scan --local`](local-scan.md) signs a scan record in. The same
committed file is the anchor for both, which is the point — a repository that
approves you as a signer says which things you are approved to sign, and says it
out loud rather than by omitting a restriction. A repository anchored before the
local lane existed carries `namespaces="git"` alone; `sscsb init` regenerates it,
and the file must be committed for either use.

**`ci` and `ai` signers get `namespaces="git"` and nothing else.** A local scan
record is a maintainer's attested word about a machine nobody else can inspect,
and it is the one lane whose local-environment verdicts count with no
independent corroboration — so only a `class = "human"` signer may assert one.
CI does not need the grant (it has the action lane, which proves strictly more,
under an identity GitHub's OIDC issuer burns into the certificate), and granting
it to an `ai` key would contradict the invariant this whole page rests on: an
AI-class signer never signs. Withholding the namespace makes that refusal
structural — `ssh-keygen -Y verify -n sscsb-scan-record` fails against the
committed anchor, so both `sscsb` and the public directory refuse without either
having to re-implement the rule.

### The one thing `agent-signing` changes (and the one it doesn't)

There is a real, legitimate reason to want an agent's commits *signed*: on a feature
branch, a verifiable agent signature makes the agent's work attributable and
non-repudiable — useful when a human, a CI bot, and an AI are all committing to the
same repo. The optional, **off-by-default** `agent-signing` control enables exactly
that: with it on, `ai`-class keys *are* emitted into `allowed_signers`, so an agent
commit verifies as `%G?=G` on a feature branch and `sscsb signers check` labels it
`agent`.

What it does **not** change is the protected-branch gate. That gate keys on the
signer's **class**, read from `signers.toml` — not on presence in `allowed_signers` —
so an agent signature is rejected on `main`/`master` whether the control is on or off.
The two properties are separate on purpose. See [`agent-signing.md`](agent-signing.md)
for the threat model, the backend matrix (TPM / FIDO2 / KMS / GitHub App / PIV), the
server-side policy gate that closes the cloud/mobile hole, and why hardware-backing an
agent key is about *non-exfiltratability*, not a human touch.

## Setting up a hardware key (recommended)

A hardware-backed key (`ed25519-sk`) cannot be copied off the device. Malware on your
laptop — or an agent with shell access — can *ask* the key to sign, but it cannot
*take* the key. With `verify-required`, it cannot even ask without you touching the
thing.

Requires OpenSSH 8.2+ (8.9+ for resident keys). Check with `ssh -V`.

```sh
# Generate. -O resident stores it on the key itself (recoverable on a new machine).
# -O verify-required demands a PIN/touch for every signature.
ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -C "you@example.com" -f ~/.ssh/id_ed25519_sk

# Tell git to sign commits with it
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_sk
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Then register it with `sscsb` and with GitHub:

```sh
# 1. Add the PUBLIC key to .sscsb/policy/signers.toml as class = "human",
#    hardware_backed = true. Re-run `sscsb init` (or any hook) to regenerate
#    .sscsb/policy/allowed_signers from it.
cat ~/.ssh/id_ed25519_sk.pub

# 2. Add the same public key to GitHub as a SIGNING key (not just an auth key):
#    Settings → SSH and GPG keys → New SSH key → Key type: Signing Key
gh ssh-key add ~/.ssh/id_ed25519_sk.pub --type signing --title "yubikey"

# 3. Prove it end to end
git commit --allow-empty -m "chore: verify signing"
git log --show-signature -1        # expect: Good "git" signature
sscsb verify commit-signing
```

If `require_hardware_backed = true` (the default), a `human`-class key that is *not*
marked `hardware_backed` is rejected on protected branches. You can relax that:

```toml
[controls.commit-signing]
require_hardware_backed = false
```

…but do it as a deliberate, visible decision in the config, which is the point of
having it be a config field rather than a silent fallback.

### Recovering a resident key on a new machine

```sh
cd ~/.ssh && ssh-keygen -K      # pulls resident keys off the device
```

## What pre-push actually enforces

On a push to a protected branch, for every commit in the range:

1. git reports a **good signature**, and
2. the signing key is in the generated `allowed_signers`, and
3. that key's class is **`human`**, and
4. if `require_hardware_backed = true`, the key is marked hardware-backed.

Any failure blocks the push and names the offending commit. Pushes to non-protected
branches are not gated — draft freely; the gate is at the branch that matters.

Merge commits are additionally checked for review evidence when their history
includes AI-assisted work, so a merge cannot launder commits that would have been
blocked on their own.

## WSL2 and Windows

This is the one genuine platform limitation, and it is not `sscsb`'s to fix: **WSL2
cannot reach USB FIDO2 devices directly.** The Linux kernel in WSL2 has no USB
passthrough for HID security keys, so `ssh-keygen -t ed25519-sk` inside WSL cannot
talk to your YubiKey. Everything else in `sscsb` works normally under WSL — this is
specifically about hardware-key signing.

Two working approaches:

**1. Borrow Windows' `ssh-keygen` (simplest).** Git for Windows ships an OpenSSH that
*can* see the key. Point git inside WSL at it:

```sh
git config --global gpg.format ssh
git config --global gpg.ssh.program "/mnt/c/Program Files/Git/usr/bin/ssh-keygen.exe"
git config --global user.signingkey "/mnt/c/Users/<you>/.ssh/id_ed25519_sk.pub"
```

The signing operation crosses into Windows, which owns the USB device. Note the paths
are Windows-side; keep the key material there.

**2. `windows-fido-bridge`.** Relays FIDO2 calls from WSL to the Windows host so
`ed25519-sk` works natively inside WSL. More setup, more moving parts, but the WSL
side then behaves like plain Linux.

`sscsb` detects WSL (`/proc/version` advertises it) and includes this note in its
degrade messaging rather than letting you discover it at the moment a push is
blocked.

## No hardware key?

A software `ed25519` key still gives you a real, verifiable signature and satisfies
the human-only rule — set `hardware_backed = false` on the signer and
`require_hardware_backed = false` on the control. You lose exfiltration resistance:
a key on disk is a key that can be stolen by anything that can read your home
directory, which in an AI-agent workflow is a larger set of things than it used to
be.

That is the actual argument for the hardware key, and it is worth the $50.
