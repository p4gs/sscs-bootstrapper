# Signing

The rule this whole system is built around:

> **Humans, CI, and AI never share a key.**

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
| `ai` | nothing — see below | no |

From `signers.toml`, `sscsb` **generates** `.sscsb/policy/allowed_signers` — the file
git consults to decide whether a signature verifies — and points
`gpg.ssh.allowedSignersFile` at it. The generator has one rule that no configuration
option can turn off:

> **An `ai`-class key is never written into `allowed_signers`.**

Not written and then rejected downstream. **Not written.** The material git would need
in order to verify an AI's signature is not present, so an AI-signed commit cannot be
verification-valid in this repository — regardless of how the policy file is edited,
and regardless of what an agent with write access to that file tries to claim about
itself. The one class it could name to grant itself signing power is the one class
that gets stripped on the way out.

An AI may draft any change. It may not sign, and it may not push to a protected
branch. That is the boundary, and it is enforced in code, not in a guideline.

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
