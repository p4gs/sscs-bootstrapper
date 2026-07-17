# Phase 1: Manual Setup Checklist

These tasks require physical access to your YubiKey and GitHub account.
Complete them in order.

---

## Task 1.6: YubiKey FIDO2 ed25519-sk Resident Key

**Prerequisites:** YubiKey 5 Series with firmware 5.2.3+ and OpenSSH 8.3+

```bash
# 1. Generate FIDO2 resident signing key ON the YubiKey
#    (Touch YubiKey when it blinks)
ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -C "git-signing $(git config user.email)" \
  -f ~/.ssh/id_ed25519_sk_git_signing

# 2. Configure git globally
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519_sk_git_signing.pub
git config --global commit.gpgSign true
git config --global tag.forceSignAnnotated true

# 3. Set up local verification
echo "$(git config user.email) namespaces=\"git\" $(cat ~/.ssh/id_ed25519_sk_git_signing.pub)" \
  >> ~/.ssh/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers

# 4. Upload public key to GitHub
#    GitHub → Settings → SSH and GPG keys → New SSH key
#    Key type: "Signing Key"
#    Paste contents of: ~/.ssh/id_ed25519_sk_git_signing.pub
```

**Verify:**
```bash
# Make a test commit and verify it's signed
echo "test" >> /tmp/test-signing && cd /tmp && git init test-signing-repo && cd test-signing-repo
git add -A && git commit -m "test signed commit"
git log --show-signature -1
# Should show: "Good git signature for <email>"
```

- [ ] FIDO2 resident key generated
- [ ] Git config updated
- [ ] Allowed signers file created
- [ ] Public key uploaded to GitHub as "Signing Key"
- [ ] Test commit verified

---

## Task 1.7: Enable GitHub Vigilant Mode

Vigilant mode flags all unsigned commits with a warning badge.

1. Go to: https://github.com/settings/ssh
2. Scroll to **Vigilant mode**
3. Check: **"Flag unsigned commits as unverified"**

- [ ] Vigilant mode enabled

---

## Task 1.8: Backup Signing Key (Second YubiKey)

**Prerequisites:** Second YubiKey 5 Series

```bash
# Generate backup key on second YubiKey
# (Insert second YubiKey, remove primary first)
ssh-keygen -t ed25519-sk -O resident -O verify-required \
  -C "git-signing-backup $(git config user.email)" \
  -f ~/.ssh/id_ed25519_sk_git_signing_backup

# Add backup key to allowed signers
echo "$(git config user.email) namespaces=\"git\" $(cat ~/.ssh/id_ed25519_sk_git_signing_backup.pub)" \
  >> ~/.ssh/allowed_signers

# Upload backup public key to GitHub as another "Signing Key"
```

- [ ] Backup key generated on second YubiKey
- [ ] Backup key added to allowed signers
- [ ] Backup key uploaded to GitHub

---

## Task 1.9: WSL2 FIDO2 Bridge (Windows/WSL users only)

WSL2 cannot directly access USB FIDO2 devices. Choose one approach:

### Option A: Use Git for Windows for signing (recommended for simplicity)
```bash
# In WSL, point git to Windows ssh-keygen for signing operations
git config --global gpg.ssh.program "/mnt/c/Windows/System32/OpenSSH/ssh-keygen.exe"
```

### Option B: windows-fido-bridge (full FIDO2 in WSL)
```bash
# Install windows-fido-bridge
# See: https://github.com/mgbowen/windows-fido-bridge
sudo apt install windows-fido-bridge
export SSH_SK_PROVIDER=/usr/lib/windows-fido-bridge/libnativemessaging.so
# Add to ~/.bashrc or ~/.zshrc for persistence
```

### Option C: usbipd-win (for PIV/advanced use)
```powershell
# In Windows PowerShell (admin):
winget install usbipd

# List USB devices:
usbipd list

# Attach YubiKey to WSL:
usbipd bind --busid <BUSID>
usbipd attach --wsl --busid <BUSID>
```

- [ ] WSL2 FIDO2 bridge configured (one of A/B/C)
- [ ] Signing works from within WSL2

---

## Task 1.10: Require FIDO2 MFA on GitHub

1. Go to: https://github.com/settings/security
2. Under **Two-factor authentication**, ensure it's enabled
3. Under **Security keys**, click **Register new security key**
4. Insert YubiKey, touch when prompted
5. Name it (e.g., "YubiKey Primary")
6. Repeat for backup YubiKey (e.g., "YubiKey Backup")
7. (Optional) Remove TOTP/SMS fallbacks for maximum security

- [ ] Primary YubiKey registered as security key
- [ ] Backup YubiKey registered as security key
- [ ] FIDO2 MFA working for GitHub login

---

## Verification

After completing all tasks, the `CommitSigningGuard.hook.ts` will automatically
verify your configuration at every Claude Code session start. You should see:

```
🔑 Commit signing: All 7 checks passing (hardware-backed ed25519-sk (FIDO2, hardware-backed))
```

If any checks fail, the hook will report specific remediation commands.
