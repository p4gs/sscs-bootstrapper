#!/usr/bin/env bun
/**
 * CommitSigningGuard.hook.ts - Hardware-Backed Commit Signing Verification (SessionStart)
 *
 * PURPOSE:
 * Verifies that hardware-backed commit signing is configured (ed25519-sk FIDO2
 * resident key via YubiKey or platform authenticator). Detects WSL2 and warns
 * about FIDO2 bridge requirements. Reports gaps with exact remediation commands.
 *
 * TRIGGER: SessionStart
 *
 * INPUT:
 * - stdin: { session_id, cwd, hook_event_name: "SessionStart" }
 *
 * OUTPUT:
 * - stdout: <system-reminder> with signing status
 * - stderr: Progress/warning messages with remediation commands
 * - exit(0): Always (non-blocking, advisory)
 *
 * SIDE EFFECTS: None (read-only)
 *
 * INTER-HOOK RELATIONSHIPS:
 * - DEPENDS ON: None
 * - COORDINATES WITH: BranchProtectionGuard.hook.ts
 * - MUST RUN BEFORE: None
 * - MUST RUN AFTER: LoadContext.hook.ts
 *
 * ERROR HANDLING:
 * - Not a git repo: Silent exit
 * - Missing git config: Reports specific gaps
 * - Missing key file: Reports with generation commands
 *
 * PERFORMANCE:
 * - Non-blocking: Yes (advisory)
 * - Typical execution: <100ms (git config reads only)
 * - Skipped for subagents: Yes
 *
 * CHECKS:
 * 1. gpg.format == ssh
 * 2. user.signingkey points to _sk key (FIDO2 indicator)
 * 3. commit.gpgSign == true
 * 4. tag.forceSignAnnotated == true
 * 5. Signing key file exists
 * 6. gpg.ssh.allowedSignersFile set and exists
 * 7. (WSL) SSH_SK_PROVIDER or gpg.ssh.program configured for FIDO2 bridge
 */

import { existsSync } from 'fs';
import { execSync } from 'child_process';

// ─── Helpers ────────────────────────────────────────────────────────────────────

function isGitRepo(cwd: string): boolean {
  try {
    execSync('git rev-parse --git-dir', { cwd, stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function gitConfig(key: string, cwd: string): string | null {
  try {
    return execSync(`git config --global ${key}`, { cwd, stdio: 'pipe' })
      .toString()
      .trim() || null;
  } catch {
    // Also try local config
    try {
      return execSync(`git config ${key}`, { cwd, stdio: 'pipe' })
        .toString()
        .trim() || null;
    } catch {
      return null;
    }
  }
}

function isWSL(): boolean {
  try {
    const release = execSync('uname -r', { stdio: 'pipe' }).toString().toLowerCase();
    return release.includes('microsoft') || release.includes('wsl');
  } catch {
    return false;
  }
}

function isHardwareKey(signingKey: string): boolean {
  // FIDO2 resident keys have _sk in the filename
  // e.g., id_ed25519_sk, id_ecdsa_sk
  return signingKey.includes('_sk');
}

function getKeyType(signingKey: string): string {
  if (signingKey.includes('ed25519_sk')) return 'ed25519-sk (FIDO2, hardware-backed)';
  if (signingKey.includes('ecdsa_sk')) return 'ecdsa-sk (FIDO2, hardware-backed)';
  if (signingKey.includes('ed25519')) return 'ed25519 (software key)';
  if (signingKey.includes('ecdsa')) return 'ecdsa (software key)';
  if (signingKey.includes('rsa')) return 'rsa (software key)';
  return 'unknown';
}

// ─── Main ───────────────────────────────────────────────────────────────────────

async function main() {
  try {
    // Skip for subagents
    const isSubagent = (process.env.CLAUDE_PROJECT_DIR || '').includes('/.claude/Agents/') ||
                       process.env.CLAUDE_AGENT_TYPE !== undefined;
    if (isSubagent) {
      process.exit(0);
    }

    // Read stdin for session context
    let cwd = process.cwd();
    try {
      const text = await Promise.race([
        Bun.stdin.text(),
        new Promise<string>((_, reject) => setTimeout(() => reject(new Error('timeout')), 500))
      ]);
      if (text.trim()) {
        const parsed = JSON.parse(text);
        if (parsed.cwd) cwd = parsed.cwd;
      }
    } catch {
      // Use process.cwd()
    }

    // Not a git repo → nothing to check
    if (!isGitRepo(cwd)) {
      process.exit(0);
    }

    const checks: Array<{ name: string; pass: boolean; detail: string; fix?: string }> = [];
    const wsl = isWSL();

    // ── Check 1: gpg.format == ssh ──
    const gpgFormat = gitConfig('gpg.format', cwd);
    checks.push({
      name: 'Signing format',
      pass: gpgFormat === 'ssh',
      detail: gpgFormat ? `gpg.format = ${gpgFormat}` : 'gpg.format not set',
      fix: gpgFormat !== 'ssh'
        ? 'git config --global gpg.format ssh'
        : undefined,
    });

    // ── Check 2: user.signingkey points to _sk key ──
    const signingKey = gitConfig('user.signingkey', cwd);
    const isHW = signingKey ? isHardwareKey(signingKey) : false;
    const keyType = signingKey ? getKeyType(signingKey) : 'none';
    checks.push({
      name: 'Signing key',
      pass: !!signingKey && isHW,
      detail: signingKey
        ? `${signingKey} (${keyType})`
        : 'No signing key configured',
      fix: !signingKey
        ? 'ssh-keygen -t ed25519-sk -O resident -O verify-required -C "git-signing $(git config user.email)" -f ~/.ssh/id_ed25519_sk_git_signing && git config --global user.signingkey ~/.ssh/id_ed25519_sk_git_signing.pub'
        : (!isHW ? 'Current key is software-only. Generate a FIDO2 hardware key: ssh-keygen -t ed25519-sk -O resident -O verify-required -f ~/.ssh/id_ed25519_sk_git_signing' : undefined),
    });

    // ── Check 3: commit.gpgSign == true ──
    const commitSign = gitConfig('commit.gpgSign', cwd);
    checks.push({
      name: 'Auto-sign commits',
      pass: commitSign === 'true',
      detail: commitSign === 'true' ? 'Enabled' : 'Disabled',
      fix: commitSign !== 'true'
        ? 'git config --global commit.gpgSign true'
        : undefined,
    });

    // ── Check 4: tag.forceSignAnnotated == true ──
    const tagSign = gitConfig('tag.forceSignAnnotated', cwd);
    checks.push({
      name: 'Auto-sign tags',
      pass: tagSign === 'true',
      detail: tagSign === 'true' ? 'Enabled' : 'Disabled',
      fix: tagSign !== 'true'
        ? 'git config --global tag.forceSignAnnotated true'
        : undefined,
    });

    // ── Check 5: Signing key file exists ──
    if (signingKey) {
      // Key path may be the .pub file or the private key path
      const keyPath = signingKey.replace(/\.pub$/, '');
      const pubPath = keyPath.endsWith('.pub') ? keyPath : `${keyPath}.pub`;
      const expandedPub = pubPath.replace(/^~/, process.env.HOME || '/home/user');
      const expandedKey = keyPath.replace(/^~/, process.env.HOME || '/home/user');

      const pubExists = existsSync(expandedPub);
      const keyExists = existsSync(expandedKey);

      checks.push({
        name: 'Key file exists',
        pass: pubExists || keyExists,
        detail: pubExists || keyExists
          ? `Found at ${pubExists ? expandedPub : expandedKey}`
          : `Not found: ${expandedPub}`,
        fix: !(pubExists || keyExists) && isHW
          ? 'ssh-keygen -K  # Download resident key handles from YubiKey'
          : undefined,
      });
    }

    // ── Check 6: allowedSignersFile ──
    const allowedSigners = gitConfig('gpg.ssh.allowedSignersFile', cwd);
    if (allowedSigners) {
      const expandedSigners = allowedSigners.replace(/^~/, process.env.HOME || '/home/user');
      checks.push({
        name: 'Allowed signers file',
        pass: existsSync(expandedSigners),
        detail: existsSync(expandedSigners)
          ? `${expandedSigners} exists`
          : `${expandedSigners} not found`,
        fix: !existsSync(expandedSigners)
          ? `echo "$(git config user.email) namespaces=\\"git\\" $(cat ${signingKey})" >> ${expandedSigners}`
          : undefined,
      });
    } else {
      checks.push({
        name: 'Allowed signers file',
        pass: false,
        detail: 'gpg.ssh.allowedSignersFile not set',
        fix: 'git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers',
      });
    }

    // ── Check 7: WSL2 FIDO2 bridge ──
    if (wsl) {
      const skProvider = process.env.SSH_SK_PROVIDER;
      const sshProgram = gitConfig('gpg.ssh.program', cwd);
      const hasBridge = !!skProvider || (sshProgram && sshProgram.includes('Windows'));

      checks.push({
        name: 'WSL2 FIDO2 bridge',
        pass: !!hasBridge,
        detail: hasBridge
          ? (skProvider ? `SSH_SK_PROVIDER=${skProvider}` : `gpg.ssh.program=${sshProgram}`)
          : 'No WSL2 FIDO2 bridge detected',
        fix: !hasBridge
          ? 'Option A: export SSH_SK_PROVIDER=/usr/lib/windows-fido-bridge/libnativemessaging.so\nOption B: git config --global gpg.ssh.program "/mnt/c/Windows/System32/OpenSSH/ssh-keygen.exe"'
          : undefined,
      });
    }

    // ── Report ──
    const passing = checks.filter(c => c.pass);
    const failing = checks.filter(c => !c.pass);

    if (failing.length === 0) {
      const hwLabel = isHW ? 'hardware-backed' : '';
      const status = `Commit signing: All ${checks.length} checks passing (${hwLabel} ${keyType})`;
      console.log(`<system-reminder>\n🔑 ${status}\n</system-reminder>`);
    } else {
      console.error(`🔑 Commit signing: ${passing.length}/${checks.length} checks passing`);
      console.error('');

      for (const check of checks) {
        const icon = check.pass ? '✅' : '⚠️';
        console.error(`  ${icon} ${check.name}: ${check.detail}`);
        if (!check.pass && check.fix) {
          console.error(`     Fix: ${check.fix}`);
        }
      }

      const gapNames = failing.map(c => c.name).join(', ');
      const status = `Commit signing: ${failing.length} gap(s) — ${gapNames}`;
      console.log(`<system-reminder>\n⚠️ ${status}\n</system-reminder>`);
    }
  } catch (err) {
    console.error('CommitSigningGuard hook error:', (err as Error).message);
  }

  process.exit(0);
}

main();
