#!/usr/bin/env bun
/**
 * PreCommitGuard.hook.ts - Ensure TruffleHog + Gitleaks Pre-Commit Hooks (SessionStart)
 *
 * PURPOSE:
 * Prevents plaintext credentials from being committed to git repos. On every
 * session start, checks that the working directory's git repo has a pre-commit
 * config with TruffleHog (OS-native binary) and Gitleaks secret-scanning hooks.
 * Installs missing components (pre-commit, trufflehog) and creates/updates
 * config as needed. Gitleaks is managed by pre-commit directly (no local install).
 *
 * TRIGGER: SessionStart
 *
 * INPUT:
 * - stdin: { session_id, cwd, hook_event_name: "SessionStart" }
 *
 * OUTPUT:
 * - stdout: <system-reminder> with guard status
 * - stderr: Progress/error messages
 * - exit(0): Always (non-blocking, informational)
 *
 * SIDE EFFECTS:
 * - May install pre-commit via pip
 * - May install trufflehog via install script
 * - May create or modify .pre-commit-config.yaml
 * - May run `pre-commit install` to register git hooks
 *
 * INTER-HOOK RELATIONSHIPS:
 * - DEPENDS ON: None
 * - COORDINATES WITH: None
 * - MUST RUN BEFORE: None
 * - MUST RUN AFTER: LoadContext.hook.ts (context should load first)
 *
 * ERROR HANDLING:
 * - Not a git repo: Silent exit (nothing to guard)
 * - Installation failures: Logged to stderr, exits cleanly
 * - Config parse failures: Creates fresh config
 *
 * PERFORMANCE:
 * - Non-blocking: Yes (security advisory, not critical path)
 * - Typical execution: <2s (fast path), <30s (installation path)
 * - Skipped for subagents: Yes
 */

import { existsSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { execSync } from 'child_process';

// ─── Pre-Commit Config Blocks ───────────────────────────────────────────────────

const TRUFFLEHOG_HOOK_YAML = `  - repo: local
    hooks:
      - id: trufflehog
        name: TruffleHog
        description: Detect secrets in your data.
        entry: trufflehog git file://. --since-commit HEAD --results=verified,unknown --fail
        language: system
        stages: ["pre-commit", "pre-push"]
        pass_filenames: false`;

const GITLEAKS_HOOK_YAML = `  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.22.1
    hooks:
      - id: gitleaks`;

const FULL_PRECOMMIT_CONFIG = `# See https://pre-commit.com for more information
# See https://pre-commit.com/hooks.html for more hooks
repos:
${TRUFFLEHOG_HOOK_YAML}
${GITLEAKS_HOOK_YAML}
`;

// ─── Helpers ────────────────────────────────────────────────────────────────────

function isGitRepo(cwd: string): boolean {
  try {
    execSync('git rev-parse --git-dir', { cwd, stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function getGitRoot(cwd: string): string {
  return execSync('git rev-parse --show-toplevel', { cwd, stdio: 'pipe' })
    .toString()
    .trim();
}

function commandExists(cmd: string): boolean {
  try {
    execSync(`command -v ${cmd}`, { stdio: 'pipe' });
    return true;
  } catch {
    // In WSL, also check .exe variants
    try {
      execSync(`command -v ${cmd}.exe`, { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * Find the actual command to use (handles WSL .exe fallback and Windows Python Scripts)
 */
function resolveCommand(cmd: string): string | null {
  // 1. Check native Linux PATH
  try {
    execSync(`command -v ${cmd}`, { stdio: 'pipe' });
    return cmd;
  } catch {}

  // 2. Check .exe on PATH (WSL interop)
  try {
    execSync(`command -v ${cmd}.exe`, { stdio: 'pipe' });
    return `${cmd}.exe`;
  } catch {}

  // 3. Check Windows Python Scripts directories (WSL-specific)
  try {
    const winUser = process.env.HOME?.includes('/home/')
      ? execSync('cmd.exe /c echo %USERPROFILE% 2>/dev/null', { stdio: 'pipe' }).toString().trim()
      : null;
    if (winUser) {
      const wslUserProfile = winUser.replace(/\\/g, '/').replace(/^([A-Za-z]):/, (_, d: string) => `/mnt/${d.toLowerCase()}`).replace(/\r?\n$/, '');
      // Check both global and per-user Python Scripts
      const scriptPaths = [
        `${wslUserProfile}/AppData/Local/Programs/Python/*/Scripts/${cmd}.exe`,
        `${wslUserProfile}/AppData/Local/Packages/PythonSoftwareFoundation.Python.*/LocalCache/local-packages/Python*/Scripts/${cmd}.exe`,
      ];
      for (const pattern of scriptPaths) {
        try {
          const found = execSync(`ls ${pattern} 2>/dev/null | head -1`, { stdio: 'pipe' }).toString().trim();
          if (found) {
            // Verify it actually runs
            execSync(`"${found}" --version`, { stdio: 'pipe', timeout: 5000 });
            return `"${found}"`;
          }
        } catch {}
      }
    }
  } catch {}

  return null;
}

function installPreCommit(): boolean {
  console.error('🔧 pre-commit not found. Installing via pip...');

  // Try multiple pip variants (handles WSL, native Linux, macOS)
  const pipCandidates = ['pip3', 'pip', 'pip3.exe', 'pip.exe', 'python3 -m pip', 'python -m pip'];

  for (const pipCmd of pipCandidates) {
    try {
      execSync(`${pipCmd} --version`, { stdio: 'pipe', timeout: 5000 });
      execSync(`${pipCmd} install pre-commit`, { stdio: 'pipe', timeout: 120000 });
      console.error(`✅ pre-commit installed successfully (via ${pipCmd})`);
      return true;
    } catch {
      continue;
    }
  }

  console.error('❌ Failed to install pre-commit: no working pip found');
  console.error('   Install manually: pip install pre-commit');
  return false;
}

function installTrufflehog(): boolean {
  console.error('🔧 trufflehog not found. Installing...');
  try {
    execSync('curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin', {
      stdio: 'pipe',
      timeout: 60000
    });
    console.error('✅ trufflehog installed successfully');
    return true;
  } catch {
    // Try without sudo first failed, try user-local
    try {
      const homeDir = process.env.HOME || '/tmp';
      const localBin = join(homeDir, '.local', 'bin');
      execSync(`mkdir -p ${localBin}`, { stdio: 'pipe' });
      execSync(`curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b ${localBin}`, {
        stdio: 'pipe',
        timeout: 60000
      });
      console.error(`✅ trufflehog installed to ${localBin}`);
      return true;
    } catch (err) {
      console.error('❌ Failed to install trufflehog:', (err as Error).message);
      console.error('   Install manually: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin');
      return false;
    }
  }
}

function hasTrufflehogHook(configContent: string): boolean {
  // Check if the config already contains a trufflehog hook entry
  return configContent.includes('id: trufflehog') || configContent.includes('trufflehog');
}

function hasGitleaksHook(configContent: string): boolean {
  return configContent.includes('id: gitleaks') || configContent.includes('gitleaks/gitleaks');
}

function addGitleaksToConfig(configPath: string, configContent: string): void {
  if (configContent.includes('repos:')) {
    const newContent = configContent.trimEnd() + '\n' + GITLEAKS_HOOK_YAML + '\n';
    writeFileSync(configPath, newContent, 'utf-8');
    console.error('✅ Added Gitleaks hook to .pre-commit-config.yaml');
  } else {
    const newContent = configContent.trimEnd() + '\nrepos:\n' + GITLEAKS_HOOK_YAML + '\n';
    writeFileSync(configPath, newContent, 'utf-8');
    console.error('✅ Added repos section with Gitleaks hook to .pre-commit-config.yaml');
  }
}

function usesSystemBinary(configContent: string): boolean {
  // Check that the trufflehog hook uses language: system (OS-native binary)
  // Find the trufflehog hook block and check its language setting
  const lines = configContent.split('\n');
  let inTrufflehogBlock = false;
  let indentLevel = -1;

  for (const line of lines) {
    if (line.includes('id: trufflehog')) {
      inTrufflehogBlock = true;
      indentLevel = line.search(/\S/);
      continue;
    }
    if (inTrufflehogBlock) {
      const currentIndent = line.search(/\S/);
      // If we've dedented back to or past the hook's indent level, we've left the block
      if (currentIndent <= indentLevel && line.trim().startsWith('- ')) {
        break;
      }
      if (line.includes('language: system')) {
        return true;
      }
    }
  }
  return false;
}

function addTrufflehogToConfig(configPath: string, configContent: string): void {
  // If it has trufflehog but not system binary, warn but don't modify
  // (user may have intentionally chosen a different approach)
  if (hasTrufflehogHook(configContent) && !usesSystemBinary(configContent)) {
    console.error('⚠️  TruffleHog hook exists but does NOT use OS-native binary (language: system).');
    console.error('   Consider updating to use: language: system');
    console.error('   Current config left unchanged to avoid breaking custom setup.');
    return;
  }

  // Append the TruffleHog hook to the repos section
  // Check if repos: key exists
  if (configContent.includes('repos:')) {
    // Append after existing repos
    const newContent = configContent.trimEnd() + '\n' + TRUFFLEHOG_HOOK_YAML + '\n';
    writeFileSync(configPath, newContent, 'utf-8');
    console.error('✅ Added TruffleHog hook to existing .pre-commit-config.yaml');
  } else {
    // Malformed config without repos — append full repos block
    const newContent = configContent.trimEnd() + '\nrepos:\n' + TRUFFLEHOG_HOOK_YAML + '\n';
    writeFileSync(configPath, newContent, 'utf-8');
    console.error('✅ Added repos section with TruffleHog hook to .pre-commit-config.yaml');
  }
}

function runPreCommitInstall(gitRoot: string, preCommitCmd: string): void {
  try {
    execSync(`${preCommitCmd} install`, { cwd: gitRoot, stdio: 'pipe', timeout: 30000 });

    // Fix WSL compatibility: pre-commit.exe creates hooks with CRLF and dual-shebang
    // that break when git runs them in WSL bash
    const hookPath = join(gitRoot, '.git', 'hooks', 'pre-commit');
    if (existsSync(hookPath)) {
      let hookContent = readFileSync(hookPath, 'utf-8');
      const needsFix = hookContent.includes('\r') || hookContent.startsWith('#!/bin/sh\n#!/usr/bin/env bash');

      if (needsFix) {
        // Remove CRLF
        hookContent = hookContent.replace(/\r\n/g, '\n');
        // Fix dual-shebang: #!/bin/sh + #!/usr/bin/env bash → just #!/usr/bin/env bash
        hookContent = hookContent.replace(/^#!\/bin\/sh\n#!\/usr\/bin\/env bash/, '#!/usr/bin/env bash');
        writeFileSync(hookPath, hookContent, 'utf-8');
        console.error('✅ Fixed WSL line endings in pre-commit hook');
      }
    }

    console.error('✅ pre-commit hooks installed in git repo');
  } catch (err) {
    console.error('⚠️  Failed to run pre-commit install:', (err as Error).message);
  }
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
      const decoder = new TextDecoder();
      const reader = Bun.stdin.stream().getReader();
      const chunks: Uint8Array[] = [];

      const readPromise = (async () => {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
        }
      })();

      await Promise.race([readPromise, new Promise<void>(r => setTimeout(r, 500))]);

      if (chunks.length > 0) {
        const input = decoder.decode(Buffer.concat(chunks));
        const parsed = JSON.parse(input);
        if (parsed.cwd) cwd = parsed.cwd;
      }
    } catch {
      // stdin read failed, use process.cwd()
    }

    // ── Step 1: Check if we're in a git repo ──
    if (!isGitRepo(cwd)) {
      // Not a git repo, nothing to do
      process.exit(0);
    }

    const gitRoot = getGitRoot(cwd);
    const configPath = join(gitRoot, '.pre-commit-config.yaml');
    const actions: string[] = [];

    // ── Step 2: Ensure pre-commit is installed ──
    let preCommitCmd = resolveCommand('pre-commit');
    if (!preCommitCmd) {
      if (!installPreCommit()) {
        console.error('⚠️  Skipping pre-commit guard: pre-commit not available');
        process.exit(0);
      }
      preCommitCmd = resolveCommand('pre-commit');
      if (!preCommitCmd) {
        console.error('⚠️  pre-commit installed but not found on PATH');
        process.exit(0);
      }
      actions.push('Installed pre-commit');
    }

    // ── Step 3: Ensure trufflehog is installed ──
    let trufflehogCmd = resolveCommand('trufflehog');
    if (!trufflehogCmd) {
      if (!installTrufflehog()) {
        console.error('⚠️  Skipping pre-commit guard: trufflehog not available');
        process.exit(0);
      }
      trufflehogCmd = resolveCommand('trufflehog');
      if (!trufflehogCmd) {
        console.error('⚠️  trufflehog installed but not found on PATH');
        process.exit(0);
      }
      actions.push('Installed trufflehog');
    }

    // ── Step 4: Check/create .pre-commit-config.yaml ──
    if (!existsSync(configPath)) {
      // No config file — create one with TruffleHog
      writeFileSync(configPath, FULL_PRECOMMIT_CONFIG, 'utf-8');
      console.error('✅ Created .pre-commit-config.yaml with TruffleHog hook');
      actions.push('Created .pre-commit-config.yaml');
    } else {
      // Config exists — check for TruffleHog
      const configContent = readFileSync(configPath, 'utf-8');

      if (!hasTrufflehogHook(configContent)) {
        addTrufflehogToConfig(configPath, configContent);
        actions.push('Added TruffleHog hook to config');
      } else if (!usesSystemBinary(configContent)) {
        console.error('⚠️  TruffleHog hook exists but may not use OS-native binary');
        actions.push('TruffleHog hook present (non-system binary)');
      } else {
        // All good — TruffleHog hook with system binary exists
      }
    }

    // ── Step 4b: Check/add Gitleaks to config ──
    {
      const configContent = readFileSync(configPath, 'utf-8');
      if (!hasGitleaksHook(configContent)) {
        addGitleaksToConfig(configPath, configContent);
        actions.push('Added Gitleaks hook to config');
      }
    }

    // ── Step 5: Run pre-commit install ──
    // Check if .git/hooks/pre-commit exists and is managed by pre-commit
    const preCommitHookPath = join(gitRoot, '.git', 'hooks', 'pre-commit');
    const needsInstall = !existsSync(preCommitHookPath) ||
      !readFileSync(preCommitHookPath, 'utf-8').includes('pre-commit');

    if (needsInstall) {
      runPreCommitInstall(gitRoot, preCommitCmd);
      actions.push('Ran pre-commit install');
    }

    // ── Output summary ──
    if (actions.length > 0) {
      const summary = actions.map(a => `  • ${a}`).join('\n');
      console.error(`🛡️  Pre-commit guard actions:\n${summary}`);
    }

    // Inject status into context so Claude knows the repo is protected
    const status = actions.length > 0
      ? `Pre-commit guard: ${actions.join(', ')}`
      : 'Pre-commit guard: TruffleHog + Gitleaks secret scanning active';

    console.log(`<system-reminder>\n🛡️ ${status}\n</system-reminder>`);

  } catch (err) {
    console.error('PreCommitGuard hook error:', (err as Error).message);
  }

  process.exit(0);
}

main();
