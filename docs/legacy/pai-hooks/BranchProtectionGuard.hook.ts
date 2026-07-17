#!/usr/bin/env bun
/**
 * BranchProtectionGuard.hook.ts - Branch Protection Verification (SessionStart)
 *
 * PURPOSE:
 * Verifies that the current GitHub repo has branch protection enabled on its
 * default branch. Reports gaps with exact `gh` commands to fix them.
 *
 * TRIGGER: SessionStart
 *
 * INPUT:
 * - stdin: { session_id, cwd, hook_event_name: "SessionStart" }
 *
 * OUTPUT:
 * - stdout: <system-reminder> with branch protection status
 * - stderr: Progress/warning messages
 * - exit(0): Always (non-blocking, advisory)
 *
 * SIDE EFFECTS: None (read-only — queries GitHub API)
 *
 * INTER-HOOK RELATIONSHIPS:
 * - DEPENDS ON: None
 * - COORDINATES WITH: CommitSigningGuard.hook.ts
 * - MUST RUN BEFORE: None
 * - MUST RUN AFTER: LoadContext.hook.ts
 *
 * ERROR HANDLING:
 * - Not a git repo: Silent exit
 * - No GitHub remote: Silent exit
 * - gh CLI not installed: Silent exit
 * - API errors (403, 404): Reported to stderr, exits cleanly
 *
 * PERFORMANCE:
 * - Non-blocking: Yes (informational)
 * - Typical execution: <2s (single GitHub API call)
 * - Skipped for subagents: Yes
 */

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

function getGitRoot(cwd: string): string {
  return execSync('git rev-parse --show-toplevel', { cwd, stdio: 'pipe' })
    .toString()
    .trim();
}

function getDefaultBranch(cwd: string): string {
  // Try to get the default branch from the remote HEAD
  try {
    const ref = execSync('git symbolic-ref refs/remotes/origin/HEAD', { cwd, stdio: 'pipe' })
      .toString()
      .trim();
    return ref.replace('refs/remotes/origin/', '');
  } catch {
    // Fallback: check if main or master exists
    try {
      execSync('git rev-parse --verify origin/main', { cwd, stdio: 'pipe' });
      return 'main';
    } catch {
      try {
        execSync('git rev-parse --verify origin/master', { cwd, stdio: 'pipe' });
        return 'master';
      } catch {
        return 'main'; // Default assumption
      }
    }
  }
}

function getGitHubOwnerRepo(cwd: string): { owner: string; repo: string } | null {
  try {
    const remoteUrl = execSync('git remote get-url origin', { cwd, stdio: 'pipe' })
      .toString()
      .trim();

    // Parse SSH or HTTPS GitHub URLs
    let match = remoteUrl.match(/github\.com[:/]([^/]+)\/([^/.]+)/);
    if (match) {
      return { owner: match[1], repo: match[2] };
    }
    return null;
  } catch {
    return null;
  }
}

function ghInstalled(): boolean {
  try {
    execSync('command -v gh', { stdio: 'pipe' });
    return true;
  } catch {
    try {
      execSync('command -v gh.exe', { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }
}

interface BranchProtection {
  requirePR: boolean;
  requiredReviewers: number;
  requireStatusChecks: boolean;
  noForcePush: boolean;
  noDeletion: boolean;
  requireSignedCommits: boolean;
}

function checkBranchProtection(owner: string, repo: string, branch: string): BranchProtection | null {
  try {
    const result = execSync(
      `gh api repos/${owner}/${repo}/branches/${branch}/protection --jq '{ ` +
      `requirePR: (.required_pull_request_reviews != null), ` +
      `requiredReviewers: (.required_pull_request_reviews.required_approving_review_count // 0), ` +
      `requireStatusChecks: (.required_status_checks != null), ` +
      `noForcePush: (.allow_force_pushes.enabled == false), ` +
      `noDeletion: (.allow_deletions.enabled == false), ` +
      `requireSignedCommits: (.required_signatures.enabled // false) ` +
      `}'`,
      { stdio: 'pipe', timeout: 10000 }
    ).toString().trim();

    return JSON.parse(result) as BranchProtection;
  } catch (err) {
    const errMsg = (err as Error).message || '';
    if (errMsg.includes('404') || errMsg.includes('Branch not protected')) {
      return {
        requirePR: false,
        requiredReviewers: 0,
        requireStatusChecks: false,
        noForcePush: false,
        noDeletion: false,
        requireSignedCommits: false,
      };
    }
    // API error (403, rate limit, etc.)
    return null;
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

    const gitRoot = getGitRoot(cwd);

    // No GitHub remote → not applicable
    const ghRepo = getGitHubOwnerRepo(gitRoot);
    if (!ghRepo) {
      process.exit(0);
    }

    // gh CLI not available → can't check
    if (!ghInstalled()) {
      console.error('⚠️  BranchProtectionGuard: gh CLI not found. Install: https://cli.github.com/');
      process.exit(0);
    }

    const branch = getDefaultBranch(gitRoot);
    const { owner, repo } = ghRepo;

    const protection = checkBranchProtection(owner, repo, branch);
    if (!protection) {
      console.error(`⚠️  BranchProtectionGuard: Could not query branch protection for ${owner}/${repo}:${branch}`);
      process.exit(0);
    }

    // Analyze gaps
    const gaps: string[] = [];
    const fixes: string[] = [];

    if (!protection.noForcePush) {
      gaps.push('Force push allowed on default branch');
      fixes.push(`gh api repos/${owner}/${repo}/branches/${branch}/protection -X PUT \\
  -f "allow_force_pushes=false" -f "enforce_admins=true" \\
  -f "required_pull_request_reviews=null" -f "required_status_checks=null" -f "restrictions=null"`);
    }

    if (!protection.noDeletion) {
      gaps.push('Branch deletion allowed');
    }

    if (!protection.requireSignedCommits) {
      gaps.push('Signed commits not required');
      fixes.push(`gh api repos/${owner}/${repo}/branches/${branch}/protection/required_signatures -X POST`);
    }

    // Report results
    if (gaps.length === 0) {
      const status = `Branch protection: ${owner}/${repo}:${branch} — All controls enabled`;
      console.log(`<system-reminder>\n🛡️ ${status}\n</system-reminder>`);
    } else {
      const gapList = gaps.map(g => `  ⚠️  ${g}`).join('\n');
      console.error(`🛡️ Branch protection gaps on ${owner}/${repo}:${branch}:`);
      console.error(gapList);

      if (fixes.length > 0) {
        console.error('\nFix with:');
        fixes.forEach(f => console.error(`  ${f}`));
      }

      const status = `Branch protection: ${owner}/${repo}:${branch} — ${gaps.length} gap(s) found: ${gaps.join('; ')}`;
      console.log(`<system-reminder>\n⚠️ ${status}\n</system-reminder>`);
    }
  } catch (err) {
    console.error('BranchProtectionGuard hook error:', (err as Error).message);
  }

  process.exit(0);
}

main();
