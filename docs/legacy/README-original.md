# sscs-scaffolding

Software Supply Chain Security scaffolding and tooling, targeting **SLSA v1.2 Build L3 + Source L3**.

## What's Here

```
sscs-scaffolding/
├── SSCS-PROJECT-PLAN.md          # Full implementation plan (5 phases)
├── PHASE1-MANUAL-SETUP.md        # Manual YubiKey/GitHub setup checklist
├── hooks/
│   ├── PreCommitGuard.hook.ts    # TruffleHog + Gitleaks pre-commit enforcement
│   ├── BranchProtectionGuard.hook.ts  # GitHub branch protection verification
│   └── CommitSigningGuard.hook.ts     # Hardware-backed commit signing verification
├── scripts/
│   └── audit-actions.sh          # GitHub Actions SHA pinning + permissions audit
└── security-patterns/
    └── patterns.yaml             # SecurityValidator supply chain patterns
```

## Phase 1 Status

| # | Task | Status |
|---|------|--------|
| 1.1 | TruffleHog pre-commit hook | Done |
| 1.2 | Gitleaks complementary scanner | Done |
| 1.3 | Branch protection verification | Done |
| 1.4 | Pin GitHub Actions to SHAs | Done (audit script) |
| 1.5 | Minimum GH Actions permissions | Done (audit script) |
| 1.6 | YubiKey FIDO2 commit signing | Done (hook + manual setup) |
| 1.7 | GitHub Vigilant Mode | Manual (see checklist) |
| 1.8 | Backup signing key | Manual (see checklist) |
| 1.9 | WSL2 FIDO2 bridge | Manual (see checklist) |
| 1.10 | FIDO2 MFA on GitHub | Manual (see checklist) |

## Quick Start

### Install hooks (Claude Code / PAI)

Copy hooks to your Claude Code hooks directory:

```bash
cp hooks/*.hook.ts ~/.claude/hooks/
```

Register in `~/.claude/settings.json` under `hooks.SessionStart`:

```json
{
  "type": "command",
  "command": "${PAI_DIR}/hooks/BranchProtectionGuard.hook.ts"
},
{
  "type": "command",
  "command": "${PAI_DIR}/hooks/CommitSigningGuard.hook.ts"
}
```

### Audit GitHub Actions

```bash
./scripts/audit-actions.sh /path/to/your/repo
```

### Manual setup

See [PHASE1-MANUAL-SETUP.md](PHASE1-MANUAL-SETUP.md) for YubiKey and GitHub configuration.
