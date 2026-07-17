#!/usr/bin/env bash
# audit-actions.sh — Audit GitHub Actions for SHA pinning and minimum permissions
#
# Usage: ./scripts/audit-actions.sh [path-to-repo-or-workflows-dir]
#
# Tasks covered:
#   1.4 — Pin all GitHub Actions to full SHAs (flags tag-based references)
#   1.5 — Set minimum permissions in all GH Actions workflows (flags missing/broad permissions)
#
# Output: Report of unpinned actions and permission gaps with suggested fixes.
#
# Dependencies: yq (optional, for YAML parsing), gh CLI (optional, for SHA resolution)

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ─── Arguments ───────────────────────────────────────────────────────────────────

TARGET="${1:-.}"

# Find workflow files
if [[ -d "$TARGET/.github/workflows" ]]; then
  WORKFLOW_DIR="$TARGET/.github/workflows"
elif [[ -d "$TARGET" ]]; then
  WORKFLOW_DIR="$TARGET"
else
  echo -e "${RED}Error: No workflows found at $TARGET${NC}"
  exit 1
fi

WORKFLOW_FILES=()
while IFS= read -r -d '' file; do
  WORKFLOW_FILES+=("$file")
done < <(find "$WORKFLOW_DIR" -maxdepth 1 -name '*.yml' -o -name '*.yaml' | tr '\n' '\0')

if [[ ${#WORKFLOW_FILES[@]} -eq 0 ]]; then
  echo -e "${YELLOW}No workflow files found in $WORKFLOW_DIR${NC}"
  exit 0
fi

echo -e "${BOLD}${CYAN}=== GitHub Actions Security Audit ===${NC}"
echo -e "Scanning: $WORKFLOW_DIR"
echo -e "Files: ${#WORKFLOW_FILES[@]} workflow(s)"
echo ""

# ─── Counters ────────────────────────────────────────────────────────────────────

TOTAL_ACTIONS=0
UNPINNED_ACTIONS=0
PINNED_ACTIONS=0
FILES_MISSING_PERMISSIONS=0
FILES_WITH_BROAD_PERMISSIONS=0
TOTAL_FILES=${#WORKFLOW_FILES[@]}

# ─── Task 1.4: Check Action Pinning ─────────────────────────────────────────────

echo -e "${BOLD}--- Task 1.4: Action SHA Pinning ---${NC}"
echo ""

for wf in "${WORKFLOW_FILES[@]}"; do
  filename=$(basename "$wf")
  file_issues=0

  # Extract all 'uses:' lines (handles both - uses: and uses: formats)
  while IFS= read -r line; do
    # Skip comments
    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    # Extract the action reference
    if [[ "$line" =~ uses:[[:space:]]*[\"\']?([^\"\'[:space:]]+) ]]; then
      action_ref="${BASH_REMATCH[1]}"
      ((TOTAL_ACTIONS++))

      # Skip Docker and local actions
      [[ "$action_ref" == docker://* ]] && continue
      [[ "$action_ref" == ./* ]] && continue

      # Check if pinned to full SHA (40+ hex chars after @)
      if [[ "$action_ref" =~ @[0-9a-f]{40} ]]; then
        ((PINNED_ACTIONS++))
      else
        ((UNPINNED_ACTIONS++))
        if [[ $file_issues -eq 0 ]]; then
          echo -e "  ${YELLOW}$filename:${NC}"
          file_issues=1
        fi

        # Extract owner/repo and tag
        if [[ "$action_ref" =~ ^([^@]+)@(.+)$ ]]; then
          action_name="${BASH_REMATCH[1]}"
          action_tag="${BASH_REMATCH[2]}"

          # Try to resolve the SHA via gh CLI
          sha=""
          if command -v gh &>/dev/null; then
            sha=$(gh api "repos/${action_name}/git/ref/tags/${action_tag}" --jq '.object.sha' 2>/dev/null || true)
            # Handle annotated tags (need to dereference)
            if [[ -n "$sha" ]]; then
              obj_type=$(gh api "repos/${action_name}/git/tags/${sha}" --jq '.object.type' 2>/dev/null || echo "commit")
              if [[ "$obj_type" == "commit" ]]; then
                sha=$(gh api "repos/${action_name}/git/tags/${sha}" --jq '.object.sha' 2>/dev/null || echo "$sha")
              fi
            fi
          fi

          if [[ -n "$sha" ]]; then
            echo -e "    ${RED}UNPINNED:${NC} ${action_ref}"
            echo -e "    ${GREEN}FIX:${NC}      ${action_name}@${sha} # ${action_tag}"
          else
            echo -e "    ${RED}UNPINNED:${NC} ${action_ref}"
            echo -e "    ${YELLOW}FIX:${NC}      Pin to full SHA (run: gh api repos/${action_name}/git/ref/tags/${action_tag} --jq '.object.sha')"
          fi
        else
          echo -e "    ${RED}UNPINNED:${NC} ${action_ref} (no tag/version reference)"
        fi
      fi
    fi
  done < "$wf"
done

echo ""
echo -e "  ${BOLD}Summary:${NC} ${PINNED_ACTIONS}/${TOTAL_ACTIONS} actions pinned to SHA"
if [[ $UNPINNED_ACTIONS -gt 0 ]]; then
  echo -e "  ${RED}${UNPINNED_ACTIONS} action(s) need SHA pinning${NC}"
fi
echo ""

# ─── Task 1.5: Check Workflow Permissions ────────────────────────────────────────

echo -e "${BOLD}--- Task 1.5: Workflow Permissions ---${NC}"
echo ""

for wf in "${WORKFLOW_FILES[@]}"; do
  filename=$(basename "$wf")
  content=$(cat "$wf")
  issues=()

  # Check for top-level permissions
  if ! grep -qE '^permissions:' "$wf"; then
    issues+=("No top-level 'permissions:' block — defaults to BROAD read-write for all scopes")
    ((FILES_MISSING_PERMISSIONS++))
  else
    # Check for overly broad permissions
    if grep -qE '^\s+contents:\s*write' "$wf" && ! grep -qE 'release|publish|deploy|push' "$wf"; then
      issues+=("contents: write may be broader than needed")
    fi

    # Check for write-all
    if grep -qE '^permissions:\s*write-all' "$wf"; then
      issues+=("permissions: write-all grants ALL write permissions — restrict to specific scopes")
      ((FILES_WITH_BROAD_PERMISSIONS++))
    fi

    # Check for read-all (acceptable but could be tighter)
    if grep -qE '^permissions:\s*read-all' "$wf"; then
      issues+=("permissions: read-all grants ALL read permissions — consider restricting to specific scopes")
    fi
  fi

  # Check for job-level permissions (good practice)
  has_job_permissions=false
  if grep -qE '^\s{2,}permissions:' "$wf"; then
    has_job_permissions=true
  fi

  if [[ ${#issues[@]} -gt 0 ]]; then
    echo -e "  ${YELLOW}$filename:${NC}"
    for issue in "${issues[@]}"; do
      echo -e "    ${RED}ISSUE:${NC} $issue"
    done

    # Suggest minimal permissions based on workflow content
    echo -e "    ${GREEN}SUGGESTED:${NC}"
    echo -e "      permissions:"

    if grep -qE 'actions/checkout' "$wf"; then
      echo -e "        contents: read"
    fi

    if grep -qE 'id-token.*write|cosign|attest|sigstore|slsa' "$wf"; then
      echo -e "        id-token: write"
    fi

    if grep -qE 'packages.*write|docker.*push|ghcr\.io' "$wf"; then
      echo -e "        packages: write"
    fi

    if grep -qE 'attestations.*write|attest-build-provenance' "$wf"; then
      echo -e "        attestations: write"
    fi

    if grep -qE 'pull_request|gh pr|pull-request' "$wf"; then
      echo -e "        pull-requests: write"
    fi

    if grep -qE 'create.*release|gh release|softprops/action-gh-release' "$wf"; then
      echo -e "        contents: write"
    fi

    echo ""
  fi
done

# Files with no issues
good_files=$((TOTAL_FILES - FILES_MISSING_PERMISSIONS - FILES_WITH_BROAD_PERMISSIONS))
if [[ $good_files -eq $TOTAL_FILES ]]; then
  echo -e "  ${GREEN}All workflows have explicit, scoped permissions${NC}"
fi

echo ""
echo -e "  ${BOLD}Summary:${NC}"
echo -e "  ${TOTAL_FILES} workflow(s) scanned"
if [[ $FILES_MISSING_PERMISSIONS -gt 0 ]]; then
  echo -e "  ${RED}${FILES_MISSING_PERMISSIONS} file(s) missing top-level permissions block${NC}"
fi
if [[ $FILES_WITH_BROAD_PERMISSIONS -gt 0 ]]; then
  echo -e "  ${RED}${FILES_WITH_BROAD_PERMISSIONS} file(s) with overly broad permissions${NC}"
fi

# ─── Final Report ────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}=== Overall Status ===${NC}"

total_issues=$((UNPINNED_ACTIONS + FILES_MISSING_PERMISSIONS + FILES_WITH_BROAD_PERMISSIONS))
if [[ $total_issues -eq 0 ]]; then
  echo -e "${GREEN}All checks passing. GitHub Actions are properly secured.${NC}"
  exit 0
else
  echo -e "${RED}${total_issues} issue(s) found across ${TOTAL_FILES} workflow(s)${NC}"
  echo ""
  echo -e "Run with fixes applied, then re-audit to verify."
  exit 1
fi
