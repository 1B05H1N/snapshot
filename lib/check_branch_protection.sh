#!/usr/bin/env bash
# check_branch_protection.sh - Module for branch protection check

# Expects the following variables/functions to be available in the parent script:
# - should_run_check, note, warn, critical, sarif_add_result

check_branch_protection() {
  should_run_check "branch" || return
  note "Verifying branch protection…"
  [[ -n "${GITHUB_TOKEN:-}" ]] || { warn "GITHUB_TOKEN not set" "low"; return; }

  : "${GITHUB_REPOSITORY:=$(git config --get remote.origin.url \
      | sed -E 's#.*/([^/]+/[^/]+)(\.git)?#\1#')}"
  branch=$(git symbolic-ref --short HEAD)
  api="https://api.github.com/repos/$GITHUB_REPOSITORY/branches/$branch"

  if curl -s -H "Authorization: token $GITHUB_TOKEN" "$api" | jq -r .protected | grep -q true; then
    ok "Branch protection enabled on $branch"
  else
    critical "Branch $branch is NOT protected"
    sarif_add_result "error" "Branch not protected" "."
  fi
} 