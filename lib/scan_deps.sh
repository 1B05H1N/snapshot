#!/usr/bin/env bash
# scan_deps.sh - Module for dependency vulnerability checks

# Expects the following variables/functions to be available in the parent script:
# - should_run_check, note, ok, warn, error, sarif_add_result, require_strict, TMP_FILES

scan_deps() {
  should_run_check "deps" || return
  note "Checking dependencies via OSV.dev…"
  require_strict jq

  local locks=() tmp
  while IFS= read -r file; do
    locks+=("$file")
  done < <(git ls-files | grep -E 'package-lock\.json$|go\.sum$|Pipfile\.lock$' || true)
  [[ ${#locks[@]} -eq 0 ]] && { ok "No lockfiles"; return; }

  tmp=$(mktemp)
  TMP_FILES+=("$tmp")
  for lf in "${locks[@]}"; do
    run_with_spinner "OSV for $lf" bash -c '
      osv=$(curl -s --fail --retry 3 --data @"'"$lf"'" https://api.osv.dev/v1/querybatch || true)
      jq -r ".results[].vulns|length" <<<"$osv" | awk "{s+=\$1}END{print s}"
    ' >"$tmp"
    cnt=$(<"$tmp")
    if (( cnt > 0 )); then
      warn "$lf: $cnt vulnerable packages" "medium"
      sarif_add_result "warning" "$cnt vulns" "$lf"
    else
      ok "$lf – no known vulns"
    fi
  done
  rm -f "$tmp"
} 