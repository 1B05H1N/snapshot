#!/usr/bin/env bash
# scan_secrets.sh - Module for secrets discovery

# Expects the following variables/functions to be available in the parent script:
# - FILES_TO_SCAN (array)
# - ENTROPY_THRESHOLD
# - should_run_check, note, info, critical, ok, error, scrub_secret, shannon_entropy, TMP_FILES

scan_secrets() {
  should_run_check "secrets" || return 0
  note "Scanning for potential secrets..."

  # Common secret patterns
  local patterns=(
    'AWS[_A-Z]*KEY[=:][A-Za-z0-9/+=]{16,}'
    'API[_-]?KEY[=:][A-Za-z0-9/+=]{16,}'
    'SECRET[=:][A-Za-z0-9/+=]{16,}'
    'PASSWORD[=:][A-Za-z0-9/+=]{8,}'
    'TOKEN[=:][A-Za-z0-9/+=]{16,}'
    'DATABASE_URL[=:].+'
    'JWT[_-]?SECRET[=:][A-Za-z0-9/+=]{16,}'
  )

  local found_secrets=0
  info "Checking files for secrets..."

  # Get list of files to scan
  local files_to_scan
  if [[ ${#FILES_TO_SCAN[@]} -gt 0 ]]; then
    files_to_scan=("${FILES_TO_SCAN[@]}")
  else
    while IFS= read -r file; do
      files_to_scan+=("$file")
    done < <(find . -type f -not -path "*/\.*" 2>/dev/null || true)
  fi

  # Search for each pattern
  for pattern in "${patterns[@]}"; do
    for file in "${files_to_scan[@]}"; do
      if [[ -f "$file" ]]; then
        while IFS=: read -r line content; do
          if [[ -n "$content" ]]; then
            critical "Found potential secret in ${file}:${line}"
            info "Pattern matched: ${pattern}"
            info "Content: $(scrub_secret "$content")"
            ((found_secrets++))
          fi
        done < <(grep -n -E -i "$pattern" "$file" 2>/dev/null || true)
      fi
    done
  done

  # Also check for high-entropy strings
  local tmp
  tmp=$(mktemp) || { error "mktemp failed"; return 1; }
  TMP_FILES+=("$tmp")
  
  for file in "${files_to_scan[@]}"; do
    if [[ -f "$file" ]]; then
      grep -Eo '\b[A-Za-z0-9/+=]{16,}\b' "$file" 2>/dev/null | while read -r token; do
        ent=$(shannon_entropy "$token")
        if (( $(echo "$ent > $ENTROPY_THRESHOLD" | bc -l) )); then
          critical "Found high-entropy string in ${file}"
          info "Entropy: ${ent} (threshold: ${ENTROPY_THRESHOLD})"
          info "Content: $(scrub_secret "$token")"
          ((found_secrets++))
        fi
      done
    fi
  done
  rm -f "$tmp"

  if ((found_secrets > 0)); then
    critical "Found ${found_secrets} potential secret(s)"
    return 1
  else
    ok "No secrets found"
    return 0
  fi
} 