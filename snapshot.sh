#!/usr/bin/env bash
#
# snapshot.sh v1.0.0
# 
# A lightweight security scanner for Git repositories:
#   - Secrets discovery via regex patterns + entropy-based filtering
#   - Dependency vulnerability checks via OSV.dev
#   - Infrastructure-as-Code validation
#   - Branch protection verification
#
# Usage: ./snapshot.sh [OPTIONS] [FILES...]
# Options:
#   --help             Show this help message
#   --version          Show version information
#   --sarif FILE       Output results in SARIF format
#   --skip CHECKS      Comma-separated list of checks to skip
#   --only CHECKS      Comma-separated list of checks to run
#   --severity LEVEL   Minimum severity to report (informational|low|medium|high|critical)
#   --parallel         Run checks in parallel (default: sequential)
#   --quiet            Reduce output verbosity
#   --verbose          Increase output verbosity
#
# Exits non-zero if any high-severity issue is found.

set -euo pipefail
IFS=$'\n\t'

# Globals
VERSION="1.0.0"
ENTROPY_THRESHOLD=4.0  # Lowered threshold to catch more potential secrets

ERRORS=0
SARIF_OUTPUT=""
SKIP_CHECKS=()
ONLY_CHECKS=()
SEVERITY="high"
PARALLEL=false
VERBOSITY=2  # Default to more verbose output
LOG_FILE="snapshot.log"
FILES_TO_SCAN=()

# Temporary files tracking and cleanup
TMP_FILES=()
cleanup() {
  for f in "${TMP_FILES[@]}"; do [[ -f "$f" ]] && rm -f "$f"; done
}
trap cleanup EXIT INT TERM

# Color support - disabled for better compatibility
RED='' GREEN='' YELLOW='' BLUE='' NC=''

# Source modularized checks
source "$(dirname "$0")/lib/scan_secrets.sh"
source "$(dirname "$0")/lib/scan_deps.sh"
source "$(dirname "$0")/lib/scan_iac.sh"
source "$(dirname "$0")/lib/check_branch_protection.sh"

### Helpers
# This section defines helper functions for the main script.
# It includes functions for checking the presence of required commands,
# printing messages with appropriate colors and verbosity, and running commands
# with optional progress indicators.

require_strict() {
  command -v "$1" >/dev/null 2>&1 \
    || { error "Required command '$1' not found"; exit 1; }
}

require_soft() {
  local cmd="$1" sev="${2:-low}"
  command -v "$cmd" >/dev/null 2>&1 \
    || warn "Optional command '$cmd' not found" "$sev"
}

log() {
  printf "%s\n" "$*" >> "$LOG_FILE"
  printf "%s\n" "$*"
}

note()     { [[ $VERBOSITY -ge 1 ]] && log "$*"; }
ok()       { [[ $VERBOSITY -ge 1 ]] && log "[OK]    $*"; }
warn()     { local sev="${2:-medium}"
             if should_report_severity "$sev" && [[ $VERBOSITY -ge 1 ]]; then
               log "[WARN]  $1"
               [[ "$sev" =~ ^(high|critical)$ ]] && ((ERRORS++))
             fi; }
error()    { local sev="${2:-high}"
             if should_report_severity "$sev" && [[ $VERBOSITY -ge 1 ]]; then
               log "[ERROR] $1"
               [[ "$sev" =~ ^(high|critical)$ ]] && ((ERRORS++))
             fi; }
critical() { if should_report_severity "critical" && [[ $VERBOSITY -ge 1 ]]; then
               log "[CRIT]  $1"
               ((ERRORS++))
             fi; }
info()     { if should_report_severity "informational" && [[ $VERBOSITY -ge 2 ]]; then
               log "[INFO]  $1"
             fi; }

spinner() {
  [[ $VERBOSITY -ge 1 ]] || return 0
  local msg="$1" sp='|/-\' i=0 pid=$2
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r[%c] %s" "${sp:i++%${#sp}:1}" "$msg"
    sleep 0.1
  done
  printf '\r\033[K'
}

run_with_spinner() {
  local msg="$1"; shift
  ("$@") & pid=$!; spinner "$msg" "$pid"; wait "$pid"
}

### SARIF Output Helpers
# This section defines functions for initializing and adding results to a SARIF file.
# It also defines a function for scrubbing secrets from output.

sarif_init() {
  [[ -n "$SARIF_OUTPUT" ]] || return
  cat >"$SARIF_OUTPUT" <<EOF
{
  "version":"2.1.0",
  "\$schema":"https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html",
  "runs":[{
    "tool":{"driver":{"name":"snapshot","version":"$VERSION","rules":[]}},
    "results":[]
  }]
}
EOF
}

sarif_add_result() {
  [[ -n "$SARIF_OUTPUT" ]] || return
  local lvl="$1" msg="$2" file="${3:-}" line="${4:-}"
  jq -r --arg lvl "$lvl" --arg msg "$msg" --arg file "$file" --arg line "$line" \
    '.runs[0].results += [{
       "level": $lvl,
       "message":{"text":$msg},
       "locations":[{
         "physicalLocation":{
           "artifactLocation":{"uri":$file},
           "region":{"startLine":($line|tonumber)}
         }
       }]
     }]' "$SARIF_OUTPUT" >"${SARIF_OUTPUT}.tmp" \
    && mv "${SARIF_OUTPUT}.tmp" "$SARIF_OUTPUT"
}

scrub_secret() {
  echo "$1" | sed -E 's/[A-Za-z0-9/+=]{8,}/****/g'
}

# Compute Shannon entropy (bits per character) of a given string.
#
# The entropy calculation uses the formula: H = -∑ p(c)·log₂ p(c) (please don't ask me how this works)
# where p(c) is the probability of character c in the string.
#  - p(c): probability of symbol c (frequency of c ÷ total symbols)
#  - log₂ p(c): how "surprising" c is, in bits
#  - p(c)·log₂ p(c): surprise weighted by how often c occurs
#  - ∑₍c₎ p(c)·log₂ p(c): total weighted surprise (will be ≤ 0)
#  - –∑ flips the sign so H is ≥ 0
#
# Plain terms:
#  – H is the average amount of information (in bits) you get from one symbol.
#  – If one symbol always appears (p=1), H=0 (no surprise).
#  – If two symbols are equally likely (p=1/2 each), H=1 (one bit per symbol).
#  – More symbols or more even distribution ⇒ higher H (more surprises).
#
#
# References:
#   - https://en.wikipedia.org/wiki/Entropy_(information_theory)
#   - https://pages.cs.wisc.edu/~sriram/ShannonEntropy-Intuition.pdf
#   - https://thehardcorecoder.com/2021/12/21/calculating-entropy-in-python/

shannon_entropy() {
  # Return 0 for empty or invalid input
  [[ -n "$1" ]] || { echo "0.0000"; return 1; }
  
  # Use awk for efficient entropy calculation
  # Please don't ask me how this works in detail, I looked it up / barely understand it myself
  awk '
    BEGIN {
      # Get input string and prevent awk from reading files
      str = ARGV[1]
      delete ARGV
      
      # Handle empty string case
      if (!str) {
        print "0.0000"
        exit
      }
      
      # Count frequency of each character
      n = length(str)
      for (i = 1; i <= n; i++) {
        c = substr(str, i, 1)
        freq[c]++
      }
      
      # Calculate Shannon entropy
      H = 0
      for (c in freq) {
        p = freq[c] / n
        H -= p * log(p) / log(2)
      }
      
      # Ensure non-negative result and format to 4 decimal places
      if (H < 0) H = 0
      printf("%.4f\n", H)
    }
  ' "$1"
}

### CLI Parsing
# This section handles command-line argument parsing.

usage() {
  cat >&2 <<EOF
Usage: $0 [OPTIONS] [FILES...]
Options:
  --help             Show this help message
  --version          Show version information
  --sarif FILE       Output results in SARIF format
  --skip CHECKS      Comma-separated list of checks to skip
  --only CHECKS      Comma-separated list of checks to run
  --severity LEVEL   Minimum severity (informational|low|medium|high|critical)
  --parallel         Run checks in parallel
  --quiet            Reduce output verbosity
  --verbose          Increase output verbosity
EOF
  exit 1
}

version() {
  echo "snapshot.sh v$VERSION"
  exit 0
}

validate_severity() {
  case "$1" in informational|low|medium|high|critical) ;; *)
    error "Invalid severity: $1"; exit 1;;
  esac
}

# Get severity level as a number
get_severity_level() {
  case "$1" in
    "informational") echo 0 ;;
    "low")          echo 1 ;;
    "medium")       echo 2 ;;
    "high")         echo 3 ;;
    "critical")     echo 4 ;;
    *)              echo 0 ;;
  esac
}

# Check if severity should be reported
should_report_severity() {
  local sev_level
  sev_level=$(get_severity_level "$1")
  local min_level
  min_level=$(get_severity_level "$SEVERITY")
  [[ $sev_level -ge $min_level ]]
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --help)     usage ;;
    --version)  version ;;
    --sarif)    SARIF_OUTPUT="$2"; shift 2 ;;
    --skip)     IFS=, read -ra SKIP_CHECKS <<<"$2"; shift 2 ;;
    --only)     IFS=, read -ra ONLY_CHECKS <<<"$2"; shift 2 ;;
    --severity) validate_severity "$2"; SEVERITY="$2"; shift 2 ;;
    --parallel) PARALLEL=true; shift ;;
    --quiet)    VERBOSITY=0; shift ;;
    --verbose)  VERBOSITY=2; shift ;;
    -*)         echo "Unknown option: $1" >&2; usage ;;
    *)          FILES_TO_SCAN+=("$1"); shift ;;
  esac
done

should_run_check() {
  [[ ${#ONLY_CHECKS[@]} -gt 0 && ! " ${ONLY_CHECKS[*]} " =~ " $1 " ]] && return 1
  [[ ${#SKIP_CHECKS[@]} -gt 0 &&   " ${SKIP_CHECKS[*]} " =~ " $1 " ]] && return 1
  return 0
}

### 2. Dependency Vulnerabilities
# This function scans the project for dependency vulnerabilities using OSV.dev.

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

### 3. IaC Misconfiguration Scan
# This function scans the project for IaC misconfigurations using tfsec and kube-linter.

scan_iac() {
  should_run_check "iac" || return
  note "Scanning IaC (Terraform & Kubernetes)…"
  require_soft tfsec "low" && tfsec . --soft-fail || warn "tfsec issues" "medium"
  require_soft kube-linter "low" && {
    mapfile -t k8s < <(git ls-files | grep -E '\.ya?ml$' \
      | xargs grep -lE '^kind:.*(Deployment|StatefulSet|DaemonSet)'||true)
    [[ ${#k8s[@]} -gt 0 ]] && kube-linter lint "${k8s[@]}" \
      || warn "kube-linter issues" "medium"
  }
}

### 4. Branch Protection Check
# This function checks if the current branch is protected on GitHub.

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

### 5. Main
# This is the main function that orchestrates the execution of all checks.

main() {
  # Clear log file
  > "$LOG_FILE"
  
  require_strict curl
  [[ -n "$SARIF_OUTPUT" ]] && sarif_init

  local exit_code=0
  if $PARALLEL; then
    scan_secrets & pid1=$!
    scan_deps    & pid2=$!
    scan_iac     & pid3=$!
    check_branch_protection & pid4=$!
    wait $pid1 $pid2 $pid3 $pid4
    exit_code=$?
  else
    scan_secrets || exit_code=1
    scan_deps || exit_code=1
    scan_iac || exit_code=1
    check_branch_protection || exit_code=1
  fi

  if (( ERRORS == 0 )); then
    note "Snapshot complete - no high-severity findings."
    exit 0
  else
    note "Snapshot finished with issues."
    exit $exit_code
  fi
}

main "$@"
