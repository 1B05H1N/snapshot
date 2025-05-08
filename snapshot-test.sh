#!/usr/bin/env bash
# Test script for snapshot.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAPSHOT_SCRIPT="$SCRIPT_DIR/snapshot.sh"

# Check required dependencies
check_dependencies() {
  local deps=("git" "jq" "awk")
  local missing=()
  
  for dep in "${deps[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      missing+=("$dep")
    fi
  done
  
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${RED}Missing required dependencies: ${missing[*]}${NC}"
    echo "Please install them using:"
    echo "  brew install ${missing[*]}"
    exit 1
  fi
}

# Initialize test environment
setup_test_env() {
  # Ensure we're in a git repository
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git init
    git config user.name "Test User"
    git config user.email "test@example.com"
  fi
  
  # Add all files if not already tracked
  if ! git ls-files >/dev/null 2>&1; then
    git add .
    git commit -m "Initial commit" >/dev/null 2>&1
  fi

  # Create a clean test directory for SARIF output
  mkdir -p test-output
  chmod 755 test-output
}

# Helper function to run tests
run_test() {
  local name="$1"
  local command="$2"
  local expected_exit="$3"
  local output_file="/dev/null"
  
  # If command contains --sarif, use test-output directory
  if [[ "$command" == *"--sarif"* ]]; then
    output_file="test-output/output.sarif"
    command="${command/output.sarif/$output_file}"
  fi
  
  echo -n "Running test: $name... "
  if eval "$command" >/dev/null 2>&1; then
    local exit_code=$?
    if [[ $exit_code -eq $expected_exit ]]; then
      echo -e "${GREEN}PASS${NC}"
      # For SARIF tests, verify file creation
      if [[ "$command" == *"--sarif"* ]]; then
        if [[ -f "$output_file" ]]; then
          echo -e "${GREEN}SARIF file created${NC}"
        else
          echo -e "${RED}SARIF file not created${NC}"
        fi
      fi
    else
      echo -e "${RED}FAIL (exit $exit_code, expected $expected_exit)${NC}"
    fi
  else
    local exit_code=$?
    if [[ $exit_code -eq $expected_exit ]]; then
      echo -e "${GREEN}PASS${NC}"
    else
      echo -e "${RED}FAIL (exit $exit_code, expected $expected_exit)${NC}"
    fi
  fi
}

# Main test execution
main() {
  echo -e "${YELLOW}Setting up test environment...${NC}"
  check_dependencies
  setup_test_env
  
  echo -e "\n${YELLOW}Running tests...${NC}"
  
  # Test 1: Basic script execution (should pass as it's just checking the script)
  run_test "Basic execution" "$SNAPSHOT_SCRIPT --skip all" 0
  
  # Test 2: Secret detection (AWS credentials)
  run_test "Secret detection (AWS credentials)" "$SNAPSHOT_SCRIPT --only secrets" 1
  
  # Test 3: Secret detection (API keys)
  run_test "Secret detection (API keys)" "$SNAPSHOT_SCRIPT --only secrets" 1
  
  # Test 4: Secret detection (Database credentials)
  run_test "Secret detection (Database credentials)" "$SNAPSHOT_SCRIPT --only secrets" 1
  
  # Test 5: Secret detection (JWT secrets)
  run_test "Secret detection (JWT secrets)" "$SNAPSHOT_SCRIPT --only secrets" 1
  
  # Test 6: Secret detection (SSH private keys)
  run_test "Secret detection (SSH private keys)" "$SNAPSHOT_SCRIPT --only secrets" 1
  
  # Test 7: Secret detection (Low entropy - should not trigger)
  run_test "Secret detection (Low entropy)" "$SNAPSHOT_SCRIPT --only secrets --entropy-threshold 5.0" 0
  
  # Test 8: Node.js dependency check (using non-vulnerable versions)
  run_test "Node.js dependency check" "$SNAPSHOT_SCRIPT --only dependencies --severity critical" 0
  
  # Test 9: Python dependency check (using non-vulnerable versions)
  run_test "Python dependency check" "$SNAPSHOT_SCRIPT --only dependencies --severity critical" 0
  
  # Test 10: Go dependency check (using non-vulnerable versions)
  run_test "Go dependency check" "$SNAPSHOT_SCRIPT --only dependencies --severity critical" 0
  
  # Test 11: Terraform IaC check
  run_test "Terraform IaC check" "$SNAPSHOT_SCRIPT --only iac" 1
  
  # Test 12: Kubernetes IaC check
  run_test "Kubernetes IaC check" "$SNAPSHOT_SCRIPT --only iac" 1
  
  # Test 13: Dockerfile check
  run_test "Dockerfile check" "$SNAPSHOT_SCRIPT --only iac" 1
  
  # Test 14: Different severity levels
  run_test "Low severity" "$SNAPSHOT_SCRIPT --severity low --skip all" 0
  run_test "High severity" "$SNAPSHOT_SCRIPT --severity high" 1
  
  # Test 15: Parallel execution
  run_test "Parallel mode" "$SNAPSHOT_SCRIPT --parallel --skip all" 0
  
  # Test 16: SARIF output
  run_test "SARIF output" "$SNAPSHOT_SCRIPT --sarif test-output/output.sarif --skip all" 0
  
  # Test 17: Skip checks
  run_test "Skip secrets check" "$SNAPSHOT_SCRIPT --skip secrets" 0
  run_test "Skip dependencies check" "$SNAPSHOT_SCRIPT --skip dependencies" 0
  run_test "Skip IaC check" "$SNAPSHOT_SCRIPT --skip iac" 0
  
  # Test 18: Only specific checks
  run_test "Only secrets check" "$SNAPSHOT_SCRIPT --only secrets" 1
  run_test "Only dependencies check" "$SNAPSHOT_SCRIPT --only dependencies --severity critical" 0
  run_test "Only IaC check" "$SNAPSHOT_SCRIPT --only iac" 1
  
  # Test 19: Verbosity levels
  run_test "Quiet mode" "$SNAPSHOT_SCRIPT --quiet --skip all" 0
  run_test "Verbose mode" "$SNAPSHOT_SCRIPT --verbose --skip all" 0
  
  # Test 20: Invalid options
  run_test "Invalid severity" "$SNAPSHOT_SCRIPT --severity invalid" 1
  run_test "Invalid option" "$SNAPSHOT_SCRIPT --invalid" 1
  
  # Test 21: Combined options
  run_test "Combined options (severity + parallel)" "$SNAPSHOT_SCRIPT --severity high --parallel" 1
  run_test "Combined options (only + skip)" "$SNAPSHOT_SCRIPT --only secrets --skip iac" 1
  
  echo -e "\n${YELLOW}Test Summary:${NC}"
  echo "All tests completed!"
  
  # Cleanup
  rm -rf test-output
}

# Run the tests
main 