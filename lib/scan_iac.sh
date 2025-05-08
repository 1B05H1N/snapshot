#!/usr/bin/env bash
# scan_iac.sh - Module for IaC misconfiguration scan

# Expects the following variables/functions to be available in the parent script:
# - should_run_check, note, require_soft, warn

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