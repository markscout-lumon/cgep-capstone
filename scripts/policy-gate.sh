#!/usr/bin/env bash
# scripts/policy-gate.sh
# Usage: policy-gate.sh --workspace <path> [--policy <dir>]
# Requires a saved tfplan inside the workspace (from terraform plan -out=tfplan).
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/conftest"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

terraform -chdir="$WORKSPACE" show -json tfplan > "$WORKSPACE/plan.json"

# --all-namespaces: every package with deny (not package main).
# --ignore tests: opa unit tests are not Conftest gates.
set +e
conftest test \
  --policy "$POLICY_DIR" \
  --all-namespaces \
  --ignore tests \
  --output=json \
  "$WORKSPACE/plan.json" | tee "$EVIDENCE_DIR/conftest-results.json"
STATUS=${PIPESTATUS[0]}
set -e

if [[ $STATUS -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit "$STATUS"
