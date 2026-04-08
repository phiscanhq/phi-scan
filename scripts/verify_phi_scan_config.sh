#!/usr/bin/env bash
set -euo pipefail

PHI_SCANIGNORE_PATH=".phi-scanignore"
CI_WORKFLOW_PATH=".github/workflows/ci.yml"
TEST_GLOB_PATTERN='^tests/test_\*\.py'
SCAN_STEP_NAME="Scan for PHI/PII"
DIFF_REF_YAML_KEY='^[[:space:]]+diff_ref:[[:space:]]+'

if ! grep -qE "${TEST_GLOB_PATTERN}" "${PHI_SCANIGNORE_PATH}"; then
    exit 0
fi

if awk -v step="${SCAN_STEP_NAME}" -v key_pattern="${DIFF_REF_YAML_KEY}" '
    $0 ~ ("name: " step) { in_step=1; next }
    in_step && /^[[:space:]]+-[[:space:]]+name:/ { exit }
    in_step && $0 ~ key_pattern { found=1; exit }
    END { exit !found }
' "${CI_WORKFLOW_PATH}"; then
    echo "OK: diff_ref compensating control present in ${SCAN_STEP_NAME} step"
    exit 0
fi

echo "FAIL: ${PHI_SCANIGNORE_PATH} excludes tests/test_*.py via glob"
echo "but ${CI_WORKFLOW_PATH} has no diff_ref: YAML key"
echo "in the '${SCAN_STEP_NAME}' step's with: block."
echo "Either restore explicit per-file entries or re-add the diff_ref key."
exit 1
