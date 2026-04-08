#!/usr/bin/env bash
set -euo pipefail

PHI_SCANIGNORE_PATH=".phi-scanignore"
CI_WORKFLOW_PATH=".github/workflows/ci.yml"
TEST_GLOB_PATTERN='^tests/test_\*\.py'
SCAN_STEP_NAME="Scan for PHI/PII"
DIFF_REF_YAML_KEY='^[[:space:]]+diff_ref:[[:space:]]+'

if [[ ! -f "${PHI_SCANIGNORE_PATH}" ]]; then
    echo "FAIL: ${PHI_SCANIGNORE_PATH} not found — cannot verify compensating controls"
    exit 1
fi

if [[ ! -f "${CI_WORKFLOW_PATH}" ]]; then
    echo "FAIL: ${CI_WORKFLOW_PATH} not found — cannot verify compensating controls"
    exit 1
fi

if ! grep -qE "${TEST_GLOB_PATTERN}" "${PHI_SCANIGNORE_PATH}"; then
    exit 0
fi

# Scan only the with: block of the target step. The block end is detected by
# the next step-start marker at the same YAML depth. This awk heuristic
# assumes no nested list within the step contains a sibling step marker
# before diff_ref: appears. Holds for the current flat ci.yml structure.
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
