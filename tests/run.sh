#!/bin/bash -p
# EMBA test runner
# Runs bats unit tests for EMBA helper and module functions

set -e

INVOCATION_PATH="$(cd "$(dirname "${0}")" && pwd)"
BATS_BIN="${INVOCATION_PATH}/bats-core/bin/bats"

if ! [[ -x "${BATS_BIN}" ]]; then
  echo "[-] bats not found at ${BATS_BIN}"
  echo "[*] Install it via: cd tests && curl -sL https://github.com/bats-core/bats-core/archive/refs/tags/v1.11.0.tar.gz | tar xz"
  echo "[*]   or: sudo apt-get install bats"
  exit 1
fi

echo "==================================="
echo " EMBA Unit Tests (bats)"
echo "==================================="
echo ""

TOTAL=0
PASSED=0
FAILED=0

while IFS= read -r -d '' TEST_FILE; do
  echo "--- Running: $(basename "${TEST_FILE}") ---"
  if "${BATS_BIN}" "${TEST_FILE}"; then
    PASSED=$((PASSED + 1))
  else
    FAILED=$((FAILED + 1))
  fi
  TOTAL=$((TOTAL + 1))
  echo ""
done < <(find "${INVOCATION_PATH}" -name 'bats-core' -prune -o -name '*.bats' -print0)

echo "==================================="
echo " Results: ${PASSED}/${TOTAL} passed, ${FAILED} failed"
echo "==================================="

exit ${FAILED}
