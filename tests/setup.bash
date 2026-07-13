#!/bin/bash -p

setup_emba_test_env() {
  # BATS_TEST_FILENAME is tests/helpers/foo.bats or tests/modules/foo.bats
  # Go up 2 levels to reach repo root
  local lTEST_DIR
  lTEST_DIR="$(cd "$(dirname "${BATS_TEST_FILENAME}")/../.." && pwd)"
  export INVOCATION_PATH="${lTEST_DIR}"
  export HELP_DIR="${INVOCATION_PATH}/helpers"
  export CONFIG_DIR="${INVOCATION_PATH}/config"
  export MOD_DIR="${INVOCATION_PATH}/modules"
  export EXT_DIR="${INVOCATION_PATH}/external"

  local lTMP_LOG_DIR
  lTMP_LOG_DIR="$(mktemp -d /tmp/emba_test_XXXXXX)"
  export LOG_DIR="${lTMP_LOG_DIR}"
  export TMP_DIR="${LOG_DIR}/tmp"
  export CSV_DIR="${LOG_DIR}/csv_logs"
  export BASIC_DATA_LOG_DIR="${LOG_DIR}/basic_data"
  export MAIN_LOG_FILE="emba.log"
  export MAIN_LOG="${LOG_DIR}/${MAIN_LOG_FILE}"
  mkdir -p "${TMP_DIR}" "${CSV_DIR}" "${BASIC_DATA_LOG_DIR}"

  export FIRMWARE_PATH="/tmp/test_fw"
  export RTOS=1
  export ARCH=""
  export THREADED=0
  export HTML=0
  export SHORT_PATH=0
  export FORMAT_LOG=0
  export DISABLE_NOTIFICATIONS=1
  export DEBUG=0
  export LOG_FILE="${LOG_DIR}/test_module.txt"

  export GREEN='\033[0;32m'
  export RED='\033[0;31m'
  export ORANGE='\033[0;33m'
  export BLUE='\033[0;34m'
  export BOLD='\033[1m'
  export NC='\033[0m'
  export CYAN='\033[0;36m'
  export MAGENTA='\033[0;35m'
}

teardown_emba_test_env() {
  rm -rf "${LOG_DIR}" 2>/dev/null || true
}
