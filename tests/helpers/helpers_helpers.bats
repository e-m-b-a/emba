# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2026-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#

# shellcheck disable=SC1091

load ../setup.bash

setup() {
  setup_emba_test_env
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_print.sh"
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_helpers.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "function_exists returns 0 for defined function" {
  run function_exists "function_exists"
  [ "${status}" -eq 0 ]
}

@test "function_exists returns non-zero for undefined function" {
  run function_exists "nonexistent_func"
  [ "${status}" -ne 0 ]
}

@test "backup_var appends to backup file" {
  backup_var "TEST_VAR" "test_value"
  grep -q 'export TEST_VAR="test_value"' "${LOG_DIR}/backup_vars.log"
}

@test "store_kill_pids creates pid file" {
  store_kill_pids "12345"
  [ -f "${TMP_DIR}/EXIT_KILL_PIDS.log" ]
  grep -q "12345" "${TMP_DIR}/EXIT_KILL_PIDS.log"
}

@test "safe_logging writes to file via pipe" {
  local lTEST_LOG="${LOG_DIR}/test_safe.log"
  printf "%b" 'test message\n' | safe_logging "${lTEST_LOG}" 0
  grep -q "test message" "${lTEST_LOG}"
}

@test "wait_for_pid handles empty array" {
  run wait_for_pid
  [ "${status}" -eq 0 ]
}

@test "cleaner handles 0 exit code" {
  run cleaner 0
  [ "${status}" -eq 0 ]
}

@test "max_pids_protection handles small pid count" {
  # shellcheck disable=SC2034
  declare -a lTEST_ARR=()
  run max_pids_protection 5 lTEST_ARR
  [ "${status}" -eq 0 ]
}
