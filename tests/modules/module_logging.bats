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
  source "${HELP_DIR}/helpers_emba_path.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "module_log_init creates LOG_FILE from function name" {
  module_log_init "S01_test_module"
  [[ "${LOG_FILE}" == *"s01_test_module.txt" ]]
}

@test "module_log_init sets LOG_FILE variable" {
  module_log_init "S01_test_module"
  [ -n "${LOG_FILE}" ]
  [[ "${LOG_FILE}" == *"s01_test_module.txt" ]]
}

@test "module_log_init handles uppercase function name" {
  module_log_init "F50_BASE_AGGREGATOR"
  [[ "${LOG_FILE_NAME}" == "f50_base_aggregator.txt" ]]
}

@test "module_title writes formatted title" {
  module_log_init "S01_test"
  run module_title "Test Module"
  [ "${status}" -eq 0 ]
}

@test "sub_module_title writes formatted sub-title" {
  module_log_init "S01_test"
  run sub_module_title "Sub Test"
  [ "${status}" -eq 0 ]
}

@test "module_end_log reports nothing for state 0" {
  module_log_init "S01_test"
  run module_end_log "S01_test" 0
  [ "${status}" -eq 0 ]
}

@test "module_end_log reports finish for state 1" {
  module_log_init "S01_test"
  run module_end_log "S01_test" 1
  [ "${status}" -eq 0 ]
}

@test "pre_module_reporter runs without error" {
  run pre_module_reporter "S01_test"
  [ "${status}" -eq 0 ]
}

@test "module_start_log runs without error" {
  run module_start_log "S01_test"
  [ "${status}" -eq 0 ]
}

@test "write_log writes to specified file" {
  local lTEST_LOG="${LOG_DIR}/write_test.log"
  write_log "test entry" "${lTEST_LOG}"
  grep -q "test entry" "${lTEST_LOG}"
}

@test "write_csv_log writes CSV line" {
  module_log_init "S01_test"
  local lCSV_FILE="${CSV_DIR}/s01_test.csv"
  write_csv_log "col1" "col2" "col3"
  [ -f "${lCSV_FILE}" ]
  grep -q "col1;col2;col3" "${lCSV_FILE}"
}

@test "multiple module_log_init creates backup of old log" {
  module_log_init "S01_test"
  local lFIRST_LOG="${LOG_FILE}"
  echo "old content" >"${lFIRST_LOG}"
  module_log_init "S01_test"
  local lFOUND_BACKUPS
  lFOUND_BACKUPS=$(find "${LOG_DIR}" -name "s01_test.txt.bak.*" 2>/dev/null | wc -l)
  [ "${lFOUND_BACKUPS}" -ge 1 ]
}

@test "write_notification runs without error" {
  run write_notification "test notification"
  [ "${status}" -eq 0 ]
}
