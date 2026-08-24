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

# shellcheck disable=SC1091,SC2034

load ../setup.bash

setup() {
  setup_emba_test_env
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_path.sh"
}

teardown() {
  teardown_emba_test_env
}

@test "abs_path returns realpath for existing file" {
  local lTMP_FILE="${LOG_DIR}/test_file"
  touch "${lTMP_FILE}"
  result="$(abs_path "${lTMP_FILE}")"
  [[ "${result}" == "/tmp/emba_test_"*"/test_file" ]]
}

@test "abs_path returns input for non-existing path" {
  result="$(abs_path "/nonexistent/path")"
  [ "${result}" = "/nonexistent/path" ]
}

@test "abs_path handles empty input" {
  result="$(abs_path "")"
  [ "${result}" = "" ]
}

@test "config_list reads config file" {
  local lTEST_CFG="${LOG_DIR}/test_config.cfg"
  printf '%s\n' "item1" "item2" "item3" >"${lTEST_CFG}"
  run config_list "${lTEST_CFG}"
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"item1"* ]]
  [[ "${output}" == *"item2"* ]]
  [[ "${output}" == *"item3"* ]]
}

@test "config_list returns C_N_F for missing file" {
  result="$(config_list "/nonexistent/file.cfg")"
  [ "${result}" = "C_N_F" ]
}

@test "config_list handles empty config file" {
  local lEMPTY_CFG="${LOG_DIR}/empty.cfg"
  touch "${lEMPTY_CFG}"
  result="$(config_list "${lEMPTY_CFG}")"
  [ -z "${result}" ]
}

@test "config_find returns C_N_F for missing config" {
  result="$(config_find "/nonexistent/file.cfg")"
  [ "${result}" = "C_N_F" ]
}

@test "config_grep returns C_N_F for missing config" {
  result="$(config_grep "/nonexistent/file.cfg" "/tmp")"
  [ "${result}" = "C_N_F" ]
}

@test "config_grep_string returns C_N_F for missing config" {
  result="$(config_grep_string "/nonexistent/file.cfg" "test")"
  [ "${result}" = "C_N_F" ]
}

@test "cut_path returns absolute path for SHORT_PATH=0" {
  SHORT_PATH=0
  result="$(cut_path "/some/long/path/file.txt")"
  [ "${result}" = "/some/long/path/file.txt" ]
}

@test "print_path returns path with attributes" {
  local lTMP_FILE="${LOG_DIR}/test_print"
  touch "${lTMP_FILE}"
  result="$(print_path "${lTMP_FILE}")"
  [ -n "${result}" ]
}

@test "permission_clean returns permissions string" {
  local lTMP_FILE="${LOG_DIR}/test_perm"
  touch "${lTMP_FILE}"
  result="$(permission_clean "${lTMP_FILE}")"
  [[ "${result}" =~ ^[drwx-]{10} ]]
}

@test "owner_clean returns owner string" {
  local lTMP_FILE="${LOG_DIR}/test_owner"
  touch "${lTMP_FILE}"
  result="$(owner_clean "${lTMP_FILE}")"
  [ -n "${result}" ]
}

@test "group_clean returns group string" {
  local lTMP_FILE="${LOG_DIR}/test_group"
  touch "${lTMP_FILE}"
  result="$(group_clean "${lTMP_FILE}")"
  [ -n "${result}" ]
}

@test "check_path_valid does not fail for empty input" {
  run check_path_valid ""
  [ "${status}" -eq 0 ]
}
