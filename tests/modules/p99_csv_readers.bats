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
# Author(s): Mihai Macarie

load ../setup.bash

# shellcheck source=helpers/helpers_emba_print.sh
source "${BATS_TEST_DIRNAME}/../../helpers/helpers_emba_print.sh"
# shellcheck source=modules/S12_binary_protection.sh
source "${BATS_TEST_DIRNAME}/../../modules/S12_binary_protection.sh"
# shellcheck source=modules/S20_shell_check.sh
source "${BATS_TEST_DIRNAME}/../../modules/S20_shell_check.sh"
# shellcheck source=modules/S21_python_check.sh
source "${BATS_TEST_DIRNAME}/../../modules/S21_python_check.sh"

module_log_init() { :; }
module_title() { :; }
pre_module_reporter() { :; }
sub_module_title() { :; }
module_end_log() { :; }
print_output() { :; }
print_ln() { :; }
write_csv_log() { :; }
write_log() { :; }
store_kill_pids() { :; }
max_pids_protection() { :; }
semgrep() { :; }
s20_eval_script_check() { :; }
binary_protection_threader() { printf '%s\0' "$1" >>"${CSV_PATH_CAPTURE}"; }
s20_script_check() { printf '%s\0' "$1" >>"${CSV_PATH_CAPTURE}"; }
s21_script_bandit() { printf '%s\0' "$1" >>"${CSV_PATH_CAPTURE}"; }
wait_for_pid() {
  local lPID=""
  for lPID in "$@"; do
    wait "${lPID}"
  done
}

setup() {
  setup_emba_test_env

  export P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  export CSV_PATH_CAPTURE="${TMP_DIR}/paths.nul"
  export LOG_PATH_MODULE="${LOG_DIR}/module"
  export EXT_DIR="${TMP_DIR}/external"
  export MAX_MOD_THREADS=2
  export SHELLCHECK=1
  export PYTHON_CHECK=1
  export BASE_LINUX_FILES="${TMP_DIR}/no-blacklist"
  mkdir -p "${EXT_DIR}" "${LOG_PATH_MODULE}"
  touch "${EXT_DIR}/checksec"

}

teardown() {
  teardown_emba_test_env
}

@test "S12 decodes newline-path CSV records before dispatching ELF workers" {
  local lPATH="${LOG_DIR}/binary"$'\n'";percent%0A.bin"$'\n'
  local lCAPTURED=()
  local IFS=$'\n\t'
  write_csv_log_to_path "${P99_CSV_LOG}" test "${lPATH}" NA NA NA NA NA 'ELF test data' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

  set -euo pipefail
  S12_binary_protection

  mapfile -d '' -t lCAPTURED <"${CSV_PATH_CAPTURE}"
  [ "${#lCAPTURED[@]}" -eq 1 ]
  [ "${lCAPTURED[0]}" = "${lPATH}" ]
}

@test "S20 decodes newline and semicolon paths before dispatching script checks" {
  local lPATH="${LOG_DIR}/script"$'\n'";percent%0A.sh"$'\n'
  local lCAPTURED=()
  local IFS=$'\n\t'
  write_csv_log_to_path "${P99_CSV_LOG}" test "${lPATH}" NA NA NA NA NA 'shell script, ASCII text executable' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

  set -euo pipefail
  S20_shell_check

  mapfile -d '' -t lCAPTURED <"${CSV_PATH_CAPTURE}"
  [ "${#lCAPTURED[@]}" -eq 1 ]
  [ "${lCAPTURED[0]}" = "${lPATH}" ]
}

@test "S21 decodes newline paths before dispatching Python checks" {
  local lPATH="${LOG_DIR}/script"$'\n'";percent%0A.py"$'\n'
  local lCAPTURED=()
  local IFS=$'\n\t'
  write_csv_log_to_path "${P99_CSV_LOG}" test "${lPATH}" NA NA NA NA NA 'Python script, ASCII text executable' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

  set -euo pipefail
  S21_python_check

  mapfile -d '' -t lCAPTURED <"${CSV_PATH_CAPTURE}"
  [ "${#lCAPTURED[@]}" -eq 1 ]
  [ "${lCAPTURED[0]}" = "${lPATH}" ]
}
