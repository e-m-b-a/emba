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

# shellcheck disable=SC1091,SC2034,SC2317

load ../setup.bash

setup() {
  setup_emba_test_env
  source "${MOD_DIR}/P60_deep_extractor.sh"

  export FIRMWARE_PATH_CP="${LOG_DIR}/firmware"
  export P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  export MAX_MOD_THREADS=2
  export MAX_EXT_SPACE=1024
  export SBOM_MINIMAL=0
  export RTOS=1
  export UEFI_VERIFIED=0
  export DJI_DETECTED=0
  export DISABLE_DEEP=0
  export MAIN_LOG_FILE="emba.log"
  export CAPTURE_FILE="${TMP_DIR}/p60-captured-files"
  export LIMIT_FILE="${TMP_DIR}/p60-worker-limits"
  export END_FILE="${TMP_DIR}/p60-module-end"
  ROOT_PATH=()
  lWAIT_PIDS_P99_ARR=()

  mkdir -p "${FIRMWARE_PATH_CP}"

  module_log_init() { :; }
  module_title() { :; }
  pre_module_reporter() { :; }
  check_disk_space() { DISK_SPACE=0; }
  deep_extractor() { :; }
  sub_module_title() { :; }
  print_output() { :; }
  print_ln() { :; }
  write_csv_log() { :; }
  linux_basic_identification() { printf '0\n'; }
  binary_architecture_threader() { printf '%q\n' "$1" >>"${CAPTURE_FILE}"; }
  max_pids_protection() { printf '%s\n' "$1" >>"${LIMIT_FILE}"; }
  wait_for_pid() { wait; }
  module_end_log() { printf '%s\n' "$2" >"${END_FILE}"; }
}

teardown() {
  teardown_emba_test_env
}

@test "P60 streams paths and bounds backend workers" {
  touch "${FIRMWARE_PATH_CP}/first.bin"
  touch "${FIRMWARE_PATH_CP}/line"$'\n'"break.bin"
  touch "${FIRMWARE_PATH_CP}/ignored.raw"

  P60_deep_extractor

  [ "$(wc -l <"${CAPTURE_FILE}")" -eq 2 ]
  [ "$(<"${END_FILE}")" -eq 2 ]
  [ "$(wc -l <"${LIMIT_FILE}")" -eq 2 ]
  [ "$(sort -u "${LIMIT_FILE}")" = "4" ]
}
