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
  source "${MOD_DIR}/P99_prepare_analyzer.sh"

  mkdir -p "${LOG_DIR}/firmware"
  export P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  export CAPTURE_FILE="${TMP_DIR}/p99-populate-capture"
  export THREADED=0
  export KERNEL=1
  export SBOM_MINIMAL=1
  export UEFI_VERIFIED=0
  ROOT_PATH=()
  WAIT_PIDS=()

  module_log_init() { :; }
  module_title() { :; }
  pre_module_reporter() { :; }
  linux_basic_identification() { printf '0\n'; }
  check_firmware() { :; }
  prepare_all_file_arrays() { :; }
  backup_var() { :; }
  print_output() { :; }
  populate_p99_backend() {
    printf '%s;%s\n' "$2" "$3" >"${CAPTURE_FILE}"
    while IFS= read -r -d '' lFILE; do
      printf '%q\n' "${lFILE}" >>"${CAPTURE_FILE}"
    done <"$1"
  }
  module_end_log() { :; }
}

teardown() {
  teardown_emba_test_env
}

@test "P99 rebuild uses the NUL-safe batch backend and skips raw files" {
  touch "${LOG_DIR}/firmware/first.bin"
  touch "${LOG_DIR}/firmware/line"$'\n'"break.bin"
  touch "${LOG_DIR}/firmware/ignored.raw"

  P99_prepare_analyzer

  [ "$(sed -n '1p' "${CAPTURE_FILE}")" = "P99_prepare_analyzer;2" ]
  [ "$(wc -l <"${CAPTURE_FILE}")" -eq 3 ]
  grep -Fqx "$(printf '%q' "${LOG_DIR}/firmware/first.bin")" "${CAPTURE_FILE}"
  grep -Fqx "$(printf '%q' "${LOG_DIR}/firmware/line"$'\n'"break.bin")" "${CAPTURE_FILE}"
}
