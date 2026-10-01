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

# shellcheck disable=SC1091,SC2016,SC2030,SC2034,SC2317

load ../setup.bash

setup() {
  setup_emba_test_env
  source "${MOD_DIR}/P60_deep_extractor.sh"
  source "${HELP_DIR}/helpers_emba_prepare.sh"

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
  export WORKER_COUNTS="${TMP_DIR}/p60-worker-counts"
  export END_FILE="${TMP_DIR}/p60-module-end"
  ROOT_PATH=()

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
  claim_p99_hash() { return 0; }
  analyze_binary_architecture() { printf '%q;%s;%s\n' "$1" "$3" "$4" >>"${CAPTURE_FILE}"; }
  wait_for_pid() {
    printf '%s\n' "$#" >>"${WORKER_COUNTS}"
    wait
  }
  module_end_log() { printf '%s\n' "$2" >"${END_FILE}"; }
}

teardown() {
  teardown_emba_test_env
}

@test "P60 batches NUL-safe paths through a fixed worker pool" {
  printf 'x' >"${FIRMWARE_PATH_CP}/first.bin"
  printf 'z' >"${FIRMWARE_PATH_CP}/line"$'\n'"break.bin"
  touch "${FIRMWARE_PATH_CP}/ignored.raw"

  P60_deep_extractor

  [ "$(wc -l <"${CAPTURE_FILE}")" -eq 2 ]
  [ "$(<"${END_FILE}")" -eq 2 ]
  grep -qx '2' "${WORKER_COUNTS}"
  grep -Fq "$(printf '%q' "${FIRMWARE_PATH_CP}/first.bin");9dd4e461268c8034f5c8564e155c67a6;very short file (no magic)" "${CAPTURE_FILE}"
  grep -Fq "$(printf '%q' "${FIRMWARE_PATH_CP}/line"$'\n'"break.bin");fbade9e36a3f36d3d676c1b808451dd7;very short file (no magic)" "${CAPTURE_FILE}"
}

@test "populate_p99_backend batches checksum subprocesses" {
  local lFILE_LIST="${TMP_DIR}/files.list"
  local lWRAPPER_DIR="${TMP_DIR}/bin"
  local lFILE_ID=0
  export MD5_INVOCATIONS="${TMP_DIR}/md5-invocations"
  export FILE_INVOCATIONS="${TMP_DIR}/file-invocations"
  export P99_HASH_BATCH_SIZE=2
  mkdir -p "${lWRAPPER_DIR}"
  printf '%s\n' '#!/bin/bash' 'printf "%s\n" "$#" >>"${MD5_INVOCATIONS}"' 'exec /usr/bin/md5sum "$@"' >"${lWRAPPER_DIR}/md5sum"
  printf '%s\n' '#!/bin/bash' 'printf "%s\n" "$#" >>"${FILE_INVOCATIONS}"' 'exec /usr/bin/file "$@"' >"${lWRAPPER_DIR}/file"
  chmod 755 "${lWRAPPER_DIR}/md5sum"
  chmod 755 "${lWRAPPER_DIR}/file"
  export PATH="${lWRAPPER_DIR}:${PATH}"

  for lFILE_ID in {1..10}; do
    printf 'payload-%s\n' "${lFILE_ID}" >"${FIRMWARE_PATH_CP}/file_${lFILE_ID}"
  done
  touch "${FIRMWARE_PATH_CP}/ignored.raw"
  find "${FIRMWARE_PATH_CP}" -type f -print0 >"${lFILE_LIST}"

  populate_p99_backend "${lFILE_LIST}" test 11

  [ "$(wc -l <"${CAPTURE_FILE}")" -eq 10 ]
  [ "$(wc -l <"${MD5_INVOCATIONS}")" -eq 7 ]
  [ "$(wc -l <"${FILE_INVOCATIONS}")" -eq 7 ]
  grep -qx '4' "${WORKER_COUNTS}"
}

@test "populate_p99_backend atomically skips duplicate content" {
  local lFILE_LIST="${TMP_DIR}/duplicates.list"
  local lFILE_ID=0
  export DISABLE_DOTS=1
  print_dot() { :; }
  write_csv_log_to_path() {
    local lOUTPUT_FILE="$1"
    shift
    local IFS=';'
    printf '%s;\n' "$*" >>"${lOUTPUT_FILE}"
  }
  source "${HELP_DIR}/helpers_emba_prepare.sh"

  for lFILE_ID in {1..20}; do
    printf 'shared-%s\n' "$((lFILE_ID % 2))" >"${FIRMWARE_PATH_CP}/duplicate_${lFILE_ID}"
  done
  find "${FIRMWARE_PATH_CP}" -type f -print0 >"${lFILE_LIST}"

  populate_p99_backend "${lFILE_LIST}" test 20

  [ "$(wc -l <"${P99_CSV_LOG}")" -eq 2 ]
  [ "$(find "${TMP_DIR}/p99_md5sum_done" -type f | wc -l)" -eq 2 ]
}
