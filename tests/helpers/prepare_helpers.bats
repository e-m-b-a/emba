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

# shellcheck disable=SC1091,SC2032

load ../setup.bash

setup() {
  setup_emba_test_env
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_print.sh"
  # shellcheck disable=SC1091
  source "${HELP_DIR}/helpers_emba_prepare.sh"
  export DISABLE_DOTS=1
}

teardown() {
  teardown_emba_test_env
}

@test "detect_root_dir_helper handles strict-mode IFS and paths containing spaces" {
  local lROOT_PATH="${LOG_DIR}/firmware root"
  export P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  IFS=$'\n\t'
  ROOT_PATH=()
  mkdir -p "${lROOT_PATH}"/{bin,etc,home,lib,sbin}
  touch "${P99_CSV_LOG}"

  print_output() { :; }
  write_link() { :; }

  detect_root_dir_helper "${LOG_DIR}"

  [ "${RTOS}" -eq 0 ]
  [ "${#ROOT_PATH[@]}" -eq 1 ]
  [ "${ROOT_PATH[0]}" = "${lROOT_PATH}" ]
}

@test "binary_architecture_threader atomically deduplicates concurrent files in strict mode" {
  local lBINARY="${LOG_DIR}/duplicate.bin"
  local IFS=$'\n\t'
  local lPID=""
  local lPIDS=()
  local P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  printf 'duplicate content' >"${lBINARY}"

  set -u
  for _ in {1..16}; do
    binary_architecture_threader "${lBINARY}" "test" &
    lPIDS+=("$!")
  done
  for lPID in "${lPIDS[@]}"; do
    wait "${lPID}"
  done
  wait
  set +u

  [ "$(wc -l <"${P99_CSV_LOG}")" -eq 1 ]
  [ "$(find "${TMP_DIR}/p99_md5sum_done" -type f | wc -l)" -eq 1 ]
}

@test "binary_architecture_threader reuses CSV hashes and preserves noclobber" {
  local lBINARY="${LOG_DIR}/existing.bin"
  local lMD5SUM=""
  local P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  printf 'existing content' >"${lBINARY}"
  lMD5SUM="$(md5sum "${lBINARY}" | cut -d ' ' -f1)"
  printf 'test;%s;NA;NA;NA;;NA;data;%s;;\n' "${lBINARY}" "${lMD5SUM}" >"${P99_CSV_LOG}"

  set -o noclobber
  binary_architecture_threader "${lBINARY}" "test"
  [[ -o noclobber ]]
  set +o noclobber

  [ -e "${TMP_DIR}/p99_md5sum_done/${lMD5SUM:0:2}/${lMD5SUM}" ]
  [ "$(wc -l <"${P99_CSV_LOG}")" -eq 1 ]
}

@test "binary_architecture_threader accepts GNU md5sum escaped filenames" {
  local lBINARY="${LOG_DIR}/escaped\\name.bin"
  local lMD5_OUTPUT=""
  local lMD5SUM=""
  local P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  printf 'escaped filename content' >"${lBINARY}"
  lMD5_OUTPUT="$(md5sum "${lBINARY}")"
  lMD5SUM="$(printf 'escaped filename content' | md5sum | cut -d ' ' -f1)"
  [[ "${lMD5_OUTPUT}" == \\* ]]

  binary_architecture_threader "${lBINARY}" "test"
  wait

  [ -e "${TMP_DIR}/p99_md5sum_done/${lMD5SUM:0:2}/${lMD5SUM}" ]
  [ "$(wc -l <"${P99_CSV_LOG}")" -eq 1 ]
  [ "$(awk -F ';' '{print $9}' "${P99_CSV_LOG}")" = "${lMD5SUM}" ]
}

@test "binary_architecture_threader accepts a precomputed checksum" {
  local lBINARY="${LOG_DIR}/precomputed.bin"
  local lMD5SUM=""
  local P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  printf 'precomputed content' >"${lBINARY}"
  lMD5SUM="$(md5sum "${lBINARY}" | cut -d ' ' -f1)"

  md5sum() { return 99; }
  binary_architecture_threader "${lBINARY}" "test" "${lMD5SUM^^}"

  [ -e "${TMP_DIR}/p99_md5sum_done/${lMD5SUM:0:2}/${lMD5SUM}" ]
  [ "$(wc -l <"${P99_CSV_LOG}")" -eq 1 ]
  [ "$(awk -F ';' '{print $9}' "${P99_CSV_LOG}")" = "${lMD5SUM}" ]
}

@test "analyze_binary_architecture accepts precomputed file output" {
  local lBINARY="${LOG_DIR}/preclassified.bin"
  local lMD5SUM="9dd4e461268c8034f5c8564e155c67a6"
  local P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  printf 'x' >"${lBINARY}"

  file() { return 99; }
  analyze_binary_architecture "${lBINARY}" "test" "${lMD5SUM}" "preclassified data"

  [ "$(wc -l <"${P99_CSV_LOG}")" -eq 1 ]
  [ "$(awk -F ';' '{print $8}' "${P99_CSV_LOG}")" = "preclassified data" ]
}

@test "analyze_binary_architecture parses ELF metadata in strict mode" {
  local lBINARY="${LOG_DIR}/strict-elf.bin"
  local lMD5SUM="9dd4e461268c8034f5c8564e155c67a6"
  local P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  touch "${lBINARY}"
  readelf() {
    printf '%s\n' \
      '  Class:                             ELF32' \
      '  Data:                              2s complement, little endian' \
      '  Machine:                           MIPS R3000' \
      '  Flags:                             0x0' \
      "String dump of section '.comment':" \
      '  [ 0] Z compiler one' \
      '  [ 1] A compiler one'
  }

  set -euo pipefail
  analyze_binary_architecture "${lBINARY}" "test" "${lMD5SUM}" "ELF test data"
  set +euo pipefail

  [ "$(awk -F ';' '{print $3}' "${P99_CSV_LOG}")" = "ELF32" ]
  [ "$(awk -F ';' '{print $5}' "${P99_CSV_LOG}")" = "MIPSR3000" ]
  [ "$(awk -F ';' '{print $7}' "${P99_CSV_LOG}")" = "  ,A compiler one,Z compiler one," ]
}

@test "claim_p99_hash caches index initialization per worker" {
  local lINITIALIZE_CALLS=0
  local lP99_HASH_INDEX_INITIALIZED_FOR=""
  initialize_p99_hash_index() {
    ((lINITIALIZE_CALLS += 1))
    mkdir -p "${TMP_DIR}/p99_md5sum_done/aa" "${TMP_DIR}/p99_md5sum_done/bb"
  }

  claim_p99_hash "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  claim_p99_hash "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

  [ "${lINITIALIZE_CALLS}" -eq 1 ]
}

@test "convert_timeformat converts days to seconds" {
  result="$(convert_timeformat "2d")"
  [ "${result}" = "$((2 * 24 * 3600))" ]
}

@test "convert_timeformat converts hours to seconds" {
  result="$(convert_timeformat "5h")"
  [ "${result}" = "$((5 * 3600))" ]
}

@test "convert_timeformat converts minutes to seconds" {
  result="$(convert_timeformat "30m")"
  [ "${result}" = "$((30 * 60))" ]
}

@test "convert_timeformat returns seconds unchanged" {
  result="$(convert_timeformat "45s")"
  [ "${result}" = "45" ]
}

@test "convert_timeformat handles combined format (days)" {
  result="$(convert_timeformat "1d")"
  [ "${result}" = "86400" ]
}

@test "convert_timeformat handles empty input" {
  result="$(convert_timeformat "")"
  [ -z "${result}" ]
}

@test "convert_timeformat handles plain number as seconds" {
  result="$(convert_timeformat "60")"
  [ "${result}" = "60" ]
}

@test "convert_timeformat handles zero" {
  result="$(convert_timeformat "0s")"
  [ "${result}" = "0" ]
}
