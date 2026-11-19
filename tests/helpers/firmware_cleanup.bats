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

setup() {
  setup_emba_test_env
  # shellcheck source=helpers/helpers_emba_path.sh
  source "${HELP_DIR}/helpers_emba_path.sh"
  # shellcheck source=helpers/helpers_emba_print.sh
  source "${HELP_DIR}/helpers_emba_print.sh"
  # shellcheck source=helpers/helpers_emba_prepare.sh
  source "${HELP_DIR}/helpers_emba_prepare.sh"
  # shellcheck source=helpers/helpers_emba_helpers.sh
  source "${HELP_DIR}/helpers_emba_helpers.sh"
  export P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  export DISABLE_DOTS=1
  export MAX_MOD_THREADS=2
  mkdir -p "${LOG_DIR}/firmware"
}

teardown() {
  teardown_emba_test_env
}

@test "cleanup sanitizes controls and semicolons but preserves UTF-8 spaces and backslashes" {
  local lNAME=$'semi;line\n\r\t\177.bin'
  local lNORMAL='space ünicode %0A back\slash.bin'
  local IFS=$'\n\t'
  set -euo pipefail
  sanitize_firmware_basename lNAME
  sanitize_firmware_basename lNORMAL
  [ "${lNAME}" = 'semi_line____.bin' ]
  [ "${lNORMAL}" = 'space ünicode %0A back\slash.bin' ]
}

@test "cleanup renames children before parents and preserves trailing-newline file contents" {
  local lROOT="${LOG_DIR}/firmware"
  local lRENAMED=0
  local IFS=$'\n\t'
  mkdir -p "${lROOT}/parent;dir/child"$'\n'
  printf 'payload' >"${lROOT}/parent;dir/child"$'\n'"/file"$'\n'
  set -euo pipefail
  remove_uprintable_paths "${lROOT}" lRENAMED
  [ "${lRENAMED}" -eq 3 ]
  [ "$(<"${lROOT}/parent_dir/child_/file_")" = payload ]
  remove_uprintable_paths "${lROOT}" lRENAMED
  [ "${lRENAMED}" -eq 0 ]
}

@test "cleanup never overwrites files directories or dangling symlinks on name collisions" {
  local lROOT="${LOG_DIR}/firmware"
  mkdir -p "${lROOT}/dir;name" "${lROOT}/dir_name"
  printf 'new' >"${lROOT}/dir;name/new.bin"
  printf 'existing' >"${lROOT}/dir_name/existing.bin"
  printf 'payload' >"${lROOT}/file;name"
  ln -s missing "${lROOT}/file_name"
  set -euo pipefail
  remove_uprintable_paths "${lROOT}"
  [ "$(<"${lROOT}/dir_name_1/new.bin")" = new ]
  [ "$(<"${lROOT}/dir_name/existing.bin")" = existing ]
  [ -L "${lROOT}/file_name" ]
  [ "$(readlink "${lROOT}/file_name")" = missing ]
  [ "$(<"${lROOT}/file_name_1")" = payload ]
}

@test "cleanup repairs relative firmware-absolute and host-absolute symlink targets" {
  local lROOT="${LOG_DIR}/firmware"
  mkdir -p "${lROOT}/dir;name"
  printf payload >"${lROOT}/dir;name/file"$'\n'
  ln -s $'dir;name/file\n' "${lROOT}/relative"
  ln -s $'/dir;name/file\n' "${lROOT}/absolute"
  ln -s "${lROOT}/dir;name/file"$'\n' "${lROOT}/host-absolute"
  ln -s $'file\n' "${lROOT}/dir;name/inside;link"
  set -euo pipefail
  remove_uprintable_paths "${lROOT}"
  [ "$(readlink "${lROOT}/relative")" = dir_name/file_ ]
  [ "$(readlink "${lROOT}/absolute")" = /dir_name/file_ ]
  [ "$(readlink "${lROOT}/host-absolute")" = "${lROOT}/dir_name/file_" ]
  [ "$(readlink "${lROOT}/dir_name/inside_link")" = file_ ]
  [ "$(<"${lROOT}/relative")" = payload ]
  [ "$(<"${lROOT}/host-absolute")" = payload ]
}

@test "cleanup refuses symlink roots and does not follow links outside the extracted tree" {
  local lROOT="${LOG_DIR}/firmware"
  mkdir -p "${LOG_DIR}/outside"
  touch "${LOG_DIR}/outside/file;name"
  ln -s "${LOG_DIR}/outside" "${lROOT}/outside"
  remove_uprintable_paths "${lROOT}"
  run remove_uprintable_paths "${lROOT}/outside"
  [ "${status}" -eq 1 ]
  [ -f "${LOG_DIR}/outside/file;name" ]
}

@test "plain P99 CSV and legacy arrays consume cleaned paths without a codec" {
  local lROOT="${LOG_DIR}/firmware"
  local lLIST="${TMP_DIR}/files.list"
  printf 'first' >"${lROOT}/line"$'\n'";100%.bin"
  printf 'second' >"${lROOT}/literal%0A.bin"
  remove_uprintable_paths "${lROOT}"
  find "${lROOT}" -type f -print0 >"${lLIST}"
  populate_p99_backend "${lLIST}" test 2
  [ "$(wc -l <"${P99_CSV_LOG}")" -eq 2 ]
  prepare_all_file_arrays "${lROOT}"
  prepare_file_arr "${lROOT}"
  [ "${#ALL_FILES_ARR[@]}" -eq 2 ]
  [ "${#FILE_ARR[@]}" -eq 2 ]
  [ -f "${FILE_ARR[0]}" ]
  [ -f "${FILE_ARR[1]}" ]
  run grep -F '@P99:' "${P99_CSV_LOG}"
  [ "${status}" -eq 1 ]
}

@test "P99 writer rejects missed cleanup without writing a broken record" {
  run write_csv_log_to_path "${P99_CSV_LOG}" test $'/firmware/line\n;break.bin' data
  [ "${status}" -eq 1 ]
  [ ! -e "${P99_CSV_LOG}" ]
}

@test "invalidating old path records preserves a recoverable CSV and hash index" {
  printf 'test;@P99:/old%%0Apath;data;\n' >"${P99_CSV_LOG}"
  mkdir -p "${TMP_DIR}/p99_md5sum_done/aa"
  touch "${TMP_DIR}/p99_md5sum_done/aa/hash" "${TMP_DIR}/p99_md5sum_done.initialized"
  invalidate_p99_path_cache
  [ ! -e "${P99_CSV_LOG}" ]
  [ ! -e "${TMP_DIR}/p99_md5sum_done" ]
  [ ! -e "${TMP_DIR}/p99_md5sum_done.initialized" ]
  [ "$(find "${CSV_DIR}" -name p99_prepare_analyzer.csv | wc -l)" -eq 1 ]
  [ "$(find "${CSV_DIR}" -name hash | wc -l)" -eq 1 ]
}

@test "cleanup preserves noclobber and invalidates interrupted hash claims without a CSV" {
  local lROOT="${LOG_DIR}/firmware"
  touch "${lROOT}/file;name"
  mkdir -p "${TMP_DIR}/p99_md5sum_done/aa"
  touch "${TMP_DIR}/p99_md5sum_done/aa/hash" "${TMP_DIR}/p99_md5sum_done.initialized"
  set -o noclobber
  remove_uprintable_paths "${lROOT}"
  [[ -o noclobber ]]
  invalidate_p99_path_cache
  [[ -o noclobber ]]
  [ -f "${lROOT}/file_name" ]
  [ ! -e "${TMP_DIR}/p99_md5sum_done.initialized" ]
  [ "$(find "${CSV_DIR}" -name hash | wc -l)" -eq 1 ]
}

@test "cleanup sanitizes shell metacharacters in basenames and extracted trees" {
  local lROOT="${LOG_DIR}/firmware"
  local lRENAMED=0
  local lDOLLAR=$'\x24'
  local lTICK=$'\x60'
  local lSQUOTE=$'\x27'
  local lMETACHAR_NAME="x\"${lSQUOTE}${lTICK}${lDOLLAR}(id>>pwn||id&&id|cat<in>out)_det.so"
  local IFS=$'\n\t'
  set -euo pipefail
  sanitize_firmware_basename lMETACHAR_NAME
  [ "${lMETACHAR_NAME}" = 'x_____id__pwn__id__id_cat_in_out__det.so' ]

  mkdir -p "${lROOT}/lib"
  printf 'ELF' >"${lROOT}/lib/x\"${lDOLLAR}(id>>PWN_S15_DET_1||id&&cd ${lDOLLAR}HOME)\"_det.so"
  printf 'ELF2' >"${lROOT}/lib/back${lTICK}tick${lTICK}${lSQUOTE}single${lSQUOTE}|pipe&amp<lt>gt(paren).so"
  remove_uprintable_paths "${lROOT}" lRENAMED
  [ "${lRENAMED}" -eq 2 ]
  [ -f "${lROOT}/lib/x___id__PWN_S15_DET_1__id__cd _HOME___det.so" ]
  [ -f "${lROOT}/lib/back_tick__single__pipe_amp_lt_gt_paren_.so" ]
  remove_uprintable_paths "${lROOT}" lRENAMED
  [ "${lRENAMED}" -eq 0 ]
}

@test "P99 writer rejects paths containing shell metacharacters" {
  local lCHAR=""
  for lCHAR in ';' $'\n' '"' "'" $'\x60' '$' '|' '&' '<' '>' '(' ')'; do
    run write_csv_log_to_path "${P99_CSV_LOG}" test "/firmware/bad${lCHAR}name.bin" data
    [ "${status}" -eq 1 ]
    [ ! -e "${P99_CSV_LOG}" ]
  done
}
