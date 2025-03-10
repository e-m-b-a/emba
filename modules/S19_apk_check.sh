#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner
#
# Description:  This module identifies Android apk packages and performs a static
#               vulnerability test with APKHunt: https://github.com/Cyber-Buddy/APKHunt


S19_apk_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Android apk checks"
  pre_module_reporter "${FUNCNAME[0]}"
  apk_identifier
  apk_checker

  module_end_log "${FUNCNAME[0]}" "${#lAPK_ARR[@]}"
}

apk_identifier() {
  sub_module_title "Android apk identifier"
  export lAPK_ARR=()
  local lAPK_FILE=""

  mapfile -t lAPK_ARR < <(find "${LOG_DIR}"/firmware -type f -name "*.apk")
  for lAPK_FILE in "${lAPK_ARR[@]}"; do
    print_output "[+] Found Android apk - ${ORANGE}$(print_path "${lAPK_FILE}")${NC}"
  done
}

apk_checker() {
  sub_module_title "Android apk analysis"
  local lAPK_FILE=""
  local lWAIT_PIDS_S19_ARR=()

  if ! [[ -d "${EXT_DIR}"/APKHunt ]]; then
    print_output "[-] APKHunt installation missing."
    return
  fi

  export GOTMPDIR="${TMP_DIR}"/apkhunt
  mkdir "${GOTMPDIR}"

  write_csv_log "APK" "Identified issues" "log path"

  for lAPK_FILE in "${lAPK_ARR[@]}"; do
    if [[ "${THREADED}" -eq 1 ]]; then
      apk_checker_helper "${lAPK_FILE}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S19_ARR+=( "${lTMP_PID}" )
    else
      apk_checker_helper "${lAPK_FILE}"
    fi
    if [[ "${THREADED}" -eq 1 ]]; then
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S19_ARR
    fi
  done
  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S19_ARR[@]}"
  [[ -d "${GOTMPDIR}" ]] && rm -rf "${GOTMPDIR}"
}

apk_checker_helper() {
  local lAPK_FILE="${1:-}"
  ! [[ -f "${lAPK_FILE}" ]] && return
  local lAPK_ISSUES=0
  local lAPK_DIR_NAME=""
  local lAPK_STACS_DIR=""
  local lAPK_JAR=""
  local lAPK_NAME=""
  lAPK_NAME=$(basename -s .apk "${lAPK_FILE}")

  print_output "[*] Testing Android apk with APKHunt - ${ORANGE}$(print_path "${lAPK_FILE}")${NC}"
  go run "${EXT_DIR}"/APKHunt/apkhunt.go -p "${lAPK_FILE}" -l 2>&1 | tee -a "${LOG_PATH_MODULE}/APKHunt-${lAPK_NAME}.txt"

  if [[ -f "${LOG_PATH_MODULE}/APKHunt-${lAPK_NAME}.txt" ]]; then
    lAPK_ISSUES=$(grep -c -E "^[0-9]+:" "${LOG_PATH_MODULE}/APKHunt-${lAPK_NAME}.txt" || true)
    if [[ "${lAPK_ISSUES}" -gt 0 ]]; then
      print_output "[+] APKHunt found ${ORANGE}${lAPK_ISSUES}${GREEN} areas of interest in ${ORANGE}$(print_path "${lAPK_FILE}")${NC}" "" "${LOG_PATH_MODULE}/APKHunt-${lAPK_NAME}.txt"
    else
      print_output "[*] APKHunt results for ${ORANGE}$(print_path "${lAPK_FILE}")${NC}" "" "${LOG_PATH_MODULE}/APKHunt-${lAPK_NAME}.txt"
    fi

    write_csv_log "${lAPK_FILE}" "${lAPK_ISSUES}" "${LOG_PATH_MODULE}/APKHunt-${lAPK_NAME}.txt"
  else
    print_output "[-] No APKHunt Android apk analysis results available - $(print_path "${lAPK_FILE}")"
    write_csv_log "${lAPK_FILE}" "${lAPK_ISSUES}" "NA"
  fi

  lAPK_DIR_NAME=$(dirname "${lAPK_FILE}")
  lAPK_STACS_DIR=$(grep "APK Static Analysis Path" "${lAPK_DIR_NAME}/APKHunt_${lAPK_NAME}"*.txt || true)
  lAPK_JAR="${lAPK_DIR_NAME}/${lAPK_NAME}.jar"
  [[ -d "${lAPK_STACS_DIR}" ]] && rm -rf "${lAPK_STACS_DIR}"
  [[ -f "${lAPK_JAR}" ]] && rm -rf "${lAPK_JAR}"
}
