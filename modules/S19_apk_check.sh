#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
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

  module_end_log "${FUNCNAME[0]}" "${#APK_ARR[@]}"
}

apk_identifier() {
  sub_module_title "Android apk identifier"
  export APK_ARR=()
  local APK=""

  mapfile -t APK_ARR < <(find "${LOG_DIR}"/firmware -type f -name "*.apk")
  for APK in "${APK_ARR[@]}"; do
    print_output "[+] Found Android apk - ${ORANGE}$(print_path "${APK}")${NC}"
  done
}

apk_checker() {
  sub_module_title "Android apk analysis"
  local APK=""
  local WAIT_PIDS_S19=()

  if ! [[ -d "${EXT_DIR}"/APKHunt ]]; then
    print_output "[-] APKHunt installation missing."
    return
  fi

  export GOTMPDIR="${TMP_DIR}"/apkhunt
  mkdir "${GOTMPDIR}"

  write_csv_log "APK" "Identified issues" "log path"

  for APK in "${APK_ARR[@]}"; do
    if [[ "${THREADED}" -eq 1 ]]; then
      apk_checker_helper "${APK}" &
      local TMP_PID="$!"
      store_kill_pids "${TMP_PID}"
      WAIT_PIDS_S19+=( "${TMP_PID}" )
    else
      apk_checker_helper "${APK}"
    fi
    if [[ "${THREADED}" -eq 1 ]]; then
      max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S19[@]}"
    fi
  done
  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S19[@]}"
  [[ -d "${GOTMPDIR}" ]] && rm -rf "${GOTMPDIR}"
}

apk_checker_helper() {
  local APK="${1:-}"
  ! [[ -f "${APK}" ]] && return
  local APK_ISSUES=0
  local APK_DIR_NAME=""
  local APK_STACS_DIR=""
  local APK_JAR=""

  print_output "[*] Testing Android apk with APKHunt - ${ORANGE}$(print_path "${APK}")${NC}"
  go run "${EXT_DIR}"/APKHunt/apkhunt.go -p "${APK}" -l 2>&1 | tee -a "${LOG_PATH_MODULE}/APKHunt-$(basename -s .apk "${APK}").txt"

  if [[ -f "${LOG_PATH_MODULE}/APKHunt-$(basename -s .apk "${APK}").txt" ]]; then
    APK_ISSUES=$(grep -c -E "^[0-9]+:" "${LOG_PATH_MODULE}/APKHunt-$(basename -s .apk "${APK}").txt" || true)
    if [[ "${APK_ISSUES}" -gt 0 ]]; then
      print_output "[+] APKHunt found ${ORANGE}${APK_ISSUES}${GREEN} areas of interest in ${ORANGE}$(print_path "${APK}")${NC}" "" "${LOG_PATH_MODULE}/APKHunt-$(basename -s .apk "${APK}").txt"
    else
      print_output "[*] APKHunt results for ${ORANGE}$(print_path "${APK}")${NC}" "" "${LOG_PATH_MODULE}/APKHunt-$(basename -s .apk "${APK}").txt"
    fi

    write_csv_log "${APK}" "${APK_ISSUES}" "${LOG_PATH_MODULE}/APKHunt-$(basename -s .apk "${APK}").txt"
  else
    print_output "[-] No APKHunt Android apk analysis results available - $(print_path "${APK}")"
    write_csv_log "${APK}" "${APK_ISSUES}" "NA"
  fi

  APK_DIR_NAME=$(dirname "${APK}")
  APK_STACS_DIR=$(grep "APK Static Analysis Path" "${APK_DIR_NAME}"/APKHunt_"$(basename -s .apk "${APK}")"*.txt || true)
  APK_JAR="${APK_DIR_NAME}"/"$(basename -s .apk "${APK}")".jar
  [[ -d "${APK_STACS_DIR}" ]] && rm -rf "${APK_STACS_DIR}"
  [[ -f "${APK_JAR}" ]] && rm -rf "${APK_JAR}"
}
