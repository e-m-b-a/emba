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
# Credits:   Binarly for support

# Description:  Uses FwHunt for identification of vulnerabilities in possible UEFI firmware
#               images:
#               fwhunt-scan https://github.com/binarly-io/fwhunt-scan
#               fwhunt rules https://github.com/binarly-io/FwHunt

S02_UEFI_FwHunt() {

  module_log_init "${FUNCNAME[0]}"
  module_title "Binarly UEFI FwHunt analyzer"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0
  local lWAIT_PIDS_S02_ARR=()
  # shellcheck disable=SC2153
  local lMAX_MOD_THREADS=$((MAX_MOD_THREADS/2))
  local lEXTRACTED_FILE=""

  if [[ "${UEFI_VERIFIED}" -eq 1 ]] || { [[ "${RTOS}" -eq 1 ]] && [[ "${UEFI_DETECTED}" -eq 1 ]]; }; then
    print_output "[*] Starting FwHunter UEFI firmware vulnerability detection"
    # we first analyze the entire firmware for performance reasons, if we do not find anything, we analyze each file
    fwhunter "${FIRMWARE_PATH_BAK}"
    if [[ $(grep -c "FwHunt rule" "${LOG_PATH_MODULE}""/fwhunt_scan_"* | cut -d: -f2 | awk '{ SUM += $1} END { print SUM }' || true) -eq 0 ]]; then
      while read -r lFILE_DETAILS; do
        lEXTRACTED_FILE=$(echo "${lFILE_DETAILS}" | cut -d ';' -f2)
        if [[ ${THREADED} -eq 1 ]]; then
          fwhunter "${lEXTRACTED_FILE}" &
          local lTMP_PID="$!"
          store_kill_pids "${lTMP_PID}"
          lWAIT_PIDS_S02_ARR+=( "${lTMP_PID}" )
          max_pids_protection "${lMAX_MOD_THREADS}" lWAIT_PIDS_S02_ARR
        else
          fwhunter "${lEXTRACTED_FILE}"
        fi
      done < <(grep -v "ASCII text\|Unicode text" "${P99_CSV_LOG}" || true)
    fi
  fi

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S02_ARR[@]}"

  fwhunter_logging

  [[ "${#FWHUNTER_RESULTS_ARR[@]}" -gt 0 ]] && lNEG_LOG=1

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

fwhunter() {
  local lFWHUNTER_CHECK_FILE="${1:-}"
  local lFWHUNTER_CHECK_FILE_NAME=""
  local lMEM_LIMIT=$(( "${TOTAL_MEMORY}"*80/100 ))

  lFWHUNTER_CHECK_FILE_NAME=$(basename "${lFWHUNTER_CHECK_FILE}")
  while [[ -f "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt" ]]; do
    lFWHUNTER_CHECK_FILE_NAME="${lFWHUNTER_CHECK_FILE_NAME}_${RANDOM}"
  done

  print_output "[*] Running FwHunt on ${ORANGE}${lFWHUNTER_CHECK_FILE}${NC}" "" "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt"
  ulimit -Sv "${lMEM_LIMIT}"
  write_log "[*] Running FwHunt on ${ORANGE}${lFWHUNTER_CHECK_FILE}${NC}" "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt"
  timeout --preserve-status --signal SIGINT 600 python3 "${EXT_DIR}"/fwhunt-scan/fwhunt_scan_analyzer.py scan-firmware "${lFWHUNTER_CHECK_FILE}" --rules_dir "${EXT_DIR}"/fwhunt-scan/rules/ | tee -a "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt" || true
  ulimit -Sv unlimited

  # delete empty log files
  if [[ $(wc -l < "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt") -eq 1 ]]; then
    rm "${LOG_PATH_MODULE}""/fwhunt_scan_${lFWHUNTER_CHECK_FILE_NAME}.txt" || true
  fi
}

fwhunter_logging() {
  export FWHUNTER_RESULTS_ARR=()
  local lFWHUNTER_RESULT=""
  local lFWHUNTER_RESULT_FILE=""
  local lFWHUNTER_BINARLY_ID=""
  local lFWHUNTER_CVE_ID=""
  local lBINARLY_ID_FILE=""
  local lFWHUNTER_BINARLY_ID_FILES_ARR=()
  local lCVE_RESULTS_BINARLY_ARR=()
  local lFWHUNTER_CVEs_ARR=()
  local lBINARLY_CVE=""
  local lBINARLY_ID_CVE=""
  local lCVE_RESULTS_BINARLY_ARR_=()
  local lFWHUNTER_BINARY_MATCH_ARR=()
  local lFWHUNTER_BINARY_MATCH=""
  local lFWHUNTER_BINARLY_IDs_ARR=()

  mapfile -t FWHUNTER_RESULTS_ARR < <(find "${LOG_PATH_MODULE}" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'grep -H "Scanner result.*FwHunt rule has been triggered" "%" || true')
  if ! [[ "${#FWHUNTER_RESULTS_ARR[@]}" -gt 0 ]]; then
    return
  fi

  print_ln
  sub_module_title "FwHunt UEFI vulnerability details"
  write_csv_log "BINARY" "VERSION" "CVE identifier" "CVSS rating" "BINARLY ID"

  for lFWHUNTER_RESULT in "${FWHUNTER_RESULTS_ARR[@]}"; do
    local lCVE_RESULTS_BINARLY_ARR=()

    lFWHUNTER_RESULT_FILE=$(echo "${lFWHUNTER_RESULT}" | cut -d: -f1)
    lFWHUNTER_RESULT=$(echo "${lFWHUNTER_RESULT}" | cut -d: -f2-)
    lFWHUNTER_BINARLY_ID=$(echo "${lFWHUNTER_RESULT}" | grep -E -o "BRLY-[0-9]+-[0-9]+" | sort -u || true)
    lFWHUNTER_CVE_ID=$(echo "${lFWHUNTER_RESULT}" | grep -E -o "CVE-[0-9]+-[0-9]+" | sort -u || true)
    # lCVE_RESULTS_BINARLY_ARR+=("${lFWHUNTER_CVE_ID}")

    if [[ -n "${lFWHUNTER_BINARLY_ID}" ]]; then
      mapfile -t lFWHUNTER_BINARLY_ID_FILES_ARR < <(find "${EXT_DIR}"/fwhunt-scan/rules -iname "${lFWHUNTER_BINARLY_ID}*")
      for lBINARLY_ID_FILE in "${lFWHUNTER_BINARLY_ID_FILES_ARR[@]}"; do
        [[ -z "${lBINARLY_ID_FILE}" ]] && continue
        print_output "[*] Testing ${lBINARLY_ID_FILE} for CVEs"
        # extract possible CVE information from the binarly scan rule:
        mapfile -t lCVE_RESULTS_BINARLY_ARR_ < <(grep "CVE number:" "${lBINARLY_ID_FILE}" 2>/dev/null | cut -d: -f2 | tr ',' '\n' | awk '{print $1}' || true)
        lCVE_RESULTS_BINARLY_ARR+=("${lCVE_RESULTS_BINARLY_ARR_[@]}")
      done
    fi

    mapfile -t lFWHUNTER_BINARY_MATCH_ARR < <(basename "$(grep "Running FwHunt on" "${lFWHUNTER_RESULT_FILE}" | cut -d\  -f5-)" | sort -u || true)
    if [[ "${lFWHUNTER_RESULT}" == *"rule has been triggered and threat detected"* ]]; then
      if [[ "${#lCVE_RESULTS_BINARLY_ARR[@]}" -gt 0 ]]; then
        for lBINARLY_ID_CVE in "${lCVE_RESULTS_BINARLY_ARR[@]}"; do
          for lFWHUNTER_BINARY_MATCH in "${lFWHUNTER_BINARY_MATCH_ARR[@]}"; do
            # if we have CVE details we include it into our reporting
            print_output "[+] ${lFWHUNTER_BINARY_MATCH} ${ORANGE}:${GREEN} ${lFWHUNTER_RESULT}${GREEN}" "" "https://binarly.io/advisories/${lFWHUNTER_BINARLY_ID}"
            print_output "$(indent "${GREEN}CVE: ${ORANGE}${lBINARLY_ID_CVE}${NC}")"
            write_csv_log "${lFWHUNTER_BINARY_MATCH}" "unknown" "${lBINARLY_ID_CVE}" "unknown" "${lFWHUNTER_BINARLY_ID}"
          done
        done
      else
        for lFWHUNTER_BINARY_MATCH in "${lFWHUNTER_BINARY_MATCH_ARR[@]}"; do
          # if we do not have CVE details we can't include it into our reporting
          print_output "[+] ${lFWHUNTER_BINARY_MATCH} ${ORANGE}:${GREEN} ${lFWHUNTER_RESULT}${NC}" "" "https://binarly.io/advisories/${lFWHUNTER_BINARLY_ID}"
          write_csv_log "${lFWHUNTER_BINARY_MATCH}" "unknown" "${lFWHUNTER_CVE_ID:-NA}" "unknown" "${lFWHUNTER_BINARLY_ID}"
        done
      fi
    fi
  done

  mapfile -t lFWHUNTER_CVEs_ARR < <(grep -E -o "CVE-[0-9]{4}-[0-9]+" "${LOG_FILE}" | sort -u || true)
  mapfile -t lFWHUNTER_BINARLY_IDs_ARR < <(grep "FwHunt rule has been triggered and threat detected" "${LOG_PATH_MODULE}"/* | grep "BRLY-" | sed 's/.*BRLY-/BRLY-/' | sed 's/\ .variant:\ .*//g' | sort -u || true)

  print_ln
  if [[ "${#lFWHUNTER_CVEs_ARR[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Detected ${ORANGE}${#lFWHUNTER_CVEs_ARR[@]}${GREEN} firmware issues with valid CVE identifier in UEFI firmware:"
    for lBINARLY_CVE in "${lFWHUNTER_CVEs_ARR[@]}"; do
      print_output "$(indent "$(orange "${lBINARLY_CVE}")")"
    done
  fi
  if [[ "${#lFWHUNTER_BINARLY_IDs_ARR[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Detected ${ORANGE}${#lFWHUNTER_BINARLY_IDs_ARR[@]}${GREEN} firmware issues with valid binarly id in UEFI firmware:"
    for BINARLY_ID in "${lFWHUNTER_BINARLY_IDs_ARR[@]}"; do
      print_output "$(indent "$(orange "${BINARLY_ID}")")"
    done
  fi
  print_ln

  write_log ""
  write_log "[*] Statistics:${#lFWHUNTER_CVEs_ARR[@]}:${#lFWHUNTER_BINARLY_IDs_ARR[@]}"
}
