#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  This module uses capa (https://github.com/mandiant/capa) for detecting binary behavior
#               Currently capa only supports x86 architecture

S18_capa_checker() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Analyse binary behavior with capa"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ ! -e "${EXT_DIR}"/capa ]]; then
    print_output "[-] Missing capa installation ... exit module"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi
  if [[ ${BINARY_EXTENDED} -ne 1 ]] ; then
    print_output "[-] ${FUNCNAME[0]} - BINARY_EXTENDED not set to 1. You can set it up via a scan-profile."
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lBINARY=""
  local lWAIT_PIDS_S18=()
  local lCAPA_RESULTS=0

  while read -r lBINARY; do
    # bypass the Linux kernel
    [[ "${lBINARY}" == *"vmlinuz"* ]] && continue

    if [[ -f "${BASE_LINUX_FILES}" && "${FULL_TEST}" -eq 0 ]]; then
      # if we have the base linux config file we only test non known Linux binaries
      # with this we do not waste too much time on open source Linux stuff
      lNAME=$(basename "${lBINARY}" 2> /dev/null)
      if grep -E -q "^${lNAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        continue 2
      fi
    fi

    # ensure we have not tested this binary
    local lBIN_MD5=""
    lBIN_MD5="$(md5sum "${lBINARY}" | awk '{print $1}')"
    if ( grep -q "${lBIN_MD5}" "${TMP_DIR}"/s18_checked.tmp 2>/dev/null); then
      # print_output "[*] ${ORANGE}${lBINARY}${NC} already tested with capa" "no_log"
      continue
    fi
    echo "${lBIN_MD5}" >> "${TMP_DIR}"/s18_checked.tmp

    if [[ "${THREADED}" -eq 1 ]]; then
      capa_runner_fct "${lBINARY}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S18+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S18
    else
      capa_runner_fct "${lBINARY}"
    fi
  done < <(grep "ELF.*Intel\|PE32\|MSI" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S18[@]}"

  if [[ -f "${TMP_DIR}"/s18_checked.tmp ]]; then
    local lBINS_AVAILABLE=0
    lBINS_AVAILABLE=$(grep -c "ELF.*Intel\|PE32\|MSI" "${P99_CSV_LOG}" || true)
    print_ln
    if [[ "$(find "${LOG_PATH_MODULE}" -name "capa_*.log" | wc -l)" -gt 0 ]]; then
      lCAPA_RESULTS=$(grep -c "Capa results for " "${LOG_FILE}" || echo 0)
    fi
    print_output "[*] Found ${ORANGE}${lCAPA_RESULTS}${NC} capa results in ${ORANGE}${lBINS_AVAILABLE:-0}${NC} binaries"
    rm "${TMP_DIR}"/s18_checked.tmp 2>/dev/null
  fi

  module_end_log "${FUNCNAME[0]}" "${lCAPA_RESULTS}"
}

capa_runner_fct() {
  local lBINARY="${1:-}"

  local lATTACK_CODES_ARR=()
  local lATTACK_CODE=""
  local lBIN_NAME=""
  lBIN_NAME="$(basename "${lBINARY}")"
  local lBIN_MD5=""
  local lCAPA_OPTS=()

  if grep -q "${lBINARY}.*ELF" "${P99_CSV_LOG}"; then
    lCAPA_OPTS=("--os" "linux")
  elif grep -q "${lBINARY}.*PE32" "${P99_CSV_LOG}"; then
    lCAPA_OPTS=("--os" "windows")
  elif grep -q "${lBINARY}.*MSI" "${P99_CSV_LOG}"; then
    lCAPA_OPTS=("--os" "windows")
  else
    print_output "[-] No supported architecture identified for capa on $(print_path "${lBINARY}")" "no_log"
    return
  fi

  print_output "[*] Testing binary behavior with capa for $(print_path "${lBINARY}")" "no_log"
  "${EXT_DIR}"/capa "${lCAPA_OPTS[@]}" "${lBINARY}" > "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" || print_error "[-] Capa analysis failed for ${lBINARY}"

  if [[ ! -f "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" ]] || [[ ! -s "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" ]] || (grep -q "no capabilities found" "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log"); then
    print_output "[*] No capa results for $(print_path "${lBINARY}")" "no_log"
    if [[ -f  "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" ]]; then
      rm "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" || true
    fi
    return
  fi

  if [[ -s "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" ]]; then
    print_output "[+] Capa results for ${ORANGE}$(print_path "${lBINARY}")${NC}" "" "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log"
    mapfile -t lATTACK_CODES_ARR < <(grep -o "T[0-9]\{4\}\(\.[0-9]\{3\}\)\?" "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" || true)
    for lATTACK_CODE in "${lATTACK_CODES_ARR[@]}"; do
      # check for ATT&CK framework codes and insert the correct links
      sed -i "/\ ${lATTACK_CODE}\ /a\[REF\] https://attack.mitre.org/techniques/${lATTACK_CODE/\./\/}" "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" || true
    done
    sed -i '/\ MBC Objective/a \[REF\] https://github.com/MBCProject/mbc-markdown' "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" || true
  fi
}

