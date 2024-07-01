#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2024 Siemens Energy AG
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

  local lBIN_COUNT=0
  local lBINARY=""
  local lWAIT_PIDS_S18=()

  for lBINARY in "${BINARIES[@]}"; do
    if ( file "${lBINARY}" | grep -q "ELF.*Intel" ); then
      lBIN_COUNT=$((lBIN_COUNT+1))
      if [[ "${THREADED}" -eq 1 ]]; then
        capa_runner_fct "${lBINARY}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S18+=( "${lTMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_S18[@]}"
      else
        capa_runner_fct "${lBINARY}"
      fi
    else
      print_output "[-] Binary behavior testing with capa for $(print_path "${lBINARY}") not possible ... unsupported architecture"
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S18[@]}"

  print_ln
  print_output "[*] Found ${ORANGE}${lBIN_COUNT}${NC} capa results in ${ORANGE}${#BINARIES[@]}${NC} binaries"

  module_end_log "${FUNCNAME[0]}" "${lBIN_COUNT}"
}

capa_runner_fct() {
  local lBINARY="${1:-}"

  local lBIN_NAME=""
  lBIN_NAME="$(basename "${lBINARY}")"

  print_output "[*] Testing binary behavior with capa for $(print_path "${lBINARY}")" "no_log"
  "${EXT_DIR}"/capa "${lBINARY}" > "${LOG_PATH_MODULE}/capa_${lBIN_NAME}".log || print_output "[-] Capa analysis failed for ${lBINARY}" "no_log"

  if [[ -s "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" ]]; then
    print_output "[+] Capa results for ${ORANGE}$(print_path "${lBINARY}")${NC}" "" "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log"
  else
    print_output "[*] No capa results for $(print_path "${lBINARY}")" "no_log"
    rm "${LOG_PATH_MODULE}/capa_${lBIN_NAME}.log" || true
  fi
}
