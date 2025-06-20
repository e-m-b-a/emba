#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Checks files with yara for suspicious patterns.
export THREAD_PRIO=0


S110_yara_check() {
  module_log_init "${FUNCNAME[0]}"

  if [[ "${QUICK_SCAN:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  module_title "Check for code patterns with yara"
  pre_module_reporter "${FUNCNAME[0]}"

  local lDIR_COMB_YARA="${TMP_DIR}""/dir-combined.yara"
  local lCOUNTING=0
  local lYRULE=""
  local lMATCH_FILE=""
  local lMATCH_FILE_NAME=""
  # shellcheck disable=SC2153
  local lMAX_MOD_THREADS=$((MAX_MOD_THREADS/2))
  local lMEM_LIMIT=$(( "${TOTAL_MEMORY}"*80/100 ))
  local lYARA_OUT_LINE=""

  if [[ ${YARA} -eq 1 ]] ; then
    # if multiple instances are running we can't overwrite it
    # after updating yara rules we should remove this file and it gets regenerated
    if [[ ! -f "${lDIR_COMB_YARA}" ]]; then
      find "${EXT_DIR}""/yara" -xdev -iname '*.yar' -exec realpath {} \; | xargs printf 'include "%s"\n'| sort -n > "${lDIR_COMB_YARA}"
    fi

    ulimit -Sv "${lMEM_LIMIT}"
    yara -p "${lMAX_MOD_THREADS}" -r -w -s -m -L -g "${lDIR_COMB_YARA}" "${LOG_DIR}"/firmware > "${LOG_PATH_MODULE}"/yara_complete_output.txt || true
    ulimit -Sv unlimited

    while read -r lYARA_OUT_LINE; do
      local lAUTHOR_STRING=" [] [author="
      if [[ "${lYARA_OUT_LINE}" == *"${lAUTHOR_STRING}"* ]]; then
        lYRULE=$(echo "${lYARA_OUT_LINE}" | awk '{print $1}')
        lMATCH_FILE=$(echo "${lYARA_OUT_LINE}" | grep "\ \[\]\ \[author=\"" | rev | awk '{print $1}' | rev)
        lMATCH_FILE_NAME=$(basename "${lMATCH_FILE}")
        # this rule does not help us a lot ... remove it from results
        [[ "${lYRULE}" =~ .*IsSuspicious.* ]] && continue
        if ! [[ -f "${LOG_PATH_MODULE}"/"${lMATCH_FILE_NAME}" ]]; then
          print_output "[+] Yara rule ${ORANGE}${lYRULE}${GREEN} matched in ${ORANGE}${lMATCH_FILE}${NC}" "" "${LOG_PATH_MODULE}/${lMATCH_FILE_NAME}".txt
          write_log "" "${LOG_PATH_MODULE}/${lMATCH_FILE_NAME}".txt
          write_log "[+] Yara rule ${ORANGE}${lYRULE}${GREEN} matched in ${ORANGE}${lMATCH_FILE}${NC}" "${LOG_PATH_MODULE}/${lMATCH_FILE_NAME}".txt
          echo "" >> "${LOG_PATH_MODULE}/${lMATCH_FILE_NAME}".txt
          lCOUNTING=$((lCOUNTING+1))
        fi
      fi
      [[ -v lMATCH_FILE_NAME ]] && echo "${lYARA_OUT_LINE}" >> "${LOG_PATH_MODULE}"/"${lMATCH_FILE_NAME}".txt
    done < "${LOG_PATH_MODULE}"/yara_complete_output.txt

    print_ln
    print_ln
    print_output "[*] Found ${ORANGE}${lCOUNTING}${NC} yara rule matches in extracted firmware files."
    write_log ""
    write_log "[*] Statistics:${lCOUNTING}"

    [[ "${lCOUNTING}" -eq 0 ]] && print_output "[-] No code patterns found with yara."
    [[ -f "${lDIR_COMB_YARA}" ]] && rm "${lDIR_COMB_YARA}"
  else
    print_output "[!] YARA checks disabled - enable it in your scanning profile with ${ORANGE}export YARA=1${NC}."
  fi

  module_end_log "${FUNCNAME[0]}" "${lCOUNTING}"
}
