#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2024 Siemens Energy AG
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


S110_yara_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check for code patterns with yara"
  pre_module_reporter "${FUNCNAME[0]}"

  local DIR_COMB_YARA="${TMP_DIR}""/dir-combined.yara"
  local COUNTING=0
  local YRULE=""
  local MATCH_FILE=""
  local MATCH_FILE_NAME=""
  local MAX_MOD_THREADS=$((MAX_MOD_THREADS/2))
  local MEM_LIMIT=$(( "${TOTAL_MEMORY}"*80/100 ))

  if [[ ${YARA} -eq 1 ]] ; then
    # if multiple instances are running we can't overwrite it
    # after updating yara rules we should remove this file and it gets regenerated
    if [[ ! -f "${DIR_COMB_YARA}" ]]; then
      find "${EXT_DIR}""/yara" -xdev -iname '*.yar' -exec realpath {} \; | xargs printf 'include "%s"\n'| sort -n > "${DIR_COMB_YARA}"
    fi

    ulimit -Sv "${MEM_LIMIT}"
    yara -p "${MAX_MOD_THREADS}" -r -w -s -m -L -g "${DIR_COMB_YARA}" "${LOG_DIR}"/firmware > "${LOG_PATH_MODULE}"/yara_complete_output.txt || true
    ulimit -Sv unlimited

    while read -r YARA_OUT_LINE; do
      local AUTHOR_STRING=" [] [author="
      if [[ "${YARA_OUT_LINE}" == *"${AUTHOR_STRING}"* ]]; then
        YRULE=$(echo "${YARA_OUT_LINE}" | awk '{print $1}')
        MATCH_FILE=$(echo "${YARA_OUT_LINE}" | grep "\ \[\]\ \[author=\"" | rev | awk '{print $1}' | rev)
        MATCH_FILE_NAME=$(basename "${MATCH_FILE}")
        # this rule does not help us a lot ... remove it from results
        [[ "${YRULE}" =~ .*IsSuspicious.* ]] && continue
        if ! [[ -f "${LOG_PATH_MODULE}"/"${MATCH_FILE_NAME}" ]]; then
          print_output "[+] Yara rule ${ORANGE}${YRULE}${GREEN} matched in ${ORANGE}${MATCH_FILE}${NC}" "" "${LOG_PATH_MODULE}/${MATCH_FILE_NAME}".txt
          write_log "" "${LOG_PATH_MODULE}/${MATCH_FILE_NAME}".txt
          write_log "[+] Yara rule ${ORANGE}${YRULE}${GREEN} matched in ${ORANGE}${MATCH_FILE}${NC}" "${LOG_PATH_MODULE}/${MATCH_FILE_NAME}".txt
          echo "" >> "${LOG_PATH_MODULE}/${MATCH_FILE_NAME}".txt
          COUNTING=$((COUNTING+1))
        fi
      fi
      [[ -v MATCH_FILE_NAME ]] && echo "${YARA_OUT_LINE}" >> "${LOG_PATH_MODULE}"/"${MATCH_FILE_NAME}".txt
    done < "${LOG_PATH_MODULE}"/yara_complete_output.txt

    print_ln
    print_ln
    print_output "[*] Found ${ORANGE}${COUNTING}${NC} yara rule matches in ${ORANGE}${#FILE_ARR[@]}${NC} files."
    write_log ""
    write_log "[*] Statistics:${COUNTING}"

    [[ "${COUNTING}" -eq 0 ]] && print_output "[-] No code patterns found with yara."
    [[ -f "${DIR_COMB_YARA}" ]] && rm "${DIR_COMB_YARA}"
  else
    print_output "[!] YARA checks disabled - enable it in your scanning profile with ${ORANGE}export YARA=1${NC}."
  fi

  module_end_log "${FUNCNAME[0]}" "${COUNTING}"
}
