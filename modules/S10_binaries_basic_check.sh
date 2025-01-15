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

# Description:  This module was the first module that existed in emba. The main idea was to identify the binaries that were using weak
#               functions and to establish a ranking of areas to look at first.

S10_binaries_basic_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries for critical functions"
  pre_module_reporter "${FUNCNAME[0]}"

  local lCOUNTER=0
  local lBIN_COUNT=0
  local lVULNERABLE_FUNCTIONS=""
  local lBINARY=""
  local lVUL_FUNC_RESULT_ARR=()
  local lVUL_FUNC=""

  lVULNERABLE_FUNCTIONS="$(config_list "${CONFIG_DIR}""/functions.cfg")"

  # nosemgrep
  local IFS=" "
  IFS=" " read -r -a VUL_FUNC_GREP <<<"$( echo -e "${lVULNERABLE_FUNCTIONS}" | sed ':a;N;$!ba;s/\n/ -e /g')"

  if [[ "${lVULNERABLE_FUNCTIONS}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "${lVULNERABLE_FUNCTIONS}" ]] ; then
    print_output "[*] Interesting functions: ""$( echo -e "${lVULNERABLE_FUNCTIONS}" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
    while read -r lBINARY; do
      lBIN_COUNT=$((lBIN_COUNT+1))
      mapfile -t lVUL_FUNC_RESULT_ARR < <(readelf -s --use-dynamic "${lBINARY}" 2> /dev/null | grep -we "${VUL_FUNC_GREP[@]}" | grep -v "file format" || true)
      if [[ "${#lVUL_FUNC_RESULT_ARR[@]}" -ne 0 ]] ; then
        print_ln
        print_output "[+] Interesting function in ""$(print_path "${lBINARY}")"" found:"
        for lVUL_FUNC in "${lVUL_FUNC_RESULT_ARR[@]}" ; do
          # shellcheck disable=SC2001
          lVUL_FUNC="$(echo "${lVUL_FUNC}" | sed -e 's/[[:space:]]\+/\t/g')"
          print_output "$(indent "${lVUL_FUNC}")"
        done
        lCOUNTER=$((lCOUNTER+1))
      fi
    done < <(grep ";ELF" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u || true)
    print_ln
    print_output "[*] Found ""${ORANGE}${lCOUNTER}${NC}"" binaries with interesting functions in ""${ORANGE}${lBIN_COUNT}${NC}"" files (vulnerable functions: ""$( echo -e "${lVULNERABLE_FUNCTIONS}" | sed ':a;N;$!ba;s/\n/ /g' )"")"
  fi

  module_end_log "${FUNCNAME[0]}" "${lCOUNTER}"
}
