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

# Description:  This module was the first module that existed in emba. The main idea was to identify the binaries that were using weak
#               functions and to establish a ranking of areas to look at first.

S10_binaries_basic_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries for critical functions"
  pre_module_reporter "${FUNCNAME[0]}"

  local COUNTER=0
  local BIN_COUNT=0
  local VULNERABLE_FUNCTIONS=""
  local BINARY=""
  local VUL_FUNC_RESULT=()
  local VUL_FUNC=""

  VULNERABLE_FUNCTIONS="$(config_list "${CONFIG_DIR}""/functions.cfg")"

  # nosemgrep
  local IFS=" "
  IFS=" " read -r -a VUL_FUNC_GREP <<<"$( echo -e "${VULNERABLE_FUNCTIONS}" | sed ':a;N;$!ba;s/\n/ -e /g')"

  if [[ "${VULNERABLE_FUNCTIONS}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "${VULNERABLE_FUNCTIONS}" ]] ; then
    print_output "[*] Interesting functions: ""$( echo -e "${VULNERABLE_FUNCTIONS}" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
    for BINARY in "${BINARIES[@]}" ; do
      if ( file "${BINARY}" | grep -q "ELF" ) ; then
        BIN_COUNT=$((BIN_COUNT+1))
        mapfile -t VUL_FUNC_RESULT < <(readelf -s --use-dynamic "${BINARY}" 2> /dev/null | grep -we "${VUL_FUNC_GREP[@]}" | grep -v "file format" || true)
        if [[ "${#VUL_FUNC_RESULT[@]}" -ne 0 ]] ; then
          print_ln
          print_output "[+] Interesting function in ""$(print_path "${BINARY}")"" found:"
          for VUL_FUNC in "${VUL_FUNC_RESULT[@]}" ; do
            # shellcheck disable=SC2001
            VUL_FUNC="$(echo "${VUL_FUNC}" | sed -e 's/[[:space:]]\+/\t/g')"
            print_output "$(indent "${VUL_FUNC}")"
          done
          COUNTER=$((COUNTER+1))
        fi
      fi
    done
    print_ln
    print_output "[*] Found ""${ORANGE}${COUNTER}${NC}"" binaries with interesting functions in ""${ORANGE}${BIN_COUNT}${NC}"" files (vulnerable functions: ""$( echo -e "${VULNERABLE_FUNCTIONS}" | sed ':a;N;$!ba;s/\n/ /g' )"")"
  fi

  module_end_log "${FUNCNAME[0]}" "${COUNTER}"
}
