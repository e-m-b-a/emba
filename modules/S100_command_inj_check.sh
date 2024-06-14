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

# Description:  Looks for web-based files in folders like www and searches for code executions inside of them.

S100_command_inj_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search areas for command injections"
  pre_module_reporter "${FUNCNAME[0]}"

  local CMD_INJ_DIRS=()
  mapfile -t CMD_INJ_DIRS < <(config_find "${CONFIG_DIR}""/check_command_inj_dirs.cfg")
  local DIR=""
  local FILE_ARRX=()
  local FILE_S=""
  local QUERY=""
  local CHECK=()
  local NEG_LOG=0
  local CHECK_=""

  if [[ "${CMD_INJ_DIRS[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#CMD_INJ_DIRS[@]}" -ne 0 ]] ; then
    print_output "[+] Found directories and files used for web scripts:"
    for DIR in "${CMD_INJ_DIRS[@]}" ; do
      if [[ -d "${DIR}" ]] ; then
        print_output "$(indent "$(print_path "${DIR}")")"
        mapfile -t FILE_ARRX < <( find "${DIR}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

        for FILE_S in "${FILE_ARRX[@]}" ; do
          if file "${FILE_S}" | grep -q -E "script.*executable" ; then
            print_output "$( indent "$(orange "$(print_path "${FILE_S}")"" -> Executable script")")"

            local QUERY_L=()
            mapfile -t QUERY_L < <(config_list "${CONFIG_DIR}""/check_command_injections.cfg" "")
            for QUERY in "${QUERY_L[@]}" ; do
              # without this check we always have an empty search string and get every file as result
              if [[ -n "${QUERY}" ]]; then
                mapfile -t CHECK < <(grep -H -h "${QUERY}" "${FILE_S}" | sort -u || true)
                if [[ "${#CHECK[@]}" -gt 0 ]] ; then
                  print_ln
                  print_output "$(indent "[${GREEN}+${NC}]${GREEN} Found ""${QUERY}"" in ""$(print_path "${FILE_S}")${NC}")"
                  for CHECK_ in "${CHECK[@]}" ; do
                    print_output "$(indent "[${GREEN}+${NC}]${GREEN} ${CHECK_}${NC}")"
                    NEG_LOG=1
                  done
                  print_ln
                fi
              fi
            done
          fi
        done
      fi
    done
  else
    print_output "[-] No directories or files used for web scripts found"
  fi
  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}
