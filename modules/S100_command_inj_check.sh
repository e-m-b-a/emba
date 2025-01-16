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

# Description:  Looks for web-based files in folders like www and searches for code executions inside of them.

S100_command_inj_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search areas for command injections"
  pre_module_reporter "${FUNCNAME[0]}"

  local lCMD_INJ_DIRS_ARR=()
  mapfile -t lCMD_INJ_DIRS_ARR < <(config_find "${CONFIG_DIR}""/check_command_inj_dirs.cfg")
  local lDIR=""
  local lFILE_ARRX=()
  local lFILE_S=""
  local lQUERY=""
  local lCHECK_ARR=()
  local lNEG_LOG=0
  local lCHECK_=""

  if [[ "${lCMD_INJ_DIRS_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#lCMD_INJ_DIRS_ARR[@]}" -ne 0 ]] ; then
    print_output "[+] Found directories and files used for web scripts:"
    for lDIR in "${lCMD_INJ_DIRS_ARR[@]}" ; do
      if [[ -d "${lDIR}" ]] ; then
        print_output "$(indent "$(print_path "${lDIR}")")"
        mapfile -t lFILE_ARRX < <( find "${lDIR}" -xdev -type f -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' | sort -u -k1,1 | cut -d\  -f3 || true)

        for lFILE_S in "${lFILE_ARRX[@]}" ; do
          if file "${lFILE_S}" | grep -q -E "script.*executable" ; then
            print_output "$( indent "$(orange "$(print_path "${lFILE_S}")"" -> Executable script")")"

            local lQUERY_L_ARR=()
            mapfile -t lQUERY_L_ARR < <(config_list "${CONFIG_DIR}""/check_command_injections.cfg" "")
            for lQUERY in "${lQUERY_L_ARR[@]}" ; do
              # without this check we always have an empty search string and get every file as result
              if [[ -n "${lQUERY}" ]]; then
                mapfile -t lCHECK_ARR < <(grep -H -h "${lQUERY}" "${lFILE_S}" | sort -u || true)
                if [[ "${#lCHECK_ARR[@]}" -gt 0 ]] ; then
                  print_ln
                  print_output "$(indent "[${GREEN}+${NC}]${GREEN} Found ""${lQUERY}"" in ""$(print_path "${lFILE_S}")${NC}")"
                  for lCHECK_ in "${lCHECK_ARR[@]}" ; do
                    print_output "$(indent "[${GREEN}+${NC}]${GREEN} ${lCHECK_}${NC}")"
                    lNEG_LOG=1
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
  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}
