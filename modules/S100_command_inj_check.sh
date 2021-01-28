#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Check directories/files, used for web, for section to inject commands
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S100_command_inj_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search areas for command injections"

  local CMD_INJ_DIRS
  mapfile -t CMD_INJ_DIRS < <(config_find "$CONFIG_DIR""/check_command_inj_dirs.cfg")

  if [[ "${CMD_INJ_DIRS[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#CMD_INJ_DIRS[@]}" -ne 0 ]] ; then
    print_output "[+] Found directories and files used for web scripts:"
    for LINE in "${CMD_INJ_DIRS[@]}" ; do
      if [[ -d "$LINE" ]] ; then
        print_output "$(indent "$(print_path "$LINE")")"
        mapfile -t FILE_ARR < <(find "$LINE" -maxdepth 1 -name "*")
        for FILE_S in "${FILE_ARR[@]}" ; do
          if file "$FILE_S" | grep -q -E "script.*executable" ; then
            print_output "$( indent "$(orange "$(print_path "$FILE_S")"" -> Executable")")"

            local QUERY_L
            QUERY_L="$(config_list "$CONFIG_DIR""/check_command_injections.cfg" "")"
            mapfile -t QUERY_L < <(config_list "$CONFIG_DIR""/check_command_injections.cfg" "")
            for QUERY in "${QUERY_L[@]}" ; do
              CHECK="$(grep -H -h "$QUERY" "$FILE_S")"
              if [[ -n "$CHECK" ]] ; then
                print_output "$(indent "$(indent "$(green "$QUERY"" in ""$(print_path "$FILE_S")")")")"
                print_output "$CHECK"
              fi
            done
          fi
        done
      fi
    done
  else
    print_output "[-] No directories or files used for web scripts found"
  fi
}

