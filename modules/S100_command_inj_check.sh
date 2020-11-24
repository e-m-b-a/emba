#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann, Stefan Haböck

# Description:  Check directories/files, used for web, for section to inject commands
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S100_command_inj_check()
{
  module_log_init "s100_check_command_inj"
  module_title "Search areas for command injections"
  CONTENT_AVAILABLE=0

  local CMD_INJ_DIRS
  CMD_INJ_DIRS="$(config_find "$CONFIG_DIR""/check_command_inj_dirs.cfg" "")"

  if [[ "$CMD_INJ_DIRS" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$CMD_INJ_DIRS" ]] ; then
    print_output "[+] Found directories and files used for web scripts:"
    for LINE in $CMD_INJ_DIRS ; do
      if [[ -d "$LINE" ]] ; then
        print_output "$(indent "$(print_path "$LINE")")"
        local FILE_LIST
        FILE_LIST=$( ls "$LINE")
        readarray -t FILE_ARR < <(printf '%s' "$FILE_LIST")
        for FILE_S in "${FILE_ARR[@]}" ; do
          if file "$LINE""/""$FILE_S" | grep -q -E "script.*executable" ; then
            print_output "$( indent "$(orange "$(print_path "$LINE""/""$FILE_S")"" -> Executable")")"

            local QUERY_L
            QUERY_L="$(config_list "$CONFIG_DIR""/check_command_injections.cfg" "")"
            for QUERY in $QUERY_L ; do
              CHECK="$(grep -H -h "$QUERY" "$LINE""/""$FILE_S")"
              if [[ -n "$CHECK" ]] ; then
                print_output "$(indent "$(indent "$(green "$QUERY"" in ""$(print_path "$LINE""/""$FILE_S")")")")"
                print_output "$CHECK"
              fi
            done
          fi
        done
      fi
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[-] No directories or files used for web scripts found"
  fi
  
  if [[ $HTML == 1 ]]; then
    generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

