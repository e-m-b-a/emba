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

# Description:  Check for history files
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S55_history_file_check()
{
  module_log_init "s55_search_history_file"
  module_title "Search history files"

  CONTENT_AVAILABLE=0
  local HIST_FILES
  HIST_FILES="$(config_find "$CONFIG_DIR""/history_files.cfg")"

  if [[ "$HIST_FILES" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$HIST_FILES" ]] ; then
      print_output "[+] Found history files:"
      for LINE in $HIST_FILES ; do
        print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      done
      CONTENT_AVAILABLE=1
  else
    print_output "[-] No history files found"
  fi
  
  if [[ $HTML == 1 ]]; then
     generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

