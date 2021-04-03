#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Searches for possible history files like .bash_history.

S55_history_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search history files"

  local HIST_FILES
  mapfile -t HIST_FILES < <(config_find "$CONFIG_DIR""/history_files.cfg")
  LOG_FILE="$( get_log_file )"

  if [[ "${HIST_FILES[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#HIST_FILES[@]}" -ne 0 ]] ; then
      print_output "[+] Found history files:"
      for LINE in "${HIST_FILES[@]}" ; do
        print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      done
  else
    print_output "[-] No history files found"
  fi

  echo -e "\\n[*] Statistics:${#HIST_FILES[@]}" >> "$LOG_FILE"

  module_end_log "${FUNCNAME[0]}" "${#HIST_FILES[@]}"
}

