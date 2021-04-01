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

# Description:  Examines all files of firmware against a database of ordinary Linux files 
#               (extracted from freshly installed distributions).

S108_linux_common_file_checker() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Module to check for common linux files"

  LOG_FILE="$( get_log_file )"
  FILE_COUNTER=0
  FILE_COUNTER_ALL=0

  if [[ -f "$BASE_LINUX_FILES" ]]; then
    print_output "[*] Using ""$BASE_LINUX_FILES"" as dictionary for common Linux files\n"
    for FILE in "${FILE_ARR[@]}" ; do
      SEARCH_TERM=$(basename "$FILE")
      if ! grep -q "$SEARCH_TERM" "$BASE_LINUX_FILES" 2>/dev/null; then
        print_output "[+] ""$ORANGE""$(print_path "$FILE")""$NC""$GREEN"" not found in default Linux file dictionary""$NC"
        FILE_COUNTER=$((FILE_COUNTER+1))
      fi
      FILE_COUNTER_ALL=$((FILE_COUNTER_ALL+1))
    done
    print_output ""
    print_output "[*] Found $ORANGE$FILE_COUNTER$NC not common Linux files and $ORANGE$FILE_COUNTER_ALL$NC files at all."
    echo -e "\\n[*] Statistics:$FILE_COUNTER:$FILE_COUNTER_ALL" >> "$LOG_FILE"
  else
    print_output "[-] No common Linux files dictionary (""$BASE_LINUX_FILES"") found in config directory"
  fi

  module_end_log "${FUNCNAME[0]}" "$FILE_COUNTER"
}
