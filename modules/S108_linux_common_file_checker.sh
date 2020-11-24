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

# Description:  Module that checks all files of the firmware against a dictionary
#               with common Linux files.

S108_linux_common_file_checker() {
  module_log_init "s108_linux_common_file_checker_log"
  module_title "Module to check the firmware files against a common dictionary of common linux files"
  CONTENT_AVAILABLE=0

  if [[ -f "$BASE_LINUX_FILES" ]]; then
    print_output "\n[*] Using ""$BASE_LINUX_FILES"" as dictionary for common Linux files\n"
    readarray -t ALL_FIRMWARE_FILES < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -iname "*" )

    local COUNTER
    COUNTER=0
    local COUNTER_ALL
    COUNTER_ALL=0
    for FILE in "${ALL_FIRMWARE_FILES[@]}" ; do
      SEARCH_TERM=$(basename "$FILE")
      if ! grep -q "$SEARCH_TERM" "$BASE_LINUX_FILES" 2>/dev/null; then
        print_output "[+] Firmware file ""$ORANGE""$SEARCH_TERM""$NC""$GREEN"" not found in dictionary -> Looks as it is not a default Linux file""$NC"
        COUNTER=$((COUNTER+1))
      fi
      COUNTER_ALL=$((COUNTER_ALL+1))
    done
    print_output "\n[*] Found ""$COUNTER"" not common Linux files in firmware ""$FIRMWARE_PATH"" with ""$COUNTER_ALL"" files at all."
    CONTENT_AVAILABLE=1
  else
    print_output "[-] No common Linux files dictionary (""$BASE_LINUX_FILES"") found in config directory"
  fi
  
  if [[ $HTML == 1 ]]; then
    generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}
