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

# Description:  Search hidden files
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S70_hidden_file_check()
{
  module_log_init "s70_search_hidden_file"
  module_title "Search hidden files"
  CONTENT_AVAILABLE=0

  local HIDDEN_FILES
  IFS=" " read -r -a HIDDEN_FILES < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -name ".*" -type f | tr '\r\n' ' ')

  if [[ ${#HIDDEN_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#HIDDEN_FILES[@]}"" hidden files:"
    for LINE in "${HIDDEN_FILES[@]}" ; do
      print_output "$(indent "$(orange "$(print_path "$LINE")")")"
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[-] No hidden files found!"
  fi
  
  if [[ $HTML == 1 ]]; then
    generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

