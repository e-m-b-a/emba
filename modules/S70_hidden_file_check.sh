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

# Description:  Search hidden files
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}
export HTML_REPORT

S70_hidden_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search hidden files"

  local HIDDEN_FILES
  IFS=" " read -r -a HIDDEN_FILES < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -name ".*" -type f | tr '\r\n' ' ')

  if [[ ${#HIDDEN_FILES[@]} -gt 0 ]] ; then
    HTML_REPORT=1
    print_output "[+] Found ""${#HIDDEN_FILES[@]}"" hidden files:"
    for LINE in "${HIDDEN_FILES[@]}" ; do
      print_output "$(indent "$(orange "$(print_path "$LINE")")")"
    done
  else
    print_output "[-] No hidden files found!"
  fi
}

