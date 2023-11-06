#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Searches for all hidden files in the firmware.

S70_hidden_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search hidden files"
  pre_module_reporter "${FUNCNAME[0]}"

  local HIDDEN_FILES=()
  local LINE=""

  mapfile -t HIDDEN_FILES < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name ".*" -type f)

  if [[ ${#HIDDEN_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#HIDDEN_FILES[@]}"" hidden files:"
    for LINE in "${HIDDEN_FILES[@]}" ; do
      print_output "$(indent "$(orange "$(print_path "${LINE}")")")"
    done
  else
    print_output "[-] No hidden files found!"
  fi

  module_end_log "${FUNCNAME[0]}" "${#HIDDEN_FILES[@]}"
}

