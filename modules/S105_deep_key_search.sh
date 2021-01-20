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

# Description:  Run trough all files and check for private keys
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}
export CONTENT_AVAILABLE

S105_deep_key_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Deep analysis of files for private keys"

  local QUERY_L
  QUERY_L="$(config_list "$CONFIG_DIR""/deep_search.cfg" "")"
  readarray -t STRING_LIST < <(printf '%s' "$QUERY_L")
  for QUERY in "${STRING_LIST[@]}" ; do
    print_output "[*] Searching all files for '""$QUERY""' ... this may take a while!"
    echo
    readarray -t FILE_ARR < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -type f)
    for DEEP_S_FILE in "${FILE_ARR[@]}"; do
      if [[ -e "$DEEP_S_FILE" ]] ; then
        local S_OUTPUT
        S_OUTPUT="$(grep -a -h "$QUERY" -A 2 -D skip "$DEEP_S_FILE" | tr "\000-\011\013-\037\177-\377" "." | cut -c-200 )"
        if [[ -n "$S_OUTPUT" ]] ; then
          CONTENT_AVAILABLE=1
          print_output "[+] ""$(print_path "$DEEP_S_FILE")"
          print_output "$( indent "$(echo "$S_OUTPUT" | tr -dc '\11\12\15\40-\176' )")"
          echo
        fi
      fi
    done
    echo
  done
}

