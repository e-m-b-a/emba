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

# Description:  Check all files for predefined code patterns with yara
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S110_yara_check()
{
  module_log_init "s110_yara_checker"
  module_title "Check for code patterns with yara"
  CONTENT_AVAILABLE=0

  if [[ $YARA -eq 1 ]] ; then
    find "$EXT_DIR""/yara" -iname '*.yar*' -printf 'include "./%p"\n' | sort -n > "./dir-combined.yara"

    local CHECK=0
    local FILE_ARR
    readarray -t FILE_ARR < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -type f)
    for YARA_S_FILE in "${FILE_ARR[@]}"; do
      if [[ -e "$YARA_S_FILE" ]] ; then
        local S_OUTPUT
        S_OUTPUT="$(yara -r -w dir-combined.yara "$YARA_S_FILE")"
        if [[ -n "$S_OUTPUT" ]] ; then
          print_output "[+] ""$(echo -e "$S_OUTPUT" | head -n1 | cut -d " " -f1)"" ""$(white "$(print_path "$YARA_S_FILE")")"
          echo
          CHECK=1
          CONTENT_AVAILABLE=1
        fi
      fi
    done

    if [[ $CHECK -eq 0 ]] ; then print_output "[-] No code patterns found with yara." ; fi
    if [[ -f "./dir-combined.yara" ]] ; then rm "./dir-combined.yara" ; fi
  else
    print_output "[!] Check with yara not possible, because it isn't installed!"
  fi

  if [[ $HTML == 2 ]]; then
    generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

