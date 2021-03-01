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

# Description:  Check all files for predefined code patterns with yara
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}
export HTML_REPORT

S110_yara_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check for code patterns with yara"
  LOG_FILE="$( get_log_file )"

  if [[ $YARA -eq 1 ]] ; then
    # if multiple instances are running we can't overwrite it
    # after updating yara rules we should remove this file and it gets regenerated
    if [[ ! -f "./dir-combined.yara" ]]; then
      find "$EXT_DIR""/yara" -xdev -iname '*.yar*' -printf 'include "./%p"\n' | sort -n > "./dir-combined.yara"
    fi

    local CHECK=0
    local FILE_ARR
    YARA_CNT=0
    readarray -t FILE_ARR < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -type f)
    for YARA_S_FILE in "${FILE_ARR[@]}"; do
      if [[ -e "$YARA_S_FILE" ]] ; then
        local S_OUTPUT
        S_OUTPUT="$(yara -r -w ./dir-combined.yara "$YARA_S_FILE")"
        if [[ -n "$S_OUTPUT" ]] ; then
          print_output "[+] ""$(echo -e "$S_OUTPUT" | head -n1 | cut -d " " -f1)"" ""$(white "$(print_path "$YARA_S_FILE")")"
          CHECK=1
          HTML_REPORT=1
          (( YARA_CNT++ ))
        fi
      fi
    done
    print_output ""
    print_output "[*] Found $ORANGE$YARA_CNT$NC yara rule matches."
    echo -e "\\n[*] Statistics:$YARA_CNT" >> "$LOG_FILE"

    if [[ $CHECK -eq 0 ]] ; then print_output "[-] No code patterns found with yara." ; fi
    # do not remove this to run multiple instances of emba
    #if [[ -f "./dir-combined.yara" ]] ; then rm "./dir-combined.yara" ; fi
  else
    print_output "[!] Check with yara not possible, because it isn't installed!"
  fi
  print_output "[*] $(date) - ${FUNCNAME[0]} finished ... " "main"
}

