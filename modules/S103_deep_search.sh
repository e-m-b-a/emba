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

# Description:  Run trough all files and check for patterns
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S103_deep_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Deep analysis of files for patterns"

  local PATTERNS
  PATTERNS="$(config_list "$CONFIG_DIR""/deep_search.cfg" "")"
  local PATTERN_COUNT

  print_output "[*] Patterns: ""$( echo -e "$PATTERNS" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
  print_output "[*] Special characters are replaced by a '.' for better readability.\\n"

  readarray -t PATTERN_LIST < <(printf '%s' "$PATTERNS")
  for PATTERN in "${PATTERN_LIST[@]}" ; do
    local COUNT=0
    print_output "[*] Searching all files for '""$PATTERN""' ... this may take a while!"
    echo
    readarray -t FILE_ARR < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -type f)
    for DEEP_S_FILE in "${FILE_ARR[@]}"; do
      if [[ -e "$DEEP_S_FILE" ]] ; then
        local S_OUTPUT
        S_OUTPUT="$(grep -E -n -a -h -o ".{0,25}""$PATTERN"".{0,25}" -D skip "$DEEP_S_FILE" | tr -d '\0' )" 
        if [[ -n "$S_OUTPUT" ]] ; then
          print_output "[+] ""$(print_path "$DEEP_S_FILE")"
          mapfile -t OUTPUT_ARR < <(echo "$S_OUTPUT")
          for O_LINE in "${OUTPUT_ARR[@]}" ; do
            COLOR_PATTERN="$GREEN""$PATTERN""$NC"
            O_LINE="${O_LINE//'\n'/.}"
            print_output "$( indent "$(echo "${O_LINE//$PATTERN/$COLOR_PATTERN}" | tr "\000-\037\177-\377" "." )")"      
            ((COUNT++))
          done
          echo
        fi
      fi
    done
    PATTERN_COUNT=("$COUNT" "${PATTERN_COUNT[@]}")
    if [[ $COUNT -eq 0 ]] ; then
      print_output "[-] No files with pattern '""$PATTERN""' found!"
    fi
    echo
  done

  local OCC_LIST
  for I in "${!PATTERN_LIST[@]}"; do
    OCC_LIST=("${PATTERN_COUNT[$I]}"": ""${PATTERN_LIST[$I]}" "${OCC_LIST[@]}")
  done

  print_output "[*] Occurences of pattern:"
  SORTED_OCC_LIST=("$(printf '%s\n' "${OCC_LIST[@]}" | sort -r --version-sort)")
  for OCC in "${SORTED_OCC_LIST[@]}"; do
    print_output "$( indent "$(orange "$OCC" )")"
  done

}
