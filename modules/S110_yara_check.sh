#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Checks files with yara for suspicious patterns.
export THREAD_PRIO=1


S110_yara_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check for code patterns with yara"
  pre_module_reporter "${FUNCNAME[0]}"

  local DIR_COMB_YARA="$TMP_DIR""/dir-combined.yara"
  local COUNTING=0
  local YRULE=""
  local MATCH_FILE=""
  local MATCH_FILE_NAME=""

  if [[ $YARA -eq 1 ]] ; then
    # if multiple instances are running we can't overwrite it
    # after updating yara rules we should remove this file and it gets regenerated
    if [[ ! -f "$DIR_COMB_YARA" ]]; then
      find "$EXT_DIR""/yara" -xdev -iname '*.yar' -exec realpath {} \; | xargs printf 'include "%s"\n'| sort -n > "$DIR_COMB_YARA"
    fi

    yara -p "$MAX_MOD_THREADS" -r -w -s -m -L -g "$DIR_COMB_YARA" "$LOG_DIR"/firmware > "$LOG_PATH_MODULE"/yara_complete_output.txt || true

    while read -r YARA_OUT_LINE; do
      if [[ "$YARA_OUT_LINE" == *" [] [author="* ]]; then
        YRULE=$(echo "$YARA_OUT_LINE" | awk '{print $1}')
        MATCH_FILE=$(echo "$YARA_OUT_LINE" | grep "\ \[\]\ \[author=\"" | rev | awk '{print $1}' | rev)
        MATCH_FILE_NAME=$(basename "$MATCH_FILE")
        if [[ "$YRULE" =~ .*IsSuspicious.* ]]; then
          # this rule does not help us a lot ... remove it from results
          continue
        fi
        if ! [[ -f "$LOG_PATH_MODULE"/"$MATCH_FILE_NAME" ]]; then
          print_output "[+] Yara rule $ORANGE$YRULE$GREEN matched in $ORANGE$MATCH_FILE$NC" "" "$LOG_PATH_MODULE/$MATCH_FILE_NAME".txt
          write_log "" "$LOG_PATH_MODULE/$MATCH_FILE_NAME".txt
          write_log "[+] Yara rule $ORANGE$YRULE$GREEN matched in $ORANGE$MATCH_FILE$NC" "$LOG_PATH_MODULE/$MATCH_FILE_NAME".txt
          echo "" >> "$LOG_PATH_MODULE/$MATCH_FILE_NAME".txt
          COUNTING=$((COUNTING+1))
        fi
      fi
      if [[ -v MATCH_FILE_NAME ]]; then
        echo "$YARA_OUT_LINE" >> "$LOG_PATH_MODULE"/"$MATCH_FILE_NAME".txt
      fi
    done < "$LOG_PATH_MODULE"/yara_complete_output.txt

    print_ln
    print_ln
    print_output "[*] Found $ORANGE$COUNTING$NC yara rule matches in $ORANGE${#FILE_ARR[@]}$NC files."
    write_log ""
    write_log "[*] Statistics:$COUNTING"

    if [[ "$COUNTING" -eq 0 ]] ; then print_output "[-] No code patterns found with yara." ; fi
    if [[ -f "$DIR_COMB_YARA" ]] ; then rm "$DIR_COMB_YARA" ; fi
  else
    print_output "[!] Check with yara not possible, because it isn't installed!"
  fi

  module_end_log "${FUNCNAME[0]}" "$COUNTING"
}
