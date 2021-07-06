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

# Description:  Checks files with yara for suspicious patterns.
export THREAD_PRIO=1


S110_yara_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check for code patterns with yara"
  YARA_CNT=0
  local WAIT_PIDS_S110=()

  if [[ $YARA -eq 1 ]] ; then
    # if multiple instances are running we can't overwrite it
    # after updating yara rules we should remove this file and it gets regenerated
    if [[ ! -f "./dir-combined.yara" ]]; then
      find "$EXT_DIR""/yara" -xdev -iname '*.yar*' -printf 'include "./%p"\n' | sort -n > "./dir-combined.yara"
    fi

    for YARA_S_FILE in "${FILE_ARR[@]}"; do
      if [[ "$THREADED" -eq 1 ]]; then
        yara_check &
        WAIT_PIDS_S110+=( "$!" )
      else
        yara_check 
      fi
    done

    if [[ "$THREADED" -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS_S110[@]}"
    fi

    if [[ -f "$TMP_DIR"/YARA_CNT.tmp ]]; then
      while read -r COUNTING; do
        (( YARA_CNT="$YARA_CNT"+"$COUNTING" ))
      done < "$TMP_DIR"/YARA_CNT.tmp
    fi

    print_output ""
    print_output "[*] Found $ORANGE$YARA_CNT$NC yara rule matches in $ORANGE${#FILE_ARR[@]}$NC files."
    write_log ""
    write_log "[*] Statistics:$YARA_CNT"

    if [[ "$YARA_CNT" -eq 0 ]] ; then print_output "[-] No code patterns found with yara." ; fi
    # do not remove this to run multiple instances of emba
    #if [[ -f "./dir-combined.yara" ]] ; then rm "./dir-combined.yara" ; fi
  else
    print_output "[!] Check with yara not possible, because it isn't installed!"
  fi

  module_end_log "${FUNCNAME[0]}" "$YARA_CNT"
}

yara_check() {
  if [[ -e "$YARA_S_FILE" ]] ; then
    local S_OUTPUT
    mapfile -t S_OUTPUT < <(yara -r -w ./dir-combined.yara "$YARA_S_FILE")
    if [[ "${#S_OUTPUT[@]}" -gt 0 ]] ; then
      for YARA_OUT in "${S_OUTPUT[@]}"; do
        print_output "[+] ""$(echo -e "$YARA_OUT" | cut -d " " -f1)"" ""$(white "$(print_path "$YARA_S_FILE")")"
        echo "1" >> "$TMP_DIR"/YARA_CNT.tmp
      done
    fi
  fi
}
