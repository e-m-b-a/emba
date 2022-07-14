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

  local YARA_CNT=0
  local WAIT_PIDS_S110=()
  local DIR_COMB_YARA="$TMP_DIR""/dir-combined.yara"
  local YARA_S_FILE=""
  local COUNTING=0

  if [[ $YARA -eq 1 ]] ; then
    # if multiple instances are running we can't overwrite it
    # after updating yara rules we should remove this file and it gets regenerated
    if [[ ! -f "$DIR_COMB_YARA" ]]; then
      find "$EXT_DIR""/yara" -xdev -iname '*.yar*' -printf 'include "%p"\n' | sort -n > "$DIR_COMB_YARA"
    fi
    if [[ "$THREADED" -eq 1 ]]; then
      MAX_THREADS_S110=$((6*"$(grep -c ^processor /proc/cpuinfo || true )"))
    fi

    for YARA_S_FILE in "${FILE_ARR[@]}"; do
      if [[ "$THREADED" -eq 1 ]]; then
        yara_check "$YARA_S_FILE" "$DIR_COMB_YARA" &
        WAIT_PIDS_S110+=( "$!" )
      else
        yara_check "$YARA_S_FILE" "$DIR_COMB_YARA"
      fi
      if [[ "$THREADED" -eq 1 ]]; then
        max_pids_protection "$MAX_THREADS_S110" "${WAIT_PIDS_S110[@]}"
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

    print_output "\\n"
    print_output "[*] Found $ORANGE$YARA_CNT$NC yara rule matches in $ORANGE${#FILE_ARR[@]}$NC files."
    write_log ""
    write_log "[*] Statistics:$YARA_CNT"

    if [[ "$YARA_CNT" -eq 0 ]] ; then print_output "[-] No code patterns found with yara." ; fi
    if [[ -f "$DIR_COMB_YARA" ]] ; then rm "$DIR_COMB_YARA" ; fi
  else
    print_output "[!] Check with yara not possible, because it isn't installed!"
  fi

  module_end_log "${FUNCNAME[0]}" "$YARA_CNT"
}

yara_check() {
  local YARA_S_FILE_="${1:-}"
  local DIR_COMB_YARA_="${2:-}"
  local Y_LOG=""
  local MATCHED_RULES=()
  local MATCHED_RULE=""

  if ! [[ -f "$YARA_S_FILE_" ]] ; then
    return
  fi
  if ! [[ -f "$DIR_COMB_YARA_" ]] ; then
    print_output "[-] Missing Yara rules file - something bad happened"
    return
  fi

  Y_LOG="$LOG_PATH_MODULE/$(basename "$YARA_S_FILE_").txt"
  yara -r -w -s -m -L -g "$DIR_COMB_YARA_" "$YARA_S_FILE_" >> "$Y_LOG"

  # remove empty logfiles
  if [[ -f "$Y_LOG" ]]; then
    [[ -s "$Y_LOG" ]] || rm "$Y_LOG" 2>/dev/null || true
  fi

  if [[ -f "$Y_LOG" ]]; then
    # as multiple rules can match per file, we need to extract the matching rules
    mapfile -t MATCHED_RULES < <(grep ".*\ \[\]\ \[.*\]\ \/" "$Y_LOG" || true)
    # iteratre through all matching rules and print success
    for MATCHED_RULE in "${MATCHED_RULES[@]}"; do
      MATCHED_RULE=$(echo "$MATCHED_RULE" | awk '{print $1}')
      if [[ "$MATCHED_RULE" =~ .*IsSuspicious.* ]]; then
        # this rule does not help us a lot ... remove it from results
        continue
      fi
      print_output "[+] Yara rule $ORANGE$MATCHED_RULE$GREEN matched in $ORANGE$YARA_S_FILE_$NC" "" "$Y_LOG"
      echo "1" >> "$TMP_DIR"/YARA_CNT.tmp
    done
  fi
}
