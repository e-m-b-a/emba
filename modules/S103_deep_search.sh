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

# Description:  Searches for files with a specified string pattern inside.

S103_deep_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Deep analysis of files for patterns"
  pre_module_reporter "${FUNCNAME[0]}"

  local PATTERNS
  PATTERNS="$(config_list "$CONFIG_DIR""/deep_search.cfg" "")"

  print_output "[*] Patterns: ""$( echo -e "$PATTERNS" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
  
  readarray -t PATTERN_LIST < <(printf '%s' "$PATTERNS")

  export OCC_LIST=()

  deep_pattern_search "${PATTERN_LIST[@]}"
  deep_pattern_reporter "${PATTERN_LIST[@]}"

  module_end_log "${FUNCNAME[0]}" "${#OCC_LIST[@]}"
}

deep_pattern_search() {
  local PATTERN_LIST=("$@")
  local PATTERN=""
  export GREP_PATTERN_COMMAND=()
  local DEEP_S_FILE=""
  local WAIT_PIDS_S103=()

  if [[ "$THREADED" -eq 1 ]]; then
    MAX_THREADS_S103=$((4*"$(grep -c ^processor /proc/cpuinfo || true )"))
  fi
  for PATTERN in "${PATTERN_LIST[@]}" ; do
    GREP_PATTERN_COMMAND=( "${GREP_PATTERN_COMMAND[@]}" "-e" ".{0,15}""$PATTERN"".{0,15}" )
  done
  print_ln "no_log"
  for DEEP_S_FILE in "${FILE_ARR[@]}"; do
    if [[ $THREADED -eq 1 ]]; then
      deep_pattern_searcher "$DEEP_S_FILE" &
      WAIT_PIDS_S103+=( "$!" )
    else
      deep_pattern_searcher "$DEEP_S_FILE"
    fi
    if [[ "$THREADED" -eq 1 ]]; then
      max_pids_protection "$MAX_THREADS_S103" "${WAIT_PIDS_S103[@]}"
    fi
  done

  if [[ $THREADED -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_S103[@]}"
  fi
}

deep_pattern_searcher() {
  local DEEP_S_FILE="${1:-}"
  local DEEP_S_LINE=""
  local PATTERN=""
  local F_COUNT=0
  local OLD_LOG_FILE=""

  if ! [[ -f "$DEEP_S_FILE" ]]; then
    print_output "[-] No file for pattern analysis provided"
    return
  fi

  if [[ -e "$DEEP_S_FILE" ]] ; then
    local S_OUTPUT=()
    readarray -t S_OUTPUT < <(grep -E -n -a -h -o -i "${GREP_PATTERN_COMMAND[@]}" -D skip "$DEEP_S_FILE" | tr -d '\0' || true)
    if [[ ${#S_OUTPUT[@]} -gt 0 ]] ; then
      write_log "[+] ""$DEEP_S_FILE" "$LOG_PATH_MODULE""/deep_search_""$(basename "$DEEP_S_FILE")"".txt"
      for DEEP_S_LINE in "${S_OUTPUT[@]}" ; do
        DEEP_S_LINE="$( echo "$DEEP_S_LINE" | tr "\000-\037\177-\377" "." )"
        write_log "$DEEP_S_LINE" "$LOG_PATH_MODULE""/deep_search_""$(basename "$DEEP_S_FILE")"".txt"
      done
      local D_S_FINDINGS=""
      for PATTERN in "${PATTERN_LIST[@]}" ; do
        F_COUNT=$(grep -c -i "$PATTERN" "$LOG_PATH_MODULE""/deep_search_""$(basename "$DEEP_S_FILE")"".txt" || true)
        if [[ $F_COUNT -gt 0 ]] ; then
          D_S_FINDINGS="$D_S_FINDINGS""    ""$F_COUNT""\t:\t""$PATTERN""\n"
        fi
      done
      # we have to write the file link manually, because threading is messing with the file (wrong order of entries and such awful stuff)
      OLD_LOG_FILE="$LOG_FILE"
      LOG_FILE="$LOG_PATH_MODULE""/deep_search_tmp_""$(basename "$DEEP_S_FILE")"".txt"
      print_output "[+] $(print_path "$DEEP_S_FILE")"

      write_link "$LOG_PATH_MODULE""/deep_search_""$(basename "$DEEP_S_FILE")"".txt"
      print_output "$D_S_FINDINGS" 
      cat "$LOG_FILE" >> "$OLD_LOG_FILE" 2> /dev/null || true
      rm "$LOG_FILE" 2> /dev/null || true
      LOG_FILE="$OLD_LOG_FILE"
    fi
  fi
}

deep_pattern_reporter() {
  local PATTERN_LIST=("$@")
  local PATTERN=""
  local OCC=""
  local P_COUNT=0
  local SORTED_OCC_LIST=()

  for PATTERN in "${PATTERN_LIST[@]}" ; do
    P_COUNT=$(grep -i "$PATTERN" "$LOG_FILE" | cut -f 1 | sed 's/\ //g' | awk '{ SUM += $1} END { print SUM }' )
    OCC_LIST=( "${OCC_LIST[@]}" "$P_COUNT"": ""$PATTERN" )
  done

  if [[ "${#PATTERN_LIST[@]}" -gt 0 ]] ; then
    print_ln
    print_output "[*] Occurences of pattern:"
    SORTED_OCC_LIST=("$(printf '%s\n' "${OCC_LIST[@]}" | sort -r --version-sort)")
    for OCC in "${SORTED_OCC_LIST[@]}"; do
      print_output "$( indent "$(orange "$OCC" )")""\n"
    done
  fi
}
