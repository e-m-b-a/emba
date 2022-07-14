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

S106_deep_key_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Deep analysis of files for private keys"
  pre_module_reporter "${FUNCNAME[0]}"

  local PATTERNS
  PATTERNS="$(config_list "$CONFIG_DIR""/deep_key_search.cfg" "")"

  readarray -t PATTERN_LIST < <(printf '%s' "$PATTERNS")

  for PATTERN in "${PATTERN_LIST[@]}";do
    print_output "[*] Pattern: $PATTERN"
  done

  SORTED_OCC_LIST=()

  deep_key_search
  deep_key_reporter

  module_end_log "${FUNCNAME[0]}" "${#SORTED_OCC_LIST[@]}"
}

deep_key_search() {
  local WAIT_PIDS_S106=()
  local DEEP_S_FILE=""
  GREP_PATTERN_COMMAND=()

  if [[ "$THREADED" -eq 1 ]]; then
    MAX_THREADS_S106=$((4*"$(grep -c ^processor /proc/cpuinfo || true )"))
  fi
  for PATTERN in "${PATTERN_LIST[@]}" ; do
    GREP_PATTERN_COMMAND=( "${GREP_PATTERN_COMMAND[@]}" "-e" ".{0,15}""$PATTERN"".{0,15}" )
  done
  print_output "" "no_log"
  for DEEP_S_FILE in "${FILE_ARR[@]}"; do
    if [[ $THREADED -eq 1 ]]; then
      deep_key_searcher "$DEEP_S_FILE" &
      WAIT_PIDS_S106+=( "$!" )
    else
      deep_key_searcher "$DEEP_S_FILE"
    fi
    if [[ "$THREADED" -eq 1 ]]; then
      max_pids_protection "$MAX_THREADS_S106" "${WAIT_PIDS_S106[@]}"
    fi
  done

  if [[ $THREADED -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_S106[@]}"
  fi
}

deep_key_searcher() {
  local DEEP_S_FILE="${1:-}"

  if [[ -e "$DEEP_S_FILE" ]] ; then
    local S_OUTPUT
    readarray -t S_OUTPUT < <(grep -A 2 -E -n -a -h "${GREP_PATTERN_COMMAND[@]}" -D skip "$DEEP_S_FILE" | tr -d '\0' | cut -c-100 || true)
    if [[ ${#S_OUTPUT[@]} -gt 0 ]] ; then
      echo "[+] $DEEP_S_FILE" >> "$LOG_PATH_MODULE"/deep_key_search_"$(basename "$DEEP_S_FILE")"".txt"
      for DEEP_S_LINE in "${S_OUTPUT[@]}" ; do
        DEEP_S_LINE="$( echo "$DEEP_S_LINE" | tr "\000-\037\177-\377" "." )"
        echo "$DEEP_S_LINE" >> "$LOG_PATH_MODULE"/deep_key_search_"$(basename "$DEEP_S_FILE")"".txt"
      done
      local D_S_FINDINGS=""
      for PATTERN in "${PATTERN_LIST[@]}" ; do
        F_COUNT=$(grep -c "$PATTERN" "$LOG_PATH_MODULE"/deep_key_search_"$(basename "$DEEP_S_FILE")"".txt" || true)
        if [[ $F_COUNT -gt 0 ]] ; then
          D_S_FINDINGS="$D_S_FINDINGS""    ""$F_COUNT""\t:\t""$PATTERN""\n"
        fi
      done
      # we have to write the file link manually, because threading is messing with the file (wrong order of entries and such awful stuff)
      OLD_LOG_FILE="$LOG_FILE"
      LOG_FILE="$LOG_PATH_MODULE""/deep_key_search_tmp_""$(basename "$DEEP_S_FILE")"".txt"
      print_output "[+] $(print_path "$DEEP_S_FILE")"
      write_link "$LOG_PATH_MODULE""/deep_key_search_""$(basename "$DEEP_S_FILE")"".txt"
      print_output "$D_S_FINDINGS" 
      if [[ -f "$LOG_FILE" ]]; then
        cat "$LOG_FILE" >> "$OLD_LOG_FILE" 2> /dev/null || true
        rm "$LOG_FILE" 2> /dev/null || true
      fi
      LOG_FILE="$OLD_LOG_FILE"
    fi
  fi
}

deep_key_reporter() {
  OCC_LIST=()
  for PATTERN in "${PATTERN_LIST[@]}" ; do
    P_COUNT=$(grep -c "$PATTERN" "$LOG_PATH_MODULE"/deep_key_search_* 2>/dev/null | cut -d: -f2 | awk '{ SUM += $1} END { print SUM }' || true )
    if [[ "$P_COUNT" -gt 0 ]]; then
      OCC_LIST=( "${OCC_LIST[@]}" "$P_COUNT"": ""$PATTERN" )
    fi
  done

  if [[ "${#PATTERN_LIST[@]}" -gt 0 ]] ; then
    if [[ "${#OCC_LIST[@]}" -gt 0 ]] ; then
      print_output ""
      print_output "[*] Occurences of pattern:"
      SORTED_OCC_LIST=("$(printf '%s\n' "${OCC_LIST[@]}" | sort -r --version-sort)")
      if [[ "${#SORTED_OCC_LIST[@]}" -gt 0 ]]; then
        for OCC in "${SORTED_OCC_LIST[@]}"; do
          print_output "$( indent "$(orange "$OCC" )")""\n"
        done
      fi
    fi
  fi
}
