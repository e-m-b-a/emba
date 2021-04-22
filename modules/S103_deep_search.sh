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

# Description:  Searches for files with a specified string pattern inside.
export THREAD_PRIO=1

S103_deep_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Deep analysis of files for patterns"

  local PATTERNS
  PATTERNS="$(config_list "$CONFIG_DIR""/deep_search.cfg" "")"

  print_output "[*] Patterns: ""$( echo -e "$PATTERNS" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
  print_output "[*] Special characters are replaced by a '.' for better readability.\\n"
  
  readarray -t PATTERN_LIST < <(printf '%s' "$PATTERNS")

  deep_pattern_search
  deep_pattern_reporter

  module_end_log "${FUNCNAME[0]}" "$PATTERN_COUNT"
}

deep_pattern_search() {
  local WAIT_PIDS_S103=()
  for PATTERN in "${PATTERN_LIST[@]}" ; do
    local COUNT=0
    print_output "[*] Searching all files for '""$PATTERN""' ... this may take a while!"
    echo
    for DEEP_S_FILE in "${FILE_ARR[@]}"; do
      if [[ "$THREADED" -eq "X" ]]; then
        # we have to check this in detail
        deep_pattern_searcher &
        WAIT_PIDS_S103+=( "$!" )
      else
        deep_pattern_searcher
      fi
    done
    PATTERN_COUNT=("$COUNT" "${PATTERN_COUNT[@]}")
    if [[ $COUNT -eq 0 ]] ; then
      print_output "[-] No files with pattern '""$PATTERN""' found!"
    fi
    echo
  done

  if [[ "$THREADED" -eq "X" ]]; then
    wait_for_pid "${WAIT_PIDS_S103[@]}"
  fi
}

deep_pattern_searcher() {
  if [[ -e "$DEEP_S_FILE" ]] ; then
    local S_OUTPUT
    S_OUTPUT="$(grep -E -n -a -h -o ".{0,25}""$PATTERN"".{0,25}" -D skip "$DEEP_S_FILE" | tr -d '\0' )" 
    if [[ -n "$S_OUTPUT" ]] ; then
      print_output "[+] ""$(print_path "$DEEP_S_FILE")"
      #print_output "[+] $DEEP_S_FILE"
      mapfile -t OUTPUT_ARR < <(echo "$S_OUTPUT")
      for O_LINE in "${OUTPUT_ARR[@]}" ; do
        #print_output "[*] $O_LINE"
        COLOR_PATTERN="$GREEN""$PATTERN""$NC"
        O_LINE="${O_LINE//'\n'/.}"
        print_output "$( indent "$(echo "${O_LINE//$PATTERN/$COLOR_PATTERN}" | tr "\000-\037\177-\377" "." )")"      
        ((COUNT++))
      done
      echo
    fi
  fi
}

deep_pattern_reporter() {

  local OCC_LIST
  for I in "${!PATTERN_LIST[@]}"; do
    if [[ "${PATTERN_COUNT[$I]}" -gt 0 ]] ; then
      OCC_LIST=("${PATTERN_COUNT[$I]}"": ""${PATTERN_LIST[$I]}" "${OCC_LIST[@]}")
    fi
  done

  if [[ "${#PATTERN_LIST[@]}" -gt 0 ]] ; then
    print_output "[*] Occurences of pattern:"
    SORTED_OCC_LIST=("$(printf '%s\n' "${OCC_LIST[@]}" | sort -r --version-sort)")
    for OCC in "${SORTED_OCC_LIST[@]}"; do
      print_output "$( indent "$(orange "$OCC" )")"
    done
  fi
}
