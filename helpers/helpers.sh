#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description: Multiple usefull helpers

run_web_reporter_mod_name() {
  MOD_NAME="$1"
  if [[ $HTML -eq 1 ]]; then
    mapfile -t LOG_FILES < <(find "$LOG_DIR" -maxdepth 1 -type f -iname "$MOD_NAME*.txt" | sort)
    for LOG_FILE in "${LOG_FILES[@]}"; do
      XREPORT=$(grep -c "[-]\ .*\ nothing\ reported" "$LOG_FILE")
      if [[ "$XREPORT" -gt 0 ]]; then
        #print_output "[*] generating log file with NO content $LOG_FILE" "no_log"
        generate_html_file "$LOG_FILE" 0
      else
        #print_output "[+] generating log file with content $LOG_FILE" "no_log"
        generate_html_file "$LOG_FILE" 1
      fi
    done
   fi
}

run_web_reporter_build_index() {
  if [[ $HTML -eq 1 ]]; then
    #print_output "[*] Building index file for web report"
    LOG_INDICATORS=( p s f )
    for LOG_INDICATOR in "${LOG_INDICATORS[@]}"; do
      mapfile -t LOG_FILES < <(find "$LOG_DIR" -maxdepth 1 -type f -iname "$LOG_INDICATOR*.txt" | sort)
      for LOG_FILE in "${LOG_FILES[@]}"; do
        XREPORT=$(grep -c "[-]\ .*\ nothing\ reported" "$LOG_FILE")
        if [[ "$XREPORT" -eq 0 ]]; then
          #print_output "[+] Generating index file with content $LOG_FILE" "no_log"
          build_index_file "$LOG_FILE"
        fi
      done
    done
  fi
}

wait_for_pid() {
  for PID in ${WAIT_PIDS[*]}; do
    print_output "[*] waiting for ${#WAIT_PIDS[@]} processes"
    if ! pgrep -v grep | grep -q "$PID"; then
      continue
    fi
    running=1
    while [[ $running -eq 1 ]]; do
      echo "." | tr -d "\n"
      if ! pgrep -v grep | grep -q "$PID"; then
        running=0
        continue
      fi
    done
  done
}

max_pids_protection() {
  while [[ ${#WAIT_PIDS[@]} -gt "$MAX_PIDS" ]]; do
    TEMP_PIDS=()
    # check for really running PIDs and re-create the array
    for PID in ${WAIT_PIDS[*]}; do
      if pgrep -v grep | grep -q "$PID"; then
        TEMP_PIDS+=( "$PID" )
      fi
    done

    if [[ ${#TEMP_PIDS[@]} -gt "$MAX_PIDS" ]]; then
      echo "." | tr -d "\n"
      echo "[*] Waiting for processess ... ${#TEMP_PIDS[@]}"
      sleep 1
    fi
    # recreate the arry with the current running PIDS
    WAIT_PIDS=("${TEMP_PIDS[@]}")
  done
}

