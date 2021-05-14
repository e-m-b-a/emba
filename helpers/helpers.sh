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

# Description: Multiple useful helpers

run_web_reporter_mod_name() {
  MOD_NAME="$1"
  if [[ $HTML -eq 1 ]]; then
    # usually we should only find one file:
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
  local WAIT_PIDS=("$@")
  local PID
  #print_output "[*] wait pid protection: ${#WAIT_PIDS[@]}"
  for PID in ${WAIT_PIDS[*]}; do
    #print_output "[*] wait pid protection: $PID"
    echo "." | tr -d "\n"
    if ! [[ -e /proc/"$PID" ]]; then
      continue
    fi
    while [[ -e /proc/"$PID" ]]; do
      #print_output "[*] wait pid protection - running pid: $PID"
      echo "." | tr -d "\n"
    done
  done
}

max_pids_protection() {
  if [[ -n "$1" ]]; then
    local MAX_PIDS_="$1"
    shift
  else
    local MAX_PIDS_="$MAX_MODS"
  fi
  local WAIT_PIDS=("$@")
  local PID
  while [[ ${#WAIT_PIDS[@]} -gt "$MAX_PIDS_" ]]; do
    TEMP_PIDS=()
    # check for really running PIDs and re-create the array
    for PID in ${WAIT_PIDS[*]}; do
      #print_output "[*] max pid protection: ${#WAIT_PIDS[@]}"
      if [[ -e /proc/"$PID" ]]; then
        TEMP_PIDS+=( "$PID" )
      fi
    done
    #print_output "[!] really running pids: ${#TEMP_PIDS[@]}"

    # recreate the arry with the current running PIDS
    WAIT_PIDS=()
    WAIT_PIDS=("${TEMP_PIDS[@]}")
    echo "." | tr -d "\n"
  done
}

cleaner() {
  print_output "[*] Ctrl+C detected!" "no_log"
  print_output "[*] Final cleanup started." "no_log"
  # now we can unmount the stuff from emulator and delete temporary stuff

  # if S115 is found only once in main.log the module was started and we have to clean it up
  if [[ $(grep -c S115 "$LOG_DIR"/"$MAIN_LOG_FILE") -eq 1 ]]; then
    print_output "[*] Terminating qemu processes - check it with ps" "no_log"
    killall -9 --quiet -r .*qemu.*sta.*
    print_output "[*] Cleaning the emulation environment\\n" "no_log"
    find "$FIRMWARE_PATH_CP" -xdev -iname "qemu*static" -exec rm {} \; 2>/dev/null
    print_output "[*] Umounting proc, sys and run" "no_log"
    mapfile -t CHECK_MOUNTS < <(mount | grep "$FIRMWARE_PATH_CP")
    for MOUNT in "${CHECK_MOUNTS[@]}"; do
      print_output "[*] Unmounting $MOUNT" "no_log"
      MOUNT=$(echo "$MOUNT" | cut -d\  -f3)
      umount -l "$MOUNT"
    done
  fi

  if [[ -d "$TMP_DIR" ]]; then
    rm -r "$TMP_DIR" 2>/dev/null
  fi
  print_output "[!] Test ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "no_log"
  exit 1
}

