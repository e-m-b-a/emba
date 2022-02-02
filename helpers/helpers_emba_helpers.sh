#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description: Multiple useful helpers

run_web_reporter_mod_name() {
  MOD_NAME="$1"
  if [[ $HTML -eq 1 ]]; then
    # usually we should only find one file:
    mapfile -t LOG_FILES < <(find "$LOG_DIR" -maxdepth 1 -type f -iname "$MOD_NAME*.txt" | sort)
    for LOG_FILE in "${LOG_FILES[@]}"; do
      generate_report_file "$LOG_FILE"
      sed -i -E '/^\[REF\]|\[ANC\].*/d' "$LOG_FILE"
    done
  fi
}

wait_for_pid() {
  local WAIT_PIDS=("$@")
  local PID
  #print_output "[*] wait pid protection: ${#WAIT_PIDS[@]}"
  for PID in "${WAIT_PIDS[@]}"; do
    #print_output "[*] wait pid protection: $PID"
    echo "." | tr -d "\n" 2>/dev/null
    if ! [[ -e /proc/"$PID" ]]; then
      continue
    fi
    while [[ -e /proc/"$PID" ]]; do
      #print_output "[*] wait pid protection - running pid: $PID"
      echo "." | tr -d "\n" 2>/dev/null
      # if S115 is running we have to kill old qemu processes
      if [[ $(grep -c S115_ "$LOG_DIR"/"$MAIN_LOG_FILE") -eq 1 && -n "$QRUNTIME" ]]; then
        killall -9 --quiet --older-than "$QRUNTIME" -r .*qemu.*sta.* || true
      fi
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
    for PID in "${WAIT_PIDS[@]}"; do
      #print_output "[*] max pid protection: ${#WAIT_PIDS[@]}"
      if [[ -e /proc/"$PID" ]]; then
        TEMP_PIDS+=( "$PID" )
      fi
    done
    # if S115 is running we have to kill old qemu processes
    if [[ $(grep -c S115_ "$LOG_DIR"/"$MAIN_LOG_FILE") -eq 1 && -n "$QRUNTIME" ]]; then
      killall -9 --quiet --older-than "$QRUNTIME" -r .*qemu.*sta.*
    fi

    #print_output "[!] really running pids: ${#TEMP_PIDS[@]}"

    # recreate the arry with the current running PIDS
    WAIT_PIDS=()
    WAIT_PIDS=("${TEMP_PIDS[@]}")
    echo "." | tr -d "\n" 2>/dev/null
  done
}

cleaner() {
  print_output "[*] User interrupt detected!" "no_log"
  print_output "[*] Final cleanup started." "no_log"

  # if S115 is found only once in main.log the module was started and we have to clean it up
  # additionally we need to check some variable from a running EMBA instance
  # otherwise the unmounter runs crazy in some corner cases
  if [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" && "${#FILE_ARR[@]}" -gt 0 ]]; then
    if [[ $(grep -c S115 "$LOG_DIR"/"$MAIN_LOG_FILE") -eq 1 ]]; then
      print_output "[*] Terminating qemu processes - check it with ps" "no_log"
      killall -9 --quiet -r .*qemu.*sta.*
      print_output "[*] Cleaning the emulation environment\\n" "no_log"
      find "$FIRMWARE_PATH_CP" -xdev -iname "qemu*static" -exec rm {} \; 2>/dev/null
      print_output "[*] Umounting proc, sys and run" "no_log"
      mapfile -t CHECK_MOUNTS < <(mount | grep "$FIRMWARE_PATH_CP")
      # now we can unmount the stuff from emulator and delete temporary stuff
      for MOUNT in "${CHECK_MOUNTS[@]}"; do
        print_output "[*] Unmounting $MOUNT" "no_log"
        MOUNT=$(echo "$MOUNT" | cut -d\  -f3)
        umount -l "$MOUNT"
      done
    fi
    if [[ $(grep -c S120 "$LOG_DIR"/"$MAIN_LOG_FILE") -eq 1 ]]; then
      print_output "[*] Terminating cwe-checker processes - check it with ps" "no_log"
      killall -9 --quiet -r .*cwe_checker.*
    fi
  fi
  if [[ -n "${CHECK_CVE_JOB_PID:-}" && "${CHECK_CVE_JOB_PID:-}" -ne 0 ]]; then
    kill -9 "$CHECK_CVE_JOB_PID"
  fi

  if [[ -d "$TMP_DIR" ]]; then
    rm -r "$TMP_DIR" 2>/dev/null
  fi
  print_output "[!] Test ended on ""$(date)"" and took about ""$(date -d@$SECONDS -u +%H:%M:%S)"" \\n" "no_log"
  exit 1
}

