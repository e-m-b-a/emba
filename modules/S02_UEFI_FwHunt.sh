#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Uses fwhunt for identification of vulnerabilities in possible UEFI firmware
#               images:
#               fwhunt-scan https://github.com/binarly-io/fwhunt-scan
#               fwhunt rules https://github.com/binarly-io/FwHunt
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
#export PRE_THREAD_ENA=1

S02_UEFI_FwHunt() {

  module_log_init "${FUNCNAME[0]}"
  module_title "Binarly UEFI FwHunt analyzer"
  pre_module_reporter "${FUNCNAME[0]}"

  local NEG_LOG=0
  local WAIT_PIDS_S02=()
  local MAX_MOD_THREADS=$((MAX_MOD_THREADS/2))
  local EXTRACTED_FILE=""

  if [[ "$UEFI_DETECTED" -eq 1 ]] ; then
    print_output "[*] Starting FwHunter"
    for EXTRACTED_FILE in "${FILE_ARR[@]}"; do
      if [[ $THREADED -eq 1 ]]; then
        fwhunter "$EXTRACTED_FILE" &
        WAIT_PIDS_S02+=( "$!" )
        max_pids_protection "$MAX_MOD_THREADS" "${WAIT_PIDS_S02[@]}"
      else
        fwhunter "$EXTRACTED_FILE"
      fi
    done
  fi

  if [[ $THREADED -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_S02[@]}"
  fi

  fwhunter_logging

  if [[ "${#FWHUNTER_RESULTS[@]}" -gt 0 ]]; then
    NEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

fwhunter() {
  local FWHUNTER_CHECK_FILE="${1:-}"
  local FWHUNTER_CHECK_FILE_NAME=$(basename "$FWHUNTER_CHECK_FILE")

  print_output "[*] Running FwHunt on $ORANGE$FWHUNTER_CHECK_FILE$NC"
  python3 "$EXT_DIR"/fwhunt-scan/fwhunt_scan_analyzer.py scan-firmware "$FWHUNTER_CHECK_FILE" --rules_dir "$EXT_DIR"/fwhunt-scan/rules/ | tee -a "$LOG_PATH_MODULE""/fwhunt_scan_$FWHUNTER_CHECK_FILE_NAME.txt" || true
}

fwhunter_logging() {
  export FWHUNTER_RESULTS=()
  local FWHUNTER_RESULT=""
  local FWHUNTER_RESULT_FILE=""

  mapfile -t FWHUNTER_RESULTS < <(find "$LOG_PATH_MODULE" -type f -exec grep -H "Scanner result" {} \;)
  if ! [[ "${#FWHUNTER_RESULTS[@]}" -gt 0 ]]; then
    return
  fi
  print_ln
  print_output "[+] FwHunt UEFI vulnerability details:"
  print_ln
  for FWHUNTER_RESULT in "${FWHUNTER_RESULTS[@]}"; do
    FWHUNTER_RESULT_FILE=$(echo "$FWHUNTER_RESULT" | cut -d: -f1)
    FWHUNTER_RESULT=$(echo "$FWHUNTER_RESULT" | cut -d: -f2-)
    if [[ "$FWHUNTER_RESULT" == *"rule has been triggered and threat detected"* ]]; then
      print_output "[+] $FWHUNTER_RESULT_FILE $ORANGE:$GREEN $FWHUNTER_RESULT"
    fi
  done
  print_ln
}
