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

# Description:  Cracks password hashes from S109 (STACS module) with jtr
#               jtr runtime is 60 minutes


S109_jtr_local_pw_cracking()
{
  module_log_init "${FUNCNAME[0]}"

  local PW_FILE="$LOG_DIR"/s108_stacs_password_search.csv
  local NEG_LOG=0
  local HASHES=()
  local HASH=""
  local HASH_SOURCE=""
  local CRACKED_HASHES=()
  local JTR_FINAL_STAT=""
  local CRACKED_HASH=""
  local CRACKED=0
  local JTR_TIMEOUT="60m"

  # This module waits for S108_stacs_password_search
  # check emba.log for S108_stacs_password_search starting
  if [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; then
    while [[ $(grep -c S108_stacs_password_search "$LOG_DIR"/"$MAIN_LOG_FILE") -eq 1 ]]; do
      sleep 1
    done
  fi

  module_title "Cracking identified password hashes"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ -f "$PW_FILE" ]]; then
    mapfile -t HASHES < <(cut -d\; -f2,3 "$PW_FILE" | grep -v "PW_PATH;PW_HASH" | sort -k 2 -t \; -u)
    for HASH in "${HASHES[@]}"; do
      HASH_SOURCE=$(basename "$(echo "$HASH" | cut -d\; -f1)")
      HASH=$(echo "$HASH" | cut -d\; -f2 | tr -d \")
      echo "$HASH_SOURCE:$HASH" >> "$LOG_PATH_MODULE"/jtr_hashes.txt
    done

    if [[ -f "$LOG_PATH_MODULE"/jtr_hashes.txt ]]; then
      print_output "[*] Starting jtr for the following hashes (runtime: $ORANGE$JTR_TIMEOUT$NC):"
      tee -a "$LOG_FILE" < "$LOG_PATH_MODULE"/jtr_hashes.txt
      print_ln
      timeout --preserve-status --signal SIGINT "$JTR_TIMEOUT" john --progress-every=120 "$LOG_PATH_MODULE"/jtr_hashes.txt | tee -a "$LOG_FILE" || true
      print_ln
      NEG_LOG=1
    fi

    mapfile -t CRACKED_HASHES < <(john --show "$LOG_PATH_MODULE"/jtr_hashes.txt | grep -v "password hash cracked" | grep -v "^$")
    JTR_FINAL_STAT=$(john --show "$LOG_PATH_MODULE"/jtr_hashes.txt | grep "password hash cracked\|No password hashes loaded" || true)
    CRACKED=$(echo "$JTR_FINAL_STAT" | awk '{print $1}')
    if [[ -n "$JTR_FINAL_STAT" ]]; then
      print_output "[*] John the ripper final status: $ORANGE$JTR_FINAL_STAT$NC"
      NEG_LOG=1
    fi

    if [[ "$CRACKED" -gt 0 ]]; then
      for CRACKED_HASH in "${CRACKED_HASHES[@]}"; do
        print_output "[+] Password hash cracked: $ORANGE$CRACKED_HASH$NC"
        NEG_LOG=1
      done
    fi
  fi

  write_log "[*] Statistics:$CRACKED"
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}
