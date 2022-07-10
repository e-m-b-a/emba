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

# Description:  Cracks password hashes from S109 (STACS module) with jtr
#               jtr runtime is 60 minutes


S109_jtr_local_pw_cracking()
{
  module_log_init "${FUNCNAME[0]}"

  local PW_FILE="$LOG_DIR"/s108_stacs_password_search.csv
  local HASHES=()
  local HASH=""
  local HASH_SOURCE=""
  local HASH=""
  local CRACKED_HASHES=()
  local JTR_FINAL_STAT=""
  local CRACKED_HASH=""
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
    mapfile -t HASHES < <(cut -d\; -f2,3 "$PW_FILE" | sort -k 2 -t \; -u)
    for HASH in "${HASHES[@]}"; do
      HASH_SOURCE=$(basename "$(echo "$HASH" | cut -d\; -f1)")
      HASH=$(echo "$HASH" | cut -d\; -f2 | tr -d \")
      echo "$HASH_SOURCE:$HASH" >> "$LOG_PATH_MODULE"/jtr_hashes.txt
    done

    if [[ -f "$LOG_PATH_MODULE"/jtr_hashes.txt ]]; then
      print_output "[*] Starting jtr for the following hashes (runtime: $ORANGE$JTR_TIMEOUT$NC):"
      tee -a "$LOG_FILE" < "$LOG_PATH_MODULE"/jtr_hashes.txt
      print_output ""
      timeout --preserve-status --signal SIGINT "$JTR_TIMEOUT" john --progress-every=120 "$LOG_PATH_MODULE"/jtr_hashes.txt | tee -a "$LOG_FILE" || true
      print_output ""
    fi

    mapfile -t CRACKED_HASHES < <(john --show "$LOG_PATH_MODULE"/jtr_hashes.txt | grep -v "password hash cracked" | grep -v "^$")
    JTR_FINAL_STAT=$(john --show "$LOG_PATH_MODULE"/jtr_hashes.txt | grep "password hash cracked" || true)
    if [[ -n "$JTR_FINAL_STAT" ]]; then
      print_output "[*] John the ripper final status: $ORANGE$JTR_FINAL_STAT$NC"
    fi

    if [[ "${#CRACKED_HASHES[@]}" -gt 0 ]]; then
      for CRACKED_HASH in "${CRACKED_HASHES[@]}"; do
        print_output "[+] Password hash cracked: $ORANGE$CRACKED_HASH$NC"
      done
    fi
  fi

  write_log "[*] Statistics:${#CRACKED_HASHES[@]}"
  module_end_log "${FUNCNAME[0]}" "${#CRACKED_HASHES[@]}"
}
