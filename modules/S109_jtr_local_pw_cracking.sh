#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Cracks password hashes from S109 (STACS module) with jtr
#               jtr runtime is 60 minutes


S109_jtr_local_pw_cracking()
{
  module_log_init "${FUNCNAME[0]}"

  local PW_FILE="${CSV_DIR}"/s108_stacs_password_search.csv
  local PW_FILE_S107="${CSV_DIR}"/s107_deep_password_search.csv
  local NEG_LOG=0
  local HASHES_S107=()
  local HASHES_S108=()
  local HASHES=()
  local HASH=""
  local HASH_SOURCE=""
  local CRACKED_HASHES=()
  local JTR_FINAL_STAT=""
  local CRACKED_HASH=""
  local CRACKED=0
  local JTR_TIMEOUT="3600"
  # optional wordlist for JTR - if no wordlist is there JTR runs in default mode
  local JTR_WORDLIST="${CONFIG_DIR}/jtr_wordlist.txt"
  local HASH_DESCRIPTION=""
  local JTR_FORMATS=()
  local JTR_FORMAT=""
  local PID=""

  # This module waits for S108_stacs_password_search and S107_deep_password_search
  # check emba.log for S108_stacs_password_search starting
  module_wait "S107_deep_password_search"
  module_wait "S108_stacs_password_search"

  module_title "Cracking identified password hashes"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ -f "${PW_FILE_S107}" ]]; then
    mapfile -t HASHES_S107 < <(cut -d\; -f1,2,3 "${PW_FILE_S107}" | grep -v "PW_HASH" | sort -k 2 -t \; -u)
  fi

  if [[ -f "${PW_FILE}" ]]; then
    mapfile -t HASHES_S108 < <(cut -d\; -f1,2,3 "${PW_FILE}" | grep -v "PW_PATH;PW_HASH" | sort -k 2 -t \; -u)

    HASHES=("${HASHES_S107[@]}" "${HASHES_S108[@]}")

    for HASH in "${HASHES[@]}"; do
      HASH_DESCRIPTION=$(basename "$(echo "${HASH}" | cut -d\; -f1)")
      HASH_SOURCE=$(basename "$(echo "${HASH}" | cut -d\; -f2)")
      HASH=$(echo "${HASH}" | cut -d\; -f3 | tr -d \")

      [[ "${HASH}" == *"BEGIN"*"KEY"* ]] && continue
      [[ "${HASH_DESCRIPTION}" == *"private key found"* ]] && continue

      if echo "${HASH}" | cut -d: -f1-3 | grep -q "::[0-9]"; then
        # nosemgrep
        # removing entries: root::0:0:99999:7:::
        continue
      fi

      if [[ "${HASH}" == "\$"*"\$"* ]]; then
        # put ontop if linux-hash
        sed -i "1s/^/${HASH}\n/" "${LOG_PATH_MODULE}"/jtr_hashes.txt
      else
        print_output "[*] Found password data ${ORANGE}${HASH}${NC} for further processing in ${ORANGE}${HASH_SOURCE}${NC}"
        echo "${HASH}" >> "${LOG_PATH_MODULE}"/jtr_hashes.txt
      fi
    done

    # sort and make unique
    if [[ -f "${LOG_PATH_MODULE}"/jtr_hashes.txt ]]; then
      sort -u --o "${LOG_PATH_MODULE}"/jtr_hashes.txt "${LOG_PATH_MODULE}"/jtr_hashes.txt
    fi

    if [[ -f "${LOG_PATH_MODULE}"/jtr_hashes.txt ]]; then
      print_output "[*] Starting jtr with a runtime of ${ORANGE}${JTR_TIMEOUT}${NC} on the following data:"
      tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/jtr_hashes.txt
      print_ln
      if [[ -f "${JTR_WORDLIST}" ]]; then
        print_output "[*] Starting jtr with the following wordlist: ${ORANGE}${JTR_WORDLIST}${NC} with ${ORANGE}$(wc -l "${JTR_WORDLIST}" | awk '{print $1}')${NC} entries."
        john --progress-every=120 --wordlist="${JTR_WORDLIST}" "${LOG_PATH_MODULE}"/jtr_hashes.txt |& safe_logging "${LOG_FILE}" 0 || true &
        PID="$!"
      else
        john --progress-every=120 "${LOG_PATH_MODULE}"/jtr_hashes.txt |& safe_logging "${LOG_FILE}" 0 || true &
        PID="$!"
      fi
      sleep 5

      local COUNT=0
      while [[ "${COUNT}" -le "${JTR_TIMEOUT}" ]];do
        ((COUNT+=1))
        if ! pgrep john > /dev/null; then
          # if no john process is running it means we are finished with cracking passwords
          # and we can exit the while loop for waiting
          break
        fi
        sleep 1
      done
      kill "${PID}" || true
      if pgrep john > /dev/null; then
        pkill -f "john" > /dev/null
      fi

      # lets check our log if we can find further hashes
      mapfile -t JTR_FORMATS < <(grep "option to force loading hashes of that type instead" "${LOG_FILE}" || true)

      # if we have further hashes we are processing these now
      if [[ "${#JTR_FORMATS[@]}" -gt 0 ]] && [[ "${COUNT}" -lt "${JTR_TIMEOUT}" ]] ; then
        print_ln
        print_output "[*] Further password hashes detected:"
        for JTR_FORMAT in "${JTR_FORMATS[@]}"; do
          JTR_FORMAT="$(echo "${JTR_FORMAT}" | cut -d '=' -f2 | awk '{print $1}' | tr -d '"' )"
          print_output "$(indent "$(orange "Detected hash type: ${JTR_FORMAT}")")"
        done

        for JTR_FORMAT in "${JTR_FORMATS[@]}"; do
          print_ln
          JTR_FORMAT="$(echo "${JTR_FORMAT}" | cut -d '=' -f2 | awk '{print $1}' | tr -d '"' )"
          print_output "[*] Testing password hash types ${ORANGE}${JTR_FORMAT}${NC}"
          if [[ -f "${JTR_WORDLIST}" ]]; then
            print_output "[*] Starting jtr with the following wordlist: ${ORANGE}${JTR_WORDLIST}${NC} with ${ORANGE}$(wc -l "${JTR_WORDLIST}" | awk '{print $1}')${NC} entries."
            find "${JTR_WORDLIST}" | tee -a "${LOG_FILE}"
            john --format="${JTR_FORMAT}" --progress-every=120 --wordlist="${JTR_WORDLIST}" "${LOG_PATH_MODULE}"/jtr_hashes.txt 2>&1 | tee -a "${LOG_FILE}" || true &
            PID="$!"
          else
            john --format="${JTR_FORMAT}" --progress-every=120 "${LOG_PATH_MODULE}"/jtr_hashes.txt 2>&1 | tee -a "${LOG_FILE}" || true &
            PID="$!"
          fi
          sleep 5

          while [[ "${COUNT}" -le "${JTR_TIMEOUT}" ]];do
            ((COUNT+=1))
            if ! pgrep john > /dev/null; then
              # if no john process is running it means we are finished with cracking passwords
              # and we can exit the while loop for waiting
              break
            fi
            sleep 1
          done
          kill "${PID}" || true
          if pgrep john > /dev/null; then
            pkill -f "john" > /dev/null
          fi
        done
      fi
      print_ln
      NEG_LOG=1

      mapfile -t CRACKED_HASHES < <(john --show "${LOG_PATH_MODULE}"/jtr_hashes.txt | grep -v "password hash\(es\)\? cracked" | grep -v "^$" || true)
      JTR_FINAL_STAT=$(john --show "${LOG_PATH_MODULE}"/jtr_hashes.txt | grep "password hash\(es\)\? cracked\|No password hashes loaded" || true)
      CRACKED=$(echo "${JTR_FINAL_STAT}" | awk '{print $1}')
      if [[ -n "${JTR_FINAL_STAT}" ]]; then
        print_ln
        print_output "[*] John the ripper final status: ${ORANGE}${JTR_FINAL_STAT}${NC}"
        NEG_LOG=1
      fi
    fi

    if [[ "${CRACKED}" -gt 0 ]]; then
      for CRACKED_HASH in "${CRACKED_HASHES[@]}"; do
        print_output "[+] Password hash cracked: ${ORANGE}${CRACKED_HASH}${NC}"
        NEG_LOG=1
      done
    fi
  fi

  write_log "[*] Statistics:${CRACKED}"
  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}
