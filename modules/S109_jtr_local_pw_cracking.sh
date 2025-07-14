#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
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


S109_jtr_local_pw_cracking() {
  module_log_init "${FUNCNAME[0]}"

  if [[ "${QUICK_SCAN:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lPW_FILE="${CSV_DIR}"/s108_stacs_password_search.csv
  local lPW_FILE_S107="${CSV_DIR}"/s107_deep_password_search.csv
  local lNEG_LOG=0
  local lHASHES_S107_ARR=()
  local lHASHES_S108_ARR=()
  local lHASHES_ARR=()
  local lHASH=""
  local lHASH_SOURCE=""
  local lCRACKED_HASHES_ARR=()
  local lJTR_FINAL_STAT=""
  local lCRACKED_HASH=""
  local lCRACKED=0
  local lJTR_TIMEOUT="3600"
  # optional wordlist for JTR - if no wordlist is there JTR runs in default mode
  local lJTR_WORDLIST="${CONFIG_DIR}/jtr_wordlist.txt"
  local lJTR_FORMATS_ARR=()
  local lJTR_FORMAT=""
  local lPID=""

  # This module waits for S108_stacs_password_search and S107_deep_password_search
  # check emba.log for S108_stacs_password_search starting
  module_wait "S107_deep_password_search"
  module_wait "S108_stacs_password_search"

  module_title "Cracking identified password hashes"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ -f "${lPW_FILE_S107}" ]]; then
    mapfile -t lHASHES_S107_ARR < <(cut -d\; -f1,2 "${lPW_FILE_S107}" | grep -v "PW_HASH" | sort -k 2 -t \; -u)
  fi

  if [[ -f "${lPW_FILE}" ]]; then
    mapfile -t lHASHES_S108_ARR < <(cut -d\; -f2,3 "${lPW_FILE}" | grep -v "PW_PATH;PW_HASH" | sort -k 2 -t \; -u)

    lHASHES_ARR=("${lHASHES_S107_ARR[@]}" "${lHASHES_S108_ARR[@]}")

    for lHASH in "${lHASHES_ARR[@]}"; do
      lHASH_SOURCE=$(basename "$(echo "${lHASH}" | cut -d\; -f1)")
      lHASH=$(echo "${lHASH}" | cut -d\; -f2 | tr -d \")

      [[ "${lHASH}" == *"BEGIN"*"KEY"* ]] && continue

      if echo "${lHASH}" | cut -d: -f1-3 | grep -q "::[0-9]"; then
        # nosemgrep
        # removing entries: root::0:0:99999:7:::
        continue
      fi

      if [[ "${lHASH}" == "\$"*"\$"* ]]; then
        print_output "[*] Found password data ${ORANGE}${lHASH}${NC} for further processing in ${ORANGE}${lHASH_SOURCE}${NC}"
        # put ontop if linux-hash
        if [[ ! -s "${LOG_PATH_MODULE}"/jtr_hashes.txt ]]; then
          echo "${lHASH}" > "${LOG_PATH_MODULE}"/jtr_hashes.txt
        else
          sed -i "1s#^#${lHASH}\n#" "${LOG_PATH_MODULE}"/jtr_hashes.txt
        fi
      else
        print_output "[*] Found password data ${ORANGE}${lHASH}${NC} for further processing in ${ORANGE}${lHASH_SOURCE}${NC}"
        echo "${lHASH}" >> "${LOG_PATH_MODULE}"/jtr_hashes.txt
      fi
    done

    # sort and make unique
    if [[ -f "${LOG_PATH_MODULE}"/jtr_hashes.txt ]]; then
      sort -u -o "${LOG_PATH_MODULE}"/jtr_hashes.txt "${LOG_PATH_MODULE}"/jtr_hashes.txt
    fi

    if [[ -f "${LOG_PATH_MODULE}"/jtr_hashes.txt ]]; then
      print_output "[*] Starting jtr with a runtime of ${ORANGE}${lJTR_TIMEOUT}${NC} on the following data:"
      tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/jtr_hashes.txt
      print_ln
      if [[ -f "${lJTR_WORDLIST}" ]]; then
        print_output "[*] Starting jtr with the following wordlist: ${ORANGE}${lJTR_WORDLIST}${NC} with ${ORANGE}$(wc -l < "${lJTR_WORDLIST}")${NC} entries."
        john --progress-every=120 --wordlist="${lJTR_WORDLIST}" "${LOG_PATH_MODULE}"/jtr_hashes.txt |& safe_logging "${LOG_FILE}" 0 || true &
        lPID="$!"
      else
        john --progress-every=120 "${LOG_PATH_MODULE}"/jtr_hashes.txt |& safe_logging "${LOG_FILE}" 0 || true &
        lPID="$!"
      fi
      sleep 5

      local lCOUNT=0
      while [[ "${lCOUNT}" -le "${lJTR_TIMEOUT}" ]];do
        ((lCOUNT+=1))
        if ! pgrep john > /dev/null; then
          # if no john process is running it means we are finished with cracking passwords
          # and we can exit the while loop for waiting
          break
        fi
        sleep 1
      done
      kill "${lPID}" || true
      if pgrep john > /dev/null; then
        pkill -f "john" > /dev/null
      fi

      # lets check our log if we can find further hashes
      mapfile -t lJTR_FORMATS_ARR < <(grep "option to force loading hashes of that type instead" "${LOG_FILE}" || true)

      # if we have further hashes we are processing these now
      if [[ "${#lJTR_FORMATS_ARR[@]}" -gt 0 ]] && [[ "${lCOUNT}" -lt "${lJTR_TIMEOUT}" ]] ; then
        print_ln
        print_output "[*] Further password hashes detected:"
        for lJTR_FORMAT in "${lJTR_FORMATS_ARR[@]}"; do
          lJTR_FORMAT="$(echo "${lJTR_FORMAT}" | cut -d '=' -f2 | awk '{print $1}' | tr -d '"' )"
          print_output "$(indent "$(orange "Detected hash type: ${lJTR_FORMAT}")")"
        done

        for lJTR_FORMAT in "${lJTR_FORMATS_ARR[@]}"; do
          print_ln
          lJTR_FORMAT="$(echo "${lJTR_FORMAT}" | cut -d '=' -f2 | awk '{print $1}' | tr -d '"' )"
          print_output "[*] Testing password hash types ${ORANGE}${lJTR_FORMAT}${NC}"
          if [[ -f "${lJTR_WORDLIST}" ]]; then
            print_output "[*] Starting jtr with the following wordlist: ${ORANGE}${lJTR_WORDLIST}${NC} with ${ORANGE}$(wc -l < "${lJTR_WORDLIST}")${NC} entries."
            find "${lJTR_WORDLIST}" | tee -a "${LOG_FILE}"
            john --format="${lJTR_FORMAT}" --progress-every=120 --wordlist="${lJTR_WORDLIST}" "${LOG_PATH_MODULE}"/jtr_hashes.txt 2>&1 | tee -a "${LOG_FILE}" || true &
            lPID="$!"
          else
            john --format="${lJTR_FORMAT}" --progress-every=120 "${LOG_PATH_MODULE}"/jtr_hashes.txt 2>&1 | tee -a "${LOG_FILE}" || true &
            lPID="$!"
          fi
          sleep 5

          while [[ "${lCOUNT}" -le "${lJTR_TIMEOUT}" ]];do
            ((lCOUNT+=1))
            if ! pgrep john > /dev/null; then
              # if no john process is running it means we are finished with cracking passwords
              # and we can exit the while loop for waiting
              break
            fi
            sleep 1
          done
          kill "${lPID}" || true
          if pgrep john > /dev/null; then
            pkill -f "john" > /dev/null
          fi
        done
      fi
      print_ln
      lNEG_LOG=1

      mapfile -t lCRACKED_HASHES_ARR < <(john --show "${LOG_PATH_MODULE}"/jtr_hashes.txt | grep -v "password hash\(es\)\? cracked" | grep -v "^$" || true)
      lJTR_FINAL_STAT=$(john --show "${LOG_PATH_MODULE}"/jtr_hashes.txt | grep "password hash\(es\)\? cracked\|No password hashes loaded" || true)
      lCRACKED=$(echo "${lJTR_FINAL_STAT}" | awk '{print $1}')
      if [[ -n "${lJTR_FINAL_STAT}" ]]; then
        print_ln
        print_output "[*] John the ripper final status: ${ORANGE}${lJTR_FINAL_STAT}${NC}"
        lNEG_LOG=1
      fi
    fi

    if [[ "${lCRACKED}" -gt 0 ]]; then
      for lCRACKED_HASH in "${lCRACKED_HASHES_ARR[@]}"; do
        print_output "[+] Password hash cracked: ${ORANGE}${lCRACKED_HASH}${NC}"
        lNEG_LOG=1
      done
    fi
  fi

  write_log "[*] Statistics:${lCRACKED}"
  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}
