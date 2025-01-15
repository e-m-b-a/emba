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

# Description:  Searches for password patterns within the firmware.
#               This module uses the stacs engine - https://github.com/stacscan/stacs
#               including the community ruleset - https://github.com/stacscan/stacs-rules

S108_stacs_password_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Stacs analysis of firmware for password hashes"
  pre_module_reporter "${FUNCNAME[0]}"

  local lSTACS_RULES_DIR="${EXT_DIR}"/stacs-rules
  local lSTACS_LOG_FILE="${LOG_PATH_MODULE}"/stacs_pw_hashes.json
  local lELEMENTS=0
  local lELEMENTS_=0
  local lPW_PATH=""
  local lPW_HASH=""
  local lPW_HASH_REAL=""
  local lMESSAGE=""
  local lHASHES_FOUND=0

  if command -v stacs > /dev/null ; then
    stacs --skip-unprocessable --rule-pack "${lSTACS_RULES_DIR}"/credential.json "${FIRMWARE_PATH}" 2> "${TMP_DIR}"/stacs.err 1> "${lSTACS_LOG_FILE}" || true

    if [[ -f "${TMP_DIR}"/stacs.err ]]; then
      print_ln
      print_output "[*] STACS log:"
      tee -a "${LOG_FILE}" < "${TMP_DIR}"/stacs.err || true
    fi

    if [[ -f "${lSTACS_LOG_FILE}" && $(jq ".runs[0] .results[] | .message[]" "${lSTACS_LOG_FILE}" | wc -l) -gt 0 ]]; then
      print_ln
      lELEMENTS_="$(jq ".runs[0] .results[] .message.text" "${lSTACS_LOG_FILE}" | wc -l)"
      print_output "[+] Found ${ORANGE}${lELEMENTS_}${GREEN} credential areas:"
      write_csv_log "Message" "PW_PATH" "PW_HASH" "PW_HASH_real"
      lELEMENTS=$((lELEMENTS_-1))

      for ELEMENT in $(seq 0 "${lELEMENTS}"); do
        lMESSAGE=$(jq ".runs[0] .results[${ELEMENT}] .message.text" "${lSTACS_LOG_FILE}" | grep -v null || true)
        lPW_PATH=$(jq ".runs[0] .results[${ELEMENT}] .locations[] .physicalLocation[].uri" "${lSTACS_LOG_FILE}" \
          | grep -v null | sed 's/^"//' | sed 's/"$//' || true)
        lPW_HASH=$(jq ".runs[0] .results[${ELEMENT}] .locations[] .physicalLocation[].snippet" "${lSTACS_LOG_FILE}" \
          | grep -v null | grep "text\|binary" | head -1 | cut -d: -f2- | sed 's/\\n//g' | tr -d '[:blank:]' || true)
        lPW_HASH_REAL=$(jq ".runs[0] .results[${ELEMENT}] .locations[] .physicalLocation[].snippet.text" "${lSTACS_LOG_FILE}" \
          | grep -v null | head -2 | tail -1 | sed 's/\\n//g' | tr -d '[:blank:]' || true)

        if [[ -s "${S108_CSV_LOG}" ]] && ! (grep -q "/${lPW_PATH};${lPW_HASH}" "${S108_CSV_LOG}"); then
          print_output "[+] PATH: ${ORANGE}/${lPW_PATH}${GREEN}\t-\tHash: ${ORANGE}${lPW_HASH}${GREEN}."
          write_csv_log "${lMESSAGE}" "/${lPW_PATH}" "${lPW_HASH}" "${lPW_HASH_REAL}"
          lHASHES_FOUND=$((lHASHES_FOUND+1))
        fi
      done

      print_ln
      print_output "[*] Found ${ORANGE}${lHASHES_FOUND}${NC} password hashes."
    fi
    write_log ""
    write_log "[*] Statistics:${lHASHES_FOUND}"
  fi

  module_end_log "${FUNCNAME[0]}" "${lHASHES_FOUND}"
}
