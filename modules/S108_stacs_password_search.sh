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

# Description:  Searches for password patterns within the firmware.
#               This module uses the stacs engine - https://github.com/stacscan/stacs
#               including the community ruleset - https://github.com/stacscan/stacs-rules

S108_stacs_password_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Stacs analysis of firmware for password hashes"
  pre_module_reporter "${FUNCNAME[0]}"

  local STACS_RULES_DIR="${EXT_DIR}"/stacs-rules
  local STACS_LOG_FILE="${LOG_PATH_MODULE}"/stacs_pw_hashes.json
  local ELEMENTS=0
  local ELEMENTS_=0
  local PW_PATH=""
  local PW_HASH=""
  local PW_HASH_REAL=""
  local MESSAGE=""

  if command -v stacs > /dev/null ; then
    stacs --skip-unprocessable --rule-pack "${STACS_RULES_DIR}"/credential.json "${FIRMWARE_PATH}" 2> "${TMP_DIR}"/stacs.err 1> "${STACS_LOG_FILE}" || true

    if [[ -f "${TMP_DIR}"/stacs.err ]]; then
      print_ln
      print_output "[*] STACS log:"
      tee -a "${LOG_FILE}" < "${TMP_DIR}"/stacs.err || true
    fi

    if [[ -f "${STACS_LOG_FILE}" && $(jq ".runs[0] .results[] | .message[]" "${STACS_LOG_FILE}" | wc -l) -gt 0 ]]; then
      print_ln
      ELEMENTS_="$(jq ".runs[0] .results[] .message.text" "${STACS_LOG_FILE}" | wc -l)"
      print_output "[+] Found ${ORANGE}${ELEMENTS_}${GREEN} credential areas:"
      write_csv_log "Message" "PW_PATH" "PW_HASH" "PW_HASH_real"
      ELEMENTS=$((ELEMENTS_-1))

      for ELEMENT in $(seq 0 "${ELEMENTS}"); do
        MESSAGE=$(jq ".runs[0] .results[${ELEMENT}] .message.text" "${STACS_LOG_FILE}" | grep -v null || true)
        PW_PATH=$(jq ".runs[0] .results[${ELEMENT}] .locations[] .physicalLocation[].uri" "${STACS_LOG_FILE}" \
          | grep -v null | sed 's/^"//' | sed 's/"$//' || true)
        PW_HASH=$(jq ".runs[0] .results[${ELEMENT}] .locations[] .physicalLocation[].snippet" "${STACS_LOG_FILE}" \
          | grep -v null | grep "text\|binary" | head -1 | cut -d: -f2- | sed 's/\\n//g' | tr -d '[:blank:]' || true)
        PW_HASH_REAL=$(jq ".runs[0] .results[${ELEMENT}] .locations[] .physicalLocation[].snippet.text" "${STACS_LOG_FILE}" \
          | grep -v null | head -2 | tail -1 | sed 's/\\n//g' | tr -d '[:blank:]' || true)

        print_output "[+] PATH: ${ORANGE}/${PW_PATH}${GREEN}\t-\tHash: ${ORANGE}${PW_HASH}${GREEN}."
        write_csv_log "${MESSAGE}" "/${PW_PATH}" "${PW_HASH}" "${PW_HASH_REAL}"
      done

      print_ln
      print_output "[*] Found ${ORANGE}${ELEMENTS_}${NC} password hashes."
    fi
    write_log ""
    write_log "[*] Statistics:${ELEMENTS_}"
  fi

  module_end_log "${FUNCNAME[0]}" "${ELEMENTS_}"
}
