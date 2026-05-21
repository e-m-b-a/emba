#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Atharva Bobde
#

# Description: Extracts Motorola S-Record firmwares and converts them into binary
export PRE_THREAD_ENA=0

P26_srec_extractor() {
  local lNEG_LOG=0

  # detect
  if [[ "${SREC_DETECTED:-0}" -ne 1 ]]; then
    return
  fi

  module_log_init "${FUNCNAME[0]}"
  module_title "Motorola S-Record firmware extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  if ! command -v srec_cat >/dev/null; then
    print_output "[-] S-Record firmware detected, but srec_cat is not installed. Skipping S-Record conversion."
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    return
  fi
  if ! command -v srec_info >/dev/null; then
    print_output "[-] S-Record firmware detected, but srec_info is not installed. Skipping S-Record conversion."
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    return
  fi

  local lFIRMWARE_BN=""
  lFIRMWARE_BN=$(basename "${FIRMWARE_PATH}")
  local lEXTRACTION_FILE="${LOG_DIR}/firmware/${lFIRMWARE_BN}.bin"

  srec_firmware_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_FILE}"

  if [[ -f "${lEXTRACTION_FILE}" ]]; then
    lNEG_LOG=1
  fi

  if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}"; then
    lNEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

srec_firmware_extractor() {
  local lSREC_FILE_PATH_="${1:-}"
  local lEXTRACTION_FILE_="${2:-}"

  if ! [[ -f "${lSREC_FILE_PATH_}" ]]; then
    print_output "[-] No S-Record file for extraction provided"
    return
  fi

  sub_module_title "S-Record firmware conversion"

  print_output "[*] Inspecting S-Record file"
  # inspect
  srec_info "${lSREC_FILE_PATH_}" -Motorola | tee -a "${LOG_FILE}"

  print_output "[*] Converting S-Record file to binary format"
  # convert
  rm -f "${lEXTRACTION_FILE_}"
  if srec_cat "${lSREC_FILE_PATH_}" -Motorola -fill 0xFF -within "${lSREC_FILE_PATH_}" -Motorola -Output "${lEXTRACTION_FILE_}" -Binary && [[ -s "${lEXTRACTION_FILE_}" ]]; then
    print_output "[+] Extracted S-Record firmware file to ${ORANGE}${lEXTRACTION_FILE_}${NC}"

    # Update the global FIRMWARE_PATH to point to the new binary file so pipeline uses the .bin
    export FIRMWARE_PATH="${lEXTRACTION_FILE_}"
    backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"

    print_ln
    print_output "[*] Firmware file details: ${ORANGE}$(file -b "${lEXTRACTION_FILE_}")${NC}"

    # Log to CSV
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "" "SREC conversion"
    write_csv_log "S-Record conversion" "${lSREC_FILE_PATH_}" "${lEXTRACTION_FILE_}" "" "NA"
  else
    print_output "[-] Extraction of S-Record firmware file failed"
  fi
}
