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

# Description:  Decrypts and extracts firmware images from Supermicro BMC
#               Using https://github.com/c0d3z3r0/smcbmc

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P18_BMC_decryptor() {
  local NEG_LOG=0

  if [[ "${BMC_ENC_DETECTED}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "BMC encrypted firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_FILE="${LOG_DIR}"/firmware/firmware_bmc_dec.bin

    bmc_extractor "${FIRMWARE_PATH}" "${EXTRACTION_FILE}"

    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

bmc_extractor() {
  local BMC_FILE_PATH_="${1:-}"
  local EXTRACTION_FILE_="${2:-}"

  if ! [[ -f "${BMC_FILE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "BMC encrypted firmware extractor"

  "${EXT_DIR}"/smcbmc/smcbmc.py "${BMC_FILE_PATH_}" "${EXTRACTION_FILE_}"

  print_ln
  if [[ -f "${EXTRACTION_FILE_}" ]]; then
    export FIRMWARE_PATH="${EXTRACTION_FILE_}"
    print_output "[+] Extracted BMC encrypted firmware file to ${ORANGE}${FIRMWARE_PATH}${NC}"
    backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
    print_ln
    print_output "[*] BMC Firmware file details: ${ORANGE}$(file "${FIRMWARE_PATH}")${NC}"
    hexdump -C "${FIRMWARE_PATH}" | head -10 | tee -a "${LOG_FILE}" || true
    unblobber "${FIRMWARE_PATH}" "${LOG_DIR}"/firmware/firmware_bmc_decrypted
    detect_root_dir_helper "${LOG_DIR}"/firmware/firmware_bmc_decrypted
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "BMC encrypted" "${BMC_FILE_PATH_}" "${FIRMWARE_PATH}" "1" "NA" "NA"
  else
    print_output "[-] Extraction of BMC encrypted firmware file failed - Trying unblob as last resort"
    unblobber "${EXTRACTION_FILE_}" "${LOG_DIR}"/firmware/firmware_bmc_failed_extracted
  fi
}
