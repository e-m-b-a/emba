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

# Description:  Decrypts and extracts firmware images from Supermicro BMC
#               Using https://github.com/c0d3z3r0/smcbmc

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P18_BMC_decryptor() {
  local lNEG_LOG=0

  if [[ "${BMC_ENC_DETECTED:-0}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "BMC encrypted firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    local lEXTRACTION_FILE="${LOG_DIR}"/firmware/firmware_bmc_dec.bin

    bmc_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_FILE}"

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

bmc_extractor() {
  local lBMC_FILE_PATH_="${1:-}"
  local lEXTRACTION_FILE_="${2:-}"

  if ! [[ -f "${lBMC_FILE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "BMC encrypted firmware extractor"

  "${EXT_DIR}"/smcbmc/smcbmc.py "${lBMC_FILE_PATH_}" "${lEXTRACTION_FILE_}" || print_error "[-] BMC decryption failed for ${lBMC_FILE_PATH_}"

  print_ln
  backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
  if [[ -s "${lEXTRACTION_FILE_}" ]]; then
    export FIRMWARE_PATH="${lEXTRACTION_FILE_}"
    print_output "[+] Extracted BMC encrypted firmware file to ${ORANGE}${FIRMWARE_PATH}${NC}"
    print_ln
    print_output "[*] BMC Firmware file details: ${ORANGE}$(file "${FIRMWARE_PATH}")${NC}"
    hexdump -C "${FIRMWARE_PATH}" | head -10 | tee -a "${LOG_FILE}" || true
    local lEXTRACTION_PATH="${LOG_DIR}/firmware/firmware_bmc_decrypted"
    print_output "[*] Extraction of BMC decrypted firmware file with unblob"
  else
    print_output "[-] Extraction of BMC encrypted firmware file failed - Trying unblob as last resort"
    export FIRMWARE_PATH="${lEXTRACTION_FILE_}"
    local lEXTRACTION_PATH="${LOG_DIR}/firmware/firmware_bmc_failed_extracted"
  fi

  binwalker_matryoshka "${FIRMWARE_PATH}" "${lEXTRACTION_PATH}"
  mapfile -t lFILES_BMC_ARR < <(find "${lEXTRACTION_PATH}" -type f ! -name "*.raw")
  print_output "[*] Extracted ${ORANGE}${#lFILES_BMC_ARR[@]}${NC} files from BMC encrypted firmware."
  print_output "[*] Populating backend data for ${ORANGE}${#lFILES_BMC_ARR[@]}${NC} files ... could take some time" "no_log"

  for lBINARY in "${lFILES_BMC_ARR[@]}" ; do
    binary_architecture_threader "${lBINARY}" "P18_BMC_decryptor" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
  done
  wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

  detect_root_dir_helper "${lEXTRACTION_PATH}"
  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
  write_csv_log "BMC encrypted" "${lBMC_FILE_PATH_}" "${lEXTRACTION_PATH}" "${#lFILES_BMC_ARR[@]}" "NA"
}
