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

# Description: Extracts Android OTA update files - see https://github.com/e-m-b-a/emba/issues/233
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P25_android_ota() {
  local NEG_LOG=0
  if [[ "${ANDROID_OTA}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Android OTA payload.bin extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_DIR="${LOG_DIR}"/firmware/android_ota/

    android_ota_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"

    if [[ "${FILES_OTA}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
    fi
    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

android_ota_extractor() {
  local OTA_INIT_PATH_="${1}"
  local EXTRACTION_DIR_="${2}"
  local DIRS_OTA=0
  export FILES_OTA=0

  if ! [[ -f "${OTA_INIT_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "Android OTA extractor"

  hexdump -C "${OTA_INIT_PATH_}" | head | tee -a "${LOG_FILE}" || true

  if [[ -d "${EXT_DIR}"/payload_dumper ]]; then
    print_ln
    print_output "[*] Extracting Android OTA payload.bin file ..."
    print_ln

    python3 "${EXT_DIR}"/payload_dumper/payload_dumper.py --out "${EXTRACTION_DIR_}" "${OTA_INIT_PATH_}" | tee -a "${LOG_FILE}"

    FILES_OTA=$(find "${EXTRACTION_DIR_}" -type f | wc -l)
    DIRS_OTA=$(find "${EXTRACTION_DIR_}" -type d | wc -l)
    print_output "[*] Extracted ${ORANGE}${FILES_OTA}${NC} files and ${ORANGE}${DIRS_OTA}${NC} directories from the firmware image."
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "Android OTA extractor" "${OTA_INIT_PATH_}" "${EXTRACTION_DIR_}" "${FILES_OTA}" "${DIRS_OTA}" "via payload_dumper.py"
  else
    print_output "[-] Android OTA payload.bin extractor not found - check your installation"
  fi
}
