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

# Description:  Extracts gpg compressed (not encrypted) firmware images
#               This technique is used by Linksys/Belkin

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P17_gpg_decompress() {
  local NEG_LOG=0

  if [[ "${GPG_COMPRESS}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "GPG compressed firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_FILE="${LOG_DIR}"/firmware/firmware_gpg_dec.bin

    gpg_decompress_extractor "${FIRMWARE_PATH}" "${EXTRACTION_FILE}"

    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

gpg_decompress_extractor() {
  local GPG_FILE_PATH_="${1:-}"
  local EXTRACTION_FILE_="${2:-}"

  if ! [[ -f "${GPG_FILE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "GPG compressed firmware extractor"

  gpg --list-packets "${GPG_FILE_PATH_}" 2>/dev/null | tee -a "${LOG_FILE}"
  gpg --decrypt "${GPG_FILE_PATH_}" > "${EXTRACTION_FILE_}" || true

  print_ln
  if [[ -f "${EXTRACTION_FILE_}" ]]; then
    print_output "[+] Extracted GPG compressed firmware file to ${ORANGE}${EXTRACTION_FILE_}${NC}"
    export FIRMWARE_PATH="${EXTRACTION_FILE_}"
    backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
    print_ln
    print_output "[*] Firmware file details: ${ORANGE}$(file "${EXTRACTION_FILE_}")${NC}"
    unblobber "${EXTRACTION_FILE_}" "${LOG_DIR}"/firmware/firmware_gpg_extracted
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "GPG decompression" "${GPG_FILE_PATH_}" "${EXTRACTION_FILE_}" "1" "NA" "NA"
  else
    print_output "[-] Extraction of GPG compressed firmware file failed"
  fi
}
