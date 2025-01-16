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

# Description:  Extracts gpg compressed (not encrypted) firmware images
#               This technique is used by Linksys/Belkin

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P17_gpg_decompress() {
  local lNEG_LOG=0

  if [[ "${GPG_COMPRESS}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "GPG compressed firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    local lEXTRACTION_FILE="${LOG_DIR}"/firmware/firmware_gpg_dec.bin

    gpg_decompress_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_FILE}"

    lNEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

gpg_decompress_extractor() {
  local lGPG_FILE_PATH_="${1:-}"
  local lEXTRACTION_FILE_="${2:-}"

  if ! [[ -f "${lGPG_FILE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "GPG compressed firmware extractor"

  gpg --list-packets "${lGPG_FILE_PATH_}" 2>/dev/null | tee -a "${LOG_FILE}"
  gpg --decrypt "${lGPG_FILE_PATH_}" > "${lEXTRACTION_FILE_}" || true

  print_ln
  if [[ -f "${lEXTRACTION_FILE_}" ]]; then
    print_output "[+] Extracted GPG compressed firmware file to ${ORANGE}${lEXTRACTION_FILE_}${NC}"
    export FIRMWARE_PATH="${lEXTRACTION_FILE_}"
    backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
    print_ln
    print_output "[*] Firmware file details: ${ORANGE}$(file "${lEXTRACTION_FILE_}")${NC}"
    unblobber "${lEXTRACTION_FILE_}" "${LOG_DIR}"/firmware/firmware_gpg_extracted
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "GPG decompression" "${lGPG_FILE_PATH_}" "${lEXTRACTION_FILE_}" "1" "NA" "NA"
  else
    print_output "[-] Extraction of GPG compressed firmware file failed"
  fi
}
