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

# Description: As binwalk has issues with UBI filesystems we are going to extract them here
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P15_ubi_extractor() {
  local NEG_LOG=0

  if [[ "${UBI_IMAGE}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "UBI filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_DIR="${LOG_DIR}/firmware/ubi_extracted"
    mkdir -p "${EXTRACTION_DIR}" || true

    ubi_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"

    if [[ "${FILES_UBI_EXT}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
    fi
    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

ubi_extractor() {
  local UBI_PATH_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"
  local UBI_FILE=""
  local UBI_INFO=""
  local UBI_1st_ROUND=""
  local UBI_DATA=""
  local DIRS_UBI_EXT=0
  export FILES_UBI_EXT=0

  if ! [[ -f "${UBI_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "UBI filesystem extractor"

  print_output "[*] Extracts UBI firmware image ${ORANGE}${UBI_PATH_}${NC} with ${ORANGE}ubireader_extract_images${NC}."
  print_output "[*] File details: ${ORANGE}$(file "${UBI_PATH_}" | cut -d ':' -f2-)${NC}"
  ubireader_extract_images -i -v -w -o "${EXTRACTION_DIR_}"/ubi_images "${UBI_PATH_}" | tee -a "${LOG_FILE}" || true
  FILES_UBI_EXT=$(find "${EXTRACTION_DIR_}"/ubi_images -type f | wc -l)
  DIRS_UBI_EXT=$(find "${EXTRACTION_DIR_}"/ubi_images -type d | wc -l)
  print_output "[*] Extracted ${ORANGE}${FILES_UBI_EXT}${NC} files and ${ORANGE}${DIRS_UBI_EXT}${NC} directories from the firmware image via UBI extraction round 1."

  print_output "[*] Extracts UBI firmware image ${ORANGE}${UBI_PATH_}${NC} with ${ORANGE}ubireader_extract_files${NC}."
  ubireader_extract_files -i -v -w -o "${EXTRACTION_DIR_}"/ubi_files "${UBI_PATH_}" | tee -a "${LOG_FILE}" || true
  FILES_UBI_EXT=$(find "${EXTRACTION_DIR_}"/ubi_files -type f | wc -l)
  DIRS_UBI_EXT=$(find "${EXTRACTION_DIR_}"/ubi_files -type d | wc -l)
  print_output "[*] Extracted ${ORANGE}${FILES_UBI_EXT}${NC} files and ${ORANGE}${DIRS_UBI_EXT}${NC} directories from the firmware image via UBI extraction round 2."

  if [[ -d "${EXTRACTION_DIR_}" ]]; then
    mapfile -t UBI_1st_ROUND < <(find "${EXTRACTION_DIR_}" -type f -exec file {} \; | grep "UBI image" || true)

    for UBI_DATA in "${UBI_1st_ROUND[@]}"; do
      UBI_FILE=$(safe_echo "${UBI_DATA}" | cut -d: -f1)
      UBI_INFO=$(safe_echo "${UBI_DATA}" | cut -d: -f2)
      if [[ "${UBI_INFO}" == *"UBIfs image"* ]]; then
        sub_module_title "UBIfs deep extraction"
        print_output "[*] Extracts UBIfs firmware image ${ORANGE}${UBI_PATH_}${NC} with ${ORANGE}ubireader_extract_files${NC}."
        print_output "[*] File details: ${ORANGE}$(file "${UBI_FILE}" | cut -d ':' -f2-)${NC}"
        ubireader_extract_files -l -i -w -v -o "${EXTRACTION_DIR_}"/UBIfs_extracted "${UBI_FILE}" | tee -a "${LOG_FILE}" || true
        FILES_UBI_EXT=$(find "${EXTRACTION_DIR_}"/UBIfs_extracted -type f | wc -l)
        DIRS_UBI_EXT=$(find "${EXTRACTION_DIR_}"/UBIfs_extracted -type d | wc -l)
        print_output "[*] Extracted ${ORANGE}${FILES_UBI_EXT}${NC} files and ${ORANGE}${DIRS_UBI_EXT}${NC} directories from the firmware image via UBI deep extraction."
      fi
    done

    print_ln
    FILES_UBI_EXT=$(find "${EXTRACTION_DIR_}" -type f | wc -l)
    DIRS_UBI_EXT=$(find "${EXTRACTION_DIR_}" -type d | wc -l)
    print_output "[*] Extracted ${ORANGE}${FILES_UBI_EXT}${NC} files and ${ORANGE}${DIRS_UBI_EXT}${NC} directories from the firmware image."
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "UBI filesystem extractor" "${UBI_PATH_}" "${EXTRACTION_DIR_}" "${FILES_UBI_EXT}" "${DIRS_UBI_EXT}" "NA"
  else
    print_output "[-] First round UBI extractor failed!"
  fi
}
