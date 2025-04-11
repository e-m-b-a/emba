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

# Description: As binwalk has issues with UBI filesystems we are going to extract them here
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P15_ubi_extractor() {
  local lNEG_LOG=0

  if [[ "${UBI_IMAGE}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "UBI filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    lEXTRACTION_DIR="${LOG_DIR}/firmware/ubi_extracted"
    mkdir -p "${lEXTRACTION_DIR}" || true

    ubi_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
    fi
    lNEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

ubi_extractor() {
  local lUBI_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lUBI_FILE=""
  local lUBI_INFO=""
  local lUBI_1st_ROUND_ARR=()
  local lUBI_DATA=""
  local FILES_UBI_EXT=0
  local lFILES_UBI_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  if ! [[ -f "${lUBI_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "UBI filesystem extractor"

  print_output "[*] Extracts UBI firmware image ${ORANGE}${lUBI_PATH_}${NC} with ${ORANGE}ubireader_extract_images${NC}."
  print_output "[*] File details: ${ORANGE}$(file -b "${lUBI_PATH_}")${NC}"
  ubireader_extract_images -i -v -w -o "${lEXTRACTION_DIR_}"/ubi_images "${lUBI_PATH_}" | tee -a "${LOG_FILE}" || true
  FILES_UBI_EXT=$(find "${lEXTRACTION_DIR_}"/ubi_images -type f | wc -l)
  print_output "[*] Extracted ${ORANGE}${FILES_UBI_EXT}${NC} files from the firmware image via UBI extraction round 1."

  print_output "[*] Extracts UBI firmware image ${ORANGE}${lUBI_PATH_}${NC} with ${ORANGE}ubireader_extract_files${NC}."
  ubireader_extract_files -i -v -w -o "${lEXTRACTION_DIR_}"/ubi_files "${lUBI_PATH_}" | tee -a "${LOG_FILE}" || true
  FILES_UBI_EXT=$(find "${lEXTRACTION_DIR_}"/ubi_files -type f | wc -l)
  print_output "[*] Extracted ${ORANGE}${FILES_UBI_EXT}${NC} files from the firmware image via UBI extraction round 2."

  if [[ -d "${lEXTRACTION_DIR_}" ]]; then
    mapfile -t lUBI_1st_ROUND_ARR < <(find "${lEXTRACTION_DIR_}" -type f  -print0|xargs -r -0 -P 16 -I % sh -c 'file -b "%"' | grep "UBI image" || true)

    for lUBI_DATA in "${lUBI_1st_ROUND_ARR[@]}"; do
      lUBI_FILE=$(safe_echo "${lUBI_DATA}" | cut -d: -f1)
      lUBI_INFO=$(safe_echo "${lUBI_DATA}" | cut -d: -f2)
      if [[ "${lUBI_INFO}" == *"UBIfs image"* ]]; then
        sub_module_title "UBIfs deep extraction"
        print_output "[*] Extracts UBIfs firmware image ${ORANGE}${lUBI_PATH_}${NC} with ${ORANGE}ubireader_extract_files${NC}."
        print_output "[*] File details: ${ORANGE}$(file -b "${lUBI_FILE}")${NC}"
        ubireader_extract_files -l -i -w -v -o "${lEXTRACTION_DIR_}"/UBIfs_extracted "${lUBI_FILE}" | tee -a "${LOG_FILE}" || true
        FILES_UBI_EXT=$(find "${lEXTRACTION_DIR_}"/UBIfs_extracted -type f | wc -l)
        print_output "[*] Extracted ${ORANGE}${FILES_UBI_EXT}${NC} files from the firmware image via UBI deep extraction."
      fi
    done

    print_ln

    mapfile -t lFILES_UBI_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")
    print_output "[*] Extracted ${ORANGE}${#lFILES_UBI_ARR[@]}${NC} files from the UBI firmware image."
    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UBI_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_UBI_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "P15_ubi_extractor" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
    write_csv_log "UBI filesystem extractor" "${lUBI_PATH_}" "${lEXTRACTION_DIR_}" "${#lFILES_UBI_ARR[@]}" "NA"
  else
    print_output "[-] First round UBI extractor failed!"
  fi
}
