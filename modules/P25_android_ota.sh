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

# Description: Extracts Android OTA update files - see https://github.com/e-m-b-a/emba/issues/233
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P25_android_ota() {
  local lNEG_LOG=0
  if [[ "${ANDROID_OTA}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Android OTA payload.bin extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/android_ota/

    android_ota_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

android_ota_extractor() {
  local lOTA_INIT_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"

  local lFILES_OTA_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  if ! [[ -f "${lOTA_INIT_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "Android OTA extractor"

  hexdump -C "${lOTA_INIT_PATH_}" | head | tee -a "${LOG_FILE}" || true

  print_ln
  print_output "[*] Extracting Android OTA payload.bin file ..."
  print_ln

  python3 "${EXT_DIR}"/payload_dumper/payload_dumper.py --out "${lEXTRACTION_DIR_}" "${lOTA_INIT_PATH_}" | tee -a "${LOG_FILE}"

  mapfile -t lFILES_OTA_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")

  print_output "[*] Extracted ${ORANGE}${#lFILES_OTA_ARR[@]}${NC} files from the firmware image."
  print_output "[*] Populating backend data for ${ORANGE}${#lFILES_OTA_ARR[@]}${NC} files ... could take some time" "no_log"

  for lBINARY in "${lFILES_OTA_ARR[@]}" ; do
    binary_architecture_threader "${lBINARY}" "P25_android_ota" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
  done
  wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
  write_csv_log "Android OTA extractor" "${lOTA_INIT_PATH_}" "${lEXTRACTION_DIR_}" "${#lFILES_OTA_ARR[@]}" "via payload_dumper.py"
}
