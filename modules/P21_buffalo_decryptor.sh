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

# Description: Extracts encrypted firmware images from the vendor Buffalo
#              See https://modemizer.wordpress.com/2015/08/05/restoring-the-original-buffalo-firmware-on-the-wbmr-hp-g300h/
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P21_buffalo_decryptor() {
  local lNEG_LOG=0

  if [[ "${BUFFALO_ENC_DETECTED}" -ne 0 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Buffalo encrypted firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    local lEXTRACTION_FILE="${LOG_DIR}"/firmware/firmware_buffalo_dec.bin

    buffalo_enc_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_FILE}"

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

buffalo_enc_extractor() {
  local lBUFFALO_ENC_PATH_="${1:-}"
  local lEXTRACTION_FILE_="${2:-}"
  local lBUFFALO_FILE_CHECK=""

  local lFILES_BUFFALO_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  if ! [[ -f "${lBUFFALO_ENC_PATH_}" ]]; then
    print_output "[-] No file for decryption provided"
    return
  fi

  sub_module_title "Buffalo encrypted firmware extractor"

  hexdump -C "${lBUFFALO_ENC_PATH_}" | head | tee -a "${LOG_FILE}" || true
  print_ln

  local lBUFFALO_DECRYTED=0
  local lBUFFALO_ENC_PATH_STRIPPED=""
  lBUFFALO_ENC_PATH_STRIPPED="${LOG_DIR}/firmware/$(basename "${lBUFFALO_ENC_PATH_}").stripped"

  print_output "[*] Removing initial 208 bytes from header to prepare firmware for decryption"
  # on other tests we had 208 -> check again with firmware that failed here:
  dd bs=208 skip=1 if="${lBUFFALO_ENC_PATH_}" of="${lBUFFALO_ENC_PATH_STRIPPED}""_208" || true

  if [[ -f "${lBUFFALO_ENC_PATH_STRIPPED}""_208" ]]; then
    hexdump -C "${lBUFFALO_ENC_PATH_STRIPPED}""_208" | head | tee -a "${LOG_FILE}" || true
    print_ln
  fi

  print_output "[*] Removing initial 228 bytes from header to prepare firmware for decryption"
  dd bs=228 skip=1 if="${lBUFFALO_ENC_PATH_}" of="${lBUFFALO_ENC_PATH_STRIPPED}""_228" || true

  if [[ -f "${lBUFFALO_ENC_PATH_STRIPPED}""_228" ]]; then
    hexdump -C "${lBUFFALO_ENC_PATH_STRIPPED}""_228" | head | tee -a "${LOG_FILE}" || true
    print_ln
  fi

  print_output "[*] Decrypting firmware ... offset 208"
  "${EXT_DIR}"/buffalo-enc.elf -d -i "${lBUFFALO_ENC_PATH_STRIPPED}""_208" -o "${lEXTRACTION_FILE_}" || true
  if ! [[ -f "${lEXTRACTION_FILE_}" ]]; then
    print_output "[*] Decrypting firmware ... offset 228"
    "${EXT_DIR}"/buffalo-enc.elf -d -i "${lBUFFALO_ENC_PATH_STRIPPED}""_228" -o "${lEXTRACTION_FILE_}" || true
  fi
  hexdump -C "${lEXTRACTION_FILE_}" | head | tee -a "${LOG_FILE}" || true
  print_ln

  if [[ -f "${lEXTRACTION_FILE_}" ]]; then
    lBUFFALO_FILE_CHECK=$(file -b "${lEXTRACTION_FILE_}")
    if [[ "${lBUFFALO_FILE_CHECK}" =~ .*u-boot\ legacy\ uImage,\ .* ]]; then
      print_ln
      print_output "[+] Decrypted Buffalo firmware file to ${ORANGE}${lEXTRACTION_FILE_}${NC}"
      export FIRMWARE_PATH="${lEXTRACTION_FILE_}"
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      print_ln
      print_output "[*] Firmware file details: ${ORANGE}$(file "${lEXTRACTION_FILE_}")${NC}"

      binwalker_matryoshka "${lEXTRACTION_FILE_}" "${lEXTRACTION_FILE/\.bin}_binwalk_extracted"

      print_output "[*] Checking ${lEXTRACTION_FILE/\.bin}_binwalk_extracted for files and directories"
      if [[ -d "${lEXTRACTION_FILE/\.bin}_binwalk_extracted" ]]; then
        mapfile -t lFILES_BUFFALO_ARR < <(find "${lEXTRACTION_FILE/\.bin}_binwalk_extracted" -type f ! -name "*.raw")
        print_ln
        print_output "[*] Extracted ${ORANGE}${#lFILES_BUFFALO_ARR[@]}${NC} files from the firmware image."
        print_output "[*] Populating backend data for ${ORANGE}${#lFILES_BUFFALO_ARR[@]}${NC} files ... could take some time" "no_log"
      fi

      for lBINARY in "${lFILES_BUFFALO_ARR[@]}" ; do
        binary_architecture_threader "${lBINARY}" "P21_buffalo_decryptor" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
      done
      wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

      write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
      write_csv_log "Buffalo decryptor" "${lBUFFALO_ENC_PATH_}" "${lEXTRACTION_FILE_}" "${#lFILES_BUFFALO_ARR[@]}" "NA"
      lBUFFALO_DECRYTED=1
      if [[ -z "${FW_VENDOR:-}" ]]; then
        export FW_VENDOR="BUFFALO"
      fi
    fi
  fi

  if [[ "${lBUFFALO_DECRYTED}" -ne 1 ]]; then
    print_output "[-] Decryption of Buffalo firmware file failed"
  fi
}

