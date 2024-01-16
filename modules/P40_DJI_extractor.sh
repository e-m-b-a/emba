#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description: Extracts DJI drone firmware with https://github.com/o-gs/dji-firmware-tools
#
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P40_DJI_extractor() {
  local NEG_LOG=0
  export DJI_DETECTED=0

  if ! [[ -d "${EXT_DIR}"/dji-firmware-tools/ ]]; then
    print_output "[-] WARNING: dji-firmware-tools not installed. Please update your installation."
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
    return
  fi

  module_log_init "${FUNCNAME[0]}"
  module_title "DJI drone firmware extraction module"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ "${RTOS}" -ne 1 ]]; then
    # if we have already found a Linux filesytem we do not need to walk through the rest of the module
    # this means that unblob was already able to extract a Linux filesystem
    print_output "[+] Found already a Linux filesytem - stopping DJI extraction module"
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
    # return
  fi

  if [[ "${DJI_XV4_DETECTED}" -eq 1 ]]; then
    sub_module_title "DJI xV4 firmware extraction"
    local FW_NAME_=""
    FW_NAME_="$(basename "${FIRMWARE_PATH_BAK}")"

    local EXTRACTION_DIR="${LOG_DIR}"/firmware/dji_xv4_extraction_"${FW_NAME_}"
    dji_xv4_firmware_extractor "${FIRMWARE_PATH_BAK}" "${EXTRACTION_DIR}"
  fi

  if [[ "${DJI_PRAK_DETECTED}" -eq 1 ]]; then
    if file "${FIRMWARE_PATH_BAK}" | grep -q "POSIX tar archive"; then
      sub_module_title "DJI IM*H firmware extraction"
      local FW_NAME_=""
      FW_NAME_="$(basename "${FIRMWARE_PATH}")"

      local EXTRACTION_DIR="${LOG_DIR}"/firmware/dji_prak_extraction_"${FW_NAME_}"
      dji_imah_firmware_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"
    fi
  fi

  if [[ -d "${EXTRACTION_DIR}" ]]; then
    FILES_DJI=$(find "${EXTRACTION_DIR}" -type f | wc -l)
    DIRS_DJI=$(find "${EXTRACTION_DIR}" -type d | wc -l)
    print_output "[*] Extracted ${ORANGE}${FILES_DJI}${NC} files and ${ORANGE}${DIRS_DJI}${NC} directories from DJI drone firmware image."
    NEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

dji_imah_firmware_extractor() {
  local FIRMWARE_PATH="${1:-}"
  local EXTRACTION_DIR="${2:-}"
  # local PRAK_KEYS_ARR=("UFIE-2021-06" "UFIE-2020-04" "UFIE-2019-11" "UFIE-2018-0" "UFIE-2018-01" "UFIE-2018-07" "PRAK-2018-01" "PRAK-2018-02" "PRAK-2020-01" "PRAK-2019-09" "PRAK-2017-12" "PRAK-2017-08" "PRAK-2017-01")

  local PRAK_KEYS_ARR=("UFIE-2021-06" "UFIE-2020-04" "UFIE-2019-11" "UFIE-2018-0" "UFIE-2018-01" "UFIE-2018-07")

  local FW_NAME_=""
  FW_NAME_="$(basename "${FIRMWARE_PATH}")"

  local UB_EXTRACTED_FILES_ARR=()
  local PRAK_FILE_ARR=()
  local PRAK_FILE=""
  local PRAK_KEY=""
  local FNAME=""
  local UNBLOBBED_1st
  local FILES_EXT_KEY_ARR=()
  local F_EXT_KEY=""

  # usually we have a tar file that we need to extract first:
  unblobber "${FIRMWARE_PATH_BAK}" "${EXTRACTION_DIR}" 0
  # just in case unblob was already able to extract our rootfs:
  detect_root_dir_helper "${EXTRACTION_DIR}"
  if [[ "${RTOS}" -ne 1 ]]; then
    # if we have already found a Linux filesytem we do not need to walk through the rest of the module
    # this means that unblob was already able to extract a Linux filesystem
    print_output "[+] Found some Linux filesytem - stopping extraction module"
    return
  fi

  mapfile -t PRAK_FILE_ARR < <(find "${EXTRACTION_DIR}" -type f -exec du -h {} + | sort -r -h | awk '{print $2}')

  for PRAK_FILE in "${PRAK_FILE_ARR[@]}"; do
    if ! grep -qoUaP "^\x49\x4d\x2a\x48" "${PRAK_FILE}"; then
      print_output "[-] No correct IM*H header found in ${ORANGE}${PRAK_FILE}${NC}:"
      hexdump -C "${PRAK_FILE}" | head | tee -a "${LOG_FILE}" || true
    fi

    for PRAK_KEY in "${PRAK_KEYS_ARR[@]}"; do
      FNAME=$(basename "${PRAK_FILE}")
      print_output "[*] Extracting ${ORANGE}${PRAK_FILE}${NC} with key ${ORANGE}${PRAK_KEY}${NC} ..." "" "${LOG_PATH_MODULE}/dji_prak_${FNAME}_${PRAK_KEY}_extracted.log"
      print_ln
      hexdump -C "${PRAK_FILE}" | head | tee -a "${LOG_FILE}" || true
      print_ln
      "${EXT_DIR}"/dji-firmware-tools/dji_imah_fwsig.py -u -vvv -m "${EXTRACTION_DIR}"/dji_prak_"${FNAME}"_"${PRAK_KEY}" -f -i "${PRAK_FILE}" -k "${PRAK_KEY}" | tee -a "${LOG_PATH_MODULE}"/dji_prak_"${FNAME}"_"${PRAK_KEY}"_extracted.log

      print_ln
      # print_output "[*] Unblob extraction of ${PRAK_FILE}:"
      unblobber "${PRAK_FILE}" "${EXTRACTION_DIR}"/dji_"${FNAME}"_"${PRAK_KEY}"_unblob

      print_output "[*] Extracted files:"
      mapfile -t UNBLOBBED_1st < <(find "${EXTRACTION_DIR}"/dji_"${FNAME}"_"${PRAK_KEY}"_unblob -type f || true)
      if [[ "${#UNBLOBBED_1st[@]}" -eq 0 ]]; then
        rm -r "${EXTRACTION_DIR}"/dji_"${FNAME}"_"${PRAK_KEY}"_unblob
      else
        find "${EXTRACTION_DIR}"/dji_prak_"${FNAME}"_"${PRAK_KEY}"_unblob -type f -ls | tee -a "${LOG_FILE}" || true
      fi

      file "${EXTRACTION_DIR}"/dji_prak_"${FNAME}"_"${PRAK_KEY}"* | tee -a "${LOG_FILE}"

      print_ln
      print_output "[*] Binwalk test:"
      binwalk "${EXTRACTION_DIR}"/dji_prak_"${FNAME}"_"${PRAK_KEY}"* | tee -a "${LOG_FILE}"

      # after the initial decryption with the dji firmware tools we walk through the results and extract
      # everything which is now decrypted with unblob
      mapfile -t FILES_EXT_KEY_ARR < <(find "${EXTRACTION_DIR}" -type f -name "dji_prak_${FNAME}_${PRAK_KEY}*" || true)

      for F_EXT_KEY in "${FILES_EXT_KEY_ARR[@]}"; do
        if [[ -f "${F_EXT_KEY}" ]]; then
          print_ln
          # print_output "[*] Unblob $(basename ${F_EXT_KEY}):"
          local OUTPUT_DIR_UNBLOB="${F_EXT_KEY}"_unblob
          unblobber "${F_EXT_KEY}" "${OUTPUT_DIR_UNBLOB}" 1
          mapfile -t UB_EXTRACTED_FILES_ARR < <(find "${OUTPUT_DIR_UNBLOB}" -type f -exec file {} \;)
          if [[ "${#UB_EXTRACTED_FILES_ARR[@]}" -gt 0 ]]; then
            print_ln
            print_output "[+] Extracted the following ${ORANGE}${#UB_EXTRACTED_FILES_ARR[@]}${GREEN} files from ${ORANGE}${F_EXT_KEY}${NC}:"
            for EFILE in "${UB_EXTRACTED_FILES_ARR[@]}"; do
              print_output "[+] DJI firmware file extracted: $(orange "$(print_path "${EFILE}")")"
            done
            export DJI_DETECTED=1
            return
          else
            rm -r "${OUTPUT_DIR_UNBLOB}" || true
          fi
          print_ln
        fi
      done
      print_ln

      detect_root_dir_helper "${LOG_DIR}"/firmware
      if [[ "${RTOS}" -ne 1 ]]; then
        # if we have already found a Linux filesytem we do not need to walk through the rest of the module
        # this means that unblob was already able to extract a Linux filesystem
        print_output "[+] Found some Linux filesytem - stopping extraction module"
        return
      fi
    done
  done
}

dji_xv4_firmware_extractor() {
  sub_module_title "xV4 DJI drone firmware extractor"
  # in my current tests this module is not needed as unblob is able to extract the firmware

  local FIRMWARE_PATH_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"
  local FIRMWARE_NAME_=""
  local XV4_EXTRACED_FILE_NAME=""
  local XV4_EXTRACTEDFILES_ARR=()
  local EXTRACTION_DIR_tmp=""

  if ! [[ -f "${FIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi
  if ! [[ -d "${EXTRACTION_DIR_}" ]]; then
    mkdir "${EXTRACTION_DIR_}"
  fi
  if ! [[ -d "${LOG_PATH_MODULE}" ]]; then
    mkdir "${LOG_PATH_MODULE}"
  fi

  FIRMWARE_NAME_="$(basename "${FIRMWARE_PATH_}")"

  python3 "${EXT_DIR}"/dji-firmware-tools/dji_xv4_fwcon.py -vvv -x -m "${EXTRACTION_DIR_}"/"${FIRMWARE_NAME_}" -p "${FIRMWARE_PATH_}" >> "${LOG_PATH_MODULE}"/dji_xv4_"${FIRMWARE_NAME_}".log || true

  if [[ -f "${LOG_PATH_MODULE}"/dji_xv4_"${FIRMWARE_NAME_}".log ]]; then
    if [[ -s "${LOG_PATH_MODULE}"/dji_xv4_"${FIRMWARE_NAME_}".log ]]; then
      tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/dji_xv4_"${FIRMWARE_NAME_}".log || true
    fi
  fi

  if ! [[ -d "${EXTRACTION_DIR_}" ]]; then
    print_output "[-] xV4 extraction mechanism failed for ${FIRMWARE_NAME_}:"
    print_ln
    hexdump -C "${FIRMWARE_PATH_}" | head || true
    return
  fi

  mapfile -t XV4_EXTRACTEDFILES_ARR < <(find "${EXTRACTION_DIR_}" -type f -name "*.bin" || true)

  for XV4_EXTRACED_FILE in "${XV4_EXTRACTEDFILES_ARR[@]}"; do
    XV4_EXTRACED_FILE_NAME=$(basename "${XV4_EXTRACED_FILE}")
    EXTRACTION_DIR_tmp="${EXTRACTION_DIR}"/dji_xv4_extraction_"${XV4_EXTRACED_FILE_NAME}"_unblob_extracted
    unblobber "${XV4_EXTRACED_FILE}" "${EXTRACTION_DIR_tmp}"
  done

  detect_root_dir_helper "${EXTRACTION_DIR}"
  if [[ "${RTOS}" -ne 1 ]]; then
    # if we have already found a Linux filesytem we do not need to walk through the rest of the module
    # this means that unblob was already able to extract a Linux filesystem
    print_output "[+] Found some Linux filesytem - stopping extraction module"
  fi
  print_bar
}

