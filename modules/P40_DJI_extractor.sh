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
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description: Extracts DJI drone firmware with https://github.com/o-gs/dji-firmware-tools
#
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P40_DJI_extractor() {
  local NEG_LOG=0
  export DJI_DETECTED=0

  module_log_init "${FUNCNAME[0]}"

  if ! [[ -d "${EXT_DIR}"/dji-firmware-tools/ ]]; then
    print_output "[-] WARNING: dji-firmware-tools not installed. Please update your installation."
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
    return
  fi

  if [[ "${DJI_XV4_DETECTED}" -ne 1 ]] && [[ "${DJI_PRAK_DETECTED}" -ne 1 ]]; then
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
    return
  fi

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
    # the original firmware should be a tar archive
    # this tar archive is hopefully already extracted to FIRMWARE_PATH
    if file "${FIRMWARE_PATH_BAK}" | grep -q "POSIX tar archive"; then
      sub_module_title "DJI IM*H firmware extraction"
      local FW_NAME_=""
      FW_NAME_="$(basename "${FIRMWARE_PATH}")"

      local EXTRACTION_DIR="${LOG_DIR}"/firmware/dji_prak_extraction_"${FW_NAME_}"
      dji_imah_firmware_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"
    fi
  fi

  if [[ -d "${EXTRACTION_DIR:-}" ]]; then
    local FILES_DJI=0
    local DIRS_DJI=0

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
  if ! [[ -d "${EXTRACTION_DIR}" ]]; then
    mkdir "${EXTRACTION_DIR}"
  fi

  local FW_NAME_=""
  FW_NAME_="$(basename "${FIRMWARE_PATH}")"

  local UB_EXTRACTED_FILES_ARR=()
  local DJI_FILE_ARR=()
  local DJI_FILE=""
  local DJI_KEY=""
  local FNAME=""
  local EFILE=""
  local FILES_EXT_KEY_ARR=()
  local FILE_EXT_KEY=""
  local DJI_KEYS_ARR=()
  local DJI_ENC_KEY_IDENTIFIER=""

  # found key identifiers from dji-firmware-tools - probably we missed some keys
  # Todo: check and add missing keys
  local UFIE_KEYS_ARR=("UFIE-2021-06" "UFIE-2020-04" "UFIE-2019-11" "UFIE-2018-0" "UFIE-2018-01" "UFIE-2018-07")
  local PRAK_KEYS_ARR=("PRAK-2017-01" "PRAK-2017-08" "PRAK-2017-12" "PRAK-2018-01" "PRAK-2019-09" "PRAK-2020-01")
  local PUEK_KEYS_ARR=("PUEK-2017-01" "PUEK-2017-04" "PUEK-2017-07" "PUEK-2017-09" "PUEK-2017-11")
  local IAEK_KEYS_ARR=("IAEK-2017-01")
  local RREK_KEYS_ARR=("RREK-2017-01")
  local TBIE_KEYS_ARR=("TBIE-2018-01" "TBIE-2018-07" "TBIE-2019-11" "TBIE-2020-02" "TBIE-2020-04" "TBIE-2021-06")

  if [[ -f "${FIRMWARE_PATH}" ]]; then
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
    mapfile -t DJI_FILE_ARR < <(find "${EXTRACTION_DIR}" -type f -exec du -h {} + | sort -r -h | awk '{print $2}')
  else
    # if we have the tar file already extracted to FIRMWARE_PATH, we can use this directory
    mapfile -t DJI_FILE_ARR < <(find "${FIRMWARE_PATH}" -type f -exec du -h {} + | sort -r -h | awk '{print $2}')
  fi

  for DJI_FILE in "${DJI_FILE_ARR[@]}"; do
    # check for main IMaH header:
    if ! grep -boUaP "\x49\x4d\x2a\x48" "${DJI_FILE}" | grep -q "0:"; then
      print_output "[-] No correct IM*H header found in ${ORANGE}${DJI_FILE}${NC}:"
      hexdump -C "${DJI_FILE}" | head | tee -a "${LOG_FILE}" || true
    fi

    FNAME=$(basename "${DJI_FILE}")

    # extract the encryption key from file:
    # for header details see table 2 from https://arxiv.org/ftp/arxiv/papers/2312/2312.16818.pdf
    print_output "[*] Extract key identifier from firmware file ${ORANGE}$(basename "${DJI_FILE}")${NC}"
    print_ln
    dd if="${DJI_FILE}" of="${TMP_DIR}"/dji_enc_key.tmp skip=44 count=4 bs=1
    if [[ -f "${TMP_DIR}"/dji_enc_key.tmp ]] && [[ -s "${TMP_DIR}"/dji_enc_key.tmp ]]; then
      DJI_ENC_KEY_IDENTIFIER=$(cat "${TMP_DIR}"/dji_enc_key.tmp)
      # check if we have a key we can work with and set the correct key array for iteration
      if [[ "${DJI_ENC_KEY_IDENTIFIER}" == "UFIE" ]]; then
        DJI_KEYS_ARR=("${UFIE_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}UFIE${GREEN} from ${ORANGE}${FNAME}${NC}"
        print_ln
        hexdump -C "${DJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      elif [[ "${DJI_ENC_KEY_IDENTIFIER}" == "PRAK" ]]; then
        DJI_KEYS_ARR=("${PRAK_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}PRAK${GREEN} from ${ORANGE}${FNAME}${NC}"
        print_ln
        hexdump -C "${DJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      elif [[ "${DJI_ENC_KEY_IDENTIFIER}" == "PUEK" ]]; then
        DJI_KEYS_ARR=("${PUEK_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}PUEK${GREEN} from ${ORANGE}${FNAME}${NC}"
        print_ln
        hexdump -C "${DJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      elif [[ "${DJI_ENC_KEY_IDENTIFIER}" == "IAEK" ]]; then
        DJI_KEYS_ARR=("${IAEK_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}IAEK${GREEN} from ${ORANGE}${FNAME}${NC}"
        print_ln
        hexdump -C "${DJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      elif [[ "${DJI_ENC_KEY_IDENTIFIER}" == "TBIE" ]]; then
        DJI_KEYS_ARR=("${TBIE_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}TBIE${GREEN} from ${ORANGE}${FNAME}${NC}"
        print_ln
        hexdump -C "${DJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      elif [[ "${DJI_ENC_KEY_IDENTIFIER}" == "RREK" ]]; then
        DJI_KEYS_ARR=("${RREK_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}RREK${GREEN} from ${ORANGE}${FNAME}${NC}"
        print_ln
        hexdump -C "${DJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      else
        print_output "[-] No valid encryption key identified ${ORANGE}${DJI_ENC_KEY_IDENTIFIER}${NC} from ${ORANGE}${FNAME}${NC}"
        print_ln
        hexdump -C "${DJI_FILE}" | head | tee -a "${LOG_FILE}" || true
        continue
      fi
      print_ln
    else
      print_output "[-] No valid encryption key found from ${ORANGE}${FNAME}${NC}"
      print_ln
      hexdump -C "${DJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      continue
    fi

    for DJI_KEY in "${DJI_KEYS_ARR[@]}"; do
      sub_module_title "DJI IM*H extraction - file ${FNAME} with key ${DJI_KEY}"
      print_output "[*] Extracting ${ORANGE}${DJI_FILE}${NC} with key ${ORANGE}${DJI_KEY}${NC} ..." "" "${LOG_PATH_MODULE}/dji_prak_${FNAME}_${DJI_KEY}_extracted.log"
      print_ln
      hexdump -C "${DJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      print_ln
      "${EXT_DIR}"/dji-firmware-tools/dji_imah_fwsig.py -u -vvv -m "${EXTRACTION_DIR}"/dji_prak_"${FNAME}"_"${DJI_KEY}" -f -i "${DJI_FILE}" -k "${DJI_KEY}" | tee -a "${LOG_PATH_MODULE}"/dji_prak_"${FNAME}"_"${DJI_KEY}"_extracted.log || true
      mapfile -t FILES_EXT_KEY_ARR < <(find "${EXTRACTION_DIR}" -type f -wholename "*dji_prak_${FNAME}_${DJI_KEY}*" ! -size 0 || true)
      if [[ "${#FILES_EXT_KEY_ARR[@]}" -gt 0 ]]; then
        print_ln "no_log"
        print_output "[+] Decrypted firmware files:"
        find "${EXTRACTION_DIR}" -type f -wholename "*dji_prak_${FNAME}_${DJI_KEY}*" ! -size 0 -ls | tee -a "${LOG_FILE}" || true
      else
        # no files extracted -> try next key
        continue
      fi

      # after the initial decryption with the dji firmware tools we walk through the results and extract
      # everything which is already decrypted. For this extraction process unblob is used

      for FILE_EXT_KEY in "${FILES_EXT_KEY_ARR[@]}"; do
        if [[ -f "${FILE_EXT_KEY}" ]]; then
          if ! [[ -s "${FILE_EXT_KEY}" ]]; then
            # just in case we created an empty file
            continue
          fi
          print_ln
          local OUTPUT_DIR_UNBLOB="${FILE_EXT_KEY}"_unblob
          unblobber "${FILE_EXT_KEY}" "${OUTPUT_DIR_UNBLOB}" 0
          mapfile -t UB_EXTRACTED_FILES_ARR < <(find "${OUTPUT_DIR_UNBLOB}" -type f -exec file {} \;)
          if [[ "${#UB_EXTRACTED_FILES_ARR[@]}" -gt 0 ]]; then
            sub_module_title "Extraction results of $(basename "${FILE_EXT_KEY}")"
            print_output "[+] Extracted the following ${ORANGE}${#UB_EXTRACTED_FILES_ARR[@]}${GREEN} files from ${ORANGE}${FILE_EXT_KEY}${GREEN}:"
            print_ln
            for EFILE in "${UB_EXTRACTED_FILES_ARR[@]}"; do
              print_output "[+] DJI firmware file extracted: $(orange "$(print_path "${EFILE}")")"
            done
            # can we just stop now or are there firmware update files with more data in it?
            print_ln
            print_output "[*] Extracted ${ORANGE}${#UB_EXTRACTED_FILES_ARR[@]}${NC} files from ${ORANGE}$(basename "${FILE_EXT_KEY}")${NC}." "no_log"
            if [[ "${#UB_EXTRACTED_FILES_ARR[@]}" -gt 100 ]]; then
              print_output "[*] Stopping extraction process now." "no_log"
              export DJI_DETECTED=1
              return
            fi
            # Todo: if we have some further files with interesting data, we need to prcess them:
            # This could increase the extraction speed a lot!
            # continue 3
          else
            rm -r "${OUTPUT_DIR_UNBLOB}" || true
          fi
        fi
      done
      print_ln

      detect_root_dir_helper "${LOG_DIR}"/firmware
      if [[ "${RTOS}" -ne 1 ]]; then
        # if we have already found a Linux filesytem we do not need to walk through the rest of the module
        # this means that unblob was already able to extract a Linux filesystem
        print_output "[+] Found extracted Linux filesytem - stopping extraction module"
        return
      fi
    done
  done
}

dji_xv4_firmware_extractor() {
  sub_module_title "xV4 DJI drone firmware extractor"
  # in my current tests this module is not needed as unblob is able to extract the firmware
  # but I'm not sure ...

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
  else
    print_output "[-] xV4 extraction mechanism failed for ${FIRMWARE_NAME_}:"
    print_ln
    hexdump -C "${FIRMWARE_PATH_}" | head || true
    return
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

