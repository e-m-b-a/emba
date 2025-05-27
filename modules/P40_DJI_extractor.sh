#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2025 Siemens Energy AG
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
  local lNEG_LOG=0
  export DJI_DETECTED=0


  if ! [[ -d "${EXT_DIR}"/dji-firmware-tools/ ]]; then
    print_output "[-] WARNING: dji-firmware-tools not installed. Please update your installation." "main"
    return
  fi

  if [[ "${DJI_XV4_DETECTED}" -ne 1 ]] && [[ "${DJI_PRAK_DETECTED}" -ne 1 ]]; then
    return
  fi

  module_log_init "${FUNCNAME[0]}"
  module_title "DJI drone firmware extraction module"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ "${RTOS}" -ne 1 ]]; then
    # if we have already found a Linux filesytem we do not need to walk through the rest of the module
    # this means that we were already able to extract a Linux filesystem
    print_output "[+] Found already a Linux filesytem - stopping DJI extraction module"
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    # return
  fi

  if [[ "${DJI_XV4_DETECTED}" -eq 1 ]]; then
    sub_module_title "DJI xV4 firmware extraction"
    local lFW_NAME_=""
    lFW_NAME_="$(basename "${FIRMWARE_PATH_BAK}")"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/dji_xv4_extraction_"${lFW_NAME_}"
    dji_xv4_firmware_extractor "${FIRMWARE_PATH_BAK}" "${lEXTRACTION_DIR}"
  fi

  if [[ "${DJI_PRAK_DETECTED}" -eq 1 ]]; then
    # the original firmware should be a tar archive
    # this tar archive is hopefully already extracted to FIRMWARE_PATH
    if file "${FIRMWARE_PATH_BAK}" | grep -q "POSIX tar archive"; then
      sub_module_title "DJI IM*H firmware extraction"
      local lFW_NAME_=""
      # shellcheck disable=SC2153
      lFW_NAME_="$(basename "${FIRMWARE_PATH}")"

      local lEXTRACTION_DIR="${LOG_DIR}"/firmware/dji_prak_extraction_"${lFW_NAME_}"
      dji_imah_firmware_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"
    fi
  fi

  if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
    local lFILES_DJI=0
    lFILES_DJI=$(grep -c "^${FUNCNAME[0]};" "${P99_CSV_LOG}")
    print_output "[*] Extracted ${ORANGE}${lFILES_DJI}${NC} files from DJI drone firmware image."
    lNEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

dji_imah_firmware_extractor() {
  local lFIRMWARE_PATH="${1:-}"
  local lEXTRACTION_DIR="${2:-}"
  if ! [[ -d "${lEXTRACTION_DIR}" ]]; then
    mkdir "${lEXTRACTION_DIR}"
  fi

  local lFW_NAME_=""
  lFW_NAME_="$(basename "${lFIRMWARE_PATH}")"

  local lUB_EXTRACTED_FILES_ARR=()
  local lDJI_FILE_ARR=()
  local lDJI_FILE=""
  local lDJI_KEY=""
  local lFNAME=""
  local lFILES_EXT_KEY_ARR=()
  local lFILE_EXT_KEY=""
  local lDJI_KEYS_ARR=()
  local lDJI_ENC_KEY_IDENTIFIER=""

  # found key identifiers from dji-firmware-tools - probably we missed some keys
  # Todo: check and add missing keys
  local lUFIE_KEYS_ARR=("UFIE-2021-06" "UFIE-2020-04" "UFIE-2019-11" "UFIE-2018-0" "UFIE-2018-01" "UFIE-2018-07")
  local lPRAK_KEYS_ARR=("PRAK-2017-01" "PRAK-2017-08" "PRAK-2017-12" "PRAK-2018-01" "PRAK-2019-09" "PRAK-2020-01")
  local lPUEK_KEYS_ARR=("PUEK-2017-01" "PUEK-2017-04" "PUEK-2017-07" "PUEK-2017-09" "PUEK-2017-11")
  local lIAEK_KEYS_ARR=("IAEK-2017-01")
  local lRREK_KEYS_ARR=("RREK-2017-01")
  local lTBIE_KEYS_ARR=("TBIE-2018-01" "TBIE-2018-07" "TBIE-2019-11" "TBIE-2020-02" "TBIE-2020-04" "TBIE-2021-06")

  if [[ -f "${lFIRMWARE_PATH}" ]]; then
    # usually we have a tar file that we need to extract first:
    unblobber "${FIRMWARE_PATH_BAK}" "${lEXTRACTION_DIR}" 0
    mapfile -t lFILES_UNBLOB_ARR < <(find "${lEXTRACTION_DIR}" -type f ! -name "*.raw")
    for lBINARY in "${lFILES_UNBLOB_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"
    # just in case unblob was already able to extract our rootfs:
    detect_root_dir_helper "${lEXTRACTION_DIR}"
    if [[ "${RTOS}" -ne 1 ]]; then
    # if we have already found a Linux filesytem we do not need to walk through the rest of the module
      # this means that unblob was already able to extract a Linux filesystem
      print_output "[+] Found some Linux filesytem - stopping extraction module"
      return
    fi
    mapfile -t lDJI_FILE_ARR < <(find "${lEXTRACTION_DIR}" -type f ! -name "*.raw" -exec du -h {} + | sort -r -h | awk '{print $2}')
  else
    # if we have the tar file already extracted to lFIRMWARE_PATH, we can use this directory
    mapfile -t lDJI_FILE_ARR < <(find "${lFIRMWARE_PATH}" -type f ! -name "*.raw" -exec du -h {} + | sort -r -h | awk '{print $2}')
  fi

  for lDJI_FILE in "${lDJI_FILE_ARR[@]}"; do
    # check for main IMaH header:
    if ! grep -boUaP "\x49\x4d\x2a\x48" "${lDJI_FILE}" | grep -q "0:"; then
      print_output "[-] No correct IM*H header found in ${ORANGE}${lDJI_FILE}${NC}:"
      hexdump -C "${lDJI_FILE}" | head | tee -a "${LOG_FILE}" || true
    fi

    lFNAME=$(basename "${lDJI_FILE}")

    # extract the encryption key from file:
    # for header details see table 2 from https://arxiv.org/ftp/arxiv/papers/2312/2312.16818.pdf
    print_output "[*] Extract key identifier from firmware file ${ORANGE}${lFNAME}${NC}"
    print_ln
    dd if="${lDJI_FILE}" of="${TMP_DIR}"/dji_enc_key.tmp skip=44 count=4 bs=1
    if [[ -f "${TMP_DIR}"/dji_enc_key.tmp ]] && [[ -s "${TMP_DIR}"/dji_enc_key.tmp ]]; then
      lDJI_ENC_KEY_IDENTIFIER=$(cat "${TMP_DIR}"/dji_enc_key.tmp)
      # check if we have a key we can work with and set the correct key array for iteration
      if [[ "${lDJI_ENC_KEY_IDENTIFIER}" == "UFIE" ]]; then
        lDJI_KEYS_ARR=("${lUFIE_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}UFIE${GREEN} from ${ORANGE}${lFNAME}${NC}"
        print_ln
        hexdump -C "${lDJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      elif [[ "${lDJI_ENC_KEY_IDENTIFIER}" == "PRAK" ]]; then
        lDJI_KEYS_ARR=("${lPRAK_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}PRAK${GREEN} from ${ORANGE}${lFNAME}${NC}"
        print_ln
        hexdump -C "${lDJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      elif [[ "${lDJI_ENC_KEY_IDENTIFIER}" == "PUEK" ]]; then
        lDJI_KEYS_ARR=("${lPUEK_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}PUEK${GREEN} from ${ORANGE}${lFNAME}${NC}"
        print_ln
        hexdump -C "${lDJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      elif [[ "${lDJI_ENC_KEY_IDENTIFIER}" == "IAEK" ]]; then
        lDJI_KEYS_ARR=("${lIAEK_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}IAEK${GREEN} from ${ORANGE}${lFNAME}${NC}"
        print_ln
        hexdump -C "${lDJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      elif [[ "${lDJI_ENC_KEY_IDENTIFIER}" == "TBIE" ]]; then
        lDJI_KEYS_ARR=("${lTBIE_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}TBIE${GREEN} from ${ORANGE}${lFNAME}${NC}"
        print_ln
        hexdump -C "${lDJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      elif [[ "${lDJI_ENC_KEY_IDENTIFIER}" == "RREK" ]]; then
        lDJI_KEYS_ARR=("${lRREK_KEYS_ARR[@]}")
        print_output "[+] Identified encryption key mechanism ${ORANGE}RREK${GREEN} from ${ORANGE}${lFNAME}${NC}"
        print_ln
        hexdump -C "${lDJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      else
        print_output "[-] No valid encryption key identified ${ORANGE}${lDJI_ENC_KEY_IDENTIFIER}${NC} from ${ORANGE}${lFNAME}${NC}"
        print_ln
        hexdump -C "${lDJI_FILE}" | head | tee -a "${LOG_FILE}" || true
        continue
      fi
      print_ln
    else
      print_output "[-] No valid encryption key found from ${ORANGE}${lFNAME}${NC}"
      print_ln
      hexdump -C "${lDJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      continue
    fi

    for lDJI_KEY in "${lDJI_KEYS_ARR[@]}"; do
      sub_module_title "DJI IM*H extraction - file ${lFNAME} with key ${lDJI_KEY}"
      print_output "[*] Extracting ${ORANGE}${lDJI_FILE}${NC} with key ${ORANGE}${lDJI_KEY}${NC} ..." "" "${LOG_PATH_MODULE}/dji_prak_${lFNAME}_${lDJI_KEY}_extracted.log"
      print_ln
      hexdump -C "${lDJI_FILE}" | head | tee -a "${LOG_FILE}" || true
      print_ln
      "${EXT_DIR}"/dji-firmware-tools/dji_imah_fwsig.py -u -vvv -m "${lEXTRACTION_DIR}"/dji_prak_"${lFNAME}"_"${lDJI_KEY}" -f -i "${lDJI_FILE}" -k "${lDJI_KEY}" | tee -a "${LOG_PATH_MODULE}"/dji_prak_"${lFNAME}"_"${lDJI_KEY}"_extracted.log || true
      mapfile -t lFILES_EXT_KEY_ARR < <(find "${lEXTRACTION_DIR}" -type f -wholename "*dji_prak_${lFNAME}_${lDJI_KEY}*" ! -size 0 || true)
      if [[ "${#lFILES_EXT_KEY_ARR[@]}" -gt 0 ]]; then
        print_ln "no_log"
        mapfile -t lFILES_DJI_ARR < <(find "${lEXTRACTION_DIR}" -type f -wholename "*dji_prak_${lFNAME}_${lDJI_KEY}*")
        print_output "[*] Extracted ${ORANGE}${#lFILES_DJI_ARR[@]}${NC} files."
        print_output "[*] Populating backend data for ${ORANGE}${#lFILES_DJI_ARR[@]}${NC} files ... could take some time" "no_log"

        print_ln "no_log"
        print_output "[+] Decrypted firmware files:"
        for lBINARY in "${lFILES_DJI_ARR[@]}" ; do
          # shellcheck disable=SC2010
          ls -1lh "${lBINARY}" | grep -v "total [0-9]" | tee -a "${LOG_FILE}" || true
          binary_architecture_threader "${lBINARY}" "P40_DJI_extractor" &
          local lTMP_PID="$!"
          store_kill_pids "${lTMP_PID}"
          lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
        done
        wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"
      else
        # no files extracted -> try next key
        continue
      fi

      # after the initial decryption with the dji firmware tools we walk through the results and extract
      # everything which is already decrypted. For this extraction process unblob is used

      for lFILE_EXT_KEY in "${lFILES_EXT_KEY_ARR[@]}"; do
        if [[ -f "${lFILE_EXT_KEY}" ]]; then
          if ! [[ -s "${lFILE_EXT_KEY}" ]]; then
            # just in case we created an empty file
            continue
          fi
          print_ln
          local lOUTPUT_DIR="${lFILE_EXT_KEY}"_unblob
          local lBINARY=""
          local lWAIT_PIDS_P99_ARR=()
          local lUB_EXTRACTED_FILES_ARR=()
          unblobber "${lFILE_EXT_KEY}" "${lOUTPUT_DIR}" 0

          # mapfile -t lUB_EXTRACTED_FILES_ARR < <(find "${lOUTPUT_DIR_UNBLOB}" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'file "%"')
          mapfile -t lUB_EXTRACTED_FILES_ARR < <(find "${lOUTPUT_DIR}" -type f ! -name "*.raw")

          if [[ "${#lUB_EXTRACTED_FILES_ARR[@]}" -gt 0 ]]; then
            # can we just stop now or are there firmware update files with more data in it?
            print_ln
            print_output "[*] Extracted ${ORANGE}${#lUB_EXTRACTED_FILES_ARR[@]}${NC} files from ${ORANGE}$(basename "${lFILE_EXT_KEY}")${NC}." "no_log"
            print_output "[*] Populating backend data for ${ORANGE}${#lUB_EXTRACTED_FILES_ARR[@]}${NC} files ... could take some time" "no_log"

            for lBINARY in "${lUB_EXTRACTED_FILES_ARR[@]}" ; do
              binary_architecture_threader "${lBINARY}" "P40_DJI_extractor" &
              local lTMP_PID="$!"
              store_kill_pids "${lTMP_PID}"
              lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
            done
            wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

            if [[ "${#lUB_EXTRACTED_FILES_ARR[@]}" -gt 100 ]]; then
              print_output "[*] Stopping extraction process now." "no_log"
              export DJI_DETECTED=1
              return
            fi
            # Todo: if we have some further files with interesting data, we need to prcess them:
            # This could increase the extraction speed a lot!
            # continue 3
          else
            rm -r "${lOUTPUT_DIR}" || true
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

  local lFIRMWARE_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lFIRMWARE_NAME_=""
  local lXV4_EXTRACED_FILE_NAME=""
  local lXV4_EXTRACTEDFILES_ARR=()
  local lXV4_EXTRACED_FILE=""
  local lEXTRACTION_DIR_tmp=""
  local lFILES_DJI_XV4_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  if ! [[ -f "${lFIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi
  if ! [[ -d "${lEXTRACTION_DIR_}" ]]; then
    mkdir "${lEXTRACTION_DIR_}"
  fi
  if ! [[ -d "${LOG_PATH_MODULE}" ]]; then
    mkdir "${LOG_PATH_MODULE}"
  fi

  lFIRMWARE_NAME_="$(basename "${lFIRMWARE_PATH_}")"

  python3 "${EXT_DIR}"/dji-firmware-tools/dji_xv4_fwcon.py -vvv -x -m "${lEXTRACTION_DIR_}"/"${lFIRMWARE_NAME_}" -p "${lFIRMWARE_PATH_}" >> "${LOG_PATH_MODULE}"/dji_xv4_"${lFIRMWARE_NAME_}".log || true

  if [[ -f "${LOG_PATH_MODULE}"/dji_xv4_"${lFIRMWARE_NAME_}".log ]]; then
    if [[ -s "${LOG_PATH_MODULE}"/dji_xv4_"${lFIRMWARE_NAME_}".log ]]; then
      tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/dji_xv4_"${lFIRMWARE_NAME_}".log || true
    fi
  else
    print_output "[-] xV4 extraction mechanism failed for ${lFIRMWARE_NAME_}:"
    print_ln
    hexdump -C "${lFIRMWARE_PATH_}" | head || true
    return
  fi

  if ! [[ -d "${lEXTRACTION_DIR_}" ]]; then
    print_output "[-] xV4 extraction mechanism failed for ${lFIRMWARE_NAME_}:"
    print_ln
    hexdump -C "${lFIRMWARE_PATH_}" | head || true
    return
  fi

  mapfile -t lXV4_EXTRACTEDFILES_ARR < <(find "${lEXTRACTION_DIR_}" -type f -name "*.bin" || true)

  for lXV4_EXTRACED_FILE in "${lXV4_EXTRACTEDFILES_ARR[@]}"; do
    lXV4_EXTRACED_FILE_NAME=$(basename "${lXV4_EXTRACED_FILE}")
    lEXTRACTION_DIR_tmp="${lEXTRACTION_DIR}"/dji_xv4_extraction_"${lXV4_EXTRACED_FILE_NAME}"_unblob_extracted
    unblobber "${lXV4_EXTRACED_FILE}" "${lEXTRACTION_DIR_tmp}" 0
  done

  mapfile -t lFILES_DJI_XV4_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")
  print_output "[*] Extracted ${ORANGE}${#lFILES_DJI_XV4_ARR[@]}${NC} files from ${ORANGE}${lFIRMWARE_NAME_}${NC}." "no_log"
  print_output "[*] Populating backend data for ${ORANGE}${#lFILES_DJI_XV4_ARR[@]}${NC} files ... could take some time" "no_log"

  for lBINARY in "${lFILES_DJI_XV4_ARR[@]}" ; do
    binary_architecture_threader "${lBINARY}" "P40_DJI_extractor" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
  done
  wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

  detect_root_dir_helper "${lEXTRACTION_DIR_}"
  if [[ "${RTOS}" -ne 1 ]]; then
    # if we have already found a Linux filesytem we do not need to walk through the rest of the module
    # this means that unblob was already able to extract a Linux filesystem
    print_output "[+] Found some Linux filesytem - stopping extraction module"
  fi
  print_bar
}

