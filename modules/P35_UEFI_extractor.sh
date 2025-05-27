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
# Credits:   Binarly for support

# Description: Extracts UEFI images with BIOSUtilities - https://github.com/platomav/BIOSUtilities/tree/refactor
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P35_UEFI_extractor() {
  local lNEG_LOG=0

  if [[ "${UEFI_DETECTED}" -eq 1 && "${RTOS}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "UEFI extraction module"
    pre_module_reporter "${FUNCNAME[0]}"
    export FILES_UEFI=0

    if [[ -d "${FIRMWARE_PATH}" ]]; then
      # as we currently handle only firmware files in the UEFI extraction module
      # we need to work with the original firmware file - if this is also a directory
      # or we already have a linux filesytem we can exit now
      detect_root_dir_helper "${FIRMWARE_PATH}"

      FIRMWARE_PATH="${FIRMWARE_PATH_BAK}"
      if [[ -d "${FIRMWARE_PATH}" || "${RTOS}" -ne 1 ]]; then
        # we exit the module now
        module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
        return
      fi
    fi

    local lFW_NAME_=""
    lFW_NAME_="$(basename "${FIRMWARE_PATH}")"

    uefi_firmware_parser "${FIRMWARE_PATH}"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_"${lFW_NAME_}"
    uefi_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"
    if [[ "${UEFI_AMI_CAPSULE}" -gt 0 ]]; then
      lEXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_ami_capsule_"${lFW_NAME_}"
      ami_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"
    fi

    if [[ "${UEFI_VERIFIED}" -ne 1 ]]; then
      # do a second round with unblob
      lEXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_"${lFW_NAME_}"_unblob_extracted
      unblobber "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}" 0

      mapfile -t lFILES_UEFI_ARR < <(find "${lEXTRACTION_DIR}" -type f ! -name "*.raw")

      print_output "[*] Extracted ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files from UEFI firmware image in Unblob mode."
      print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files ... could take some time" "no_log"

      for lBINARY in "${lFILES_UEFI_ARR[@]}" ; do
        binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
      done
      wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

      detect_root_dir_helper "${lEXTRACTION_DIR}"
      # detect_root_dir_helper sets RTOS to 1 if no Linux rootfs is found
      # we only further test for UEFI systems if we have not Linux rootfs detected
      if [[ -d "${lEXTRACTION_DIR}" && "${RTOS}" -eq 1 ]]; then
        # lets check for UEFI firmware
        local lTMP_UEFI_FILES_ARR=()
        local lUEFI_FILE=""
        mapfile -t lTMP_UEFI_FILES_ARR < <(grep "^${FUNCNAME[0]};" "${P99_CSV_LOG}" | cut -d ';' -f2 | grep "${lEXTRACTION_DIR}" | sort -u)
        for lUEFI_FILE in "${lTMP_UEFI_FILES_ARR[@]}"; do
          uefi_firmware_parser "${lUEFI_FILE}"
          if [[ "${UEFI_VERIFIED}" -eq 1 ]]; then
            lNEG_LOG=1
            break
          fi
        done
        if [[ "${UEFI_VERIFIED}" -ne 1 && "${RTOS}" -eq 1 ]]; then
          # if we have no UEFI firmware and no Linux filesystem, we remove this file junks now
          rm -rf "${lEXTRACTION_DIR}" || true
        fi
      fi
    fi

    if [[ "${UEFI_VERIFIED}" -ne 1 && "${RTOS}" -eq 1 ]]; then
      # do an additional backup round with binwalk
      # e.g. https://ftp.hp.com/pub/softpaq/sp148001-148500/sp148108.exe
      lEXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_"${lFW_NAME_}"_binwalk_extracted
      binwalker_matryoshka "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

      mapfile -t lFILES_UEFI_ARR < <(find "${lEXTRACTION_DIR}" -type f ! -name "*.raw")

      print_output "[*] Extracted ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files from UEFI firmware image in Binwalk mode."
      print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files ... could take some time" "no_log"

      for lBINARY in "${lFILES_UEFI_ARR[@]}" ; do
        binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
      done
      wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

      detect_root_dir_helper "${lEXTRACTION_DIR}"
      # detect_root_dir_helper sets RTOS to 1 if no Linux rootfs is found
      # we only further test for UEFI systems if we have not Linux rootfs detected
      if [[ -d "${lEXTRACTION_DIR}" && "${RTOS}" -eq 1 ]]; then
        local lTMP_UEFI_FILES_ARR=()
        local lUEFI_FILE=""
        mapfile -t lTMP_UEFI_FILES_ARR < <(grep "^${FUNCNAME[0]};" "${P99_CSV_LOG}" | cut -d ';' -f2 | grep "${lEXTRACTION_DIR}" | sort -u)
        for lUEFI_FILE in "${lTMP_UEFI_FILES_ARR[@]}"; do
          uefi_firmware_parser "${lUEFI_FILE}"
          if [[ "${UEFI_VERIFIED}" -eq 1 ]]; then
            lNEG_LOG=1
            break
          fi
        done
        if [[ "${UEFI_VERIFIED}" -ne 1 && "${RTOS}" -eq 1 ]]; then
          # if we have no UEFI firmware and no Linux filesystem, we remove this file junks now
          rm -rf "${lEXTRACTION_DIR}" || true
        fi
      fi
    fi

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      lNEG_LOG=1
    fi
    if [[ "${UEFI_VERIFIED}" -eq 1 || "${RTOS}" -eq 0 ]]; then
      lNEG_LOG=1
    fi

    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

uefi_firmware_parser() {
  sub_module_title "UEFI firmware-parser analysis"
  local lFIRMWARE_PATH_="${1:-}"
  local lFW_NAME_=""
  lFW_NAME_="$(basename "${lFIRMWARE_PATH_}")"

  uefi-firmware-parser -b "${lFIRMWARE_PATH_}" > "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${lFW_NAME_}".txt

  if [[ -s "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${lFW_NAME_}".txt ]]; then
    print_ln
    print_output "[*] UEFI firmware parser results for ${lFW_NAME_}." "" "${LOG_PATH_MODULE}/uefi-firmware-parser_${lFW_NAME_}.txt"
    cat "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${lFW_NAME_}".txt
    print_ln

    if [[ "$(grep -c "Found volume magic at \|Firmware Volume:" "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${lFW_NAME_}".txt)" -gt 1 ]]; then
      # with UEFI_VERIFIED=1 we do not further run deep-extraction
      export UEFI_VERIFIED=1
    fi
  else
    print_output "[-] No results from UEFI firmware-parser for ${ORANGE}${lFIRMWARE_PATH_}${NC}." "no_log"
  fi
}

ami_extractor() {
  sub_module_title "AMI capsule UEFI extractor"

  local lFIRMWARE_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lDIRS_UEFI=0
  local lFIRMWARE_NAME_=""

  if ! [[ -f "${lFIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  lFIRMWARE_NAME_="$(basename "${lFIRMWARE_PATH_}")"

  echo -ne '\n' | python3 "${EXT_DIR}"/BIOSUtilities/biosutilities/ami_pfat_extract.py -o "${lEXTRACTION_DIR_}" "${lFIRMWARE_PATH_}" &> "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log || true

  if [[ -s "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log ]] && ! grep -q "Error: " "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log; then
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log

    print_ln
    print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR_}${NC}) as base directory:"
    find "${lEXTRACTION_DIR_}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
    print_ln

    mapfile -t lFILES_UEFI_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")
    print_output "[*] Extracted ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files from the firmware image."
    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_UEFI_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "P35_UEFI_extractor" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
    write_csv_log "UEFI AMI extractor" "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}" "${FILES_UEFI}" "NA"

    if [[ "${#lFILES_UEFI_ARR[@]}" -gt 5 ]]; then
      # with UEFI_VERIFIED=1 we do not run deep-extraction
      export UEFI_VERIFIED=1
    fi
  else
    print_output "[-] No results from AMI capsule UEFI extractor"
  fi
  print_ln
}

uefi_extractor() {
  sub_module_title "UEFITool extractor"

  local lFIRMWARE_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"

  local lFIRMWARE_NAME_=""
  local lUEFI_EXTRACT_REPORT_FILE=""

  local lUEFI_EXTRACT_BIN="${EXT_DIR}""/UEFITool/UEFIExtract"
  local lDIRS_UEFI=0
  local lNVARS=0
  local lPE32_IMAGE=0
  local lDRIVER_COUNT=0
  local lEFI_ARCH=""

  if ! [[ -f "${lFIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  lFIRMWARE_NAME_="$(basename "${lFIRMWARE_PATH_}")"
  if ! [[ -d "${lEXTRACTION_DIR_}" ]]; then
    mkdir -p "${lEXTRACTION_DIR_}"
  fi
  cp "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}"
  "${lUEFI_EXTRACT_BIN}" "${lEXTRACTION_DIR_}"/firmware all &> "${LOG_PATH_MODULE}"/uefi_extractor_"${lFIRMWARE_NAME_}".log || print_error "[-] UEFI firmware extraction failed"

  lUEFI_EXTRACT_REPORT_FILE="${lEXTRACTION_DIR_}"/firmware.report.txt
  if [[ -f "${lUEFI_EXTRACT_REPORT_FILE}" ]]; then
    mv "${lUEFI_EXTRACT_REPORT_FILE}" "${LOG_PATH_MODULE}"
    lUEFI_EXTRACT_REPORT_FILE="${LOG_PATH_MODULE}"/firmware.report.txt
  else
    print_output "[-] UEFI firmware extraction failed" "no_log"
    return
  fi

  if [[ -f "${lEXTRACTION_DIR_}"/firmware ]]; then
    rm "${lEXTRACTION_DIR_}"/firmware
  fi

  if [[ -f "${LOG_PATH_MODULE}"/uefi_extractor_"${lFIRMWARE_NAME_}".log ]]; then
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/uefi_extractor_"${lFIRMWARE_NAME_}".log
    if grep -q "parse: not a single Volume Top File is found, the image may be corrupted" "${LOG_PATH_MODULE}"/uefi_extractor_"${lFIRMWARE_NAME_}".log; then
      print_output "[-] No results from UEFITool UEFI Extractor"
      return
    fi
  fi

  print_ln
  print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR_}/firmware.dump${NC}) as base directory:"
  find "${lEXTRACTION_DIR_}"/firmware.dump -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
  print_ln

  lNVARS=$(grep -c "NVAR entry" "${lUEFI_EXTRACT_REPORT_FILE}" || true)
  lPE32_IMAGE=$(grep -c "PE32 image" "${lUEFI_EXTRACT_REPORT_FILE}" || true)
  lDRIVER_COUNT=$(grep -c "DXE driver" "${lUEFI_EXTRACT_REPORT_FILE}" || true)

  mapfile -t lFILES_UEFI_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")

  print_output "[*] Extracted ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files from UEFI firmware image."
  print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UEFI_ARR[@]}${NC} files ... could take some time" "no_log"

  for lBINARY in "${lFILES_UEFI_ARR[@]}" ; do
    binary_architecture_threader "${lBINARY}" "P35_UEFI_extractor" &
    local lTMP_PID="$!"
    lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
  done
  wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

  lEFI_ARCH=$(find "${lEXTRACTION_DIR_}" -name "info.txt" -exec grep "Machine type" {} \; | sort -u | sed -E 's/Machine\ type\:\ //g' | head -n 1)

  print_output "[*] Found ${ORANGE}${lNVARS}${NC} NVARS and ${ORANGE}${lDRIVER_COUNT}${NC} drivers."
  if [[ -n "${lEFI_ARCH}" ]]; then
    print_output "[*] Found ${ORANGE}${lPE32_IMAGE}${NC} PE32 images for architecture ${ORANGE}${lEFI_ARCH}${NC} drivers."
    print_output "[+] Possible architecture details found (${ORANGE}UEFI Extractor${GREEN}): ${ORANGE}${lEFI_ARCH}${NC}"
    backup_var "EFI_ARCH" "${lEFI_ARCH}"
    if [[ "${FILES_UEFI}" -gt 0 ]] && [[ "${lDIRS_UEFI}" -gt 0 ]]; then
      # with UEFI_VERIFIED=1 we do not run deep-extraction
      export UEFI_VERIFIED=1
    fi
  fi

  print_ln

  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "UEFI architecture"
  write_csv_log "UEFITool extractor" "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}" "${FILES_UEFI}" "${lDIRS_UEFI}" "${lEFI_ARCH}"
}
