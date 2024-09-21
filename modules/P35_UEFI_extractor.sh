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
      unblobber "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

      detect_root_dir_helper "${lEXTRACTION_DIR}"
      # detect_root_dir_helper sets RTOS to 1 if no Linux rootfs is found
      # we only further test for UEFI systems if we have not Linux rootfs detected
      if [[ -d "${lEXTRACTION_DIR}" && "${RTOS}" -eq 1 ]]; then
        local lFILES_UEFI_UNBLOB=0
        local lDIRS_UEFI_UNBLOB=0

        lFILES_UEFI_UNBLOB=$(find "${lEXTRACTION_DIR}" -type f | wc -l)
        lDIRS_UEFI_UNBLOB=$(find "${lEXTRACTION_DIR}" -type d | wc -l)
        print_output "[*] Extracted ${ORANGE}${lFILES_UEFI_UNBLOB}${NC} files and ${ORANGE}${lDIRS_UEFI_UNBLOB}${NC} directories from UEFI firmware image (with unblob)."

        # lets check for UEFI firmware
        local lTMP_UEFI_FILES_ARR=()
        local lUEFI_FILE=""
        mapfile -t lTMP_UEFI_FILES_ARR < <(find "${lEXTRACTION_DIR}" -xdev -type f)
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

      detect_root_dir_helper "${lEXTRACTION_DIR}"
      # detect_root_dir_helper sets RTOS to 1 if no Linux rootfs is found
      # we only further test for UEFI systems if we have not Linux rootfs detected
      if [[ -d "${lEXTRACTION_DIR}" && "${RTOS}" -eq 1 ]]; then
        local lFILES_UEFI_BINWALK=0
        local lDIRS_UEFI_BINWALK=0

        lFILES_UEFI_BINWALK=$(find "${lEXTRACTION_DIR}" -type f | wc -l)
        lDIRS_UEFI_BINWALK=$(find "${lEXTRACTION_DIR}" -type d | wc -l)
        print_output "[*] Extracted ${ORANGE}${lFILES_UEFI_BINWALK}${NC} files and ${ORANGE}${lDIRS_UEFI_BINWALK}${NC} directories from UEFI firmware image (with binwalk)."

        local lTMP_UEFI_FILES_ARR=()
        local lUEFI_FILE=""
        mapfile -t lTMP_UEFI_FILES_ARR < <(find "${LOG_DIR}"/firmware -xdev -type f)
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

    if [[ "${FILES_UEFI}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      lNEG_LOG=1
    fi
    if [[ "${UEFI_VERIFIED}" -eq 1 ]]; then
      lNEG_LOG=1
    fi
    if [[ "${RTOS}" -eq 0 ]]; then
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

  echo -ne '\n' | python3 "${EXT_DIR}"/BIOSUtilities/AMI_PFAT_Extract.py -o "${lEXTRACTION_DIR_}" "${lFIRMWARE_PATH_}" &> "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log || true

  if [[ -s "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log ]] && ! grep -q "Error: " "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log; then
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/uefi_ami_"${lFIRMWARE_NAME_}".log

    print_ln
    print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR_}${NC}) as base directory:"
    find "${lEXTRACTION_DIR_}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
    print_ln

    FILES_UEFI=$(find "${lEXTRACTION_DIR_}" -type f | wc -l)
    lDIRS_UEFI=$(find "${lEXTRACTION_DIR_}" -type d | wc -l)
    print_output "[*] Extracted ${ORANGE}${FILES_UEFI}${NC} files and ${ORANGE}${lDIRS_UEFI}${NC} directories from the firmware image."
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "UEFI AMI extractor" "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}" "${FILES_UEFI}" "${lDIRS_UEFI}" "NA"

    if [[ "${FILES_UEFI}" -gt 5 ]]; then
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
  export EFI_ARCH=""

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
  EFI_ARCH=$(find "${lEXTRACTION_DIR_}" -name 'info.txt' -exec grep 'Machine type:' {} \; | sed -E 's/Machine\ type\:\ //g' | uniq | head -n 1)
  # FILES_UEFI=$(grep -c "File" "${lUEFI_EXTRACT_REPORT_FILE}" || true)
  lDIRS_UEFI=$(find "${lEXTRACTION_DIR_}" -type d | wc -l)
  FILES_UEFI=$(find "${lEXTRACTION_DIR_}" -type f | wc -l)

  print_output "[*] Extracted ${ORANGE}${FILES_UEFI}${NC} files and ${ORANGE}${lDIRS_UEFI}${NC} directories from UEFI firmware image."
  print_output "[*] Found ${ORANGE}${lNVARS}${NC} NVARS and ${ORANGE}${lDRIVER_COUNT}${NC} drivers."
  if [[ -n "${EFI_ARCH}" ]]; then
    print_output "[*] Found ${ORANGE}${lPE32_IMAGE}${NC} PE32 images for architecture ${ORANGE}${EFI_ARCH}${NC} drivers."
    print_output "[+] Possible architecture details found (${ORANGE}UEFI Extractor${GREEN}): ${ORANGE}${EFI_ARCH}${NC}"
    backup_var "EFI_ARCH" "${EFI_ARCH}"
    if [[ "${FILES_UEFI}" -gt 0 ]] && [[ "${lDIRS_UEFI}" -gt 0 ]]; then
      # with UEFI_VERIFIED=1 we do not run deep-extraction
      export UEFI_VERIFIED=1
    fi
  fi

  print_ln

  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "UEFI architecture"
  write_csv_log "UEFITool extractor" "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}" "${FILES_UEFI}" "${lDIRS_UEFI}" "${EFI_ARCH}"
}
