#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner
# Credits:   Binarly for support

# Description: Extracts UEFI images with BIOSUtilities - https://github.com/platomav/BIOSUtilities/tree/refactor
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P35_UEFI_extractor() {
  local NEG_LOG=0

  if [[ "${UEFI_DETECTED}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "UEFI extraction module"
    pre_module_reporter "${FUNCNAME[0]}"
    export FILES_UEFI=0


    uefi_firmware_parser "${FIRMWARE_PATH}"

    EXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction
    uefi_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"
    if [[ "${UEFI_AMI_CAPSULE}" -gt 0 ]]; then
      EXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_ami_capsule
      ami_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"
    fi

    if [[ "${UEFI_VERIFIED}" -ne 1 ]]; then
      # do a second round with unblob
      unblobber "${FIRMWARE_PATH_}" "${EXTRACTION_DIR_}_unblob_extracted"

      if [[ -d "${EXTRACTION_DIR_}_unblob_extracted" ]]; then
        FILES_UEFI_UNBLOB=$(find "${EXTRACTION_DIR_}_unblob_extracted" -type f | wc -l)
        DIRS_UEFI_UNBLOB=$(find "${EXTRACTION_DIR_}_unblob_extracted" -type d | wc -l)
        print_output "[*] Extracted ${ORANGE}${FILES_UEFI_UNBLOB}${NC} files and ${ORANGE}${DIRS_UEFI_UNBLOB}${NC} directories from UEFI firmware image (with unblob)."
      fi
    fi

    if [[ "${FILES_UEFI}" -gt 0 ]]; then
      MD5_DONE_DEEP+=( "$(md5sum "${FIRMWARE_PATH}" | awk '{print $1}')" )
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      NEG_LOG=1
    fi

    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

uefi_firmware_parser() {
  sub_module_title "UEFI firmware-parser analysis"
  local FIRMWARE_PATH_="${1:-}"

  uefi-firmware-parser -b "${FIRMWARE_PATH_}" > "${LOG_PATH_MODULE}"/uefi-firmware-parser.txt

  if [[ -s "${LOG_PATH_MODULE}"/uefi-firmware-parser.txt ]]; then
    print_ln
    print_output "[*] UEFI firmware parser results." "" "${LOG_PATH_MODULE}/uefi-firmware-parser.txt"
    cat "${LOG_PATH_MODULE}"/uefi-firmware-parser.txt
    print_ln

    if [[ "$(grep -c "Found volume magic at \|Firmware Volume:" "${LOG_PATH_MODULE}"/uefi-firmware-parser.txt)" -gt 1 ]]; then
      # with UEFI_VERIFIED=1 we do not run deep-extraction
      export UEFI_VERIFIED=1
    fi
  else
    print_output "[-] No results from UEFI firmware-parser"
  fi
}

ami_extractor() {
  sub_module_title "AMI capsule UEFI extractor"

  local FIRMWARE_PATH_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"
  local DIRS_UEFI=0
  local FIRMWARE_NAME_=""

  if ! [[ -f "${FIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  FIRMWARE_NAME_="$(basename "${FIRMWARE_PATH_}")"

  echo -ne '\n' | python3 "${EXT_DIR}"/BIOSUtilities/AMI_PFAT_Extract.py -o "${EXTRACTION_DIR_}" "${FIRMWARE_PATH_}" &> "${LOG_PATH_MODULE}"/uefi_ami_"${FIRMWARE_NAME_}".log || true

  if [[ -s "${LOG_PATH_MODULE}"/uefi_ami_"${FIRMWARE_NAME_}".log ]] && ! grep -q "Error: " "${LOG_PATH_MODULE}"/uefi_ami_"${FIRMWARE_NAME_}".log; then
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/uefi_ami_"${FIRMWARE_NAME_}".log

    print_ln
    print_output "[*] Using the following firmware directory (${ORANGE}${EXTRACTION_DIR_}${NC}) as base directory:"
    find "${EXTRACTION_DIR_}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
    print_ln

    FILES_UEFI=$(find "${EXTRACTION_DIR_}" -type f | wc -l)
    DIRS_UEFI=$(find "${EXTRACTION_DIR_}" -type d | wc -l)
    print_output "[*] Extracted ${ORANGE}${FILES_UEFI}${NC} files and ${ORANGE}${DIRS_UEFI}${NC} directories from the firmware image."
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "UEFI AMI extractor" "${FIRMWARE_PATH_}" "${EXTRACTION_DIR_}" "${FILES_UEFI}" "${DIRS_UEFI}" "NA"

    if [[ "${FILES_UEFI}" -gt 5 ]]; then
      # with UEFI_VERIFIED=1 we do not run deep-extraction
      export UEFI_VERIFIED=1
    fi
  else
    print_output "[-] No results from AMI capsule UEFI extractor"
  fi
  print_ln
}

uefi_extractor(){
  sub_module_title "UEFITool extractor"

  local FIRMWARE_PATH_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"

  local FIRMWARE_NAME_=""
  local UEFI_EXTRACT_REPORT_FILE=""

  local UEFI_EXTRACT_BIN="${EXT_DIR}""/UEFITool/UEFIExtract"
  local DIRS_UEFI=0
  local NVARS=0
  local PE32_IMAGE=0
  export EFI_ARCH=""

  if ! [[ -f "${FIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  FIRMWARE_NAME_="$(basename "${FIRMWARE_PATH_}")"
  if ! [[ -d "${EXTRACTION_DIR_}" ]]; then
    mkdir -p "${EXTRACTION_DIR_}"
  fi
  cp "${FIRMWARE_PATH_}" "${EXTRACTION_DIR_}"
  "${UEFI_EXTRACT_BIN}" "${EXTRACTION_DIR_}"/firmware all &> "${LOG_PATH_MODULE}"/uefi_extractor_"${FIRMWARE_NAME_}".log

  UEFI_EXTRACT_REPORT_FILE="${EXTRACTION_DIR_}"/firmware.report.txt
  mv "${UEFI_EXTRACT_REPORT_FILE}" "${LOG_PATH_MODULE}"
  UEFI_EXTRACT_REPORT_FILE="${LOG_PATH_MODULE}"/firmware.report.txt
  if [[ -f "${EXTRACTION_DIR_}"/firmware ]]; then
    rm "${EXTRACTION_DIR_}"/firmware
  fi

  if [[ -f "${LOG_PATH_MODULE}"/uefi_extractor_"${FIRMWARE_NAME_}".log ]]; then
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/uefi_extractor_"${FIRMWARE_NAME_}".log
  fi

  print_ln
  print_output "[*] Using the following firmware directory (${ORANGE}${EXTRACTION_DIR_}/firmware.dump${NC}) as base directory:"
  find "${EXTRACTION_DIR_}"/firmware.dump -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
  print_ln

  NVARS=$(grep -c "NVAR entry" "${UEFI_EXTRACT_REPORT_FILE}" || true)
  PE32_IMAGE=$(grep -c "PE32 image" "${UEFI_EXTRACT_REPORT_FILE}" || true)
  DRIVER_COUNT=$(grep -c "DXE driver" "${UEFI_EXTRACT_REPORT_FILE}" || true)
  EFI_ARCH=$(find "${EXTRACTION_DIR_}" -name 'info.txt' -exec grep 'Machine type:' {} \; | sed -E 's/Machine\ type\:\ //g' | uniq | head -n 1)
  FILES_UEFI=$(grep -c "File" "${UEFI_EXTRACT_REPORT_FILE}" || true)
  DIRS_UEFI=$(find "${EXTRACTION_DIR_}" -type d | wc -l)

  print_output "[*] Extracted ${ORANGE}${FILES_UEFI}${NC} files and ${ORANGE}${DIRS_UEFI}${NC} directories from UEFI firmware image."
  print_output "[*] Found ${ORANGE}${NVARS}${NC} NVARS and ${ORANGE}${DRIVER_COUNT}${NC} drivers."
  if [[ -n "${EFI_ARCH}" ]]; then
    print_output "[*] Found ${ORANGE}${PE32_IMAGE}${NC} PE32 images for architecture ${ORANGE}${EFI_ARCH}${NC} drivers."
    print_output "[+] Possible architecture details found (${ORANGE}UEFI Extractor${GREEN}): ${ORANGE}${EFI_ARCH}${NC}"
    backup_var "EFI_ARCH" "${EFI_ARCH}"
    if [[ "${FILES_UEFI}" -gt 0 ]] && [[ "${DIRS_UEFI}" -gt 0 ]]; then
      # with UEFI_VERIFIED=1 we do not run deep-extraction
      export UEFI_VERIFIED=1
    fi
  fi

  print_ln

  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "UEFI architecture"
  write_csv_log "UEFITool extractor" "${FIRMWARE_PATH_}" "${EXTRACTION_DIR_}" "${FILES_UEFI}" "${DIRS_UEFI}" "${EFI_ARCH}"
}
