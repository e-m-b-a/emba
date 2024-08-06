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
  local NEG_LOG=0

  if [[ "${UEFI_DETECTED}" -eq 1 && "${RTOS}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "UEFI extraction module"
    pre_module_reporter "${FUNCNAME[0]}"
    export FILES_UEFI=0

    if [[ -d "${FIRMWARE_PATH}" ]]; then
      # as we currently handle only firmware files in the UEFI extraction module
      # we need to work with the original firmware file - if this is also a directory
      # we exit the module now
      FIRMWARE_PATH="${FIRMWARE_PATH_BAK}"
      if [[ -d "${FIRMWARE_PATH}" ]]; then
        module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
        return
      fi
    fi

    local FW_NAME_=""
    FW_NAME_="$(basename "${FIRMWARE_PATH}")"

    uefi_firmware_parser "${FIRMWARE_PATH}"

    EXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_"${FW_NAME_}"
    uefi_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"
    if [[ "${UEFI_AMI_CAPSULE}" -gt 0 ]]; then
      EXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_ami_capsule_"${FW_NAME_}"
      ami_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"
    fi

    if [[ "${UEFI_VERIFIED}" -ne 1 ]]; then
      # do a second round with unblob
      EXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_"${FW_NAME_}"_unblob_extracted
      unblobber "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"

      detect_root_dir_helper "${EXTRACTION_DIR}"
      # detect_root_dir_helper sets RTOS to 1 if no Linux rootfs is found
      # we only further test for UEFI systems if we have not Linux rootfs detected
      if [[ -d "${EXTRACTION_DIR}" && "${RTOS}" -eq 1 ]]; then
        local FILES_UEFI_UNBLOB=0
        local DIRS_UEFI_UNBLOB=0

        FILES_UEFI_UNBLOB=$(find "${EXTRACTION_DIR}" -type f | wc -l)
        DIRS_UEFI_UNBLOB=$(find "${EXTRACTION_DIR}" -type d | wc -l)
        print_output "[*] Extracted ${ORANGE}${FILES_UEFI_UNBLOB}${NC} files and ${ORANGE}${DIRS_UEFI_UNBLOB}${NC} directories from UEFI firmware image (with unblob)."

        # lets check for UEFI firmware
        local TMP_UEFI_FILES=()
        local UEFI_FILE=""
        mapfile -t TMP_UEFI_FILES < <(find "${EXTRACTION_DIR}" -xdev -type f)
        for UEFI_FILE in "${TMP_UEFI_FILES[@]}"; do
          uefi_firmware_parser "${UEFI_FILE}"
          if [[ "${UEFI_VERIFIED}" -eq 1 ]]; then
            NEG_LOG=1
            break
          fi
        done
        if [[ "${UEFI_VERIFIED}" -ne 1 && "${RTOS}" -eq 1 ]]; then
          # if we have no UEFI firmware and no Linux filesystem, we remove this file junks now
          rm -rf "${EXTRACTION_DIR}" || true
        fi
      fi
    fi

    if [[ "${UEFI_VERIFIED}" -ne 1 && "${RTOS}" -eq 1 ]]; then
      # do an additional backup round with binwalk
      # e.g. https://ftp.hp.com/pub/softpaq/sp148001-148500/sp148108.exe
      EXTRACTION_DIR="${LOG_DIR}"/firmware/uefi_extraction_"${FW_NAME_}"_binwalk_extracted
      binwalker_matryoshka "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"

      detect_root_dir_helper "${EXTRACTION_DIR}"
      # detect_root_dir_helper sets RTOS to 1 if no Linux rootfs is found
      # we only further test for UEFI systems if we have not Linux rootfs detected
      if [[ -d "${EXTRACTION_DIR}" && "${RTOS}" -eq 1 ]]; then
        local FILES_UEFI_BINWALK=0
        local DIRS_UEFI_BINWALK=0

        FILES_UEFI_BINWALK=$(find "${EXTRACTION_DIR}" -type f | wc -l)
        DIRS_UEFI_BINWALK=$(find "${EXTRACTION_DIR}" -type d | wc -l)
        print_output "[*] Extracted ${ORANGE}${FILES_UEFI_BINWALK}${NC} files and ${ORANGE}${DIRS_UEFI_BINWALK}${NC} directories from UEFI firmware image (with binwalk)."

        local TMP_UEFI_FILES=()
        local UEFI_FILE=""
        mapfile -t TMP_UEFI_FILES < <(find "${LOG_DIR}"/firmware -xdev -type f)
        for UEFI_FILE in "${TMP_UEFI_FILES[@]}"; do
          uefi_firmware_parser "${UEFI_FILE}"
          if [[ "${UEFI_VERIFIED}" -eq 1 ]]; then
            NEG_LOG=1
            break
          fi
        done
        if [[ "${UEFI_VERIFIED}" -ne 1 && "${RTOS}" -eq 1 ]]; then
          # if we have no UEFI firmware and no Linux filesystem, we remove this file junks now
          rm -rf "${EXTRACTION_DIR}" || true
        fi
      fi
    fi

    if [[ "${FILES_UEFI}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      NEG_LOG=1
    fi
    if [[ "${UEFI_VERIFIED}" -eq 1 ]]; then
      NEG_LOG=1
    fi
    if [[ "${RTOS}" -eq 0 ]]; then
      NEG_LOG=1
    fi

    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

uefi_firmware_parser() {
  sub_module_title "UEFI firmware-parser analysis"
  local FIRMWARE_PATH_="${1:-}"
  local FW_NAME_=""
  FW_NAME_="$(basename "${FIRMWARE_PATH_}")"

  uefi-firmware-parser -b "${FIRMWARE_PATH_}" > "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${FW_NAME_}".txt

  if [[ -s "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${FW_NAME_}".txt ]]; then
    print_ln
    print_output "[*] UEFI firmware parser results for ${FW_NAME_}." "" "${LOG_PATH_MODULE}/uefi-firmware-parser_${FW_NAME_}.txt"
    cat "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${FW_NAME_}".txt
    print_ln

    if [[ "$(grep -c "Found volume magic at \|Firmware Volume:" "${LOG_PATH_MODULE}"/uefi-firmware-parser_"${FW_NAME_}".txt)" -gt 1 ]]; then
      # with UEFI_VERIFIED=1 we do not further run deep-extraction
      export UEFI_VERIFIED=1
    fi
  else
    print_output "[-] No results from UEFI firmware-parser for ${ORANGE}${FIRMWARE_PATH_}${NC}." "no_log"
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

uefi_extractor() {
  sub_module_title "UEFITool extractor"

  local FIRMWARE_PATH_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"

  local FIRMWARE_NAME_=""
  local UEFI_EXTRACT_REPORT_FILE=""

  local UEFI_EXTRACT_BIN="${EXT_DIR}""/UEFITool/UEFIExtract"
  local DIRS_UEFI=0
  local NVARS=0
  local PE32_IMAGE=0
  local DRIVER_COUNT=0
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
  "${UEFI_EXTRACT_BIN}" "${EXTRACTION_DIR_}"/firmware all &> "${LOG_PATH_MODULE}"/uefi_extractor_"${FIRMWARE_NAME_}".log || print_error "[-] UEFI firmware extraction failed"

  UEFI_EXTRACT_REPORT_FILE="${EXTRACTION_DIR_}"/firmware.report.txt
  if [[ -f "${UEFI_EXTRACT_REPORT_FILE}" ]]; then
    mv "${UEFI_EXTRACT_REPORT_FILE}" "${LOG_PATH_MODULE}"
    UEFI_EXTRACT_REPORT_FILE="${LOG_PATH_MODULE}"/firmware.report.txt
  else
    print_output "[-] UEFI firmware extraction failed" "no_log"
    return
  fi

  if [[ -f "${EXTRACTION_DIR_}"/firmware ]]; then
    rm "${EXTRACTION_DIR_}"/firmware
  fi

  if [[ -f "${LOG_PATH_MODULE}"/uefi_extractor_"${FIRMWARE_NAME_}".log ]]; then
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/uefi_extractor_"${FIRMWARE_NAME_}".log
    if grep -q "parse: not a single Volume Top File is found, the image may be corrupted" "${LOG_PATH_MODULE}"/uefi_extractor_"${FIRMWARE_NAME_}".log; then
      print_output "[-] No results from UEFITool UEFI Extractor"
      return
    fi
  fi

  print_ln
  print_output "[*] Using the following firmware directory (${ORANGE}${EXTRACTION_DIR_}/firmware.dump${NC}) as base directory:"
  find "${EXTRACTION_DIR_}"/firmware.dump -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
  print_ln

  NVARS=$(grep -c "NVAR entry" "${UEFI_EXTRACT_REPORT_FILE}" || true)
  PE32_IMAGE=$(grep -c "PE32 image" "${UEFI_EXTRACT_REPORT_FILE}" || true)
  DRIVER_COUNT=$(grep -c "DXE driver" "${UEFI_EXTRACT_REPORT_FILE}" || true)
  EFI_ARCH=$(find "${EXTRACTION_DIR_}" -name 'info.txt' -exec grep 'Machine type:' {} \; | sed -E 's/Machine\ type\:\ //g' | uniq | head -n 1)
  # FILES_UEFI=$(grep -c "File" "${UEFI_EXTRACT_REPORT_FILE}" || true)
  DIRS_UEFI=$(find "${EXTRACTION_DIR_}" -type d | wc -l)
  FILES_UEFI=$(find "${EXTRACTION_DIR_}" -type f | wc -l)

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
