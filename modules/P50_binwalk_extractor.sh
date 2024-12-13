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

# Description:  Extracts firmware with binwalk to the module log directory.
#               This module is a fallback module for the very rare case that our extraction process was failing
#               e.g. in cases like this https://github.com/onekey-sec/sasquatch/issues/19

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# This module extracts the firmware and is blocking modules that needs executed before the following modules can run
export PRE_THREAD_ENA=0

P50_binwalk_extractor() {
  module_log_init "${FUNCNAME[0]}"

  # if we have a verified UEFI firmware we do not need to do anything here
  # if we have already found a linux (RTOS==0) we do not need to do anything here
  # if [[ "${UEFI_VERIFIED}" -eq 1 ]] || [[ "${RTOS}" -eq 0 ]] || [[ "${DJI_DETECTED}" -eq 1 ]] || [[ "${WINDOWS_EXE}" -eq 1 ]] || [[ "${DISABLE_DEEP}" -eq 1 ]]; then
  #  module_end_log "${FUNCNAME[0]}" 0
  #  return
  # fi

  # shellcheck disable=SC2153
  if [[ -d "${FIRMWARE_PATH}" ]] && [[ "${RTOS}" -eq 1 ]]; then
    detect_root_dir_helper "${FIRMWARE_PATH}"
  fi

  # we do not rely on any EMBA extraction mechanism -> we use the original firmware file
  local lFW_PATH_BINWALK="${FIRMWARE_PATH_BAK}"

  if [[ -d "${lFW_PATH_BINWALK}" ]]; then
    print_output "[-] Binwalk module only deals with firmware files - directories should be already handled via deep extractor"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lFILES_EXT_BW=0
  local lUNIQUE_FILES_BW=0
  local lDIRS_EXT_BW=0
  local lBINS_BW=0

  module_title "Binwalk binary firmware extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  export LINUX_PATH_COUNTER_BINWALK=0
  export OUTPUT_DIR_BINWALK="${LOG_DIR}"/firmware/binwalk_extracted

  if [[ -f "${lFW_PATH_BINWALK}" ]]; then
    binwalker_matryoshka "${lFW_PATH_BINWALK}" "${OUTPUT_DIR_BINWALK}"
  fi

  if [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
    linux_basic_identification_binwalk "${OUTPUT_DIR_BINWALK}"
    print_ln
    if [[ -d "${OUTPUT_DIR_BINWALK}" ]]; then
      lFILES_EXT_BW=$(find "${OUTPUT_DIR_BINWALK}" -xdev -type f | wc -l )
      lUNIQUE_FILES_BW=$(find "${OUTPUT_DIR_BINWALK}" "${EXCL_FIND[@]}" -xdev -type f -exec md5sum {} \; | sort -u -k1,1 | cut -d\  -f3 | wc -l )
      lDIRS_EXT_BW=$(find "${OUTPUT_DIR_BINWALK}" -xdev -type d | wc -l )
      # lBINS_BW=$(find "${OUTPUT_DIR_BINWALK}" "${EXCL_FIND[@]}" -xdev -type f -exec file {} \; | grep -c "ELF" || true)
    fi

    if [[ "${lBINS_BW}" -gt 0 ]] || [[ "${lFILES_EXT_BW}" -gt 0 ]]; then
      sub_module_title "Firmware extraction details"
      print_output "[*] ${ORANGE}Binwalk${NC} results:"
      print_output "[*] Found ${ORANGE}${lFILES_EXT_BW}${NC} files (${ORANGE}${lUNIQUE_FILES_BW}${NC} unique files) and ${ORANGE}${lDIRS_EXT_BW}${NC} directories at all."
      # print_output "[*] Found ${ORANGE}${lBINS_BW}${NC} binaries."
      print_output "[*] Additionally the Linux path counter is ${ORANGE}${LINUX_PATH_COUNTER_BINWALK}${NC}."
      print_ln
      tree -sh "${OUTPUT_DIR_BINWALK}" | tee -a "${LOG_FILE}"
      print_ln
    fi
  fi

  detect_root_dir_helper "${OUTPUT_DIR_BINWALK}"

  write_csv_log "FILES Binwalk" "UNIQUE FILES Binwalk" "directories Binwalk" "Binaries Binwalk" "LINUX_PATH_COUNTER Binwalk"
  write_csv_log "${lFILES_EXT_BW}" "${lUNIQUE_FILES_BW}" "${lDIRS_EXT_BW}" "${lBINS_BW}" "${LINUX_PATH_COUNTER_BINWALK}"

  module_end_log "${FUNCNAME[0]}" "${lFILES_EXT_BW}"
}

linux_basic_identification_binwalk() {
  local lFIRMWARE_PATH_CHECK="${1:-}"
  if ! [[ -d "${lFIRMWARE_PATH_CHECK}" ]]; then
    return
  fi
  LINUX_PATH_COUNTER_BINWALK="$(find "${lFIRMWARE_PATH_CHECK}" "${EXCL_FIND[@]}" -xdev -type d -iname bin -o -type f -iname busybox -o -type f -name shadow -o -type f -name passwd -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"
}
