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
#
# Description:  This module is for the firmware diffing mode. To use the diffing mode
#               a second firmware to compare with the first one needs to be configured
#               via the -o EMBA parameter.
#               This module is for the extraction of both firmware images. It uses the
#               unblob extraction from module p55. There is currently no deep extraction
#               mode supported.

export PRE_THREAD_ENA=0

D05_firmware_diffing_extractor() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Firmware diffing - extractor module"
  pre_module_reporter "${FUNCNAME[0]}"
  local lNEG_LOG=0

  local lMD5_FW_BIN1=""
  local lMD5_FW_BIN2=""
  export OUTPUT_DIR_UNBLOB1=""
  export OUTPUT_DIR_UNBLOB2=""
  local lDIRS_EXT_UB=0
  local lUNIQUE_FILES_UB=0
  local lFILES_EXT_UB=0

  # shellcheck disable=SC2153
  lMD5_FW_BIN1=$(md5sum "${FIRMWARE_PATH}")
  # shellcheck disable=SC2153
  lMD5_FW_BIN2=$(md5sum "${FIRMWARE_PATH1}")
  if [[ "${lMD5_FW_BIN1}" == "${lMD5_FW_BIN2}" ]]; then
    print_output "[-] Same firmware binary files - no further analysis"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  sub_module_title "Firmware extraction - firmware image 1"
  OUTPUT_DIR_UNBLOB1="${LOG_PATH_MODULE}"/extractor_"$(basename "${FIRMWARE_PATH}")"
  unblobber "${FIRMWARE_PATH}" "${OUTPUT_DIR_UNBLOB1}" 0

  if [[ -d "${OUTPUT_DIR_UNBLOB1}" ]]; then
    lNEG_LOG=1
    linux_basic_identification_unblobber "${OUTPUT_DIR_UNBLOB1}"
    lFILES_EXT_UB=$(find "${OUTPUT_DIR_UNBLOB1}" -xdev -type f | wc -l )
    lUNIQUE_FILES_UB=$(find "${OUTPUT_DIR_UNBLOB1}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
    lDIRS_EXT_UB=$(find "${OUTPUT_DIR_UNBLOB1}" -xdev -type d | wc -l )
    tree -Csh "${OUTPUT_DIR_UNBLOB1}" > "${LOG_PATH_MODULE}"/firmware_image1.txt

    print_output "[*] ${ORANGE}Unblob${NC} results:"
    print_output "[*] Found ${ORANGE}${lFILES_EXT_UB}${NC} files (${ORANGE}${lUNIQUE_FILES_UB}${NC} unique files) and ${ORANGE}${lDIRS_EXT_UB}${NC} directories at all."
    if [[ -f "${LOG_PATH_MODULE}"/firmware_image1.txt ]]; then
      write_link "${LOG_PATH_MODULE}"/firmware_image1.txt
    fi
    print_output "[*] Additionally the Linux path counter is ${ORANGE}${LINUX_PATH_COUNTER_UNBLOB}${NC}."
    prepare_binary_arr "${OUTPUT_DIR_UNBLOB1}"
    architecture_check
    detect_root_dir_helper "${OUTPUT_DIR_UNBLOB1}"
  fi

  sub_module_title "Firmware extraction - firmware image 2"
  OUTPUT_DIR_UNBLOB2="${LOG_PATH_MODULE}"/extractor_"$(basename "${FIRMWARE_PATH1}")"
  unblobber "${FIRMWARE_PATH1}" "${OUTPUT_DIR_UNBLOB2}" 0

  if [[ -d "${OUTPUT_DIR_UNBLOB2}" ]]; then
    lNEG_LOG=1
    linux_basic_identification_unblobber "${OUTPUT_DIR_UNBLOB2}"
    lFILES_EXT_UB=$(find "${OUTPUT_DIR_UNBLOB2}" -xdev -type f | wc -l )
    lUNIQUE_FILES_UB=$(find "${OUTPUT_DIR_UNBLOB2}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
    lDIRS_EXT_UB=$(find "${OUTPUT_DIR_UNBLOB2}" -xdev -type d | wc -l )
    tree -Csh "${OUTPUT_DIR_UNBLOB2}" > "${LOG_PATH_MODULE}"/firmware_image2.txt

    print_output "[*] ${ORANGE}Unblob${NC} results:"
    print_output "[*] Found ${ORANGE}${lFILES_EXT_UB}${NC} files (${ORANGE}${lUNIQUE_FILES_UB}${NC} unique files) and ${ORANGE}${lDIRS_EXT_UB}${NC} directories at all."
    if [[ -f "${LOG_PATH_MODULE}"/firmware_image2.txt ]]; then
      write_link "${LOG_PATH_MODULE}"/firmware_image2.txt
    fi
    print_output "[*] Additionally the Linux path counter is ${ORANGE}${LINUX_PATH_COUNTER_UNBLOB}${NC}."
    prepare_binary_arr "${OUTPUT_DIR_UNBLOB2}"
    architecture_check
    detect_root_dir_helper "${OUTPUT_DIR_UNBLOB2}"

    # detect_root_dir_helper includes a link to a module that is usually not executed in diff mode
    # let's remove this link now:
    if ! [[ -f "${LOG_DIR}"/S05_firmware_details.txt ]]; then
      sed -i "/\[REF\]\ s05/d" "${LOG_FILE}"
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

