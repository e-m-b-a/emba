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
#               This module is doing some basic checks on the firmware. It uses mainly
#               the functionality from the p02 module but on both firmware images.

export PRE_THREAD_ENA=0

D02_firmware_diffing_bin_details() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Firmware differ - binary details"
  pre_module_reporter "${FUNCNAME[0]}"
  local lNEG_LOG=0

  if ! [[ -f "${FIRMWARE_PATH}" ]]; then
    print_output "[-] No 1st file for diffing provided"
    return
  fi
  if ! [[ -f "${FIRMWARE_PATH1}" ]]; then
    print_output "[-] No 2nd file for diffing provided"
    return
  fi

  local lMD5_FW_BIN1=""
  local lMD5_FW_BIN2=""

  # shellcheck disable=SC2153
  lMD5_FW_BIN1=$(md5sum "${FIRMWARE_PATH}")
  # shellcheck disable=SC2153
  lMD5_FW_BIN2=$(md5sum "${FIRMWARE_PATH1}")
  if [[ "${lMD5_FW_BIN1}" == "${lMD5_FW_BIN2}" ]]; then
    print_output "[-] Same firmware binary files - no further analysis"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  lNEG_LOG=1
  sub_module_title "Firmware binary details - firmware image 1"
  get_fw_file_details "${FIRMWARE_PATH}"
  generate_entropy_graph "${FIRMWARE_PATH}"
  print_fw_file_details "${FIRMWARE_PATH}"
  # generate_pixde "${FIRMWARE_PATH}"
  fw_bin_detector "${FIRMWARE_PATH}"
  if [[ -f "${LOG_DIR}"/firmware_entropy.png ]]; then
    mv "${LOG_DIR}"/firmware_entropy.png "${LOG_PATH_MODULE}"/firmware1_entropy.png
    write_link "${LOG_PATH_MODULE}"/firmware1_entropy.png
  fi

  sub_module_title "Firmware binary details - firmware image 2"
  get_fw_file_details "${FIRMWARE_PATH1}"
  generate_entropy_graph "${FIRMWARE_PATH1}"
  print_fw_file_details "${FIRMWARE_PATH1}"
  # generate_pixde "${FIRMWARE_PATH1}"
  fw_bin_detector "${FIRMWARE_PATH1}"
  if [[ -f "${LOG_DIR}"/firmware_entropy.png ]]; then
    mv "${LOG_DIR}"/firmware_entropy.png "${LOG_PATH_MODULE}"/firmware2_entropy.png
    write_link "${LOG_PATH_MODULE}"/firmware2_entropy.png
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}
