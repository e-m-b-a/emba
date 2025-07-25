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

# Description:  Extracts firmware with binwalk to the module log directory.
#               This module is a fallback module for the very rare case that our extraction process was failing
#               e.g. in cases like this https://github.com/onekey-sec/sasquatch/issues/19

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# This module extracts the firmware and is blocking modules that needs executed before the following modules can run
export PRE_THREAD_ENA=0

P50_binwalk_extractor() {
  module_log_init "${FUNCNAME[0]}"

  # shellcheck disable=SC2153
  if [[ -d "${FIRMWARE_PATH}" ]] && [[ "${RTOS}" -eq 1 ]]; then
    detect_root_dir_helper "${FIRMWARE_PATH}"
  fi

  # if we have a verified UEFI firmware we do not need to do anything here
  # if we have already found a linux (RTOS==0) we do not need to do anything here
  if [[ "${UEFI_VERIFIED}" -eq 1 ]] || [[ "${RTOS}" -eq 0 ]] || [[ "${DJI_DETECTED}" -eq 1 ]] || [[ "${WINDOWS_EXE}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # We have seen multiple issues in system emulation while using binwalk
  # * unprintable chars in paths -> remediation in place
  # * lost symlinks in different firmware extractions -> Todo: Issue
  # * lost permissions of executables -> remediation in place
  # Currently we disable binwalk here and switch automatically to unblob is main extractor while
  # system emulation runs. If unblob fails we are going to try an additional extraction round with
  # binwalk.
  if [[ "${FULL_EMULATION}" -eq 1 ]]; then
    print_output "[-] Binwalk v3 has issues with symbolic links and is disabled for system emulation"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # we do not rely on any EMBA extraction mechanism -> we use the original firmware file
  local lFW_PATH_BINWALK="${FIRMWARE_PATH_BAK}"

  if [[ -d "${lFW_PATH_BINWALK}" ]]; then
    print_output "[-] Binwalk module only deals with firmware files - directories should be already handled via deep extractor"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lFILES_BINWALK_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  module_title "Binwalk binary firmware extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  local lLINUX_PATH_COUNTER_BINWALK=0
  local lOUTPUT_DIR_BINWALK="${LOG_DIR}"/firmware/binwalk_extracted

  if [[ -f "${lFW_PATH_BINWALK}" ]]; then
    binwalker_matryoshka "${lFW_PATH_BINWALK}" "${lOUTPUT_DIR_BINWALK}"
  fi

  print_ln
  if [[ -d "${lOUTPUT_DIR_BINWALK}" ]]; then
    remove_uprintable_paths "${lOUTPUT_DIR_BINWALK}"
    mapfile -t lFILES_BINWALK_ARR < <(find "${lOUTPUT_DIR_BINWALK}" -type f)
  fi

  if [[ "${#lFILES_BINWALK_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Extracted ${ORANGE}${#lFILES_BINWALK_ARR[@]}${NC} files."
    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_BINWALK_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_BINWALK_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done

    lLINUX_PATH_COUNTER_BINWALK=$(linux_basic_identification "${lOUTPUT_DIR_BINWALK}" "${FUNCNAME[0]}")
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    sub_module_title "Firmware extraction details"
    print_output "[*] ${ORANGE}Binwalk${NC} results:"
    print_output "[*] Found ${ORANGE}${#lFILES_BINWALK_ARR[@]}${NC} files."
    print_output "[*] Additionally the Linux path counter is ${ORANGE}${lLINUX_PATH_COUNTER_BINWALK}${NC}."
    print_ln
    tree -sh "${lOUTPUT_DIR_BINWALK}" | tee -a "${LOG_FILE}"
  fi

  detect_root_dir_helper "${lOUTPUT_DIR_BINWALK}"

  write_csv_log "FILES Binwalk" "LINUX_PATH_COUNTER Binwalk"
  write_csv_log "${#lFILES_BINWALK_ARR[@]}" "${lLINUX_PATH_COUNTER_BINWALK}"

  module_end_log "${FUNCNAME[0]}" "${#lFILES_BINWALK_ARR[@]}"
}

linux_basic_identification() {
  local lFIRMWARE_PATH_CHECK="${1:-}"
  local lIDENTIFIER="${2:-}"
  local lLINUX_PATH_COUNTER_BINWALK=0

  if ! [[ -d "${lFIRMWARE_PATH_CHECK}" ]]; then
    return
  fi
  if [[ -f "${P99_CSV_LOG}" ]]; then
    if [[ -n "${lIDENTIFIER}" ]]; then
      lLINUX_PATH_COUNTER_BINWALK="$(grep "${lIDENTIFIER}" "${P99_CSV_LOG}" | grep -c "/bin/\|/busybox;\|/shadow;\|/passwd;\|/sbin/\|/etc/" || true)"
    else
      lLINUX_PATH_COUNTER_BINWALK="$(grep -c "/bin/\|/busybox;\|/shadow;\|/passwd;\|/sbin/\|/etc/" "${P99_CSV_LOG}" || true)"
    fi
  fi
  echo "${lLINUX_PATH_COUNTER_BINWALK}"
}

remove_uprintable_paths() {
  local lOUTPUT_DIR_BINWALK="${1:-}"

  local lFIRMWARE_UNPRINT_FILES_ARR=()
  local lFW_FILE=""

  mapfile -t lFIRMWARE_UNPRINT_FILES_ARR < <(find "${lOUTPUT_DIR_BINWALK}" -name '*[^[:print:]]*')
  if [[ "${#lFIRMWARE_UNPRINT_FILES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Unprintable characters detected in extracted files -> cleanup started"
    for lFW_FILE in "${lFIRMWARE_UNPRINT_FILES_ARR[@]}"; do
      print_output "[*] Cleanup of ${lFW_FILE} with unprintable characters"
      print_output "[*] Moving ${lFW_FILE} to ${lFW_FILE//[![:print:]]/_}"
      mv "${lFW_FILE}" "${lFW_FILE//[![:print:]]/_}" || true
    done
  fi
}
