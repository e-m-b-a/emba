#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Some preparation tasks:
#               * check_firmware
#               * prepare_binary_arr
#               * architecture_check
#               * detect_root_dir_helper
#               * set_etc_paths
#               * prepare_file_arr
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P99_prepare_analyzer() {

  # this module is the latest in the preparation phase. So, wait for all the others
  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${WAIT_PIDS[@]}"

  module_log_init "${FUNCNAME[0]}"
  module_title "Analysis preparation"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=1
  local lFILES_EXT=0
  local lUNIQUE_FILES=0
  local lDIRS_EXT=0
  local lBINS=0
  local lR_PATH=""

  export LINUX_PATH_COUNTER=0
  LINUX_PATH_COUNTER="$(find "${LOG_DIR}"/firmware "${EXCL_FIND[@]}" -xdev -type d -iname bin -o -type f -iname busybox -o -type f -name shadow -o -type f -name passwd -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"

  # we have a linux:
  if [[ ${LINUX_PATH_COUNTER} -gt 0 || ${#ROOT_PATH[@]} -gt 1 ]] ; then
    export FIRMWARE=1
    # FIRMWARE_PATH="$(abs_path "${OUTPUT_DIR}")"
    export FIRMWARE_PATH="${LOG_DIR}"/firmware
    backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
  fi

  print_output "[*] Quick check for Linux operating-system"
  check_firmware

  if [[ "${SBOM_MINIMAL:-0}" -eq 1 ]]; then
    lNEG_LOG=0
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    return
  fi

  prepare_file_arr "${FIRMWARE_PATH}"
  prepare_binary_arr "${FIRMWARE_PATH}"
  prepare_file_arr_limited "${LOG_DIR}"/firmware

  if [[ ${KERNEL} -eq 0 ]] ; then
    architecture_check "${FIRMWARE_PATH}"
    architecture_dep_check
  fi

  if [[ "${UEFI_VERIFIED}" -ne 1 ]] && [[ "${#ROOT_PATH[@]}" -eq 0 ]]; then
    detect_root_dir_helper "${FIRMWARE_PATH}" "main"
  fi

  set_etc_paths
  print_ln
  if [[ "${RTOS}" -eq 1 ]] && [[ "${UEFI_VERIFIED}" -eq 1 ]]; then
    print_output "[+] UEFI firmware detected"
    if [[ -f "${LOG_DIR}"/p35_uefi_extractor.txt ]]; then
      write_link "p35"
    fi
  elif [[ "${RTOS}" -eq 1 ]] && [[ "${UEFI_DETECTED}" -eq 1 ]]; then
    print_output "[*] Possible UEFI firmware detected"
    if [[ -f "${LOG_DIR}"/p02_firmware_bin_file_check.txt ]]; then
      write_link "p02"
    fi
  elif [[ "${WINDOWS_EXE}" -eq 1 ]]; then
    print_output "[*] Windows binaries detected"
    if [[ -f "${LOG_DIR}"/p07_windows_exe_extract.txt ]]; then
      write_link "p07"
    fi
  elif [[ "${RTOS}" -eq 1 ]]; then
    print_output "[*] Possible RTOS system detected"
  fi

  if [[ "${#ROOT_PATH[@]}" -gt 0 ]] && ! [[ -f "${CSV_DIR}"/p99_prepare_analyzer.csv ]]; then
    write_csv_log "FILES" "UNIQUE_FILES" "DIRS" "Binaries" "LINUX_PATH_COUNTER" "Root PATH detected" "architecture" "endianess"
    for lR_PATH in "${ROOT_PATH[@]}"; do
      lFILES_EXT=$(find "${ROOT_PATH}" -xdev -type f | wc -l )
      lUNIQUE_FILES=$(find "${ROOT_PATH}" "${EXCL_FIND[@]}" -xdev -type f  -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 | wc -l )
      lDIRS_EXT=$(find "${ROOT_PATH}" -xdev -type d | wc -l )
      lBINS=$(find "${ROOT_PATH}" "${EXCL_FIND[@]}" -xdev -type f  -print0|xargs -r -0 -P 16 -I % sh -c 'file "%"' | grep -c "ELF" || true)
      write_csv_log "${lFILES_EXT}" "${lUNIQUE_FILES}" "${lDIRS_EXT}" "${lBINS}" "${LINUX_PATH_COUNTER}" "${lR_PATH}" "${ARCH}" "${D_END:-"NA"}"
    done
  fi

  write_log "[*] Statistics:${ARCH:-NA}:${D_END:-NA}"
  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

