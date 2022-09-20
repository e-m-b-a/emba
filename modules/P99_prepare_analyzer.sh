#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
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

  if [[ $THREADED -eq 1 ]]; then
    # this module is the latest in the preparation phase. So, wait for all the others
    wait_for_pid "${WAIT_PIDS[@]}"
  fi

  module_log_init "${FUNCNAME[0]}"
  module_title "Analysis preparation"
  pre_module_reporter "${FUNCNAME[0]}"

  # we have a linux:
  if [[ $LINUX_PATH_COUNTER -gt 0 || ${#ROOT_PATH[@]} -gt 1 ]] ; then
    export FIRMWARE=1
    export FIRMWARE_PATH
    FIRMWARE_PATH="$(abs_path "$OUTPUT_DIR")"
    backup_var "FIRMWARE_PATH" "$FIRMWARE_PATH"
  fi

  print_output "[*] Quick check if it is a real Linux system"
  check_firmware
  print_ln

  prepare_file_arr
  print_ln
  prepare_binary_arr
  print_ln

  if [[ $KERNEL -eq 0 ]] ; then
    architecture_check
    architecture_dep_check
  fi

  if [[ "${#ROOT_PATH[@]}" -eq 0 ]]; then
    detect_root_dir_helper "$FIRMWARE_PATH" "main"
  fi

  set_etc_paths
  print_ln "no_log"
  if [[ "$RTOS" -eq 1 ]] && [[ "$UEFI_DETECTED" -eq 1 ]]; then
    print_output "[*] UEFI firmware detected"
    # -> we run only Sxx modules with UEFI in the name
  elif [[ "$RTOS" -eq 1 ]]; then
    print_output "[*] RTOS system detected"
  fi

  local NEG_LOG=1
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

