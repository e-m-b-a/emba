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

# Description:  Extracts firmware with unblob to the module log directory.
#               IMPORTANT: The results are currently not used for further analysis.
#               This module is currently only for evaluation purposes.

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# This module extracts the firmware and is blocking modules that needs executed before the following modules can run
export PRE_THREAD_ENA=0

P55_unblob_extractor() {
  module_log_init "${FUNCNAME[0]}"

  if [[ "${UEFI_VERIFIED}" -eq 1 || "${DISABLE_DEEP:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # shellcheck disable=SC2153
  if [[ -d "${FIRMWARE_PATH}" ]] && [[ "${RTOS}" -eq 1 ]]; then
    detect_root_dir_helper "${FIRMWARE_PATH}"
  fi

  # If we have found a linux filesystem we do not need an unblob extraction
  if [[ ${RTOS} -eq 0 ]] ; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  if [[ -f "${TMP_DIR}""/unblob_disable.cfg" ]]; then
    # if we disable unblob from a background module we need to work with a file to
    # store the state of this variable (bash rules ;))
    UNBLOB="$(cat "${TMP_DIR}"/unblob_disable.cfg)"
  fi

  if [[ "${UNBLOB:-1}" -eq 0 ]]; then
    if [[ -f "${TMP_DIR}""/unblob_disable.cfg" ]]; then
      print_output "[-] Unblob module automatically disabled from other module."
    else
      print_output "[-] Unblob module currently disabled - enable it in emba setting the UNBLOB variable to 1"
    fi
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lFW_PATH_UNBLOB="${FIRMWARE_PATH_BAK}"

  if [[ -d "${lFW_PATH_UNBLOB}" ]]; then
    print_output "[-] Unblob module only deals with firmware files - directories are handled via deep extractor"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  if ! command -v unblob >/dev/null; then
    print_output "[-] Unblob not correct installed - check your installation"
    return
  fi

  local lFILES_UNBLOB_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  module_title "Unblob binary firmware extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  local lLINUX_PATH_COUNTER_UNBLOB=0
  local lOUTPUT_DIR_UNBLOB="${LOG_DIR}"/firmware/unblob_extracted

  if [[ -f "${lFW_PATH_UNBLOB}" ]]; then
    unblobber "${lFW_PATH_UNBLOB}" "${lOUTPUT_DIR_UNBLOB}" 0
  fi

  if [[ "${SBOM_MINIMAL:-0}" -ne 1 ]]; then
    print_ln
    if [[ -d "${lOUTPUT_DIR_UNBLOB}" ]]; then
      remove_uprintable_paths "${lOUTPUT_DIR_UNBLOB}"
      mapfile -t lFILES_UNBLOB_ARR < <(find "${lOUTPUT_DIR_UNBLOB}" -type f ! -name "*.raw")
    fi

    if [[ "${#lFILES_UNBLOB_ARR[@]}" -gt 0 ]]; then
      print_output "[*] Extracted ${ORANGE}${#lFILES_UNBLOB_ARR[@]}${NC} files."
      print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UNBLOB_ARR[@]}${NC} files ... could take some time" "no_log"

      for lBINARY in "${lFILES_UNBLOB_ARR[@]}" ; do
        binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
      done

      lLINUX_PATH_COUNTER_UNBLOB=$(linux_basic_identification "${lOUTPUT_DIR_UNBLOB}" "${FUNCNAME[0]}")
      wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

      sub_module_title "Firmware extraction details"
      print_output "[*] ${ORANGE}Unblob${NC} results:"
      print_output "[*] Found ${ORANGE}${#lFILES_UNBLOB_ARR[@]}${NC} files."
      print_output "[*] Additionally the Linux path counter is ${ORANGE}${lLINUX_PATH_COUNTER_UNBLOB}${NC}."
      print_ln
      tree -sh "${lOUTPUT_DIR_UNBLOB}" | tee -a "${LOG_FILE}"
      print_ln
    fi
  fi

  detect_root_dir_helper "${lOUTPUT_DIR_UNBLOB}"

  # this is the 2nd run for full sytem emulation
  # further comments on this mechanism in P50
  # this will be removed in the future after binwalk is running as expected
  if [[ "${FULL_EMULATION}" -eq 1 && "${RTOS}" -eq 1 ]]; then
    local lOUTPUT_DIR_BINWALK=""
    local lFILES_BINWALK_ARR=()

    lOUTPUT_DIR_BINWALK="${lOUTPUT_DIR_UNBLOB//unblob/binwalk_recover}"
    binwalker_matryoshka "${lFW_PATH_UNBLOB}" "${lOUTPUT_DIR_BINWALK}"
    if [[ -d "${lOUTPUT_DIR_BINWALK}" ]]; then
      remove_uprintable_paths "${lOUTPUT_DIR_BINWALK}"
      mapfile -t lFILES_BINWALK_ARR < <(find "${lOUTPUT_DIR_BINWALK}" -type f ! -name "*.raw")
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
      print_output "[*] ${ORANGE}Binwalk recovery${NC} results:"
      print_output "[*] Found ${ORANGE}${#lFILES_BINWALK_ARR[@]}${NC} files."
      print_output "[*] Additionally the Linux path counter is ${ORANGE}${lLINUX_PATH_COUNTER_BINWALK}${NC}."
      print_ln
      tree -sh "${lOUTPUT_DIR_BINWALK}" | tee -a "${LOG_FILE}"
      detect_root_dir_helper "${lOUTPUT_DIR_BINWALK}"
      write_csv_log "FILES Binwalk recovery mode" "LINUX_PATH_COUNTER Binwalk"
      write_csv_log "${#lFILES_BINWALK_ARR[@]}" "${lLINUX_PATH_COUNTER_BINWALK}"
    fi
  fi

  write_csv_log "FILES Unblob" "LINUX_PATH_COUNTER Unblob"
  write_csv_log "${#lFILES_UNBLOB_ARR[@]}" "${lLINUX_PATH_COUNTER_UNBLOB}"

  module_end_log "${FUNCNAME[0]}" "${#lFILES_UNBLOB_ARR[@]}"
}

unblobber() {
  local lFIRMWARE_PATH="${1:-}"
  local lOUTPUT_DIR_UNBLOB="${2:-}"
  local lVERBOSE="${3:-0}"
  local lUNBLOB_BIN="unblob"
  local lTIMEOUT="300m"

  if [[ "${DIFF_MODE}" -ne 1 ]]; then
    sub_module_title "Analyze binary firmware $(basename "${lFIRMWARE_PATH}") with unblob"
  fi

  print_output "[*] Extracting binary blob ${ORANGE}$(basename "${lFIRMWARE_PATH}")${NC} to directory ${ORANGE}${lOUTPUT_DIR_UNBLOB}${NC}"

  if ! [[ -d "${lOUTPUT_DIR_UNBLOB}" ]]; then
    mkdir -p "${lOUTPUT_DIR_UNBLOB}"
  fi

  if [[ "${lVERBOSE}" -eq 1 ]]; then
    # Warning: the safe_logging is very slow.
    # TODO: We need to check on this!
    timeout --preserve-status --signal SIGINT "${lTIMEOUT}" "${lUNBLOB_BIN}" -v -k --log "${LOG_PATH_MODULE}"/unblob_"$(basename "${lFIRMWARE_PATH}")".log -e "${lOUTPUT_DIR_UNBLOB}" "${lFIRMWARE_PATH}" \
      |& safe_logging "${LOG_FILE}" 0 || true
  else
    local COLUMNS=""
    COLUMNS=100 timeout --preserve-status --signal SIGINT "${lTIMEOUT}" "${lUNBLOB_BIN}" -k --log "${LOG_PATH_MODULE}"/unblob_"$(basename "${lFIRMWARE_PATH}")".log -e "${lOUTPUT_DIR_UNBLOB}" "${lFIRMWARE_PATH}" \
      |& safe_logging "${LOG_FILE}" 0 || true
  fi
}

