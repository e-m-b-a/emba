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

# Description: Extracts zip, tar, tgz archives with patools
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P05_patools_init() {
  local lNEG_LOG=0

  # WARNING: Patool module is deprecated and will be replaced with unblob
  if [[ "${PATOOLS_INIT:-0}" -eq 5 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Initial extractor of different archive types via patools"
    pre_module_reporter "${FUNCNAME[0]}"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/patool_extraction/

    patools_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

    if [[ "${FILES_PATOOLS}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
    fi

    lNEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

patools_extractor() {
  sub_module_title "Patool filesystem extractor"

  local lFIRMWARE_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  export FILES_PATOOLS=0
  local lDIRS_PATOOLS=0
  local lFIRMWARE_NAME_=""

  if ! [[ -f "${lFIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  lFIRMWARE_NAME_="$(basename "${lFIRMWARE_PATH_}")"

  [[ "${STRICT_MODE}" -eq 1 ]] && set +e

  patool -v test "${lFIRMWARE_PATH_}" 2>&1 | tee -a "${LOG_PATH_MODULE}"/paextract_test_"${lFIRMWARE_NAME_}".log || print_error "[-] Patool test run failed - no extraction with patool module possible"

  [[ "${STRICT_MODE}" -eq 1 ]] && set -e

  cat "${LOG_PATH_MODULE}"/paextract_test_"${lFIRMWARE_NAME_}".log >> "${LOG_FILE}"

  if ! [[ -d "${lEXTRACTION_DIR_}" ]]; then
    mkdir "${lEXTRACTION_DIR_}"
  fi

  if grep -q "patool: ... tested ok." "${LOG_PATH_MODULE}"/paextract_test_"${lFIRMWARE_NAME_}".log ; then
    print_ln
    print_output "[*] Valid compressed file detected - extraction process via patool started"

    patool -v extract "${lFIRMWARE_PATH_}" --outdir "${lEXTRACTION_DIR_}" 2>&1 | tee -a "${LOG_PATH_MODULE}"/paextract_extract_"${lFIRMWARE_NAME_}".log
    cat "${LOG_PATH_MODULE}"/paextract_extract_"${lFIRMWARE_NAME_}".log >> "${LOG_FILE}"
  else
    # Fallback if unzip does not work:
    print_ln
    print_output "[*] No valid compressed file detected - extraction process via unblob started"

    unblobber "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}"
  fi

  print_ln
  print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR_}${NC}) as base directory:"
  find "${lEXTRACTION_DIR_}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
  print_ln

  FILES_PATOOLS=$(find "${lEXTRACTION_DIR_}" -type f | wc -l)
  lDIRS_PATOOLS=$(find "${lEXTRACTION_DIR_}" -type d | wc -l)
  print_output "[*] Extracted ${ORANGE}${FILES_PATOOLS}${NC} files and ${ORANGE}${lDIRS_PATOOLS}${NC} directories from the firmware image."
  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
  write_csv_log "Patool extractor" "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}" "${FILES_PATOOLS}" "${lDIRS_PATOOLS}" "NA"
  print_ln
}
