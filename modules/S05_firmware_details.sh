#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Counts the number of files and executables in firmware and prints firmware tree in the log files.
#               It also searches through possible release files config/release_files.cfg for strings.

S05_firmware_details()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Firmware and testing details"

  pre_module_reporter "${FUNCNAME[0]}"

  if [[ ! -f "${P99_CSV_LOG}" ]]; then
    print_error "[-] Missing P99 CSV log file"
    return
  fi

  local lDETECTED_DIR=""

  lDETECTED_DIR=$(find "${LOG_DIR}/firmware" -xdev -type d 2>/dev/null | wc -l)

  local lFILE_CNT=0
  lFILE_CNT="$(wc -l < "${P99_CSV_LOG}" || true)"
  print_output "[*] ${ORANGE}${lFILE_CNT}${NC} files and ${ORANGE}${lDETECTED_DIR}${NC} directories detected."

  release_info
  filesystem_tree

  write_log ""
  write_log "[*] Statistics:${lFILE_CNT}:${lDETECTED_DIR}"

  module_end_log "${FUNCNAME[0]}" "${lFILE_CNT}"
}

filesystem_tree() {
  sub_module_title "Filesystem information"
  write_anchor "file_dirs"
  local lLPATH="${LOG_DIR}/firmware"

  # excluded paths will be also printed
  if command -v tree > /dev/null 2>&1 ; then
    if [[ ${FORMAT_LOG} -eq 1 ]] ; then
      tree -p -s -a -C "${lLPATH}" >> "${LOG_FILE}" || true
    else
      tree -p -s -a -n "${lLPATH}" >> "${LOG_FILE}" || true
    fi
  else
    if [[ ${FORMAT_LOG} -eq 1 ]] ; then
      ls -laR "${lLPATH}" >> "${LOG_FILE}"
    else
      ls -laR --color=never "${lLPATH}" >> "${LOG_FILE}"
    fi
  fi
}

# Test source: http://linuxmafia.com/faq/Admin/release-files.html
release_info() {
  sub_module_title "Release/Version information"
  local lR_INFO=""
  local lRELEASE=""
  local lRELEASE_STUFF_ARR=()

  mapfile -t lRELEASE_STUFF_ARR < <(config_find "${CONFIG_DIR}""/release_files.cfg")
  if [[ "${lRELEASE_STUFF_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#lRELEASE_STUFF_ARR[@]}" -gt 0 ]] ; then
    print_output "[+] Specific release/version information of target:"
    for lR_INFO in "${lRELEASE_STUFF_ARR[@]}" ; do
      if [[ -f "${lR_INFO}" ]] ; then
        if file "${lR_INFO}" | grep -a -q text; then
          print_output "\\n""$( print_path "${lR_INFO}")"
          lRELEASE="$( cat "${lR_INFO}" )"
          if [[ "${lRELEASE}" ]] ; then
            print_ln
            print_output "$(indent "$(magenta "${lRELEASE}")")"
          fi
        fi
      else
        print_output "\\n""$(magenta "Directory:")"" ""$( print_path "${lR_INFO}")""\\n"
      fi
    done
  else
    print_output "[-] No release/version information of target found"
  fi
}
