#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2024 Siemens Energy AG
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

  local DETECTED_DIR=""

  # we use the file FILE_ARR from helpers module
  DETECTED_DIR=$(find "${LOG_DIR}/firmware" -xdev -type d 2>/dev/null | wc -l)

  print_output "[*] ${ORANGE}${#FILE_ARR[@]}${NC} files and ${ORANGE}${DETECTED_DIR}${NC} directories detected."

  release_info
  filesystem_tree

  write_log ""
  write_log "[*] Statistics:${#FILE_ARR[@]}:${DETECTED_DIR}"

  module_end_log "${FUNCNAME[0]}" "${#FILE_ARR[@]}"
}

filesystem_tree() {
  sub_module_title "Filesystem information"
  write_anchor "file_dirs"
  local LPATH="${LOG_DIR}/firmware"

  # excluded paths will be also printed
  if command -v tree > /dev/null 2>&1 ; then
    if [[ ${FORMAT_LOG} -eq 1 ]] ; then
      tree -p -s -a -C "${LPATH}" >> "${LOG_FILE}" || true
    else
      tree -p -s -a -n "${LPATH}" >> "${LOG_FILE}" || true
    fi
  else
    if [[ ${FORMAT_LOG} -eq 1 ]] ; then
      ls -laR "${LPATH}" >> "${LOG_FILE}"
    else
      ls -laR --color=never "${LPATH}" >> "${LOG_FILE}"
    fi
  fi
}

# Test source: http://linuxmafia.com/faq/Admin/release-files.html
release_info() {
  sub_module_title "Release/Version information"
  local R_INFO=""
  local RELEASE=""
  local RELEASE_STUFF=()

  mapfile -t RELEASE_STUFF < <(config_find "${CONFIG_DIR}""/release_files.cfg")
  if [[ "${RELEASE_STUFF[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#RELEASE_STUFF[@]}" -gt 0 ]] ; then
    print_output "[+] Specific release/version information of target:"
    for R_INFO in "${RELEASE_STUFF[@]}" ; do
      if [[ -f "${R_INFO}" ]] ; then
        if file "${R_INFO}" | grep -a -q text; then
          print_output "\\n""$( print_path "${R_INFO}")"
          RELEASE="$( cat "${R_INFO}" )"
          if [[ "${RELEASE}" ]] ; then
            print_ln
            print_output "$(indent "$(magenta "${RELEASE}")")"
          fi
        fi
      else
        print_output "\\n""$(magenta "Directory:")"" ""$( print_path "${R_INFO}")""\\n"
      fi
    done
  else
    print_output "[-] No release/version information of target found"
  fi
}
