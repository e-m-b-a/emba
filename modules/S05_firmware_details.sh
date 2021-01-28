#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Check for information (release/version) about firmware and dump directory tree into log
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}
export HTML_REPORT

S05_firmware_details()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Firmware and testing details"

  print_output "[*] ""$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f | wc -l )"" files and ""$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type d | wc -l)"" directories detected."

  if [[ "$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f | wc -l)" -gt 0 ]] || [[ "$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type d | wc -l)" -gt 0 ]];then
     HTML_REPORT=1
  fi
  
  LOG_FILE="$( get_log_file )"

  # excluded paths will be also printed
  if command -v tree > /dev/null 2>&1 ; then
    if [[ $FORMAT_LOG -eq 1 ]] ; then
      tree -p -s -a -C "$FIRMWARE_PATH" >> "$LOG_FILE" > /dev/null
    else
      tree -p -s -a -n "$FIRMWARE_PATH" >> "$LOG_FILE" > /dev/null
    fi
  else
    if [[ $FORMAT_LOG -eq 1 ]] ; then
      ls -laR "$FIRMWARE_PATH" >> "$LOG_FILE" > /dev/null
    else
      ls -laR --color=never "$FIRMWARE_PATH" >> "$LOG_FILE" > /dev/null
    fi
  fi
  release_info
}

# Test source: http://linuxmafia.com/faq/Admin/release-files.html
release_info()
{
  sub_module_title "Release/Version information"

  local RELEASE_STUFF
  mapfile -t RELEASE_STUFF < <(config_find "$CONFIG_DIR""/release_files.cfg")
  if [[ "${RELEASE_STUFF[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#RELEASE_STUFF[@]}" -ne 0 ]] ; then
    print_output "[+] Specific release/version information of target:"
    for R_INFO in "${RELEASE_STUFF[@]}" ; do
      if [[ -f "$R_INFO" ]] ; then
        print_output "\\n""$( print_path "$R_INFO")"
        RELEASE="$( cat "$R_INFO" )"
        if [[ "$RELEASE" ]] ; then
          print_output ""
          print_output "$(indent "$(magenta "$RELEASE")")"
        fi
      else
        print_output "\\n""$(magenta "Directory:")"" ""$( print_path "$R_INFO")""\\n"
      fi
    done
  else
    print_output "[-] No release/version information of target found"
  fi

}
