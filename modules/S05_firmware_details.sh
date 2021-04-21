#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Counts the number of files and executables in firmware and prints firmware tree in the log files. 
#               It also searches through possible release files config/release_files.cfg for strings.

S05_firmware_details()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Firmware and testing details"

  LOG_FILE="$( get_log_file )"

  local DETECTED_DIR
  
  # we use the file FILE_ARR from helpers module
  DETECTED_DIR=$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -type d 2>/dev/null | wc -l)
  
  print_output "[*] ""${#FILE_ARR[@]}"" files and ""$DETECTED_DIR"" directories detected."

  # excluded paths will be also printed
  if command -v tree > /dev/null 2>&1 ; then
    if [[ $FORMAT_LOG -eq 1 ]] ; then
      tree -p -s -a -C "$FIRMWARE_PATH" >> "$LOG_FILE"
    else
      tree -p -s -a -n "$FIRMWARE_PATH" >> "$LOG_FILE"
    fi
  else
    if [[ $FORMAT_LOG -eq 1 ]] ; then
      ls -laR "$FIRMWARE_PATH" >> "$LOG_FILE"
    else
      ls -laR --color=never "$FIRMWARE_PATH" >> "$LOG_FILE"
    fi
  fi
  release_info

  echo -e "\\n[*] Statistics:${#FILE_ARR[@]}:$DETECTED_DIR" >> "$LOG_FILE"

  module_end_log "${FUNCNAME[0]}" "${#FILE_ARR[@]}"
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
        if file "$R_INFO" | grep -a -q text; then
          print_output "\\n""$( print_path "$R_INFO")"
          RELEASE="$( cat "$R_INFO" )"
          if [[ "$RELEASE" ]] ; then
            print_output ""
            print_output "$(indent "$(magenta "$RELEASE")")"
          fi
        fi
      else
        print_output "\\n""$(magenta "Directory:")"" ""$( print_path "$R_INFO")""\\n"
      fi
    done
  else
    print_output "[-] No release/version information of target found"
  fi
}
