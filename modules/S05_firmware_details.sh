#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann, Stefan Haböck

# Description:  Check for information (release/version) about firmware and dump directory tree into log
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S05_firmware_details()
{
  CONTENT_AVAILABLE=0
  module_log_init "s05_firmware_and_testing_details"
  module_title "Firmware and testing details"

  print_output "[*] ""$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f | wc -l )"" files and ""$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type d | wc -l)"" directories detected."
  
  if [[ "$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f | wc -l)" > 0 ]] || [[ "$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type d | wc -l)" > 0 ]];then
     CONTENT_AVAILABLE=1
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
  
  if [[ $HTML == 1 ]]; then
     generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

# Test source: http://linuxmafia.com/faq/Admin/release-files.html
release_info()
{
  sub_module_title "Release/Version information"

  local RELEASE_STUFF
  RELEASE_STUFF="$(config_find "$CONFIG_DIR""/release_files.cfg" "/etc")"

  if [[ "$RELEASE_STUFF" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$RELEASE_STUFF" ]] ; then
    print_output "[+] Specific release/version information of target:"
    for R_INFO in $RELEASE_STUFF ; do
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
    CONTENT_AVAILABLE=1
  else
    print_output "[-] No release/version information of target found"
  fi
}
