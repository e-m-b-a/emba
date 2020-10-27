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
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Check various certification files
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S60_cert_file_check()
{
  module_log_init "S60_certification_etc_search"
  module_title "Search certification files and other critical interesting stuff"

  local CERT_FILES_ARR
  readarray -t CERT_FILES_ARR < <(config_find "$CONFIG_DIR""/cert_files.cfg")

  if [[ "${CERT_FILES_ARR[0]}" == "C_N_F" ]]; then print_output "[!] Config not found"
  elif [[ ${#CERT_FILES_ARR[@]} -ne 0 ]]; then
    print_output "[+] Found ""${#CERT_FILES_ARR[@]}"" certification files:"
    for LINE in "${CERT_FILES_ARR[@]}" ; do
      if [[ -f "$LINE" ]]; then
        print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      fi
    done
  else
    print_output "[-] No certification files found"
  fi
}

