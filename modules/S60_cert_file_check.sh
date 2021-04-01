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

# Description:  Scrapes firmware for certification files and their end date.

S60_cert_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search certification files and other critical interesting stuff"

  LOG_FILE="$( get_log_file )"

  local CERT_FILES_ARR
  readarray -t CERT_FILES_ARR < <(config_find "$CONFIG_DIR""/cert_files.cfg")

  CERT_CNT=0
  CERT_OUT_CNT=0

  if [[ "${CERT_FILES_ARR[0]}" == "C_N_F" ]]; then print_output "[!] Config not found"
  elif [[ ${#CERT_FILES_ARR[@]} -ne 0 ]]; then
    print_output "[+] Found ""${#CERT_FILES_ARR[@]}"" certification files:"
    CURRENT_DATE=$(date +%s)
    for LINE in "${CERT_FILES_ARR[@]}" ; do
      if [[ -f "$LINE" ]]; then
        ((CERT_CNT++))
        if command -v openssl > /dev/null ; then
          CERT_DATE=$(date --date="$(openssl x509 -enddate -noout -in "$LINE" 2>/dev/null | cut -d= -f2)" --iso-8601)
          CERT_DATE_=$(date --date="$(openssl x509 -enddate -noout -in "$LINE" 2>/dev/null | cut -d= -f2)" +%s)
          if [[ $CERT_DATE_ -lt $CURRENT_DATE ]]; then
            print_output "  ${RED}""$CERT_DATE"" - ""$(print_path "$LINE")""${NC}"
            ((CERT_OUT_CNT++))
          else
            print_output "  ${GREEN}""$CERT_DATE"" - ""$(print_path "$LINE")""${NC}"
          fi
        else
          print_output "$(indent "$(orange "$(print_path "$LINE")")")"
        fi
      fi
    done
    echo -e "\\n[*] Statistics:$CERT_CNT:$CERT_OUT_CNT" >> "$LOG_FILE"
  else
    print_output "[-] No certification files found"
  fi

  module_end_log "${FUNCNAME[0]}" "$CERT_CNT"
}

