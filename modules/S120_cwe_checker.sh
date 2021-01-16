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

# Description:  Check binaries with cwe-checker and bap (binary analysis platform)
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S120_cwe_checker()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries with bap and cwe-checker"

  if [[ $BAP -eq 1 ]] ; then
    for LINE in "${BINARIES[@]}" ; do
      if ( file "$LINE" | grep -q ELF ) ; then
        NAME=$(basename "$LINE")
        readarray -t TEST_OUTPUT < <( docker run --rm -v "$LINE":/tmp/input fkiecad/cwe_checker bap /tmp/input --pass=cwe-checker 2> /dev/null | tee -a "$LOG_DIR"/bap_cwe_checker/bap_"$NAME".log )
        if [[ ${#TEST_OUTPUT[@]} -ne 0 ]] ; then
          print_output "[*] ""$(print_path "$LINE")"
        fi
        for ENTRY in "${TEST_OUTPUT[@]}" ; do
          if [[ -n "$ENTRY" ]] ; then
            print_output "$(indent "$ENTRY")"
          fi
        done

        mapfile -t BAP_OUT < <( grep -v "ERROR" "$LOG_DIR"/bap_cwe_checker/bap_"$NAME".log | sed -z 's/\ ([0-9]\.[0-9]).\n//g' | cut -d\) -f1 | sort -u | tr -d '(' )

        if [[ ${#BAP_OUT[@]} -ne 0 ]] ; then
          print_output ""
          print_output "[+] Found ""${#BAP_OUT[@]}"" different security issues in ""$NAME"":"
          for BAP_LINE in "${BAP_OUT[@]}"; do
            CWE="$(echo "$BAP_LINE" | cut -d\  -f1)"
            CWE_DESC="$(echo "$BAP_LINE" | cut -d\  -f2-)"
            CWE_CNT="$(grep -c "$CWE" "$LOG_DIR"/bap_cwe_checker/bap_"$NAME".log)"
            print_output "$(indent "$(orange "$CWE""$GREEN"" - ""$CWE_DESC"" - ""$ORANGE""$CWE_CNT"" times.")")"
          done
        fi
        if [[ ${#TEST_OUTPUT[@]} -ne 0 ]] ; then echo ; fi
      fi
    done

    SUM_FCW_FIND=$(cat "$LOG_DIR"/bap_cwe_checker/bap_*.log | awk '{print $1}' | grep -c -v "ERROR")
    print_output ""
    if [[ $SUM_FCW_FIND -eq 0 ]] ; then
      print_output "[-] cwe-checker found 0 security issues."
    else
      print_output "[+] cwe-checker found a total of $SUM_FCW_FIND of the following security issues:"
      print_output "$( indent "$( orange "$( cat "$LOG_DIR"/bap_cwe_checker/bap_*.log | grep -v "ERROR" | sed -z 's/\ ([0-9]\.[0-9]).\n//g' | cut -d\) -f1 | sort -u | tr -d '(' )")")"
    fi
    
  else
    print_output "[!] Check with bap and cwe-checker is disabled!"
  fi
}

