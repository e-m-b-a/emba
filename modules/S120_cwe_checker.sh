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

# Description:  Check binaries with cwe-checker and bap (binary analysis platform)
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S120_cwe_checker()
{
  module_log_init "s120_check_bap_and_cwe"
  module_title "Check binaries with bap and cwe-checker"
  CONTENT_AVAILABLE=0

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
        local CHECK_COUNT
        CHECK_COUNT="$( awk '{print $1}' "$LOG_DIR"/bap_cwe_checker/bap_"$NAME".log | sort -u | grep -o "^\[.*\]" | wc -l )"
        local CHECK
        CHECK="$( awk '{print $1}' "$LOG_DIR"/bap_cwe_checker/bap_"$NAME".log | grep -o "^\[.*\]" | sort -u )"
        if ! [[ $CHECK_COUNT -eq 0 ]] ; then
          print_output "[+] Found ""$CHECK_COUNT"" different security issues in ""$NAME"":"
          print_output "$( indent "$( orange "$CHECK")")"
        fi
        if [[ ${#TEST_OUTPUT[@]} -ne 0 ]] ; then echo ; fi
      fi
    done
    SUM_FCW_FIND=$(cat "$LOG_DIR"/bap_cwe_checker/bap_*.log | awk '{print $1}' | wc -l)
    if [[ $SUM_FCW_FIND -eq 0 ]] ; then
      print_output "[-] cwe-checker found 0 security issues:"
    else
      print_output "[+] cwe-checker found a total of $SUM_FCW_FIND of the following security issues:"
      print_output "$( cat "$LOG_DIR"/bap_cwe_checker/bap_*.log | grep -i '^\[' | sort -u | tr -d '[' | sed 's/].*/,/g' | tr -d '\n'  | sed 's/.$//g' | sed 's/,/, /g' )"
      CONTENT_AVAILABLE=1
    fi
    
  else
    print_output "[!] Check with bap and cwe-checker is disabled!"
  fi
  
  if [[ $HTML == 1 ]]; then
    generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}



