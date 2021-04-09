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

# Description:  Runs a Docker container with cwe-checker on Ghidra to check binary for
#               common bug classes such as vicious functions or integer overflows.
#               As the runtime is quite long, it needs to be activated separately via -c switch.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=1

S120_cwe_checker()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries with cwe-checker"

  LOG_FILE="$( get_log_file )"

  if [[ $CWE_CHECKER -eq 1 ]] ; then
    cwe_check
    final_cwe_log "$TOTAL_CWE_CNT"

    echo -e "\\n[*] Statistics:$TOTAL_CWE_CNT" >> "$LOG_FILE"
  else
    print_output "[!] Check with cwe-checker is disabled!"
    print_output "[!] Enable it with the -c switch."
  fi

  module_end_log "${FUNCNAME[0]}" "${#CWE_OUT[@]}"
}

cwe_check() {
  TOTAL_CWE_CNT=0

  for LINE in "${BINARIES[@]}" ; do
    if ( file "$LINE" | grep -q ELF ) ; then
      NAME=$(basename "$LINE")
      LINE=$(readlink -f "$LINE")
      readarray -t TEST_OUTPUT < <( docker run --rm -v "$LINE":/tmp/input fkiecad/cwe_checker /tmp/input | tee -a "$LOG_DIR"/cwe_checker/cwe_"$NAME".log )
      if [[ ${#TEST_OUTPUT[@]} -ne 0 ]] ; then
        print_output "[*] ""$(print_path "$LINE")"
      fi
      for ENTRY in "${TEST_OUTPUT[@]}" ; do
        if [[ -n "$ENTRY" ]] ; then
          if ! [[ "$ENTRY" == *"ERROR:"* || "$ENTRY" == *"DEBUG:"* || "$ENTRY" == *"INFO:"* ]] ; then
            print_output "$(indent "$ENTRY")"
          fi
        fi
      done

      mapfile -t CWE_OUT < <( grep -v "ERROR\|DEBUG\|INFO" "$LOG_DIR"/cwe_checker/cwe_"$NAME".log | grep "CWE[0-9]" | sed -z 's/[0-9]\.[0-9]//g' | cut -d\( -f1,3 | cut -d\) -f1 | sort -u | tr -d '(' | tr -d "[" | tr -d "]" )

      # this is the logging after every tested file
      if [[ ${#CWE_OUT[@]} -ne 0 ]] ; then
        print_output ""
        print_output "[+] cwe-checker found ""$ORANGE""${#CWE_OUT[@]}""$GREEN"" different security issues in ""$ORANGE""$NAME""$GREEN"":"
        for CWE_LINE in "${CWE_OUT[@]}"; do
          CWE="$(echo "$CWE_LINE" | cut -d\  -f1)"
          CWE_DESC="$(echo "$CWE_LINE" | cut -d\  -f2-)"
          CWE_CNT="$(grep -c "$CWE" "$LOG_DIR"/cwe_checker/cwe_"$NAME".log 2>/dev/null)"
          (( TOTAL_CWE_CNT="$TOTAL_CWE_CNT"+"$CWE_CNT" ))
          print_output "$(indent "$(orange "$CWE""$GREEN"" - ""$CWE_DESC"" - ""$ORANGE""$CWE_CNT"" times.")")"
        done
      fi
      if [[ ${#TEST_OUTPUT[@]} -ne 0 ]] ; then echo ; fi
    fi
  done
}

final_cwe_log() {
  TOTAL_CWE_CNT="$1"

  if [[ -d "$LOG_DIR""/cwe_checker" ]]; then
    mapfile -t CWE_OUT < <( cat "$LOG_DIR"/cwe_checker/cwe_*.log 2>/dev/null | grep -v "ERROR\|DEBUG\|INFO" | grep "CWE[0-9]" | sed -z 's/[0-9]\.[0-9]//g' | cut -d\( -f1,3 | cut -d\) -f1 | sort -u | tr -d '(' | tr -d "[" | tr -d "]" )
    print_output ""
    if [[ ${#CWE_OUT[@]} -eq 0 ]] ; then
      print_output "[-] cwe-checker found 0 security issues."
    else
      print_output "[+] cwe-checker found a total of ""$ORANGE""$TOTAL_CWE_CNT""$GREEN"" of the following security issues:"
      for CWE_LINE in "${CWE_OUT[@]}"; do
        CWE="$(echo "$CWE_LINE" | cut -d\  -f1)"
        CWE_DESC="$(echo "$CWE_LINE" | cut -d\  -f2-)"
        CWE_CNT="$(cat "$LOG_DIR"/cwe_checker/cwe_*.log 2>/dev/null | grep -c "$CWE")"
        print_output "$(indent "$(orange "$CWE""$GREEN"" - ""$CWE_DESC"" - ""$ORANGE""$CWE_CNT"" times.")")"
      done
    fi
  fi
}

