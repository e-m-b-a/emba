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

# Description:  Check shell scripts with shellchecker
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}
export HTML_REPORT

S20_shell_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check scripts (shellchecker)"

  S20_SHELL_VULNS=0
  S20_SCRIPTS=0
  if [[ $SHELLCHECK -eq 1 ]] ; then
    HTML_REPORT=1
    if ! [[ -d "$LOG_DIR""/shellchecker/" ]] ; then
      mkdir "$LOG_DIR""/shellchecker/" 2> /dev/null
    fi
    for LINE in "${BINARIES[@]}" ; do
      if ( file "$LINE" | grep -q "shell script" ) ; then
        ((S20_SCRIPTS++))
        NAME=$(basename "$LINE" 2> /dev/null)
        SHELL_LOG="$LOG_DIR""/shellchecker/shellchecker_""$NAME"".txt"
        shellcheck "$LINE" > "$SHELL_LOG" 2> /dev/null
        VULNS=$(grep -c "\\^-- SC" "$SHELL_LOG" 2> /dev/null)
        (( S20_SHELL_VULNS="$S20_SHELL_VULNS"+"$VULNS" ))
        if [[ "$VULNS" -ne 0 ]] ; then
          #check if this is common linux file:
          local COMMON_FILES_FOUND
          if [[ -f "$BASE_LINUX_FILES" ]]; then
            COMMON_FILES_FOUND="(""${RED}""common linux file: no""${NC}"")"
            if grep -q "^$NAME\$" "$BASE_LINUX_FILES" 2>/dev/null; then
              COMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${NC}"")"
            fi
          else
            COMMON_FILES_FOUND=""
          fi

          if [[ "$VULNS" -gt 20 ]] ; then
            print_output "[+] Found ""$RED""$VULNS"" issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$LINE")"
          else
            print_output "[+] Found ""$ORANGE""$VULNS"" issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$LINE")"
          fi
        fi
      fi
    done
    print_output ""
    print_output "[+] Found ""$ORANGE""$S20_SHELL_VULNS"" issues""$GREEN"" in ""$S20_SCRIPTS"" scripts.""$NC"""
  else
    print_output "[-] Shellchecker is disabled ... no tests performed"
  fi
}
