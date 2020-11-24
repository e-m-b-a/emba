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

# Description:  Check shell scripts with shellchecker
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S20_shell_check()
{
  module_log_init "s20_check_scripts"
  module_title "Check scripts (shellchecker)"
  CONTENT_AVAILABLE=0

  if [[ $SHELLCHECK -eq 1 ]] ; then
    if ! [[ -d "$LOG_DIR""/shellchecker/" ]] ; then
      mkdir "$LOG_DIR""/shellchecker/" 2> /dev/null
    fi
    for LINE in "${BINARIES[@]}" ; do
      if ( file "$LINE" | grep -q "shell script" ) ; then
        NAME=$(basename "$LINE" 2> /dev/null)
        SHELL_LOG="$LOG_DIR""/shellchecker/shellchecker_""$NAME"".txt"
        shellcheck "$LINE" > "$SHELL_LOG" 2> /dev/null
        VULNS=$(grep -c "\\^-- SC" "$SHELL_LOG" 2> /dev/null)
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
    CONTENT_AVAILABLE=1
  else
    print_output "[-] Shellchecker is disabled ... no tests performed"
  fi
  if [[ $HTML == 1 ]]; then
     generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}
