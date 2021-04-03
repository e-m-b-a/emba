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

# Description:  Checks for bugs, stylistic errors, etc. in shell scripts, then it lists the found error types.

S20_shell_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check scripts (shellchecker)"

  export S20_SHELL_VULNS=0
  export S20_SCRIPTS=0
  LOG_FILE="$( get_log_file )"

  if [[ $SHELLCHECK -eq 1 ]] ; then
    if ! [[ -d "$LOG_DIR""/shellchecker/" ]] ; then
      mkdir "$LOG_DIR""/shellchecker/" 2> /dev/null
    fi
    mapfile -t SH_SCRIPTS < <( find "$FIRMWARE_PATH" -xdev -type f -iname "*.sh" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
    for LINE in "${SH_SCRIPTS[@]}" ; do
      if ( file "$LINE" | grep -q "shell script" ) ; then
        ((S20_SCRIPTS++))
        NAME=$(basename "$LINE" 2> /dev/null | sed -e 's/:/_/g')
        SHELL_LOG="$LOG_DIR""/shellchecker/shellchecker_""$NAME"".txt"
        shellcheck "$LINE" > "$SHELL_LOG" 2> /dev/null
        VULNS=$(grep -c "\\^-- SC" "$SHELL_LOG" 2> /dev/null)
        (( S20_SHELL_VULNS="$S20_SHELL_VULNS"+"$VULNS" ))
        if [[ "$VULNS" -ne 0 ]] ; then
          #check if this is common linux file:
          local COMMON_FILES_FOUND
          if [[ -f "$BASE_LINUX_FILES" ]]; then
            COMMON_FILES_FOUND="(""${RED}""common linux file: no""${GREEN}"")"
            if grep -q "^$NAME\$" "$BASE_LINUX_FILES" 2>/dev/null; then
              COMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${GREEN}"")"
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
    print_output "[+] Found ""$ORANGE""$S20_SHELL_VULNS"" issues""$GREEN"" in ""$ORANGE""$S20_SCRIPTS""$GREEN"" shell scripts:""$NC""\\n"
    echo -e "\\n[*] Statistics:$S20_SHELL_VULNS:$S20_SCRIPTS" >> "$LOG_FILE"

    mapfile -t S20_VULN_TYPES < <(grep "\^--\ SC[0-9]" "$LOG_DIR"/shellchecker/shellchecker_* | cut -d: -f2- | sed -e 's/\ \+\^--\ //g' | sed -e 's/\^--\ //g' | sort -u -t: -k1,1)
    for VTYPE in "${S20_VULN_TYPES[@]}" ; do
      print_output "$(indent "$NC""[""$GREEN""+""$NC""]""$GREEN"" ""$VTYPE""$NC")"
    done

  else
    print_output "[-] Shellchecker is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "$S20_SHELL_VULNS"
}
