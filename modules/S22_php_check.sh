#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Checks for bugs, stylistic errors, etc. in php scripts, then it lists the found error types.

S22_php_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check php scripts for syntax errors"

  LOG_FILE="$( get_log_file )"

  S22_PHP_VULNS=0
  S22_PHP_SCRIPTS=0

  if [[ $PHP_CHECK -eq 1 ]] ; then
    if ! [[ -d "$LOG_DIR""/php_checker/" ]] ; then
      mkdir "$LOG_DIR""/php_checker/" 2> /dev/null
    fi
    mapfile -t PHP_SCRIPTS < <( find "$FIRMWARE_PATH" -xdev -type f -iname "*.php" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
    for LINE in "${PHP_SCRIPTS[@]}" ; do
      if ( file "$LINE" | grep -q "PHP script" ) ; then
        ((S22_PHP_SCRIPTS++))
        NAME=$(basename "$LINE" 2> /dev/null | sed -e 's/:/_/g')
        PHP_LOG="$LOG_DIR""/php_checker/php_""$NAME"".txt"
        php -l "$LINE" > "$PHP_LOG" 2>&1
        VULNS=$(grep -c "PHP Parse error" "$PHP_LOG" 2> /dev/null)
        (( S22_PHP_VULNS="$S22_PHP_VULNS"+"$VULNS" ))
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
          print_output "[+] Found ""$ORANGE""parsing issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$LINE")"
        fi
      fi
    done
    print_output ""
    print_output "[+] Found ""$ORANGE""$S22_PHP_VULNS"" issues""$GREEN"" in ""$ORANGE""$S22_PHP_SCRIPTS""$GREEN"" php files.""$NC""\\n"
    echo -e "\\n[*] Statistics:$S22_PHP_VULNS:$S22_PHP_SCRIPTS" >> "$LOG_FILE"

  else
    print_output "[-] PHP check is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "$S22_PHP_VULNS"
}
