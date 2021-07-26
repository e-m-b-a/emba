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

  S22_PHP_VULNS=0
  S22_PHP_SCRIPTS=0

  if [[ $PHP_CHECK -eq 1 ]] ; then
    mapfile -t PHP_SCRIPTS < <( find "$FIRMWARE_PATH" -xdev -type f -iname "*.php" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
    for LINE in "${PHP_SCRIPTS[@]}" ; do
      if ( file "$LINE" | grep -q "PHP script" ) ; then
        ((S22_PHP_SCRIPTS++))
        if [[ "$THREADED" -eq 1 ]]; then
          s22_script_check &
          WAIT_PIDS_S22+=( "$!" )
        else
          s22_script_check
        fi
      fi
    done

    if [[ "$THREADED" -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS_S22[@]}"
    fi

    if [[ -f "$TMP_DIR"/S22_VULNS.tmp ]]; then
      while read -r VULNS; do
        (( S22_PHP_VULNS="$S22_PHP_VULNS"+"$VULNS" ))
      done < "$TMP_DIR"/S22_VULNS.tmp
    fi
    
    s22_check_php_init
    print_output ""
    print_output "[+] Found ""$ORANGE""$S22_PHP_VULNS"" issues""$GREEN"" in ""$ORANGE""$S22_PHP_SCRIPTS""$GREEN"" php files.""$NC""\\n"
    write_log ""
    write_log "[*] Statistics:$S22_PHP_VULNS:$S22_PHP_SCRIPTS"

  else
    print_output "[-] PHP check is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "$S22_PHP_VULNS"
}

s22_script_check() {
  NAME=$(basename "$LINE" 2> /dev/null | sed -e 's/:/_/g')
  PHP_LOG="$LOG_PATH_MODULE""/php_""$NAME"".txt"
  php -l "$LINE" > "$PHP_LOG" 2>&1
  VULNS=$(grep -c "PHP Parse error" "$PHP_LOG" 2> /dev/null)
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
    print_output "[+] Found ""$ORANGE""parsing issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$LINE")" "" "$PHP_LOG"
    echo "$VULNS" >> "$TMP_DIR"/S22_VULNS.tmp
  fi
}

add_recommendations(){
   local VALUE
   local KEY
   VALUE="$1"
   KEY="$2"

   if [[ $VALUE == *"M"* ]]; then
      echo ".""$VALUE""."
      LIMIT="${VALUE//M/}"
   fi

   if [[ $KEY == *"memory_limit"* ]] && [[ $(( LIMIT)) -gt 50 ]]; then
     CURRENT_VALUE="$CYAN""$VALUE"
   elif [[ $KEY == *"post_max_size"* ]] && [[ $(( LIMIT)) -gt 20 ]]; then
     CURRENT_VALUE="$CYAN""$VALUE"
   elif [[ $KEY == *"max_execution_time"* ]] && [[ $(( LIMIT )) -gt 60 ]]; then
     CURRENT_VALUE="$CYAN""$VALUE"
   else
     CURRENT_VALUE="$WHITE""$VALUE"
   fi
}

s22_check_php_init(){

  mapfile -t FILES < <( sudo find / -name php.ini )
  for PHP_FILE in "${FILES[@]}"
  do
    mapfile -t INISCAN_RESULT < <( sudo "./external/iniscan/vendor/bin/iniscan" scan --path="$PHP_FILE")
    for LINE in "${INISCAN_RESULT[@]}"
    do
      if [[ $VALUE == *"|"* ]]; then
        IFS='|' read -ra LINE_ARR <<< "$LINE"
      
        if [[ "${LINE_ARR[0]}" == "FAIL"* ]]; then
          add_recommendations "${LINE_ARR[3]}" "${LINE_ARR[4]}"
          STATUS="$RED""${LINE_ARR[0]}"
        elif [[ "${LINE_ARR[0]}" == "PASS"* ]]; then
          add_recommendations "${LINE_ARR[3]}" "${LINE_ARR[4]}"
          STATUS="$GREEN""${LINE_ARR[0]}"
        else
          add_recommendations "${LINE_ARR[3]}" "${LINE_ARR[4]}"
          STATUS="$WHITE""${LINE_ARR[0]}"
        fi

        if [[ "${LINE_ARR[1]}" == "ERROR"* ]]; then
          SEVERTIY="$RED""${LINE_ARR[1]}"
          echo "$RED"
          echo "Test"
        elif [[ "${LINE_ARR[1]}" == "WARNING"* ]]; then
          SEVERTIY="$CYAN""${LINE_ARR[1]}"
        else
          SEVERTIY="$WHITE""${LINE_ARR[1]}"
        fi

        print_output "[-] ""$STATUS"" | ""$SEVERTIY"" | ""${LINE_ARR[2]}"" | ""$CURRENT_VALUE"" | ""${LINE_ARR[4]}"" | ""${LINE_ARR[5]}"
      
      else
        print_output "[-]""$WHITE""$LINE"
      fi
      CURRENT_VALUE=""
    done
  done
}