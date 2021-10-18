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
# Contributor(s): Stefan Haboeck

# Description:  Checks for bugs, stylistic errors, etc. in php scripts, then it lists the found error types.
 
S22_php_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check php scripts for vulnerabilities"

  S22_PHP_VULNS=0
  S22_PHP_SCRIPTS=0
  S22_PHP_INI_ISSUES=0
  S22_PHP_INI_CONFIGS=0

  if [[ $PHP_CHECK -eq 1 ]] ; then
    mapfile -t PHP_SCRIPTS < <( find "$FIRMWARE_PATH" -xdev -type f -iname "*.php" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
    for LINE in "${PHP_SCRIPTS[@]}" ; do
      if ( file "$LINE" | grep -q "PHP script" ) ; then
        ((S22_PHP_SCRIPTS++))
        if [[ "$THREADED" -eq 1 ]]; then
          s22_vuln_check &
          WAIT_PIDS_S22+=( "$!" )
        else
          s22_vuln_check
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
    s22_check_php_ini
    print_output ""
    print_output "[+] Found ""$ORANGE""$S22_PHP_VULNS"" vulnerabilities""$GREEN"" in ""$ORANGE""$S22_PHP_SCRIPTS""$GREEN"" php files.""$NC""\\n"
    write_log ""
    write_log "[*] Statistics:$S22_PHP_VULNS:$S22_PHP_SCRIPTS:$S22_PHP_INI_ISSUES:$S22_PHP_INI_CONFIGS"

  else
    print_output "[-] PHP check is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "$(( $S22_PHP_VULNS + $S22_PHP_INI_ISSUES ))"
}

s22_vuln_check() {
  NAME=$(basename "$LINE" 2> /dev/null | sed -e 's/:/_/g')
  PHP_LOG="$LOG_PATH_MODULE""/php_vuln""$NAME"".txt"
  ./external/progpilot "$LINE" > "$PHP_LOG" 2>&1
  VULNS=$(grep -c "vuln_name" "$PHP_LOG" 2> /dev/null)

  if [[ "$VULNS" -ne 0 ]] ; then
    #check if this is common linux file:
    local COMMON_FILES_FOUND
    if [[ -f "$BASE_LINUX_FILES" ]]; then
      COMMON_FILES_FOUND=" (""${RED}""common linux file: no""${GREEN}"")"
      if grep -q "^$NAME\$" "$BASE_LINUX_FILES" 2>/dev/null; then
        COMMON_FILES_FOUND=" (""${CYAN}""common linux file: yes""${GREEN}"")"
      fi
    else
      COMMON_FILES_FOUND=""
    fi
    print_output "[+] Found ""$ORANGE""$VULNS"" vulnerabilities""$GREEN"" in php file"": ""$ORANGE""$(print_path "$LINE")""$GREEN""$COMMON_FILES_FOUND""$NC" "" "$PHP_LOG"
    echo "$VULNS" >> "$TMP_DIR"/S22_VULNS.tmp
  fi
}

# lets leave this here. Probably it is of interest for dev teams
# for this you need to call it (see line 32/35)
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
    print_output "[+] Found ""$ORANGE""parsing issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$LINE")"
    echo "$VULNS" >> "$TMP_DIR"/S22_VULNS.tmp
  fi
}

add_recommendations(){
   local VALUE
   local KEY
   VALUE="$1"
   KEY="$2"

   if [[ $VALUE == *"M"* ]]; then
      LIMIT="${VALUE//M/}"
   fi

   if [[ $KEY == *"memory_limit"* ]] && [[ $(( LIMIT)) -gt 50 ]]; then
     return 1
   elif [[ $KEY == *"post_max_size"* ]] && [[ $(( LIMIT)) -gt 20 ]]; then
     return 1
   elif [[ $KEY == *"max_execution_time"* ]] && [[ $(( LIMIT )) -gt 60 ]]; then
     return 1
   else
     return 0
   fi
}

s22_check_php_ini(){
  local PHP_INI_FAILURE
  local PHP_INI_LIMIT_EXCEEDED
  local PHP_INI_WARNINGS
  PHP_INI_FAILURE=0
  PHP_INI_LIMIT_EXCEEDED=0
  PHP_INI_WARNINGS=0
  mapfile -t PHP_INI_FILE < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname 'php.ini' -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  for PHP_FILE in "${PHP_INI_FILE[@]}" ;  do
    print_output "[*] iniscan check of ""$(print_path "$PHP_FILE")"
    mapfile -t INISCAN_RESULT < <( "$PHP_INISCAN_PATH" scan --path="$PHP_FILE" 2>/dev/null)
    for LINE in "${INISCAN_RESULT[@]}" ; do  
      local LIMIT_CHECK
      IFS='|' read -ra LINE_ARR <<< "$LINE"
      add_recommendations "${LINE_ARR[3]}" "${LINE_ARR[4]}"
      LIMIT_CHECK="$?"
      if [[ "$LIMIT_CHECK" -eq 1 ]]; then
        print_output "$(magenta "$LINE")"
        PHP_INI_LIMIT_EXCEEDED=$(( PHP_INI_LIMIT_EXCEEDED+1 ))
      elif ( echo "$LINE" | grep -q "FAIL" ) && ( echo "$LINE" | grep -q "ERROR" ) ; then
        print_output "$(red "$LINE")"
      elif ( echo "$LINE" | grep -q "FAIL" ) && ( echo "$LINE" | grep -q "WARNING" )  ; then
        print_output "$(orange "$LINE")"
      elif ( echo "$LINE" | grep -q "FAIL" ) && ( echo "$LINE" | grep -q "INFO" ) ; then
        print_output "$(blue "$LINE")"
      elif ( echo "$LINE" | grep -q "PASS" ) ; then
        continue
      else
        if ( echo "$LINE" | grep -q "failure" ) && ( echo "$LINE" | grep -q "warning" ) ; then
          IFS=' ' read -ra LINE_ARR <<< "$LINE"
          PHP_INI_FAILURE=${LINE_ARR[0]}
          PHP_INI_WARNINGS=${LINE_ARR[3]}
          (( S22_PHP_INI_ISSUES="$S22_PHP_INI_ISSUES"+"$PHP_INI_LIMIT_EXCEEDED"+"$PHP_INI_FAILURE"+"$PHP_INI_WARNINGS" ))
          S22_PHP_INI_CONFIGS=$(( S22_PHP_INI_CONFIGS+1 ))
        elif ( echo "$LINE" | grep -q "passing" ) ; then
          IFS=' ' read -ra LINE_ARR <<< "$LINE"
          LINE_ARR[0]=$(( LINE_ARR[0]-PHP_INI_LIMIT_EXCEEDED ))
        fi
      fi
    done
  done
}
