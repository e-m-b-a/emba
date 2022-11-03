#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck

# Description:  Checks for vulnerabilities in php scripts.
#               Checks for configuration issues in php.ini files
 
S22_php_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "PHP vulnerability checks"
  pre_module_reporter "${FUNCNAME[0]}"

  local PHP_SCRIPTS=()
  export S22_PHP_VULNS=0
  S22_PHP_SCRIPTS=0
  S22_PHP_INI_ISSUES=0
  S22_PHP_INI_CONFIGS=0
  S22_PHPINFO_ISSUES=0

  if [[ $PHP_CHECK -eq 1 ]] ; then
    mapfile -t PHP_SCRIPTS < <( find "$FIRMWARE_PATH" -xdev -type f -iname "*.php" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
    s22_vuln_check_caller "${PHP_SCRIPTS[@]}"

    s22_check_php_ini

    s22_phpinfo_check "${PHP_SCRIPTS[@]}"

    write_log ""
    write_log "[*] Statistics:$S22_PHP_VULNS:$S22_PHP_SCRIPTS:$S22_PHP_INI_ISSUES:$S22_PHP_INI_CONFIGS"

  else
    print_output "[-] PHP check is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "$(( "$S22_PHP_VULNS" + "$S22_PHP_INI_ISSUES" + "$S22_PHPINFO_ISSUES" ))"
}

s22_phpinfo_check() {
  sub_module_title "PHPinfo file detection"
  local PHP_SCRIPTS=("$@")
  local PHPINFO=""

  for PHPINFO in "${PHP_SCRIPTS[@]}" ; do
    if grep -q "phpinfo()" "$PHPINFO"; then
      print_output "[+] Found php file with debugging information: $ORANGE$PHPINFO$NC"
      grep -A 2 -B 2 "phpinfo()" "$PHPINFO" | tee -a "$LOG_FILE"
      ((S22_PHPINFO_ISSUES+=1))
    fi
  done
  print_ln
}

s22_vuln_check_caller() {
  sub_module_title "PHP script vulnerabilities"
  write_csv_log "Script path" "PHP issues detected" "common linux file"
  local PHP_SCRIPTS=("$@")
  local VULNS=0
  local PHP_SCRIPT=""

  for PHP_SCRIPT in "${PHP_SCRIPTS[@]}" ; do
    if ( file "$PHP_SCRIPT" | grep -q "PHP script" ) ; then
      ((S22_PHP_SCRIPTS+=1))
      if [[ "$THREADED" -eq 1 ]]; then
        s22_vuln_check "$PHP_SCRIPT" &
        WAIT_PIDS_S22+=( "$!" )
        max_pids_protection "$MAX_MOD_THREADS" "${WAIT_PIDS_S22[@]}"
        continue
      else
        s22_vuln_check "$PHP_SCRIPT"
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
 
  print_ln
  if [[ "$S22_PHP_VULNS" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$S22_PHP_VULNS"" vulnerabilities""$GREEN"" in ""$ORANGE""$S22_PHP_SCRIPTS""$GREEN"" php files.""$NC""\\n"
  fi
}

s22_vuln_check() {
  local PHP_SCRIPT_="${1:-}"

  if ! [[ -f "$PHP_SCRIPT_" ]]; then
    print_output "[-] No PHP script for analysis provided"
    return
  fi

  local NAME=""
  local VULNS=0

  TOTAL_MEMORY="$(grep MemTotal /proc/meminfo | awk '{print $2}' || true)"
  local MEM_LIMIT=$(( "$TOTAL_MEMORY"/2 ))

  NAME=$(basename "$PHP_SCRIPT_" 2> /dev/null | sed -e 's/:/_/g')
  local PHP_LOG="$LOG_PATH_MODULE""/php_vuln_""$NAME""-$RANDOM.txt"

  ulimit -Sv "$MEM_LIMIT"
  "$EXT_DIR"/progpilot "$PHP_SCRIPT_" >> "$PHP_LOG" 2>&1 || true
  ulimit -Sv unlimited

  VULNS=$(grep -c "vuln_name" "$PHP_LOG" 2> /dev/null || true)

  if [[ "$VULNS" -gt 0 ]] ; then
    #check if this is common linux file:
    local COMMON_FILES_FOUND
    local CFF
    if [[ -f "$BASE_LINUX_FILES" ]]; then
      COMMON_FILES_FOUND=" (""${RED}""common linux file: no""${GREEN}"")"
      CFF="no"
      if grep -q "^$NAME\$" "$BASE_LINUX_FILES" 2>/dev/null; then
        COMMON_FILES_FOUND=" (""${CYAN}""common linux file: yes""${GREEN}"")"
        CFF="yes"
      fi
    else
      COMMON_FILES_FOUND=""
      CFF="NA"
    fi
    print_output "[+] Found ""$ORANGE""$VULNS"" vulnerabilities""$GREEN"" in php file"": ""$ORANGE""$(print_path "$PHP_SCRIPT_")""$GREEN""$COMMON_FILES_FOUND""$NC" "" "$PHP_LOG"
    write_csv_log "$(print_path "$PHP_SCRIPT_")" "$VULNS" "$CFF"
    echo "$VULNS" >> "$TMP_DIR"/S22_VULNS.tmp
  else
    print_output "[*] Warning: No VULNS detected in $PHP_LOG" "no_log"
    rm "$PHP_LOG" 2>/dev/null || true
  fi
}

s22_check_php_ini(){
  sub_module_title "PHP configuration checks"
  local PHP_INI_FAILURE
  local PHP_INI_LIMIT_EXCEEDED
  local PHP_INI_WARNINGS
  local PHP_INI_FILE=()
  local PHP_FILE=""
  local INISCAN_RESULT=()
  local LINE=""
  local PHP_INISCAN_PATH="$EXT_DIR""/iniscan/vendor/bin/iniscan"
  PHP_INI_FAILURE=0
  PHP_INI_LIMIT_EXCEEDED=0
  PHP_INI_WARNINGS=0

  mapfile -t PHP_INI_FILE < <( find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -iname 'php.ini' -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  disable_strict_mode "$STRICT_MODE"
  for PHP_FILE in "${PHP_INI_FILE[@]}" ;  do
    #print_output "[*] iniscan check of ""$(print_path "$PHP_FILE")"
    mapfile -t INISCAN_RESULT < <( "$PHP_INISCAN_PATH" scan --path="$PHP_FILE" || true)
    for LINE in "${INISCAN_RESULT[@]}" ; do  
      local LIMIT_CHECK
      IFS='|' read -ra LINE_ARR <<< "$LINE"
      # TODO: STRICT mode not working here:
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
    if [[ "$S22_PHP_INI_ISSUES" -gt 0 ]]; then
      print_ln
      print_output "[+] Found ""$ORANGE""$S22_PHP_INI_ISSUES""$GREEN"" PHP configuration issues in php config file :""$ORANGE"" ""$(print_path "$PHP_FILE")"
      print_ln
    fi
  done
  enable_strict_mode "$STRICT_MODE"
}

add_recommendations(){
   local VALUE="${1:-}"
   local KEY="${2:-}"

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

