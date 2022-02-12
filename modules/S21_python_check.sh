#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Checks for bugs, stylistic errors, etc. in python scripts, then it lists the found error types.

S21_python_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check python scripts for security issues"
  pre_module_reporter "${FUNCNAME[0]}"

  S21_PY_VULNS=0
  S21_PY_SCRIPTS=0

  if [[ $PYTHON_CHECK -eq 1 ]] ; then
    mapfile -t PYTHON_SCRIPTS < <(find "$FIRMWARE_PATH" -xdev -type f -iname "*.py" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
    for LINE in "${PYTHON_SCRIPTS[@]}" ; do
      if ( file "$LINE" | grep -q "Python script.*executable" ) ; then
        ((S21_PY_SCRIPTS+=1))
        if [[ "$THREADED" -eq 1 ]]; then
          s21_script_bandit &
          WAIT_PIDS_S21+=( "$!" )
        else
          s21_script_bandit
        fi
      fi
    done

    if [[ "$THREADED" -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS_S21[@]}"
    fi

    if [[ -f "$TMP_DIR"/S21_VULNS.tmp ]]; then
      while read -r VULNS; do
        (( S21_PY_VULNS="$S21_PY_VULNS"+"$VULNS" ))
      done < "$TMP_DIR"/S21_VULNS.tmp
    fi

    if [[ "$S21_PY_VULNS" -gt 0 ]]; then
      print_output ""
      print_output "[+] Found ""$ORANGE""$S21_PY_VULNS"" vulnerabilities""$GREEN"" in ""$ORANGE""$S21_PY_SCRIPTS""$GREEN"" python files:""$NC""\\n"
    fi

    write_log ""
    write_log "[*] Statistics:$S21_PY_VULNS:$S21_PY_SCRIPTS"

    # we just print one issue per issue type:
    # W1505: Using deprecated method assert_() (deprecated-method)
    # W1505: Using deprecated method gcd() (deprecated-method)
    # W1505: Using deprecated method splitunc() (deprecated-method)
    # -> we only print one W1505

    mapfile -t S21_VULN_TYPES < <(grep "[A-Z][0-9][0-9][0-9]" "$LOG_PATH_MODULE"/pylint_* 2>/dev/null || true | cut -d: -f5- | sort -u -t: -k1,1)
    for VTYPE in "${S21_VULN_TYPES[@]}" ; do
      print_output "$(indent "$NC""[""$GREEN""+""$NC""]""$GREEN"" ""$VTYPE""$GREEN")"
    done
  else
    print_output "[-] Python check is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "$S21_PY_VULNS"
}

s21_script_bandit() {
  NAME=$(basename "$LINE" 2> /dev/null | sed -e 's/:/_/g')
  PY_LOG="$LOG_PATH_MODULE""/bandit""$NAME"".txt"
  bandit -r "$LINE" > "$PY_LOG" 2> /dev/null || true

  VULNS=$(grep -c ">> Issue: " "$PY_LOG" 2> /dev/null || true)
  if [[ "$VULNS" -ne 0 ]] ; then
    if [[ "$VULNS" -gt 20 ]] ; then
      print_output "[+] Found ""$RED""$VULNS"" issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$LINE")" ""  "$PY_LOG"
    else
      print_output "[+] Found ""$ORANGE""$VULNS"" issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$LINE")" "" "$PY_LOG"
    fi
    echo "$VULNS" >> "$TMP_DIR"/S21_VULNS.tmp
  fi

}

# lets leave this here for reasons ;)
s21_script_check() {
  NAME=$(basename "$LINE" 2> /dev/null | sed -e 's/:/_/g')
  PY_LOG="$LOG_PATH_MODULE""/pylint_""$NAME"".txt"
  pylint --max-line-length=240 -d C0115,C0114,C0116,W0511,E0401 "$LINE" > "$PY_LOG" 2> /dev/null
  VULNS=$(cut -d: -f4 "$PY_LOG" | grep -c "[A-Z][0-9][0-9][0-9]" 2> /dev/null || true)
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
      print_output "[+] Found ""$RED""$VULNS"" issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$LINE")" ""  "$PY_LOG"
    else
      print_output "[+] Found ""$ORANGE""$VULNS"" issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$LINE")" "" "$PY_LOG"
    fi
    echo "$VULNS" >> "$TMP_DIR"/S21_VULNS.tmp
  fi
}
