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

# Description:  Checks for bugs, stylistic errors, etc. in python scripts, then it lists the found error types.

S21_python_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check python scripts with pylint"

  LOG_FILE="$( get_log_file )"

  S21_PY_VULNS=0
  S21_PY_SCRIPTS=0

  if [[ $PYTHON_CHECK -eq 1 ]] ; then
    if ! [[ -d "$LOG_DIR""/pylint_checker/" ]] ; then
      mkdir "$LOG_DIR""/pylint_checker/" 2> /dev/null
    fi
    mapfile -t PYTHON_SCRIPTS < <(find "$FIRMWARE_PATH" -xdev -type f -iname "*.py" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
    for LINE in "${PYTHON_SCRIPTS[@]}" ; do
      if ( file "$LINE" | grep -q "Python script.*executable" ) ; then
        ((S21_PY_SCRIPTS++))
        NAME=$(basename "$LINE" 2> /dev/null | sed -e 's/:/_/g')
        PY_LOG="$LOG_DIR""/pylint_checker/pylint_""$NAME"".txt"
        pylint "$LINE" > "$PY_LOG" 2> /dev/null
        VULNS=$(cut -d: -f4 "$PY_LOG" | grep -c "[A-Z][0-9][0-9][0-9]" 2> /dev/null)
        (( S21_PY_VULNS="$S21_PY_VULNS"+"$VULNS" ))
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
    print_output "[+] Found ""$ORANGE""$S21_PY_VULNS"" issues""$GREEN"" in ""$ORANGE""$S21_PY_SCRIPTS""$GREEN"" python files:""$NC""\\n"
    echo -e "\\n[*] Statistics:$S21_PY_VULNS:$S21_PY_SCRIPTS" >> "$LOG_FILE"

    # we just print one issue per issue type:
    # W1505: Using deprecated method assert_() (deprecated-method)
    # W1505: Using deprecated method gcd() (deprecated-method)
    # W1505: Using deprecated method splitunc() (deprecated-method)
    # -> we only print one W1505

    mapfile -t S21_VULN_TYPES < <(grep "[A-Z][0-9][0-9][0-9]" "$LOG_DIR"/pylint_checker/pylint_* 2>/dev/null | cut -d: -f5- | sort -u -t: -k1,1)
    for VTYPE in "${S21_VULN_TYPES[@]}" ; do
      print_output "$(indent "$NC""[""$GREEN""+""$NC""]""$GREEN"" ""$VTYPE""$GREEN")"
    done
  else
    print_output "[-] Pylint check is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "$S21_PY_VULNS"
}
