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

# Description:  Checks for bugs, stylistic errors, etc. in shell scripts, then it lists the found error types.

S20_shell_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check scripts with shellcheck and semgrep"
  pre_module_reporter "${FUNCNAME[0]}"

  export S20_SHELL_VULNS=0
  export S20_SCRIPTS=0
  local SH_SCRIPTS=()
  local SH_SCRIPT=""
  local S20_VULN_TYPES=()
  local VTYPE=""
  local SEMGREP=1

  mapfile -t SH_SCRIPTS < <( find "$FIRMWARE_PATH" -xdev -type f -iname "*.sh" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  write_csv_log "Script path" "Shell issues detected" "common linux file" "shellcheck/semgrep"

  if [[ $SHELLCHECK -eq 1 ]] ; then
    sub_module_title "Check scripts with shellcheck"
    for SH_SCRIPT in "${SH_SCRIPTS[@]}" ; do
      if ( file "$SH_SCRIPT" | grep -q "shell script" ) ; then
        ((S20_SCRIPTS+=1))
        if [[ "$THREADED" -eq 1 ]]; then
          s20_script_check "$SH_SCRIPT" &
          WAIT_PIDS_S20+=( "$!" )
          max_pids_protection "$MAX_MOD_THREADS" "${WAIT_PIDS_S20[@]}"
          continue
        else
          s20_script_check "$SH_SCRIPT"
        fi
      fi
    done

    if [[ "$THREADED" -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS_S20[@]}"
    fi

    if [[ -f "$TMP_DIR"/S20_VULNS.tmp ]]; then
      while read -r VULNS; do
        S20_SHELL_VULNS=$((S20_SHELL_VULNS+VULNS))
      done < "$TMP_DIR"/S20_VULNS.tmp
      rm "$TMP_DIR"/S20_VULNS.tmp
    fi

    print_ln
    sub_module_title "Summary of shell issues (shellcheck)"
    print_output "[+] Found ""$ORANGE""$S20_SHELL_VULNS"" issues""$GREEN"" in ""$ORANGE""$S20_SCRIPTS""$GREEN"" shell scripts""$NC""\\n"
    write_log ""
    write_log "[*] Statistics:$S20_SHELL_VULNS:$S20_SCRIPTS"

    mapfile -t S20_VULN_TYPES < <(grep "\^--\ SC[0-9]" "$LOG_PATH_MODULE"/shellchecker_* 2>/dev/null | cut -d: -f2- | sed -e 's/\ \+\^--\ //g' | sed -e 's/\^--\ //g' | sort -u -t: -k1,1 || true)
    for VTYPE in "${S20_VULN_TYPES[@]}" ; do
      print_output "$(indent "$NC""[""$GREEN""+""$NC""]""$GREEN"" ""$VTYPE""$NC")"
    done

  else
    print_output "[-] Shellchecker is disabled ... no tests performed"
  fi

  if [[ $SEMGREP -eq 1 ]] ; then
    sub_module_title "Check scripts with semgrep"
    export S20_SCRIPTS=0
    export S20_SHELL_VULNS=0
    SHELL_LOG="$LOG_PATH_MODULE"/semgrep.log

    for SH_SCRIPT in "${SH_SCRIPTS[@]}" ; do
      if ( file "$SH_SCRIPT" | grep -q "shell script" ) ; then
        ((S20_SCRIPTS+=1))
        if [[ "$THREADED" -eq 1 ]]; then
          s20_semgrep_script_check "$SH_SCRIPT" &
          WAIT_PIDS_S20+=( "$!" )
          max_pids_protection "$MAX_MOD_THREADS" "${WAIT_PIDS_S20[@]}"
          continue
        else
          s20_semgrep_script_check "$SH_SCRIPT"
        fi
      fi
    done

    if [[ "$THREADED" -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS_S20[@]}"
    fi

    if [[ -f "$TMP_DIR"/S20_VULNS.tmp ]]; then
      while read -r VULNS; do
        S20_SHELL_VULNS=$((S20_SHELL_VULNS+VULNS))
      done < "$TMP_DIR"/S20_VULNS.tmp
      rm "$TMP_DIR"/S20_VULNS.tmp
    fi

    print_ln
    print_output "[+] Found ""$ORANGE""$S20_SHELL_VULNS"" issues""$GREEN"" in ""$ORANGE""$S20_SCRIPTS""$GREEN"" shell scripts""$NC""\\n"
    write_log ""
    write_log "[*] Statistics:$S20_SHELL_VULNS:$S20_SCRIPTS"
  else
    print_output "[-] Semgrepper is disabled ... no tests performed"
  fi

  module_end_log "${FUNCNAME[0]}" "$S20_SHELL_VULNS"
}

s20_semgrep_script_check() {
  local SH_SCRIPT_="${1:-}"
  local NAME=""
  local SHELL_LOG=""
  local VULNS=""
  if ! [[ -d "$EXT_DIR"/semgrep-rules/bash ]]; then
    print_output "[*] No semgrep rules found"
    return
  fi

  NAME=$(basename "$SH_SCRIPT_" 2> /dev/null | sed -e 's/:/_/g')
  SHELL_LOG="$LOG_PATH_MODULE""/semgrep_""$NAME"".txt"
  #semgrep --disable-version-check --config "$EXT_DIR"/semgrep-rules/bash "$SH_SCRIPT_" > "$SHELL_LOG" 2>&1
  print_output "[*] Testing $SH_SCRIPT_"
  semgrep --disable-version-check --config "$EXT_DIR"/semgrep-rules/bash "$SH_SCRIPT_"
  VULNS=$(grep "\ findings\." "$SHELL_LOG" | cut -d: -f2 | awk '{print $1}')

  s20_reporter "$VULNS" "$SH_SCRIPT_" "$SHELL_LOG"
}

s20_script_check() {
  local SH_SCRIPT_="${1:-}"
  local CFF=""
  local NAME=""
  local SHELL_LOG=""
  local VULNS=""

  NAME=$(basename "$SH_SCRIPT_" 2> /dev/null | sed -e 's/:/_/g')
  SHELL_LOG="$LOG_PATH_MODULE""/shellchecker_""$NAME"".txt"
  shellcheck -C "$SH_SCRIPT_" > "$SHELL_LOG" 2> /dev/null || true
  VULNS=$(grep -c "\\^-- SC" "$SHELL_LOG" 2> /dev/null || true)

  s20_reporter "$VULNS" "$SH_SCRIPT_" "$SHELL_LOG"
}

s20_reporter() {
  local VULNS="${1:0}"
  local SH_SCRIPT_="${2:0}"
  local SHELL_LOG="${3:0}"

  if [[ "$VULNS" -ne 0 ]] ; then
    #check if this is common linux file:
    local COMMON_FILES_FOUND
    if [[ -f "$BASE_LINUX_FILES" ]]; then
      COMMON_FILES_FOUND="(""${RED}""common linux file: no""${GREEN}"")"
      CFF="no"
      if grep -q "^$NAME\$" "$BASE_LINUX_FILES" 2>/dev/null; then
        COMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${GREEN}"")"
        CFF="yes"
      fi
    else
      COMMON_FILES_FOUND=""
    fi

    if [[ "$VULNS" -gt 20 ]] ; then
      print_output "[+] Found ""$RED""$VULNS"" issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$SH_SCRIPT")" "" "$SHELL_LOG"
    else
      print_output "[+] Found ""$ORANGE""$VULNS"" issues""$GREEN"" in script ""$COMMON_FILES_FOUND"":""$NC"" ""$(print_path "$SH_SCRIPT")" "" "$SHELL_LOG"
    fi
    write_csv_log "$(print_path "$SH_SCRIPT")" "$VULNS" "$CFF" "NA"
    
    echo "$VULNS" >> "$TMP_DIR"/S20_VULNS.tmp
  fi
}
