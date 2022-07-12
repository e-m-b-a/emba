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
# Contributor(s): Chao Yang - firmianay

# Description:  Runs a Docker container with cwe-checker on Ghidra to check binary for
#               common bug classes such as vicious functions or integer overflows.
#               As the runtime is quite long, it needs to be activated separately via -c switch.
#               Currently this module only work in a non docker environment!

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=1

S120_cwe_checker()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries with cwe-checker"
  pre_module_reporter "${FUNCNAME[0]}"
  local CWE_CNT_=0

  if [[ $CWE_CHECKER -eq 1 ]] ; then
    if [[ "$IN_DOCKER" -eq 1 ]]; then
      cwe_container_prepare
    fi
    cwe_check

    if [[ -f "$TMP_DIR"/CWE_CNT.tmp ]]; then
      while read -r COUNTING; do
        (( CWE_CNT_="$CWE_CNT_"+"$COUNTING" ))
      done < "$TMP_DIR"/CWE_CNT.tmp
    fi

    final_cwe_log "$CWE_CNT_"

    write_log ""
    write_log "[*] Statistics:$CWE_CNT_"
  else
    print_output "[!] Check with cwe-checker is disabled!"
    print_output "[!] Enable it with the -c switch."
  fi

  module_end_log "${FUNCNAME[0]}" "$CWE_CNT_"
}

cwe_container_prepare() {
  if [[ -d "$EXT_DIR"/cwe_checker/.config ]]; then
    print_output "[*] Restoring config directory in read-only container"
    cp -r "$EXT_DIR"/cwe_checker/.config /root/
    cp -r "$EXT_DIR"/cwe_checker/.local /root/
  fi
}

cwe_check() {
  local BINARY=""

  export PATH=$EXT_DIR/cwe_checker/bin:$PATH # needed for docker setup

  for BINARY in "${BINARIES[@]}" ; do
    if ( file "$BINARY" | grep -q ELF ) ; then
      if [[ "$THREADED" -eq 1 ]]; then
        MAX_THREADS_S120=$((1*"$(grep -c ^processor /proc/cpuinfo || true)"))
        if [[ $(grep -c S09_ "$LOG_DIR"/"$MAIN_LOG_FILE" || true) -eq 1 ]]; then
          MAX_THREADS_S120=1
        fi

        cwe_checker_threaded "$BINARY" &
        WAIT_PIDS_S120+=( "$!" )
        max_pids_protection "$MAX_THREADS_S120" "${WAIT_PIDS_S120[@]}"
      else
        cwe_checker_threaded "$BINARY"
      fi
    fi
  done

  if [[ $THREADED -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_S120[@]}"
  fi
}

cwe_checker_threaded () {
  local BINARY_="${1:-}"
  local TEST_OUTPUT=()
  local CWE_OUT=()
  local CWE_LINE=""
  local CWE=""
  local CWE_DESC=""
  local CWE_CNT=0

  local NAME=""
  NAME=$(basename "$BINARY_")
  local OLD_LOG_FILE="$LOG_FILE"
  local LOG_FILE="$LOG_PATH_MODULE""/cwe_check_""$NAME"".txt"
  BINARY_=$(readlink -f "$BINARY_")
  readarray -t TEST_OUTPUT < <( cwe_checker "$LINE" 2>/dev/null | tee -a "$LOG_PATH_MODULE"/cwe_"$NAME".log || true)
  print_output "[*] Tested $ORANGE""$(print_path "$BINARY_")""$NC"
  for ENTRY in "${TEST_OUTPUT[@]}" ; do
    if [[ -n "$ENTRY" ]] ; then
      if ! [[ "$ENTRY" == *"ERROR:"* || "$ENTRY" == *"DEBUG:"* || "$ENTRY" == *"INFO:"* ]] ; then
        print_output "$(indent "$ENTRY")"
      fi
    fi
  done
  if [[ -f "$LOG_PATH_MODULE"/cwe_"$NAME".log ]]; then
    mapfile -t CWE_OUT < <( grep -v "ERROR\|DEBUG\|INFO" "$LOG_PATH_MODULE"/cwe_"$NAME".log | grep "CWE[0-9]" | sed -z 's/[0-9]\.[0-9]//g' | cut -d\( -f1,3 | cut -d\) -f1 | sort -u | tr -d '(' | tr -d "[" | tr -d "]" || true)
    # this is the logging after every tested file
    if [[ ${#CWE_OUT[@]} -ne 0 ]] ; then
      print_output ""
      print_output "[+] cwe-checker found ""$ORANGE""${#CWE_OUT[@]}""$GREEN"" different security issues in ""$ORANGE""$NAME""$GREEN"":" "" "$LOG_PATH_MODULE"/cwe_"$NAME".log
      for CWE_LINE in "${CWE_OUT[@]}"; do
        CWE="$(echo "$CWE_LINE" | cut -d\  -f1)"
        CWE_DESC="$(echo "$CWE_LINE" | cut -d\  -f2-)"
        CWE_CNT="$(grep -c "$CWE" "$LOG_PATH_MODULE"/cwe_"$NAME".log 2>/dev/null || true)"
        echo "$CWE_CNT" >> "$TMP_DIR"/CWE_CNT.tmp
        print_output "$(indent "$(orange "$CWE""$GREEN"" - ""$CWE_DESC"" - ""$ORANGE""$CWE_CNT"" times.")")"
      done
      print_output ""
    else
      print_output ""
      print_output "[-] Nothing found in ""$ORANGE""$NAME""$NC""\\n"
    fi
  fi
  if [[ ${#TEST_OUTPUT[@]} -ne 0 ]] ; then print_output "" ; fi

  if [[ -f "$LOG_FILE" ]]; then
    cat "$LOG_FILE" >> "$OLD_LOG_FILE"
    rm "$LOG_FILE" 2> /dev/null
  fi
  LOG_FILE="$OLD_LOG_FILE"
}

final_cwe_log() {
  local TOTAL_CWE_CNT="${1:-}"
  local CWE_OUT=()
  local CWE_LINE=""
  local CWE=""
  local CWE_DESC=""
  local CWE_CNT=""

  if [[ -d "$LOG_PATH_MODULE" ]]; then
    mapfile -t CWE_OUT < <( cat "$LOG_PATH_MODULE"/cwe_*.log 2>/dev/null | grep -v "ERROR\|DEBUG\|INFO" | grep "CWE[0-9]" | sed -z 's/[0-9]\.[0-9]//g' | cut -d\( -f1,3 | cut -d\) -f1 | sort -u | tr -d '(' | tr -d "[" | tr -d "]" || true)
    print_output ""
    if [[ ${#CWE_OUT[@]} -gt 0 ]] ; then
      print_output "[+] cwe-checker found a total of ""$ORANGE""$TOTAL_CWE_CNT""$GREEN"" of the following security issues:"
      for CWE_LINE in "${CWE_OUT[@]}"; do
        CWE="$(echo "$CWE_LINE" | cut -d\  -f1)"
        CWE_DESC="$(echo "$CWE_LINE" | cut -d\  -f2-)"
        CWE_CNT="$(cat "$LOG_PATH_MODULE"/cwe_*.log 2>/dev/null | grep -c "$CWE" || true)"
        print_output "$(indent "$(orange "$CWE""$GREEN"" - ""$CWE_DESC"" - ""$ORANGE""$CWE_CNT"" times.")")"
      done
      print_output ""
    fi
  fi
}

