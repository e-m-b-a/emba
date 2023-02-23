#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner
# Credits:   Binarly for support

# Description:  Uses FwHunt for identification of vulnerabilities in possible UEFI firmware
#               images:
#               fwhunt-scan https://github.com/binarly-io/fwhunt-scan
#               fwhunt rules https://github.com/binarly-io/FwHunt

S02_UEFI_FwHunt() {

  module_log_init "${FUNCNAME[0]}"
  module_title "Binarly UEFI FwHunt analyzer"
  pre_module_reporter "${FUNCNAME[0]}"

  local NEG_LOG=0
  local WAIT_PIDS_S02=()
  local MAX_MOD_THREADS=$((MAX_MOD_THREADS/2))
  local EXTRACTED_FILE=""

  if [[ "$RTOS" -eq 1 ]] && [[ "$UEFI_DETECTED" -eq 1 ]] && [[ -v FILE_ARR_LIMITED ]]; then
    print_output "[*] Starting FwHunter UEFI firmware vulnerability detection"
    for EXTRACTED_FILE in "${FILE_ARR_LIMITED[@]}"; do
      if [[ $THREADED -eq 1 ]]; then
        fwhunter "$EXTRACTED_FILE" &
        local TMP_PID="$!"
        store_kill_pids "$TMP_PID"
        WAIT_PIDS_S02+=( "$TMP_PID" )
        max_pids_protection "$MAX_MOD_THREADS" "${WAIT_PIDS_S02[@]}"
      else
        fwhunter "$EXTRACTED_FILE"
      fi
    done
  fi

  [[ $THREADED -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S02[@]}"

  fwhunter_logging

  [[ "${#FWHUNTER_RESULTS[@]}" -gt 0 ]] && NEG_LOG=1

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

fwhunter() {
  local FWHUNTER_CHECK_FILE="${1:-}"
  local FWHUNTER_CHECK_FILE_NAME=""
  FWHUNTER_CHECK_FILE_NAME=$(basename "$FWHUNTER_CHECK_FILE")
  local MEM_LIMIT=$(( "$TOTAL_MEMORY"*80/100 ))

  print_output "[*] Running FwHunt on $ORANGE$FWHUNTER_CHECK_FILE$NC" "" "$LOG_PATH_MODULE""/fwhunt_scan_$FWHUNTER_CHECK_FILE_NAME.txt"
  ulimit -Sv "$MEM_LIMIT"
  write_log "[*] Running FwHunt on $ORANGE$FWHUNTER_CHECK_FILE$NC" "$LOG_PATH_MODULE""/fwhunt_scan_$FWHUNTER_CHECK_FILE_NAME.txt"
  timeout --preserve-status --signal SIGINT 600 python3 "$EXT_DIR"/fwhunt-scan/fwhunt_scan_analyzer.py scan-firmware "$FWHUNTER_CHECK_FILE" --rules_dir "$EXT_DIR"/fwhunt-scan/rules/ | tee -a "$LOG_PATH_MODULE""/fwhunt_scan_$FWHUNTER_CHECK_FILE_NAME.txt" || true
  ulimit -Sv unlimited

  # delete empty log files
  if [[ $(wc -l "$LOG_PATH_MODULE""/fwhunt_scan_$FWHUNTER_CHECK_FILE_NAME.txt" | awk '{print $1}') -eq 1 ]]; then
    rm "$LOG_PATH_MODULE""/fwhunt_scan_$FWHUNTER_CHECK_FILE_NAME.txt" || true
  fi
}

fwhunter_logging() {
  export FWHUNTER_RESULTS=()
  local FWHUNTER_RESULT=""
  local FWHUNTER_RESULT_FILE=""
  local FWHUNTER_BINARLY_ID=""
  local BINARLY_ID_FILE=""
  local FWHUNTER_BINARLY_ID_FILES=()
  local CVE_RESULTS_BINARLY=()
  local FWHUNTER_CVEs=""

  mapfile -t FWHUNTER_RESULTS < <(find "$LOG_PATH_MODULE" -type f -exec grep -H "Scanner result.*FwHunt rule has been triggered" {} \;)
  if ! [[ "${#FWHUNTER_RESULTS[@]}" -gt 0 ]]; then
    return
  fi

  sub_module_title "FwHunt UEFI vulnerability details"
  write_csv_log "BINARY" "VERSION" "CVE identifier" "CVSS rating" "BINARLY ID"

  for FWHUNTER_RESULT in "${FWHUNTER_RESULTS[@]}"; do
    local CVE_RESULTS_BINARLY=()

    FWHUNTER_RESULT_FILE=$(echo "$FWHUNTER_RESULT" | cut -d: -f1)
    FWHUNTER_BINARLY_ID=$(echo "$FWHUNTER_RESULT" | sed 's/.*\ BRLY-/BRLY-/' | sed 's/\ .variant:\ .*//g')
    mapfile -t FWHUNTER_BINARLY_ID_FILES < <(find "$EXT_DIR"/fwhunt-scan/rules -iname "$FWHUNTER_BINARLY_ID*")
    for BINARLY_ID_FILE in "${FWHUNTER_BINARLY_ID_FILES[@]}"; do
      # extract possible CVE information from the binarly scan rule:
      mapfile -t CVE_RESULTS_BINARLY_ < <(grep "CVE number:" "$BINARLY_ID_FILE" | cut -d: -f2 | tr ',' '\n' | awk '{print $1}')
      CVE_RESULTS_BINARLY+=("${CVE_RESULTS_BINARLY_[@]}")
    done
    FWHUNTER_BINARY_MATCH=$(basename "$(grep "Running FwHunt on" "$FWHUNTER_RESULT_FILE" | cut -d\  -f5-)")
    FWHUNTER_RESULT=$(echo "$FWHUNTER_RESULT" | cut -d: -f2-)
    BINARLY_RULE=$(echo "$FWHUNTER_RESULT" | sed -e 's/.*\ BRLY/BRLY/' | sed -e 's/\ .variant\:\ .*//')
    if [[ "$FWHUNTER_RESULT" == *"rule has been triggered and threat detected"* ]]; then
      if [[ "${#CVE_RESULTS_BINARLY[@]}" -gt 0 ]]; then
        for BINARLY_ID_CVE in "${CVE_RESULTS_BINARLY[@]}"; do
          # if we have CVE details we include it into our reporting
          print_output "[+] $FWHUNTER_BINARY_MATCH $ORANGE:$GREEN $FWHUNTER_RESULT$GREEN - CVE: $ORANGE$BINARLY_ID_CVE$NC" "" "https://binarly.io/advisories/$BINARLY_RULE"
          write_csv_log "$FWHUNTER_BINARY_MATCH" "unknown" "$BINARLY_ID_CVE" "unknown" "$BINARLY_RULE"
        done
      else
        # if we do not have CVE details we can't include it into our reporting
        print_output "[+] $FWHUNTER_BINARY_MATCH $ORANGE:$GREEN $FWHUNTER_RESULT$NC" "" "https://binarly.io/advisories/$BINARLY_RULE"
        write_csv_log "$FWHUNTER_BINARY_MATCH" "unknown" "NA" "unknown" "$BINARLY_RULE"
      fi
    fi
  done

  mapfile -t FWHUNTER_CVEs < <(grep "CVE" "$LOG_FILE" | cut -d: -f4 | sort -u || true)
  mapfile -t FWHUNTER_BINARLY_IDs < <(grep "FwHunt rule has been triggered and threat detected" "$LOG_PATH_MODULE"/* | sed 's/.*BRLY-/BRLY-/' | sed 's/\ .variant:\ .*//g' | sort -u || true)

  print_ln
  print_ln
  # default: output of CVE data
  # backup: output of binarly IDs
  if [[ "${#FWHUNTER_CVEs[@]}" -gt 0 ]]; then
    print_output "[*] Detected $ORANGE${#FWHUNTER_CVEs[@]}$NC firmware issues in UEFI firmware:"
    for BINARLY_CVE in "${FWHUNTER_CVEs[@]}"; do
      print_output "$(indent "$(orange "$BINARLY_CVE")")"
    done
  elif [[ "${#FWHUNTER_BINARLY_IDs[@]}" -gt 0 ]]; then
    print_output "[*] Detected $ORANGE${#FWHUNTER_BINARLY_IDs[@]}$NC firmware issues in UEFI firmware:"
    for BINARLY_ID in "${FWHUNTER_BINARLY_IDs[@]}"; do
      print_output "$(indent "$(orange "$BINARLY_ID")")"
    done
  fi
  print_ln

  write_log ""
  write_log "[*] Statistics:${#FWHUNTER_CVEs[@]}"
}
