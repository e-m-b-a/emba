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


S17_apk_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Android apk checks"

  apk_identifier
  apk_checker

  module_end_log "${FUNCNAME[0]}" "${#COUNT_FINDINGS[@]}"
}

apk_identifier() {
  sub_module_title "Android apk identifier"
  export APK_ARR=()
  local APK=""

  mapfile -t APK_ARR < <(find "$FIRMWARE_PATH" -type f -name "*.apk")
  for APK in "${APK_ARR[@]}"; do
    print_output "[+] Found Android apk - $(print_path "$APK")"
  done
}

apk_checker() {
  sub_module_title "Android apk analysis"
  local APK=""
  if ! [[ -d "$EXT_DIR"/APKHunt ]]; then
    print_output "[-] APKHunt installation missing."
    return
  fi

  export GOTMPDIR="$TMP_DIR"/apkhunt
  mkdir "$GOTMPDIR"

  for APK in "${APK_ARR[@]}"; do
    if [[ "$THREADED" -eq 1 ]]; then
      apk_checker_helper "$APK" &
      local TMP_PID="$!"
      store_kill_pids "$TMP_PID"
      WAIT_PIDS_S17+=( "$TMP_PID" )
    else
      apk_checker_helper "$APK"
    fi
    if [[ "$THREADED" -eq 1 ]]; then
      max_pids_protection "$MAX_MOD_THREADS" "${WAIT_PIDS_S17[@]}"
    fi
  done
  [[ "$THREADED" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S17[@]}"
  [[ -d "$GOTMPDIR" ]] && rm -rf "$GOTMPDIR"
}

apk_checker_helper() {
  print_ln
  print_output "[*] Testing Android apk - $(print_path "$APK")"
  go run "$EXT_DIR"/APKHunt/apkhunt.go -p "$APK" -l | tee -a "$LOG_PATH_MODULE/APKHunt-$(basename -s .apk "$APK").txt"
  print_output "[*] APKHunt Android apk analysis results - $(print_path "$APK")" "" "$LOG_PATH_MODULE/APKHunt-$(basename -s .apk "$APK").txt"
  APK_DIR_NAME=$(dirname "$APK")
  APK_STACS_DIR=$(grep "APK Static Analysis Path" "$APK_DIR_NAME"/APKHunt_"$(basename -s .apk "$APK")"*.txt)
  APK_JAR="$APK_DIR_NAME"/"$(basename -s .apk "$APK")".jar
  [[ -d "$APK_STACS_DIR" ]] && rm -rf "$APK_STACS_DIR"
  [[ -f "$APK_JAR" ]] && rm -rf "$APK_JAR"
}
