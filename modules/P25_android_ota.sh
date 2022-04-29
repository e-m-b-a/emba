#!/bin/bash

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

# Description: Extracts Android OTA update files - see https://github.com/e-m-b-a/emba/issues/233
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P25_android_ota() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0
  if [[ "$ANDROID_OTA" -eq 1 ]]; then
    module_title "Android OTA payload.bin extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_DIR="$LOG_DIR"/firmware/android_ota/

    android_ota_extractor "$FIRMWARE_PATH" "$EXTRACTION_DIR"

    if [[ "$FILES_OTA" -gt 0 ]]; then
      export FIRMWARE_PATH="$LOG_DIR"/firmware/
    fi
    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

android_ota_extractor() {
  local OTA_INIT_PATH_="$1"
  local EXTRACTION_DIR_="$2"
  local DIRS_OTA=0
  FILES_OTA=0
  sub_module_title "Android OTA extractor"

  hexdump -C "$OTA_INIT_PATH_" | head | tee -a "$LOG_FILE" || true

  if [[ -d "$EXT_DIR"/payload_dumper ]]; then
    print_output ""
    print_output "[*] Extracting Android OTA payload.bin file ..."
    print_output ""
    python3 "$EXT_DIR"/payload_dumper/payload_dumper.py --out "$EXTRACTION_DIR_" "$OTA_INIT_PATH_" | tee -a "$LOG_FILE"
    FILES_OTA=$(find "$EXTRACTION_DIR_" -type f | wc -l)
    DIRS_OTA=$(find "$EXTRACTION_DIR_" -type d | wc -l)
    print_output "[*] Extracted $ORANGE$FILES_OTA$NC files and $ORANGE$DIRS_OTA$NC directories from the firmware image."
  else
    print_output "[-] Android OTA payload.bin extractor not found - check your installation"
  fi
}
