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

# Description: Extracts AVM firmware images with Freetz-NG (see https://github.com/Freetz-NG/freetz-ng.git)
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P12_avm_freetz_ng_extract() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0

  if [[ "$AVM_DETECTED" -eq 1 ]]; then
    module_title "AVM freetz-ng firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_DIR="$LOG_DIR"/firmware/freetz_ng_extractor

    avm_extractor "$FIRMWARE_PATH" "$EXTRACTION_DIR"

    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

avm_extractor() {
  local AVM_FW_PATH_="$1"
  local EXTRACTION_DIR_="$2"
  local FRITZ_FILES
  local FRITZ_DIRS
  local FRITZ_VERSION
  sub_module_title "AVM freetz-ng firmware extractor"

  "$EXT_DIR"/freetz-ng/fwmod -u -d "$EXTRACTION_DIR_" "$AVM_FW_PATH_" | tee -a "$LOG_FILE"

  FRITZ_FILES=$(find "$EXTRACTION_DIR_" -type f | wc -l)
  FRITZ_DIRS=$(find "$EXTRACTION_DIR_" -type d | wc -l)

  FRITZ_VERSION=$(grep "detected firmware version:" "$LOG_FILE" | cut -d ":" -f2-)
  if [[ -n "$FRITZ_VERSION" ]]; then
    FRITZ_VERSION="NA"
  fi

  if [[ "$FRITZ_FILES" -gt 0 ]]; then
    print_output ""
    print_output "[*] Extracted $ORANGE$FRITZ_FILES$NC files and $ORANGE$FRITZ_DIRS$NC directories from the firmware image."
    write_csv_log "Extractor" "files" "directories" "firmware directory" "detected firmware version"
    write_csv_log "Freetz-NG" "$FRITZ_FILES" "$FRITZ_DIRS" "$EXTRACTION_DIR_" "$FRITZ_VERSION"
    export DEEP_EXTRACTOR=1
  fi
}
