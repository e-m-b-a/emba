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

# Description: Extracts zip, tar, tgz archives with FACT extractor
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P05_fact_init() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0

  if [[ "$FACT_INIT" -eq 1 ]]; then
    module_title "FACT initial extractor of different archives"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_DIR="$LOG_DIR"/firmware/fact_extraction/

    fact_extractor "$FIRMWARE_PATH" "$EXTRACTION_DIR"

    export FIRMWARE_PATH="$LOG_DIR"/firmware/

    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

fact_extractor() {
  sub_module_title "FACT filesystem extractor"

  local FIRMWARE_PATH_="$1"
  local EXTRACTION_DIR_="$2"
  local FILES_FACT
  local DIRS_FACT

  if [[ -d /tmp/extractor ]]; then
    # This directory is currently hard coded in FACT-extractor
    rm -rf /tmp/extractor
  fi

  "$EXT_DIR"/fact_extractor/fact_extractor/fact_extract.py -d "$FIRMWARE_PATH_" >> "$TMP_DIR"/FACTer.txt

  if [[ -d /tmp/extractor/files ]]; then
    cat /tmp/extractor/reports/meta.json >> "$TMP_DIR"/FACTer.txt
    cp -r /tmp/extractor/files "$EXTRACTION_DIR_"
    rm -rf /tmp/extractor

    print_output ""
    print_output "[*] Using the following firmware directory ($ORANGE$EXTRACTION_DIR_$NC) as base directory:"
    #shellcheck disable=SC2012
    ls -lh "$EXTRACTION_DIR_" | tee -a "$LOG_FILE"
    print_output ""

    FILES_FACT=$(find "$EXTRACTION_DIR_" -type f | wc -l)
    DIRS_FACT=$(find "$EXTRACTION_DIR_" -type d | wc -l)
    print_output "[*] Extracted $ORANGE$FILES_FACT$NC files and $ORANGE$DIRS_FACT$NC directories from the firmware image."
    print_output ""
  fi
}
