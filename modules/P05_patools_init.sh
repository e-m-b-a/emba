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

# Description: Extracts zip, tar, tgz archives with patools
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P05_patools_init() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0

  if [[ "$PATOOLS_INIT" -eq 1 ]]; then
    module_title "Initial extractor of different archive types via patools"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_DIR="$LOG_DIR"/firmware/patool_extraction/

    patools_extractor "$FIRMWARE_PATH" "$EXTRACTION_DIR"

    if [[ "$FILES_PATOOLS" -gt 0 ]]; then
      export FIRMWARE_PATH="$LOG_DIR"/firmware/
    fi

    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

patools_extractor() {
  sub_module_title "Patool filesystem extractor"

  local FIRMWARE_PATH_="$1"
  local EXTRACTION_DIR_="$2"
  FILES_PATOOLS=0
  local DIRS_PATOOLS=0
  local FIRMWARE_NAME_
  FIRMWARE_NAME_="$(basename "$FIRMWARE_PATH_")"

  patool -v test "$FIRMWARE_PATH_" | tee -a "$LOG_PATH_MODULE"/paextract_test_"$FIRMWARE_NAME_".log
  cat "$LOG_PATH_MODULE"/paextract_test_"$FIRMWARE_NAME_".log >> "$LOG_FILE"

  if grep -q "patool: ... tested ok." "$LOG_PATH_MODULE"/paextract_test_"$FIRMWARE_NAME_".log ; then

    print_output ""
    print_output "[*] Valid compressed file detected - extraction process via patool started"

    patool -v extract "$FIRMWARE_PATH_" --outdir "$EXTRACTION_DIR_" | tee -a "$LOG_PATH_MODULE"/paextract_extract_"$FIRMWARE_NAME_".log
    cat "$LOG_PATH_MODULE"/paextract_extract_"$FIRMWARE_NAME_".log >> "$LOG_FILE"

    print_output ""
    print_output "[*] Using the following firmware directory ($ORANGE$EXTRACTION_DIR_$NC) as base directory:"
    #shellcheck disable=SC2012
    ls -lh "$EXTRACTION_DIR_" | tee -a "$LOG_FILE"
    print_output ""

    FILES_PATOOLS=$(find "$EXTRACTION_DIR_" -type f | wc -l)
    DIRS_PATOOLS=$(find "$EXTRACTION_DIR_" -type d | wc -l)
    print_output "[*] Extracted $ORANGE$FILES_PATOOLS$NC files and $ORANGE$DIRS_PATOOLS$NC directories from the firmware image."
    print_output ""
  fi
}
