#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner
# Credits:   Binarly for support

# Description: Extracts UEFI images with BIOSUtilities - https://github.com/platomav/BIOSUtilities/tree/refactor
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P35_UEFI_extractor() {
  local NEG_LOG=0

  if [[ "$UEFI_DETECTED" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "UEFI extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_DIR="$LOG_DIR"/firmware/uefi_extraction/

    if [[ "$UEFI_AMI_CAPSULE" -gt 0 ]]; then
      ami_extractor "$FIRMWARE_PATH" "$EXTRACTION_DIR"
    fi

    if [[ "$FILES_UEFI" -gt 0 ]]; then
      MD5_DONE_DEEP+=( "$(md5sum "$FIRMWARE_PATH" | awk '{print $1}')" )
      export FIRMWARE_PATH="$LOG_DIR"/firmware/
    fi

    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
  fi
}

ami_extractor() {
  sub_module_title "AMI capsule extractor"

  local FIRMWARE_PATH_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"
  FILES_UEFI=0
  local DIRS_UEFI=0
  local FIRMWARE_NAME_=""

  if ! [[ -f "$FIRMWARE_PATH_" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  FIRMWARE_NAME_="$(basename "$FIRMWARE_PATH_")"

  echo -ne '\n' | python3 "$EXT_DIR"/BIOSUtilities/AMI_PFAT_Extract.py -o "$EXTRACTION_DIR_" "$FIRMWARE_PATH_" &> "$LOG_PATH_MODULE"/uefi_ami_"$FIRMWARE_NAME_".log

  if [[ -f "$LOG_PATH_MODULE"/uefi_ami_"$FIRMWARE_NAME_".log ]]; then
    tee -a "$LOG_FILE" < "$LOG_PATH_MODULE"/uefi_ami_"$FIRMWARE_NAME_".log
  fi

  print_ln
  print_output "[*] Using the following firmware directory ($ORANGE$EXTRACTION_DIR_$NC) as base directory:"
  #shellcheck disable=SC2012
  ls -lh "$EXTRACTION_DIR_" | tee -a "$LOG_FILE"
  print_ln

  FILES_UEFI=$(find "$EXTRACTION_DIR_" -type f | wc -l)
  DIRS_UEFI=$(find "$EXTRACTION_DIR_" -type d | wc -l)
  print_output "[*] Extracted $ORANGE$FILES_UEFI$NC files and $ORANGE$DIRS_UEFI$NC directories from the firmware image."
  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
  write_csv_log "UEFI AMI extractor" "$FIRMWARE_PATH_" "$EXTRACTION_DIR_" "$FILES_UEFI" "$DIRS_UEFI" "NA"
  print_ln
}
