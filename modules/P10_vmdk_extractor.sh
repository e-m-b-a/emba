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

# Description: Extracts vmdk images
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P10_vmdk_extractor() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0
  if [[ "$VMDK_DETECTED" -eq 1 ]]; then
    module_title "VMDK extractor"
    EXTRACTION_DIR="$LOG_DIR"/firmware/vmdk_extractor/

    vmdk_extractor "$FIRMWARE_PATH" "$EXTRACTION_DIR"

    export FIRMWARE_PATH="$LOG_DIR"/firmware/
    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

vmdk_extractor() {
  local VMDK_PATH_="$1"
  local EXTRACTION_DIR_="$2"
  local MOUNT_DEV
  local DEV_NAME
  local VMDK_FILES
  local VMDK_DIRS
  local TMP_VMDK_MNT="$TMP_DIR/vmdk_mount_$RANDOM"
  sub_module_title "VMDK extractor"

  print_output "[*] Connect to device $ORANGE$VMDK_PATH_$NC"
  mkdir -p "$TMP_VMDK_MNT"

  for MOUNT_DEV in /dev/sda{1..5}; do
    DEV_NAME=$(basename "$MOUNT_DEV")
    print_output "[*] Trying to mount $ORANGE$MOUNT_DEV$NC to $ORANGE$TMP_VMDK_MNT$NC directory"
    # if troubles ahead with vmdk mount, remove the error redirection
    guestmount -a "$VMDK_PATH_" -m "$MOUNT_DEV" --ro "$TMP_VMDK_MNT" 2>/dev/null
    if mount | grep -q vmdk_mount; then
      print_output "[*] Copying $ORANGE$MOUNT_DEV$NC to firmware directory $EXTRACTION_DIR_"
      mkdir -p "$EXTRACTION_DIR"/"$DEV_NAME"/
      cp -pri "$TMP_VMDK_MNT"/* "$EXTRACTION_DIR_"/"$DEV_NAME"/
      umount "$TMP_VMDK_MNT"
    fi
  done

  VMDK_FILES=$(find "$EXTRACTION_DIR_" -type f | wc -l)
  VMDK_DIRS=$(find "$EXTRACTION_DIR_" -type d | wc -l)

  if [[ "$VMDK_FILES" -gt 0 ]]; then
    print_output ""
    print_output "[*] Extracted $ORANGE$VMDK_FILES$NC files and $ORANGE$VMDK_DIRS$NC directories from the firmware image."
    write_csv_log "Extractor" "files" "directories" "firmware dir"
    write_csv_log "VMDK extractor" "$VMDK_FILES" "$VMDK_DIRS" "$EXTRACTION_DIR_"
  fi
  rm -r "$TMP_VMDK_MNT"
}
