#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description: Extracts vmdk images
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P10_vmdk_extractor() {
  module_log_init "${FUNCNAME[0]}"
  # This module is currently in an unworking PoC state. You can enable it via changing the following to -eq 0
  # otherwise this module gets skipped
  NEG_LOG=0
  if [[ "$VMDK_DETECTED" -eq 1 ]]; then
    module_title "VMDK extractor"
    print_output "[*] Connect to device $ORANGE$FIRMWARE_PATH$NC"
    mkdir -p "$TMP_DIR"/vmdk_mount
    for MOUNT_DEV in /dev/sda{1..5}; do
      DEV_NAME=$(basename "$MOUNT_DEV")
      print_output "[*] Trying to mount $ORANGE$MOUNT_DEV$NC to $ORANGE$TMP_DIR/vmdk_mount$NC directory"
      # if troubles ahead with vmdk mount, remove the error redirection
      guestmount -a "$FIRMWARE_PATH" -m "$MOUNT_DEV" --ro "$TMP_DIR"/vmdk_mount 2>/dev/null
      if mount | grep -q vmdk_mount; then
        print_output "[*] Copying $ORANGE$MOUNT_DEV$NC to firmware directory $LOG_DIR/firmware/vmdk_extractor/"
        mkdir -p "$LOG_DIR"/firmware/vmdk_extractor/"$DEV_NAME"/
        cp -pri "$TMP_DIR"/vmdk_mount/* "$LOG_DIR"/firmware/vmdk_extractor/"$DEV_NAME"/
        umount "$TMP_DIR"/vmdk_mount
      fi
    done
    VMDK_FILES=$(find "$LOG_DIR"/firmware/vmdk_extractor -type f | wc -l)
    VMDK_DIRS=$(find "$LOG_DIR"/firmware/vmdk_extractor -type d | wc -l)

    if [[ "$VMDK_FILES" -gt 0 ]]; then
      print_output ""
      print_output "[*] Extracted $ORANGE$VMDK_FILES$NC files and $ORANGE$VMDK_DIRS$NC directories from the firmware image."
      write_csv_log "Extractor" "files" "directories" "firmware dir"
      write_csv_log "VMDK extractor" "$VMDK_FILES" "$VMDK_DIRS" "$LOG_DIR/firmware/vmdk_extractor/"
    fi
    export FIRMWARE_PATH="$LOG_DIR"/firmware/
    rm -r "$TMP_DIR"/vmdk_mount
    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}
