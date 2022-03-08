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

# Description: Mounts and extracts ext2 images (currently binwalk destroys the permissions and the symlinks)
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P14_ext2_mounter() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0
  if [[ "$EXT_IMAGE" -eq 1 ]]; then
    module_title "EXT filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    print_output "[*] Connect to device $ORANGE$FIRMWARE_PATH$NC"

    EXTRACTION_DIR="$LOG_DIR"/firmware/ext_mount_filesystem/

    ext2_extractor "$FIRMWARE_PATH" "$EXTRACTION_DIR"

    if [[ "$FILES_EXT_MOUNT" -gt 0 ]]; then
      export FIRMWARE_PATH="$LOG_DIR"/firmware/
    fi
    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

ext2_extractor() {
  local EXT_PATH_="$1"
  local EXTRACTION_DIR_="$2"
  local TMP_EXT_MOUNT="$TMP_DIR""/ext_mount_$RANDOM"
  local DIRS_EXT_MOUNT=0
  FILES_EXT_MOUNT=0
  sub_module_title "EXT filesystem extractor"

  mkdir -p "$TMP_EXT_MOUNT"
  print_output "[*] Trying to mount $ORANGE$EXT_PATH_$NC to $ORANGE$TMP_EXT_MOUNT$NC directory"
  mount "$EXT_PATH_" "$TMP_EXT_MOUNT"
  if mount | grep -q ext_mount; then
    print_output "[*] Copying $ORANGE$TMP_EXT_MOUNT$NC to firmware tmp directory ($EXTRACTION_DIR_)"
    mkdir -p "$EXTRACTION_DIR_"
    cp -pri "$TMP_EXT_MOUNT"/* "$EXTRACTION_DIR_"
    print_output ""
    print_output "[*] Using the following firmware directory ($ORANGE$EXTRACTION_DIR_$NC) as base directory:"
    #shellcheck disable=SC2012
    ls -lh "$EXTRACTION_DIR_" | tee -a "$LOG_FILE"
    print_output ""
    print_output "[*] Unmounting $ORANGE$TMP_EXT_MOUNT$NC directory"

    FILES_EXT_MOUNT=$(find "$EXTRACTION_DIR_" -type f | wc -l)
    DIRS_EXT_MOUNT=$(find "$EXTRACTION_DIR_" -type d | wc -l)
    print_output "[*] Extracted $ORANGE$FILES_EXT_MOUNT$NC files and $ORANGE$DIRS_EXT_MOUNT$NC directories from the firmware image."
    umount "$TMP_EXT_MOUNT"
  fi
  rm -r "$TMP_EXT_MOUNT"

}
