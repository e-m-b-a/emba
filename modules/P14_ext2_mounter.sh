#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
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
    print_output "[*] Connect to device $ORANGE$FIRMWARE_PATH$NC"
    mkdir -p "$TMP_DIR"/ext_mount
    print_output "[*] Trying to mount $ORANGE$FIRMWARE_PATH$NC to $ORANGE$TMP_DIR/ext_mount$NC directory"
    mount "$FIRMWARE_PATH" "$TMP_DIR"/ext_mount
    if mount | grep -q ext_mount; then
      print_output "[*] Copying $ORANGE$TMP_DIR/ext_mount$NC to firmware tmp directory ($TMP_DIR/ext_mount)"
      mkdir -p "$LOG_DIR"/firmware/ext_mount_filesystem/
      cp -pri "$TMP_DIR"/ext_mount/* "$LOG_DIR"/firmware/ext_mount_filesystem/
      print_output ""
      print_output "[*] Using the following firmware directory ($LOG_DIR/firmware/ext_mount_filesystem) as base directory:"
      ls -lh "$LOG_DIR"/firmware/ext_mount_filesystem/ | tee -a "$LOG_FILE"
      print_output ""
      print_output "[*] Unmounting $ORANGE$TMP_DIR/ext_mount$NC directory"
      umount "$TMP_DIR"/ext_mount
    fi
    export FIRMWARE_PATH="$LOG_DIR"/firmware/
    rm -r "$TMP_DIR"/ext_mount
    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}
