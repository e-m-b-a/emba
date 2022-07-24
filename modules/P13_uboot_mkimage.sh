#!/bin/bash

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

# Description: Shows internals of Uboot images
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P13_uboot_mkimage() {
  local NEG_LOG=0
  if [[ "$UBOOT_IMAGE" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    local IMAGE_NAME=""
    local IMAGE_TYPE=""
    module_title "Uboot image details"
    pre_module_reporter "${FUNCNAME[0]}"
    mkimage -l "$FIRMWARE_PATH" | tee -a "$LOG_FILE"
    IMAGE_NAME=$(grep "Image Name" "$LOG_FILE" 2>/dev/null | awk '{print $3,$4,$5,$6,$7,$8,$9,$10}' || true)
    IMAGE_TYPE=$(grep "Image Type" "$LOG_FILE" 2>/dev/null | awk '{print $3,$4,$5,$6,$7,$8,$9,$10}' || true)
    write_csv_log "Identifier" "Value"
    write_csv_log "ImageName" "$IMAGE_NAME"
    write_csv_log "ImageType" "$IMAGE_TYPE"
    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
  fi
}
