#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description: Mounts and extracts extX images (currently binwalk destroys the permissions and the symlinks)
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P14_ext_mounter() {
  local lNEG_LOG=0
  if [[ "${EXT_IMAGE:-0}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "EXT filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    print_output "[*] Connect to device ${ORANGE}${FIRMWARE_PATH}${NC}"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/ext_mount_filesystem/

    ext_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

    if [[ "${FILES_EXT_MOUNT}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
    fi
    lNEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

ext_extractor() {
  local lEXT_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lTMP_EXT_MOUNT="${TMP_DIR}""/ext_mount_${RANDOM}"
  local lDIRS_EXT_MOUNT=0
  export FILES_EXT_MOUNT=0

  if ! [[ -f "${lEXT_PATH_}" ]]; then
    print_output "[-] No file for decryption provided"
    return
  fi

  sub_module_title "EXT filesystem extractor"

  mkdir -p "${lTMP_EXT_MOUNT}" || true
  print_output "[*] Trying to mount ${ORANGE}${lEXT_PATH_}${NC} to ${ORANGE}${lTMP_EXT_MOUNT}${NC} directory"
  mount -o ro "${lEXT_PATH_}" "${lTMP_EXT_MOUNT}"
  if mount | grep -q ext_mount; then
    print_output "[*] Copying ${ORANGE}${lTMP_EXT_MOUNT}${NC} to firmware tmp directory (${lEXTRACTION_DIR_})"
    mkdir -p "${lEXTRACTION_DIR_}"
    cp -pri "${lTMP_EXT_MOUNT}"/* "${lEXTRACTION_DIR_}"
    print_ln
    print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR_}${NC}) as base directory:"
    find "${lEXTRACTION_DIR_}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
    print_ln
    print_output "[*] Unmounting ${ORANGE}${lTMP_EXT_MOUNT}${NC} directory"

    FILES_EXT_MOUNT=$(find "${lEXTRACTION_DIR_}" -type f | wc -l)
    lDIRS_EXT_MOUNT=$(find "${lEXTRACTION_DIR_}" -type d | wc -l)
    print_output "[*] Extracted ${ORANGE}${FILES_EXT_MOUNT}${NC} files and ${ORANGE}${lDIRS_EXT_MOUNT}${NC} directories from the firmware image."
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "EXT filesystem extractor" "${lEXT_PATH_}" "${lEXTRACTION_DIR_}" "${FILES_EXT_MOUNT}" "${lDIRS_EXT_MOUNT}" "NA"
    umount "${lTMP_EXT_MOUNT}" || true
  fi
  rm -r "${lTMP_EXT_MOUNT}"
}
