#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description: Mounts and extracts BSD UFS images
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P19_bsd_ufs_mounter() {
  local NEG_LOG=0

  if [[ "${BSD_UFS}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "BSD UFS filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    print_output "[*] Connect to device ${ORANGE}${FIRMWARE_PATH}${NC}"

    EXTRACTION_DIR="${LOG_DIR}"/firmware/ufs_mount_filesystem/

    ufs_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"

    if [[ "${FILES_UFS_MOUNT}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      NEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

ufs_extractor() {
  local UFS_PATH_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"
  local TMP_UFS_MOUNT="${TMP_DIR}""/ufs_mount_${RANDOM}"
  local DIRS_UFS_MOUNT=0
  export FILES_UFS_MOUNT=0

  if ! [[ -f "${UFS_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "UFS filesystem extractor"

  mkdir -p "${TMP_UFS_MOUNT}" 2>/dev/null || true
  print_output "[*] Trying to mount ${ORANGE}${UFS_PATH_}${NC} to ${ORANGE}${TMP_UFS_MOUNT}${NC} directory"
  # modprobe ufs
  if ! lsmod | grep -q "^ufs[[:space:]]"; then
    print_output "[-] WARNING: Ufs kernel module not loaded - can't proceed"
    return
  fi
  mount -r -t ufs -o ufstype=ufs2 "${UFS_PATH_}" "${TMP_UFS_MOUNT}"

  if mount | grep -q ufs_mount; then
    print_output "[*] Copying ${ORANGE}${TMP_UFS_MOUNT}${NC} to firmware tmp directory (${ORANGE}${EXTRACTION_DIR_}${NC})"
    mkdir -p "${EXTRACTION_DIR_}" 2>/dev/null || true
    cp -pri "${TMP_UFS_MOUNT}"/* "${EXTRACTION_DIR_}" 2>/dev/null || true
    print_ln
    print_output "[*] Using the following firmware directory (${ORANGE}${EXTRACTION_DIR_}${NC}) as base directory:"
    find "${EXTRACTION_DIR_}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
    print_ln
    print_output "[*] Unmounting ${ORANGE}${TMP_UFS_MOUNT}${NC} directory"

    FILES_UFS_MOUNT=$(find "${EXTRACTION_DIR_}" -type f | wc -l)
    DIRS_UFS_MOUNT=$(find "${EXTRACTION_DIR_}" -type d | wc -l)
    print_output "[*] Extracted ${ORANGE}${FILES_UFS_MOUNT}${NC} files and ${ORANGE}${DIRS_UFS_MOUNT}${NC} directories from the firmware image."
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "UFS filesystem extractor" "${UFS_PATH_}" "${EXTRACTION_DIR_}" "${FILES_UFS_MOUNT}" "${DIRS_UFS_MOUNT}" "NA"
    umount "${TMP_UFS_MOUNT}" 2>/dev/null || true
    detect_root_dir_helper "${EXTRACTION_DIR_}"
  fi
  rm -r "${TMP_UFS_MOUNT}"
}
