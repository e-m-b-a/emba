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

# Description: Extracts vmdk images
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P10_vmdk_extractor() {
  local NEG_LOG=0

  if [[ "${VMDK_DETECTED-0}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "VMDK (Virtual Machine Disk) extractor"
    pre_module_reporter "${FUNCNAME[0]}"
    EXTRACTION_DIR="${LOG_DIR}"/firmware/vmdk_extractor/

    vmdk_extractor "${FIRMWARE_PATH}" "${EXTRACTION_DIR}"

    if [[ "${VMDK_FILES}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
    fi
    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

vmdk_extractor() {
  local VMDK_PATH_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"
  local MOUNT_DEV=""
  local DEV_NAME=""
  local TMP_VMDK_MNT="${TMP_DIR}/vmdk_mount_${RANDOM}"
  local VMDK_DIRS=0
  local RET=0
  export VMDK_FILES=0
  local VMDK_VIRT_FS=()

  if ! [[ -f "${VMDK_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "VMDK (Virtual Machine Disk) extractor"

  print_output "[*] Enumeration of devices in VMDK images ${ORANGE}${VMDK_PATH_}${NC}"
  disable_strict_mode "${STRICT_MODE}" 0
  virt-filesystems -a "${VMDK_PATH_}" > "${TMP_DIR}"/vmdk.log
  RET="$?"

  if [[ "${RET}" -ne 0 ]]; then
    # backup with 7z
    7z x -o"${EXTRACTION_DIR_}" "${VMDK_PATH_}"
    RET="$?"
    if [[ "${RET}" -ne 0 ]]; then
      print_output "[-] WARNING: VMDK filesystem not enumerated"
      enable_strict_mode "${STRICT_MODE}" 0
      return
    fi
  else
    mapfile -t VMDK_VIRT_FS < "${TMP_DIR}"/vmdk.log
    for MOUNT_DEV in "${VMDK_VIRT_FS[@]}"; do
      print_output "[*] Found device ${ORANGE}${MOUNT_DEV}${NC}"
    done
  fi
  enable_strict_mode "${STRICT_MODE}" 0

  mkdir -p "${TMP_VMDK_MNT}" || true

  for MOUNT_DEV in "${VMDK_VIRT_FS[@]}"; do
    DEV_NAME=$(basename "${MOUNT_DEV}")
    print_output "[*] Trying to mount ${ORANGE}${MOUNT_DEV}${NC} to ${ORANGE}${TMP_VMDK_MNT}${NC} directory"
    # if troubles ahead with vmdk mount, remove the error redirection
    guestmount -a "${VMDK_PATH_}" -m "${MOUNT_DEV}" --ro "${TMP_VMDK_MNT}" 2>/dev/null || true
    if mount | grep -q vmdk_mount; then
      print_output "[*] Copying ${ORANGE}${MOUNT_DEV}${NC} to firmware directory ${ORANGE}${EXTRACTION_DIR_}/${DEV_NAME}${NC}"
      mkdir -p "${EXTRACTION_DIR_}"/"${DEV_NAME}"/ || true
      cp -pr "${TMP_VMDK_MNT}"/* "${EXTRACTION_DIR_}"/"${DEV_NAME}"/ || true
      umount "${TMP_VMDK_MNT}"
    fi
  done

  if [[ -d "${EXTRACTION_DIR_}" ]]; then
    VMDK_FILES=$(find "${EXTRACTION_DIR_}" -type f | wc -l)
    VMDK_DIRS=$(find "${EXTRACTION_DIR_}" -type d | wc -l)
  fi

  if [[ "${VMDK_FILES}" -gt 0 ]]; then
    print_ln
    print_output "[*] Extracted ${ORANGE}${VMDK_FILES}${NC} files and ${ORANGE}${VMDK_DIRS}${NC} directories from the firmware image."
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "VMDK extractor" "${VMDK_PATH_}" "${EXTRACTION_DIR_}" "${VMDK_FILES}" "${VMDK_DIRS}" "NA"
    # currently unblob has issues with VMDKs. We need to disable it for this extraction process
    safe_echo 0 > "${TMP_DIR}"/unblob_disable.cfg
  fi
  rm -r "${TMP_VMDK_MNT}" || true
}
