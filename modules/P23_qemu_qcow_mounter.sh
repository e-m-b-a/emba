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

# Description: Mounts and extracts Qemu QCOW2 images
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P23_qemu_qcow_mounter() {
  local lNEG_LOG=0
  if [[ "${QCOW_DETECTED}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Qemu QCOW filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"


    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/qemu_qcow_mount_filesystem/
    local lFIRMWARE_PATHx=""

    if [[ "${IN_DOCKER}" -eq 1 ]]; then
      # we need rw access to firmware -> in docker container we need to copy
      # the firmware to TMP_DIR and use this for extraction
      # afterwards we are going to remove this path
      cp /firmware "${TMP_DIR}"
      lFIRMWARE_PATHx="${TMP_DIR}"/firmware
    else
      lFIRMWARE_PATHx="${FIRMWARE_PATH}"
    fi

    qcow_extractor "${lFIRMWARE_PATHx}" "${lEXTRACTION_DIR}"

    if [[ -f "${TMP_DIR}"/firmware ]]; then
      rm "${TMP_DIR}"/firmware
    fi

    if [[ "${FILES_QCOW_MOUNT}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

qcow_extractor() {
  local lQCOW_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lTMP_QCOW_MOUNT="${TMP_DIR}""/qcow_mount_${RANDOM}"
  local lDIRS_QCOW_MOUNT=0
  local lNBD_DEV=""
  local lNBD_DEVS_ARR=()
  local lEXTRACTION_DIR_FINAL=""
  export FILES_QCOW_MOUNT=0

  if ! [[ -f "${lQCOW_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "Qemu QCOW filesystem extractor"

  mkdir -p "${lTMP_QCOW_MOUNT}" 2>/dev/null || true
  print_output "[*] Trying to mount ${ORANGE}${lQCOW_PATH_}${NC} to ${ORANGE}${lTMP_QCOW_MOUNT}${NC} directory"

  # if lsmod | grep -q nbd; then
  #   rmmod nbd || true
  # fi
  if ! [[ -d /var/lock ]]; then
    mkdir /var/lock || true
  fi

  print_output "[*] Checking nandsim kernel module"
  if ! (lsmod | grep -E -q "^nbd\ "); then
    print_output "[-] WARNING: Is the nbd kernel module loaded - can we proceed?"
    lsmod | grep -E "^nbd "
    # return
  fi

  # print_output "[*] Load kernel module ${ORANGE}nbd${NC}."
  # modprobe nbd max_part=8
  # The following code is based on the code from here: https://superuser.com/a/1117082
  local lNBD_SIZE=""
  local lNBD_DEV_NAME=""
  local lIS_MOUNTED="no"
  for lNBD_DEV in /sys/class/block/nbd[0-9]{1,}; do
    lNBD_SIZE=$(cat "${lNBD_DEV}"/size || true)
    if [[ "${lNBD_SIZE}" == "0" ]]; then
      lNBD_DEV_NAME=$(basename "${lNBD_DEV}")
      print_output "[*] Qemu disconnect device ${ORANGE}/dev/${lNBD_DEV_NAME}${NC}."
      qemu-nbd -d /dev/"${lNBD_DEV_NAME}" || true
      print_output "[*] Qemu connecting device ${lQCOW_PATH_} to /dev/${lNBD_DEV_NAME}"
      if qemu-nbd -c /dev/"${lNBD_DEV_NAME}" "${lQCOW_PATH_}"; then
        lIS_MOUNTED="yes"
      else
        qemu-nbd -d /dev/"${lNBD_DEV_NAME}"
      fi
      [[ "${lIS_MOUNTED:-no}" != "yes" ]] && continue
      break
    fi
  done

  print_output "[*] Identification of partitions on ${ORANGE}/dev/${lNBD_DEV_NAME}${NC}."
  mapfile -t lNBD_DEVS_ARR < <(fdisk -l /dev/"${lNBD_DEV_NAME}" | grep "^/dev/" | awk '{print $1}' || true)
  if [[ "${#lNBD_DEVS_ARR[@]}" -eq 0 ]]; then
    # sometimes we are not able to find the partitions with fdisk -> fallback
    lNBD_DEVS_ARR+=( "/dev/nbd0" )
  fi

  print_ln
  fdisk /dev/"${lNBD_DEV_NAME}" -l
  print_ln

  for NBD_DEV in "${lNBD_DEVS_ARR[@]}"; do
    print_output "[*] Extract data from partition ${ORANGE}${NBD_DEV}${NC}"
    mount "${NBD_DEV}" "${lTMP_QCOW_MOUNT}" || true

    if mount | grep -q "${NBD_DEV}"; then
      lEXTRACTION_DIR_FINAL="${lEXTRACTION_DIR_}"/"$(basename "${NBD_DEV}")"

      copy_qemu_nbd "${lTMP_QCOW_MOUNT}" "${lEXTRACTION_DIR_FINAL}"

      FILES_QCOW_MOUNT=$(find "${lEXTRACTION_DIR_FINAL}" -type f | wc -l)
      lDIRS_QCOW_MOUNT=$(find "${lEXTRACTION_DIR_FINAL}" -type d | wc -l)
      print_output "[*] Extracted ${ORANGE}${FILES_QCOW_MOUNT}${NC} files and ${ORANGE}${lDIRS_QCOW_MOUNT}${NC} directories from the firmware image."
      write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
      write_csv_log "Qemu QCOW filesystem extractor" "${lQCOW_PATH_}" "${lEXTRACTION_DIR_FINAL}" "${FILES_QCOW_MOUNT}" "${lDIRS_QCOW_MOUNT}" "NA"

      print_output "[*] Unmounting ${ORANGE}${lTMP_QCOW_MOUNT}${NC} directory"
      umount "${lTMP_QCOW_MOUNT}"
    fi
  done
  qemu-nbd --disconnect /dev/"${lNBD_DEV_NAME}"
  rm -r "${lTMP_QCOW_MOUNT}"
}

copy_qemu_nbd() {
  local lSOURCE_CP="${1:-}"
  local lDEST_CP="${2:-}"
  if ! [[ -d "${lSOURCE_CP}" ]]; then
    return
  fi

  print_output "[*] Copying ${ORANGE}${lSOURCE_CP}${NC} to firmware tmp directory (${ORANGE}${lDEST_CP}${NC})"
  mkdir -p "${lDEST_CP}" 2>/dev/null || true
  cp -pri "${lSOURCE_CP}"/* "${lDEST_CP}" 2>/dev/null || true
  print_ln
  print_output "[*] Using the following firmware directory (${ORANGE}${lDEST_CP}${NC}) as base directory:"
  find "${lDEST_CP}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
  print_ln
}
