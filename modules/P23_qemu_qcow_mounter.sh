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
#
# Author(s): Michael Messner

# Description: Mounts and extracts Qemu QCOW2 images
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P23_qemu_qcow_mounter() {
  local NEG_LOG=0
  if [[ "${QCOW_DETECTED}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Qemu QCOW filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"


    EXTRACTION_DIR="${LOG_DIR}"/firmware/qemu_qcow_mount_filesystem/
    local FIRMWARE_PATHx=""

    if [[ "${IN_DOCKER}" -eq 1 ]]; then
      # we need rw access to firmware -> in docker container we need to copy
      # the firmware to TMP_DIR and use this for extraction
      # afterwards we are going to remove this path
      cp /firmware "${TMP_DIR}"
      FIRMWARE_PATHx="${TMP_DIR}"/firmware
    else
      FIRMWARE_PATHx="${FIRMWARE_PATH}"
    fi

    qcow_extractor "${FIRMWARE_PATHx}" "${EXTRACTION_DIR}"

    if [[ -f "${TMP_DIR}"/firmware ]]; then
      rm "${TMP_DIR}"/firmware
    fi

    if [[ "${FILES_QCOW_MOUNT}" -gt 0 ]]; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      NEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

qcow_extractor() {
  local QCOW_PATH_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"
  local TMP_QCOW_MOUNT="${TMP_DIR}""/qcow_mount_${RANDOM}"
  local DIRS_QCOW_MOUNT=0
  local NBD_DEV=""
  local NBD_DEVS=()
  local EXTRACTION_DIR_FINAL=""
  export FILES_QCOW_MOUNT=0

  if ! [[ -f "${QCOW_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "Qemu QCOW filesystem extractor"

  mkdir -p "${TMP_QCOW_MOUNT}" 2>/dev/null || true
  print_output "[*] Trying to mount ${ORANGE}${QCOW_PATH_}${NC} to ${ORANGE}${TMP_QCOW_MOUNT}${NC} directory"

  # if lsmod | grep -q nbd; then
  #   rmmod nbd || true
  # fi
  if ! [[ -d /var/lock ]]; then
    mkdir /var/lock || true
  fi

  print_output "[*] Checking nandsim kernel module"
  if ! (lsmod | grep -q "nbd"); then
    print_output "[-] WARNING: nbd kernel module not loaded - can't proceed"
    lsmod | grep -E "^nbd "
    # return
  fi

  # print_output "[*] Load kernel module ${ORANGE}nbd${NC}."
  # modprobe nbd max_part=8
  print_output "[*] Qemu disconnect device ${ORANGE}/dev/nbd${NC}."
  qemu-nbd --disconnect /dev/nbd0
  print_output "[*] Qemu connect device ${ORANGE}/dev/nbd${NC}."
  qemu-nbd --connect /dev/nbd0 "${QCOW_PATH_}"

  print_output "[*] Identification of partitions on ${ORANGE}/dev/nbd${NC}."
  mapfile -t NBD_DEVS < <(fdisk -l /dev/nbd0 | grep "^/dev/" | awk '{print $1}' || true)
  if [[ "${#NBD_DEVS[@]}" -eq 0 ]]; then
    # sometimes we are not able to find the partitions with fdisk -> fallback
    NBD_DEVS+=( "/dev/nbd0" )
  fi

  print_ln
  fdisk /dev/nbd0 -l
  print_ln

  for NBD_DEV in "${NBD_DEVS[@]}"; do
    print_output "[*] Extract data from partition ${ORANGE}${NBD_DEV}${NC}"
    mount "${NBD_DEV}" "${TMP_QCOW_MOUNT}" || true

    if mount | grep -q "${NBD_DEV}"; then
      EXTRACTION_DIR_FINAL="${EXTRACTION_DIR_}"/"$(basename "${NBD_DEV}")"

      copy_qemu_nbd "${TMP_QCOW_MOUNT}" "${EXTRACTION_DIR_FINAL}"

      FILES_QCOW_MOUNT=$(find "${EXTRACTION_DIR_FINAL}" -type f | wc -l)
      DIRS_QCOW_MOUNT=$(find "${EXTRACTION_DIR_FINAL}" -type d | wc -l)
      print_output "[*] Extracted ${ORANGE}${FILES_QCOW_MOUNT}${NC} files and ${ORANGE}${DIRS_QCOW_MOUNT}${NC} directories from the firmware image."
      write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
      write_csv_log "Qemu QCOW filesystem extractor" "${QCOW_PATH_}" "${EXTRACTION_DIR_FINAL}" "${FILES_QCOW_MOUNT}" "${DIRS_QCOW_MOUNT}" "NA"

      print_output "[*] Unmounting ${ORANGE}${TMP_QCOW_MOUNT}${NC} directory"
      umount "${TMP_QCOW_MOUNT}"
    fi
  done
  qemu-nbd --disconnect /dev/nbd0
  rm -r "${TMP_QCOW_MOUNT}"
}

copy_qemu_nbd() {
  local SOURCE_CP="${1:-}"
  local DEST_CP="${2:-}"
  if ! [[ -d "${SOURCE_CP}" ]]; then
    return
  fi

  print_output "[*] Copying ${ORANGE}${SOURCE_CP}${NC} to firmware tmp directory (${ORANGE}${DEST_CP}${NC})"
  mkdir -p "${DEST_CP}" 2>/dev/null || true
  cp -pri "${SOURCE_CP}"/* "${DEST_CP}" 2>/dev/null || true
  print_ln
  print_output "[*] Using the following firmware directory (${ORANGE}${DEST_CP}${NC}) as base directory:"
  find "${DEST_CP}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
  print_ln
}
