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

# Description: Extracts encrypted firmware images from the vendor Foscam
#              See https://github.com/pr0v3rbs/FirmAE/issues/21
#              See https://northwave-security.com/de/blog-abusing-ip-cameras-for-red-teaming-part-1-obtaining-the-firmware/
#              See https://github.com/mcw0/PoC/blob/master/decrypt-foscam.py
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P20_foscam_decryptor() {
  local NEG_LOG=0

  if [[ "${OPENSSL_ENC_DETECTED}" -ne 0 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Foscam encrypted firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_FILE="${LOG_DIR}"/firmware/firmware_foscam_dec.bin

    foscam_enc_extractor "${FIRMWARE_PATH}" "${EXTRACTION_FILE}"

    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
  fi
}

foscam_enc_extractor() {
  local FOSCAM_ENC_PATH_="${1:-}"
  local EXTRACTION_FILE_="${2:-}"
  local FOSCAM_FILE_CHECK=""
  local KEY_FILE="${CONFIG_DIR}/foscam_enc_keys.txt"
  local _FOSCAM_KEY=""
  local FOSCAM_KEYS=()

  if ! [[ -f "${FOSCAM_ENC_PATH_}" ]]; then
    print_output "[-] No file for decryption provided"
    return
  fi
  if ! [[ -f "${KEY_FILE}" ]]; then
    print_output "[-] No key file found in config directory"
    return
  fi

  sub_module_title "Foscam encrypted firmware extractor"

  hexdump -C "${FOSCAM_ENC_PATH_}" | head | tee -a "${LOG_FILE}" || true

  mapfile FOSCAM_KEYS < <(grep -v "ID" "${KEY_FILE}" | cut -d\; -f2 | tr -d \')
  for _FOSCAM_KEY in "${FOSCAM_KEYS[@]}"; do
    local FOSCAM_DECRYTED=0
    print_output "[*] Testing FOSCAM decryption key ${ORANGE}${_FOSCAM_KEY}${NC}."
    # shellcheck disable=SC2086
    openssl enc -d -aes-128-cbc -md md5 -k ${_FOSCAM_KEY} -in "${FOSCAM_ENC_PATH_}" > "${EXTRACTION_FILE_}" || true

    if [[ -f "${EXTRACTION_FILE_}" ]]; then
      FOSCAM_FILE_CHECK=$(file "${EXTRACTION_FILE_}")
      if [[ "${FOSCAM_FILE_CHECK}" =~ .*gzip\ compressed\ data.* ]]; then
        print_ln
        print_output "[+] Decrypted Foscam firmware file to ${ORANGE}${EXTRACTION_FILE_}${NC}"
        export FIRMWARE_PATH="${EXTRACTION_FILE_}"
        backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
        print_ln
        print_output "[*] Firmware file details: ${ORANGE}$(file "${EXTRACTION_FILE_}")${NC}"
        write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
        write_csv_log "Foscam decryptor" "${FOSCAM_ENC_PATH_}" "${EXTRACTION_FILE_}" "1" "NA" "NA"
        FOSCAM_DECRYTED=1
        if [[ -z "${FW_VENDOR:-}" ]]; then
          export FW_VENDOR="Foscam"
        fi

        foscam_ubi_extractor "${EXTRACTION_FILE_}"
        # as we have already found a working key we can now exit the loop
        break
      fi
    fi
  done

  if [[ "${FOSCAM_DECRYTED}" -ne 1 ]]; then
    print_output "[-] Decryption of Foscam firmware file failed"
  fi
}

# TODO: Check if we can improve our ubifs extractor in a way to support this Foscam thing
# without the following function! Currently it is working together with our
# deep extractor quite fine.
foscam_ubi_extractor() {
  local FIRMWARE_PATH_="${1:-}"
  local MTD_DEVICE=""
  local UBI_MNT_PT="${LOG_DIR}"/tmp/ubi_mnt_foscam
  local EXTRACTION_DIR_="${LOG_DIR}/firmware/foscam_ubi_extractor"
  local EXTRACTION_DIR_GZ="${LOG_DIR}/firmware/foscam_gz_extractor"
  local UBI_DEV=""
  local UBI_DEVS=()
  local FOSCAM_UBI_FILES=0
  local FOSCAM_UBI_DIRS=0

  if ! [[ -f "${FIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction found"
    return
  fi

  print_output "[*] Extracting decrypted firmware to ${ORANGE}${EXTRACTION_DIR_GZ}${NC}"
  mkdir -p "${EXTRACTION_DIR_GZ}" || true
  tar -xzf "${FIRMWARE_PATH_}" -C "${EXTRACTION_DIR_GZ}" || true

  # check if we have the kernel modules available - special interest in docker
  # if ! [[ -d "/lib/modules/" ]]; then
  #   print_output "[-] Kernel modules not mounted from host system - please update your docker-compose file!"
  #   return
  # fi

  if [[ -f "${EXTRACTION_DIR_GZ}"/app_ubifs ]]; then
    print_output "[*] 2nd extraction round successful - ${ORANGE}app_ubifs${NC} found"
    print_output "[*] Checking nandsim kernel module"
    if ! lsmod | grep -q "^nandsim[[:space:]]"; then
      print_output "[-] WARNING: Nandsim kernel module not loaded - can't proceed"
      return
      #   # we need to load nandsim with some parameters - unload it before
      #   modprobe -r nandsim
    fi
    # modprobe nandsim first_id_byte=0x2c second_id_byte=0xac third_id_byte=0x90 fourth_id_byte=0x15
    MTD_DEVICE=$(grep "mtd[0-9]" /proc/mtd | cut -d: -f1)
    print_output "[*] Found ${ORANGE}/dev/${MTD_DEVICE}${NC} MTD device"
    print_output "[*] Erasing ${ORANGE}/dev/${MTD_DEVICE}${NC} MTD device"
    flash_erase /dev/"${MTD_DEVICE}" 0 0 || true
    print_output "[*] Formating ${ORANGE}/dev/${MTD_DEVICE}${NC} MTD device"
    ubiformat /dev/"${MTD_DEVICE}" -O 2048 -f "${EXTRACTION_DIR_GZ}"/app_ubifs || true
    # if ! lsmod | grep -q "^ubi[[:space:]]"; then
    #   print_output "[*] Loading ubi kernel module"
    #   modprobe ubi
    # fi
    print_output "[*] Attaching ubi device"
    ubiattach -p /dev/"${MTD_DEVICE}" -O 2048

    # should be only one UBI dev, but just in case ...
    mapfile -t UBI_DEVS < <(find /dev -iname "ubi[0-9]_[0-9]")
    for UBI_DEV in "${UBI_DEVS[@]}"; do
      local UBI_MNT_PT="${UBI_MNT_PT}-${RANDOM}"
      print_output "[*] Mounting ${ORANGE}${UBI_DEV}${NC} ubi device to ${ORANGE}${UBI_MNT_PT}${NC}"
      mkdir -p "${UBI_MNT_PT}" || true
      mount -t ubifs "${UBI_DEV}" "${UBI_MNT_PT}"
      print_output "[*] Copy mounted ubi device to ${ORANGE}${EXTRACTION_DIR_}/${UBI_DEV}${NC}"
      mkdir -p "${EXTRACTION_DIR_}/${UBI_DEV}"
      cp -pri "${UBI_MNT_PT}" "${EXTRACTION_DIR_}/${UBI_DEV}"
      umount "${UBI_MNT_PT}" || true
      rm -r "${UBI_MNT_PT}" || true
    done

    # do some cleanup
    print_output "[*] Detaching ubi device"
    ubidetach -d 0 || true
    # print_output "[*] Unloading nandsim module"
    # modprobe -r nandsim || true
    # print_output "[*] Unloading ubi module"
    # modprobe -r ubi || true

    if [[ -d "${EXTRACTION_DIR_}" ]]; then
      FOSCAM_UBI_FILES=$(find "${EXTRACTION_DIR_}" -type f | wc -l)
      FOSCAM_UBI_DIRS=$(find "${EXTRACTION_DIR_}" -type d | wc -l)
    fi

    if [[ "${FOSCAM_UBI_FILES}" -gt 0 ]]; then
      print_ln
      print_output "[*] Extracted ${ORANGE}${FOSCAM_UBI_FILES}${NC} files and ${ORANGE}${FOSCAM_UBI_DIRS}${NC} directories from the firmware image."
      write_csv_log "Foscam UBI extractor" "${FIRMWARE_PATH_}" "${EXTRACTION_DIR_}" "${FOSCAM_UBI_FILES}" "${FOSCAM_UBI_DIRS}" "NA"
      export FIRMWARE_PATH="${LOG_DIR}"/firmware
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      write_csv_log "Foscam decryptor/extractor" "${FIRMWARE_PATH_}" "${EXTRACTION_DIR_}" "${FOSCAM_UBI_FILES}" "${FOSCAM_UBI_DIRS}" "NA"
    fi
  fi
}
