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

# Description: Extracts encrypted firmware images from the vendor Foscam
#              See https://github.com/pr0v3rbs/FirmAE/issues/21
#              See https://northwave-security.com/de/blog-abusing-ip-cameras-for-red-teaming-part-1-obtaining-the-firmware/
#              See https://github.com/mcw0/PoC/blob/master/decrypt-foscam.py
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P20_foscam_decryptor() {
  local lNEG_LOG=0

  if [[ "${OPENSSL_ENC_DETECTED}" -ne 0 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Foscam encrypted firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    local lEXTRACTION_FILE="${LOG_DIR}"/firmware/firmware_foscam_dec.bin

    foscam_enc_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_FILE}"
    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

foscam_enc_extractor() {
  local lFOSCAM_ENC_PATH_="${1:-}"
  local lEXTRACTION_FILE_="${2:-}"
  local lFOSCAM_FILE_CHECK=""
  local lKEY_FILE="${CONFIG_DIR}/foscam_enc_keys.txt"
  local l_FOSCAM_KEY=""
  local lFOSCAM_KEYS_ARR=()

  if ! [[ -f "${lFOSCAM_ENC_PATH_}" ]]; then
    print_output "[-] No file for decryption provided"
    return
  fi
  if ! [[ -f "${lKEY_FILE}" ]]; then
    print_output "[-] No key file found in config directory"
    return
  fi

  sub_module_title "Foscam encrypted firmware extractor"

  hexdump -C "${lFOSCAM_ENC_PATH_}" | head | tee -a "${LOG_FILE}" || true

  mapfile lFOSCAM_KEYS_ARR < <(grep -v "ID" "${lKEY_FILE}" | cut -d\; -f2 | tr -d \')
  for l_FOSCAM_KEY in "${lFOSCAM_KEYS_ARR[@]}"; do
    local lFOSCAM_DECRYTED=0
    print_output "[*] Testing FOSCAM decryption key ${ORANGE}${l_FOSCAM_KEY}${NC}."
    # shellcheck disable=SC2086
    # nosemgrep
    openssl enc -d -aes-128-cbc -md md5 -k ${l_FOSCAM_KEY} -in "${lFOSCAM_ENC_PATH_}" > "${lEXTRACTION_FILE_}" || true

    if [[ -f "${lEXTRACTION_FILE_}" ]]; then
      lFOSCAM_FILE_CHECK=$(file "${lEXTRACTION_FILE_}")
      if [[ "${lFOSCAM_FILE_CHECK}" =~ .*gzip\ compressed\ data.* ]]; then
        print_ln
        print_output "[+] Decrypted Foscam firmware file to ${ORANGE}${lEXTRACTION_FILE_}${NC}"
        export FIRMWARE_PATH="${lEXTRACTION_FILE_}"
        backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
        print_ln
        print_output "[*] Firmware file details: ${ORANGE}$(file "${lEXTRACTION_FILE_}")${NC}"
        write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
        write_csv_log "Foscam decryptor" "${lFOSCAM_ENC_PATH_}" "${lEXTRACTION_FILE_}" "1" "NA" "NA"
        lFOSCAM_DECRYTED=1
        if [[ -z "${FW_VENDOR:-}" ]]; then
          export FW_VENDOR="Foscam"
        fi

        foscam_ubi_extractor "${lEXTRACTION_FILE_}"
        # as we have already found a working key we can now exit the loop
        break
      fi
    fi
  done

  if [[ "${lFOSCAM_DECRYTED}" -ne 1 ]]; then
    print_output "[-] Decryption of Foscam firmware file failed"
  fi
}

# TODO: Check if we can improve our ubifs extractor in a way to support this Foscam thing
# without the following function! Currently it is working together with our
# deep extractor quite fine.
foscam_ubi_extractor() {
  local lFIRMWARE_PATH_="${1:-}"
  local lMTD_DEVICE=""
  local lUBI_MNT_PT="${LOG_DIR}"/tmp/ubi_mnt_foscam
  local lEXTRACTION_DIR_="${LOG_DIR}/firmware/foscam_ubi_extractor"
  local lEXTRACTION_DIR_GZ="${LOG_DIR}/firmware/foscam_gz_extractor"
  local lUBI_DEV=""
  local lUBI_DEVS_ARR=()
  local lFILES_FOSCAM_UBI_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  if ! [[ -f "${lFIRMWARE_PATH_}" ]]; then
    print_output "[-] No file for extraction found"
    return
  fi

  print_output "[*] Extracting decrypted firmware to ${ORANGE}${lEXTRACTION_DIR_GZ}${NC}"
  mkdir -p "${lEXTRACTION_DIR_GZ}" || true
  tar -xzf "${lFIRMWARE_PATH_}" -C "${lEXTRACTION_DIR_GZ}" || true

  # check if we have the kernel modules available - special interest in docker
  # if ! [[ -d "/lib/modules/" ]]; then
  #   print_output "[-] Kernel modules not mounted from host system - please update your docker-compose file!"
  #   return
  # fi

  if [[ -f "${lEXTRACTION_DIR_GZ}"/app_ubifs ]]; then
    print_output "[*] 2nd extraction round successful - ${ORANGE}app_ubifs${NC} found"
    print_output "[*] Checking nandsim kernel module"
    if ! lsmod | grep -q "^nandsim[[:space:]]"; then
      lsmod | grep "nandsim" || true
      print_output "[-] WARNING: Nandsim kernel module loading issue - trying to proceed"
      # return
      #   # we need to load nandsim with some parameters - unload it before
      #   modprobe -r nandsim
    fi
    # modprobe nandsim first_id_byte=0x2c second_id_byte=0xac third_id_byte=0x90 fourth_id_byte=0x15
    lMTD_DEVICE=$(grep "mtd[0-9]" /proc/mtd | cut -d: -f1)
    print_output "[*] Found ${ORANGE}/dev/${lMTD_DEVICE}${NC} MTD device"
    print_output "[*] Erasing ${ORANGE}/dev/${lMTD_DEVICE}${NC} MTD device"
    flash_erase /dev/"${lMTD_DEVICE}" 0 0 || true
    print_output "[*] Formating ${ORANGE}/dev/${lMTD_DEVICE}${NC} MTD device"
    ubiformat /dev/"${lMTD_DEVICE}" -O 2048 -f "${lEXTRACTION_DIR_GZ}"/app_ubifs || true
    # if ! lsmod | grep -q "^ubi[[:space:]]"; then
    #   print_output "[*] Loading ubi kernel module"
    #   modprobe ubi
    # fi
    print_output "[*] Attaching ubi device"
    ubiattach -p /dev/"${lMTD_DEVICE}" -O 2048

    # should be only one UBI dev, but just in case ...
    mapfile -t lUBI_DEVS_ARR < <(find /dev -iname "ubi[0-9]_[0-9]")
    for lUBI_DEV in "${lUBI_DEVS_ARR[@]}"; do
      local lUBI_MNT_PT="${lUBI_MNT_PT}-${RANDOM}"
      print_output "[*] Mounting ${ORANGE}${lUBI_DEV}${NC} ubi device to ${ORANGE}${lUBI_MNT_PT}${NC}"
      mkdir -p "${lUBI_MNT_PT}" || true
      mount -t ubifs "${lUBI_DEV}" "${lUBI_MNT_PT}"
      print_output "[*] Copy mounted ubi device to ${ORANGE}${lEXTRACTION_DIR_%\/}/${lUBI_DEV}${NC}"
      mkdir -p "${lEXTRACTION_DIR_%\/}/${lUBI_DEV}"
      cp -pri "${lUBI_MNT_PT}" "${lEXTRACTION_DIR_%\/}/${lUBI_DEV}"
      # after this we should have a ubi image in our extraction directory. This should be extractable via unblob
      print_output "[*] Umount ubi device from ${ORANGE}${lUBI_MNT_PT}/${lUBI_DEV}${NC}"
      umount "${lUBI_MNT_PT}" || true
      rm -r "${lUBI_MNT_PT}" || true
    done

    # do some cleanup
    print_output "[*] Detaching ubi device"
    ubidetach -d 0 || true
    # ensure we have some extracted ubifs:
    lUBI_FS_TARGET=$(find "${lEXTRACTION_DIR_%\/}/${lUBI_DEV}" -name ubifs)
    if [[ -f "${lUBI_FS_TARGET}" ]]; then
      # unblobber "${lUBI_FS_TARGET}" "${lEXTRACTION_DIR_%\/}_unblob_extracted" 0
      binwalker_matryoshka "${lUBI_FS_TARGET}" "${lEXTRACTION_DIR_%\/}_binwalk_extracted"

      print_output "[*] Checking ${lEXTRACTION_DIR_%\/}_binwalk_extracted for files and directories"
      mapfile -t lFILES_FOSCAM_UBI_ARR < <(find "${lEXTRACTION_DIR_%\/}_binwalk_extracted" -type f ! -name "*.raw")
      print_ln
      print_output "[*] Extracted ${ORANGE}${#lFILES_FOSCAM_UBI_ARR[@]}${NC} files from the firmware image."
      print_output "[*] Populating backend data for ${ORANGE}${#lFILES_FOSCAM_UBI_ARR[@]}${NC} files ... could take some time" "no_log"

      for lBINARY in "${lFILES_FOSCAM_UBI_ARR[@]}" ; do
        binary_architecture_threader "${lBINARY}" "P20_foscam_decryptor" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
      done
      wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

      export FIRMWARE_PATH="${LOG_DIR}"/firmware
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      write_csv_log "Foscam decryptor/extractor" "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}" "${#lFILES_FOSCAM_UBI_ARR[@]}" "NA"
    fi

    # print_output "[*] Unloading nandsim module"
    # modprobe -r nandsim || true
    # print_output "[*] Unloading ubi module"
    # modprobe -r ubi || true
  fi
}
