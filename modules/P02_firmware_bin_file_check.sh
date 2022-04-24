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

# Description:  Gives some very basic information about the provided firmware binary.
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P02_firmware_bin_file_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware file analyzer"

  local FILE_BIN_OUT
  export SHA512_CHECKSUM="NA"
  export MD5_CHECKSUM="NA"
  export ENTROPY="NA"
  export DLINK_ENC_DETECTED=0
  export VMDK_DETECTED=0
  export UBOOT_IMAGE=0
  export EXT_IMAGE=0 
  export AVM_DETECTED=0
  export UBI_IMAGE=0
  export ENGENIUS_ENC_DETECTED=0
  export GPG_COMPRESS=0
  export QNAP_ENC_DETECTED=0
  export BSD_UFS=0
  export FACT_INIT=0
  export ANDROID_OTA=0

  if [[ -f "$FIRMWARE_PATH" ]]; then
    SHA512_CHECKSUM=$(sha512sum "$FIRMWARE_PATH" | awk '{print $1}')
    MD5_CHECKSUM=$(md5sum "$FIRMWARE_PATH" | awk '{print $1}')

     # entropy checking on binary file
    ENTROPY=$(ent "$FIRMWARE_PATH" | grep Entropy)
  fi

  local FILE_LS_OUT
  FILE_LS_OUT=$(ls -lh "$FIRMWARE_PATH")
  
  print_output "[*] Details of the binary file:"
  print_output ""
  print_output "$(indent "$FILE_LS_OUT")"
  print_output ""
  if [[ -f "$FIRMWARE_PATH" ]]; then
    hexdump -C "$FIRMWARE_PATH"| head | tee -a "$LOG_FILE" || true
    print_output ""
    print_output "[*] SHA512 checksum: $ORANGE$SHA512_CHECKSUM$NC"
    print_output ""
    print_output "$(indent "$ENTROPY")"
    print_output ""
    if [[ -x "$EXT_DIR"/pixde ]]; then
      print_output "[*] Visualized firmware file (first 2000 bytes):\n"
      "$EXT_DIR"/pixde -r-0x2000 "$FIRMWARE_PATH" | tee -a "$LOG_DIR"/p02_pixd.txt
      print_output ""
      python3 "$EXT_DIR"/pixd_png.py -i "$LOG_DIR"/p02_pixd.txt -o "$LOG_DIR"/pixd.png -p 10 > /dev/null
      write_link "$LOG_DIR"/pixd.png
    fi

    fw_bin_detector "$FIRMWARE_PATH"
  fi

  write_csv_log "Firmware name" "SHA512 checksum" "MD5 checksum" "Entropy" "Dlink enc state" "VMDK detected" "UBOOT image" "EXT filesystem" "AVM system detected"
  write_csv_log "$(basename "$FIRMWARE_PATH")" "${SHA512_CHECKSUM:-}" "${MD5_CHECKSUM:-}" "${ENTROPY:-}" "${DLINK_ENC_DETECTED:-}" "${VMDK_DETECTED:-}" "${UBOOT_IMAGE:-}" "${EXT_IMAGE:-}" "${AVM_DETECTED:-}"

  module_end_log "${FUNCNAME[0]}" 1
}

fw_bin_detector() {
  local CHECK_FILE="${1:-}"
  local FILE_BIN_OUT
  local DLINK_ENC_CHECK
  local AVM_CHECK

  export FACT_INIT=0
  export VMDK_DETECTED=0
  export DLINK_ENC_DETECTED=0
  export QNAP_ENC_DETECTED=0
  export AVM_DETECTED=0
  export UBOOT_IMAGE=0
  export EXT_IMAGE=0
  export UBI_IMAGE=0
  export ENGENIUS_ENC_DETECTED=0
  export GPG_COMPRESS=0
  export BSD_UFS=0
  export ANDROID_OTA=0

  FILE_BIN_OUT=$(file "$CHECK_FILE")
  DLINK_ENC_CHECK=$(hexdump -C "$CHECK_FILE" | head -1 || true)
  AVM_CHECK=$(strings "$CHECK_FILE" | grep -c "AVM GmbH .*. All rights reserved.\|(C) Copyright .* AVM" || true)
  QNAP_ENC_CHECK=$(binwalk -y "qnap encrypted" "$CHECK_FILE")

  if [[ "$AVM_CHECK" -gt 0 ]] || [[ "$FW_VENDOR" == *"AVM"* ]]; then
    print_output "[*] Identified AVM firmware - using AVM extraction module"
    export AVM_DETECTED=1
  fi
  # if we have a zip, tgz, tar archive we are going to use the FACT extractor
  if [[ "$FILE_BIN_OUT" == *"gzip compressed data"* || "$FILE_BIN_OUT" == *"Zip archive data"* || "$FILE_BIN_OUT" == *"POSIX tar archive"* ]]; then
    # as the AVM images are also zip files we need to bypass it here:
    if [[ "$AVM_DETECTED" -ne 1 ]]; then
      print_output "[*] Identified gzip/zip/tar archive file - using FACT extraction module"
      export FACT_INIT=1
    fi
  fi
  if [[ "$FILE_BIN_OUT" == *"VMware4 disk image"* ]]; then
    print_output "[*] Identified VMWware VMDK archive file - using VMDK extraction module"
    export VMDK_DETECTED=1
  fi
  if [[ "$FILE_BIN_OUT" == *"UBI image"* ]]; then
    print_output "[*] Identified UBI filesystem image - using UBI extraction module"
    export UBI_IMAGE=1
  fi
  if [[ "$DLINK_ENC_CHECK" == *"SHRS"* ]]; then
    print_output "[*] Identified D-Link SHRS encrpyted firmware - using D-Link extraction module"
    export DLINK_ENC_DETECTED=1
  fi
  if [[ "$DLINK_ENC_CHECK" =~ 00000000\ \ 00\ 00\ 00\ 00\ 00\ 00\ 0.\ ..\ \ 00\ 00\ 0.\ ..\ 31\ 32\ 33\ 00 ]]; then
    print_output "[*] Identified Engenius encrpyted firmware - using Engenius extraction module"
    export ENGENIUS_ENC_DETECTED=1
  fi
  if [[ "$DLINK_ENC_CHECK" =~ 00000000\ \ 00\ 00\ 00\ 00\ 00\ 00\ 01\ 01\ \ 00\ 00\ 0.\ ..\ 33\ 2e\ 3[89]\ 2e ]]; then
    print_output "[*] Identified Engenius encrpyted firmware - using Engenius extraction module"
    export ENGENIUS_ENC_DETECTED=1
  fi
  if [[ "$DLINK_ENC_CHECK" == *"encrpted_img"* ]]; then
    print_output "[*] Identified D-Link encrpted_img encrpyted firmware - using D-Link extraction module"
    export DLINK_ENC_DETECTED=2
  fi
  if [[ "$FILE_BIN_OUT" == *"u-boot legacy uImage"* ]]; then
    print_output "[*] Identified u-boot firmware - using u-boot module"
    export UBOOT_IMAGE=1
  fi
  if [[ "$FILE_BIN_OUT" == *"Unix Fast File system [v2]"* ]]; then
    print_output "[*] Identified UFS filesytem - using UFS filesytem extraction module"
    export BSD_UFS=1
  fi
  if [[ "$FILE_BIN_OUT" == *"Linux rev 1.0 ext2 filesystem data"* ]]; then
    print_output "[*] Identified Linux ext2 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
  fi
  if [[ "$FILE_BIN_OUT" == *"Linux rev 1.0 ext3 filesystem data"* ]]; then
    print_output "[*] Identified Linux ext3 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
  fi
  if [[ "$FILE_BIN_OUT" == *"Linux rev 1.0 ext4 filesystem data"* ]]; then
    print_output "[*] Identified Linux ext4 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
  fi
  if [[ "$QNAP_ENC_CHECK" == *"QNAP encrypted firmware footer , model"* ]]; then
    print_output "[*] Identified QNAP encrpyted firmware - using QNAP extraction module"
    export QNAP_ENC_DETECTED=1
  fi
  # probably we need to take a deeper look to identify the gpg compressed firmware files better.
  # Currently this detection mechanism works quite good on the known firmware images
  if [[ "$DLINK_ENC_CHECK" =~ 00000000\ \ a3\ 01\  ]]; then
    GPG_CHECK="$(gpg --list-packets "$FIRMWARE_PATH" | grep "compressed packet:")"
    if [[ "$GPG_CHECK" == *"compressed packet: algo="* ]]; then
      print_output "[*] Identified GPG compressed firmware - using GPG extraction module"
      export GPG_COMPRESS=1
    fi
  fi
  if [[ "$DLINK_ENC_CHECK" == *"CrAU"* ]]; then
    print_output "[*] Identified Android OTA payload.bin update file - using Android extraction module"
    export ANDROID_OTA=1
  fi
}
