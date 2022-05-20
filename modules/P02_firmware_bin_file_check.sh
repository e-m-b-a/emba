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
  export PATOOLS_INIT=0
  export ANDROID_OTA=0

  write_csv_log "Entity" "data" "Notes"
  write_csv_log "Firmware path" "$FIRMWARE_PATH" "NA"
  if [[ -f "$FIRMWARE_PATH" ]]; then
    SHA512_CHECKSUM="$(sha512sum "$FIRMWARE_PATH" | awk '{print $1}')"
    write_csv_log "SHA512" "${SHA512_CHECKSUM:-}" "NA"
    SHA1_CHECKSUM="$(sha1sum "$FIRMWARE_PATH" | awk '{print $1}')"
    write_csv_log "SHA1" "${SHA1_CHECKSUM:-}" "NA"
    MD5_CHECKSUM="$(md5sum "$FIRMWARE_PATH" | awk '{print $1}')"
    write_csv_log "MD5" "${MD5_CHECKSUM:-}" "NA"

     # entropy checking on binary file
    ENTROPY="$(ent "$FIRMWARE_PATH" | grep Entropy)"
    write_csv_log "Entropy" "${ENTROPY:-}" "NA"
  fi

  local FILE_LS_OUT
  FILE_LS_OUT=$(ls -lh "$FIRMWARE_PATH")
  
  print_output "[*] Details of the firmware file:"
  print_output ""
  print_output "$(indent "$FILE_LS_OUT")"
  print_output ""
  if [[ -f "$FIRMWARE_PATH" ]]; then
    print_output ""
    print_output "$(indent "$(file "$FIRMWARE_PATH")")"
    print_output ""
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

  module_end_log "${FUNCNAME[0]}" 1
}

fw_bin_detector() {
  local CHECK_FILE="${1:-}"
  local FILE_BIN_OUT
  local DLINK_ENC_CHECK
  local AVM_CHECK

  export PATOOLS_INIT=0
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
    write_csv_log "AVM firmware detected" "yes" "NA"
  fi
  # if we have a zip, tgz, tar archive we are going to use the patools extractor
  if [[ "$FILE_BIN_OUT" == *"gzip compressed data"* || "$FILE_BIN_OUT" == *"Zip archive data"* || "$FILE_BIN_OUT" == *"POSIX tar archive"* || "$FILE_BIN_OUT" == *"ISO 9660 CD-ROM filesystem data"* ]]; then
    # as the AVM images are also zip files we need to bypass it here:
    if [[ "$AVM_DETECTED" -ne 1 ]]; then
      print_output "[*] Identified gzip/zip/tar/iso archive file - using patools extraction module"
      export PATOOLS_INIT=1
      write_csv_log "basic compressed (patool)" "yes" "NA"
    fi
  fi
  if [[ "$FILE_BIN_OUT" == *"VMware4 disk image"* ]]; then
    print_output "[*] Identified VMWware VMDK archive file - using VMDK extraction module"
    export VMDK_DETECTED=1
    write_csv_log "VMDK" "yes" "NA"
  fi
  if [[ "$FILE_BIN_OUT" == *"UBI image"* ]]; then
    print_output "[*] Identified UBI filesystem image - using UBI extraction module"
    export UBI_IMAGE=1
    write_csv_log "UBI filesystem" "yes" "NA"
  fi
  if [[ "$DLINK_ENC_CHECK" == *"SHRS"* ]]; then
    print_output "[*] Identified D-Link SHRS encrpyted firmware - using D-Link extraction module"
    export DLINK_ENC_DETECTED=1
    write_csv_log "D-Link SHRS" "yes" "NA"
  fi
  if [[ "$DLINK_ENC_CHECK" =~ 00000000\ \ 00\ 00\ 00\ 00\ 00\ 00\ 0.\ ..\ \ 00\ 00\ 0.\ ..\ 31\ 32\ 33\ 00 ]]; then
    print_output "[*] Identified EnGenius encrpyted firmware - using Engenius extraction module"
    export ENGENIUS_ENC_DETECTED=1
    write_csv_log "EnGenius encrypted" "yes" "NA"
  fi
  if [[ "$DLINK_ENC_CHECK" =~ 00000000\ \ 00\ 00\ 00\ 00\ 00\ 00\ 01\ 01\ \ 00\ 00\ 0.\ ..\ 33\ 2e\ 3[89]\ 2e ]]; then
    print_output "[*] Identified Engenius encrpyted firmware - using Engenius extraction module"
    export ENGENIUS_ENC_DETECTED=1
    write_csv_log "EnGenius encrypted" "yes" "NA"
  fi
  if [[ "$DLINK_ENC_CHECK" == *"encrpted_img"* ]]; then
    print_output "[*] Identified D-Link encrpted_img encrpyted firmware - using D-Link extraction module"
    export DLINK_ENC_DETECTED=2
    write_csv_log "D-Link encrpted_img encrypted" "yes" "NA"
  fi
  if [[ "$FILE_BIN_OUT" == *"u-boot legacy uImage"* ]]; then
    print_output "[*] Identified u-boot firmware - using u-boot module"
    export UBOOT_IMAGE=1
    write_csv_log "Uboot image" "yes" "NA"
  fi
  if [[ "$FILE_BIN_OUT" == *"Unix Fast File system [v2]"* ]]; then
    print_output "[*] Identified UFS filesytem - using UFS filesytem extraction module"
    export BSD_UFS=1
    write_csv_log "BSD UFS filesystem" "yes" "NA"
  fi
  if [[ "$FILE_BIN_OUT" == *"Linux rev 1.0 ext2 filesystem data"* ]]; then
    print_output "[*] Identified Linux ext2 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
    write_csv_log "Ext2 filesystem" "yes" "NA"
  fi
  if [[ "$FILE_BIN_OUT" == *"Linux rev 1.0 ext3 filesystem data"* ]]; then
    print_output "[*] Identified Linux ext3 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
    write_csv_log "Ext3 filesystem" "yes" "NA"
  fi
  if [[ "$FILE_BIN_OUT" == *"Linux rev 1.0 ext4 filesystem data"* ]]; then
    print_output "[*] Identified Linux ext4 filesytem - using EXT filesytem extraction module"
    export EXT_IMAGE=1
    write_csv_log "Ext4 filesystem" "yes" "NA"
  fi
  if [[ "$QNAP_ENC_CHECK" == *"QNAP encrypted firmware footer , model"* ]]; then
    print_output "[*] Identified QNAP encrpyted firmware - using QNAP extraction module"
    export QNAP_ENC_DETECTED=1
    write_csv_log "QNAP encrypted filesystem" "yes" "NA"
  fi
  # probably we need to take a deeper look to identify the gpg compressed firmware files better.
  # Currently this detection mechanism works quite good on the known firmware images
  if [[ "$DLINK_ENC_CHECK" =~ 00000000\ \ a3\ 01\  ]]; then
    GPG_CHECK="$(gpg --list-packets "$FIRMWARE_PATH" | grep "compressed packet:")"
    if [[ "$GPG_CHECK" == *"compressed packet: algo="* ]]; then
      print_output "[*] Identified GPG compressed firmware - using GPG extraction module"
      export GPG_COMPRESS=1
      write_csv_log "GPG compressed firmware" "yes" "NA"
    fi
  fi
  if [[ "$DLINK_ENC_CHECK" == *"CrAU"* ]]; then
    print_output "[*] Identified Android OTA payload.bin update file - using Android extraction module"
    export ANDROID_OTA=1
    write_csv_log "Android OTA update" "yes" "NA"
  fi
}
