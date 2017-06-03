#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
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

  if [[ -f "$FIRMWARE_PATH" ]]; then
    SHA512_CHECKSUM=$(sha512sum "$FIRMWARE_PATH" | awk '{print $1}')
    MD5_CHECKSUM=$(md5sum "$FIRMWARE_PATH" | awk '{print $1}')

    fw_bin_detector "$FIRMWARE_PATH"

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
    hexdump -C "$FIRMWARE_PATH"| head | tee -a "$LOG_FILE"
    print_output ""
    print_output "[*] SHA512 checksum: $ORANGE$CHECKSUM$NC"
    print_output ""
    print_output "$(indent "$FILE_BIN_OUT")"
    print_output ""
    print_output "$(indent "$ENTROPY")"
    print_output ""
    if [[ -x "$EXT_DIR"/pixde ]]; then
      print_output "[*] Visualized firmware file (first 2000 bytes):"
      "$EXT_DIR"/pixde -r-0x2000 "$FIRMWARE_PATH" | tee -a "$LOG_DIR"/p02_pixd.txt
      print_output ""
      python3 "$EXT_DIR"/pixd_png.py -i "$LOG_DIR"/p02_pixd.txt -o "$LOG_DIR"/pixd.png -p 10 > /dev/null
      write_link "$LOG_DIR"/pixd.png
    fi
  fi

  write_csv_log "Firmware name" "SHA512 checksum" "MD5 checksum" "Entropy" "Dlink enc state" "VMDK detected" "UBOOT image" "EXT filesystem" "AVM system detected"
  write_csv_log "$(basename "$FIRMWARE_PATH")" "$SHA512_CHECKSUM" "$MD5_CHECKSUM" "$ENTROPY" "$DLINK_ENC_DETECTED" "$VMDK_DETECTED" "$UBOOT_IMAGE" "$EXT_IMAGE" "$AVM_DETECTED"

  module_end_log "${FUNCNAME[0]}" 1
}

fw_bin_detector() {
  local CHECK_FILE="$1"
  local FILE_BIN_OUT
  local DLINK_ENC_CHECK
  local AVM_CHECK

  export VMDK_DETECTED=0
  export DLINK_ENC_DETECTED=0
  export AVM_DETECTED=0
  export UBOOT_IMAGE=0
  export EXT_IMAGE=0
  export UBI_IMAGE=0
  export EnGenius_DETECTED=0

  FILE_BIN_OUT=$(file "$CHECK_FILE")
  DLINK_ENC_CHECK=$(hexdump -C "$CHECK_FILE"| head -1)
  AVM_CHECK=$(strings "$CHECK_FILE" | grep -c "AVM GmbH .*. All rights reserved.\|(C) Copyright .* AVM")

  if [[ "$FILE_BIN_OUT" == *"VMware4 disk image"* ]]; then
    export VMDK_DETECTED=1
  fi
  if [[ "$FILE_BIN_OUT" == *"UBI image"* ]]; then
    export UBI_IMAGE=1
  fi
  if [[ "$DLINK_ENC_CHECK" == *"SHRS"* ]]; then
    export DLINK_ENC_DETECTED=1
  fi
  if [[ "$DLINK_ENC_CHECK" =~ 00000000\ \ 00\ 00\ 00\ 00\ 00\ 00\ 0.\ ..\ \ 00\ 00\ 0.\ ..\ 31\ 32\ 33\ 00 ]]; then
    export EnGenius_ENC_DETECTED=1
  fi
  if [[ "$DLINK_ENC_CHECK" =~ 00000000\ \ 00\ 00\ 00\ 00\ 00\ 00\ 01\ 01\ \ 00\ 00\ 0.\ ..\ 33\ 2e\ 3[89]\ 2e ]]; then
    export EnGenius_ENC_DETECTED=1
  fi
  if [[ "$DLINK_ENC_CHECK" == *"encrpted_img"* ]]; then
    export DLINK_ENC_DETECTED=2
  fi
  if [[ "$AVM_CHECK" -gt 0 ]]; then
    export AVM_DETECTED=1
  fi
  if [[ "$FILE_BIN_OUT" == *"u-boot legacy uImage"* ]]; then
    export UBOOT_IMAGE=1
  fi
  if [[ "$FILE_BIN_OUT" == *"Linux rev 1.0 ext2 filesystem data"* ]]; then
    export EXT_IMAGE=1
  fi
}
