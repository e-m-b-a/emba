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

# Description: Extracts encrypted firmware images from D-Link (See https://github.com/0xricksanchez/dlink-decrypt)
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P11_dlink_SHRS_enc_extract() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0

  if [[ "$DLINK_ENC_DETECTED" -ne 0 ]]; then
    module_title "DLink encrypted firmware extractor"
    EXTRACTION_FILE="$LOG_DIR"/firmware/firmware_dlink_dec.bin

    if [[ "$DLINK_ENC_DETECTED" -eq 1 ]]; then
      dlink_SHRS_enc_extractor "$FIRMWARE_PATH" "$EXTRACTION_FILE"
    elif [[ "$DLINK_ENC_DETECTED" -eq 2 ]]; then
      print_output "[-] Decryption of this file is currently not supported"
    fi

    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

dlink_SHRS_enc_extractor() {
  local DLINK_ENC_PATH_="$1"
  local EXTRACTION_FILE_="$2"

  hexdump -C "$DLINK_ENC_PATH_" | head | tee -a "$LOG_FILE"

  dd if="$DLINK_ENC_PATH_" skip=1756 iflag=skip_bytes|openssl aes-128-cbc -d -p -nopad -nosalt -K "c05fbf1936c99429ce2a0781f08d6ad8" -iv "67c6697351ff4aec29cdbaabf2fbe346" --nosalt -in /dev/stdin -out "$EXTRACTION_FILE_" 2>&1 | tee -a "$LOG_FILE"

  if [[ -f "$EXTRACTION_FILE_" ]]; then
    print_output "[+] Decrypted D-Link firmware file to $ORANGE$EXTRACTION_FILE_$NC"
    export FIRMWARE_PATH="$EXTRACTION_FILE_"
  else
    print_output "[-] Decryption of D-Link firmware file failed"
  fi
}
