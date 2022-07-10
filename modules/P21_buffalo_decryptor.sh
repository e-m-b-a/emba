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

# Description: Extracts encrypted firmware images from the vendor Buffalo
#              See https://modemizer.wordpress.com/2015/08/05/restoring-the-original-buffalo-firmware-on-the-wbmr-hp-g300h/
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P21_buffalo_decryptor() {
  module_log_init "${FUNCNAME[0]}"
  local NEG_LOG=0

  if [[ "$BUFFALO_ENC_DETECTED" -ne 0 ]]; then
    module_title "Buffalo encrypted firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_FILE="$LOG_DIR"/firmware/firmware_buffalo_dec.bin

    buffalo_enc_extractor "$FIRMWARE_PATH" "$EXTRACTION_FILE"

    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

buffalo_enc_extractor() {
  local BUFFALO_ENC_PATH_="${1:-}"
  local EXTRACTION_FILE_="${2:-}"
  local BUFFALO_FILE_CHECK=""

  if ! [[ -f "$BUFFALO_ENC_PATH_" ]]; then
    print_output "[-] No file for decryption provided"
    return
  fi

  sub_module_title "Buffalo encrypted firmware extractor"

  hexdump -C "$BUFFALO_ENC_PATH_" | head | tee -a "$LOG_FILE" || true
  print_output ""

  BUFFALO_DECRYTED=0
  local BUFFALO_ENC_PATH_STRIPPED
  BUFFALO_ENC_PATH_STRIPPED="$LOG_DIR/firmware/$(basename "$BUFFALO_ENC_PATH_").stripped"

  print_output "[*] Removing initial 208 bytes from header to prepare firmware for decryption"
  dd bs=208 skip=1 if="$BUFFALO_ENC_PATH_" of="$BUFFALO_ENC_PATH_STRIPPED"
  hexdump -C "$BUFFALO_ENC_PATH_STRIPPED" | head | tee -a "$LOG_FILE" || true
  print_output ""

  print_output "[*] Decrypting firmware ..."
  "$EXT_DIR"/buffalo-enc.elf -d -i "$BUFFALO_ENC_PATH_STRIPPED" -o "$EXTRACTION_FILE_"
  hexdump -C "$EXTRACTION_FILE_" | head | tee -a "$LOG_FILE" || true
  print_output ""

  if [[ -f "$EXTRACTION_FILE_" ]]; then
    BUFFALO_FILE_CHECK=$(file "$EXTRACTION_FILE_")
    if [[ "$BUFFALO_FILE_CHECK" =~ .*u-boot\ legacy\ uImage,\ .* ]]; then
      print_output ""
      print_output "[+] Decrypted Buffalo firmware file to $ORANGE$EXTRACTION_FILE_$NC"
      MD5_DONE_DEEP+=( "$(md5sum "$BUFFALO_ENC_PATH_" | awk '{print $1}')" )
      export FIRMWARE_PATH="$EXTRACTION_FILE_"
      print_output ""
      print_output "[*] Firmware file details: $ORANGE$(file "$EXTRACTION_FILE_")$NC"
      write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
      write_csv_log "Buffalo decryptor" "$BUFFALO_ENC_PATH_" "$EXTRACTION_FILE_" "1" "NA" "NA"
      BUFFALO_DECRYTED=1
      if [[ -z "${FW_VENDOR:-}" ]]; then
        FW_VENDOR="BUFFALO"
      fi
    fi
  fi

  if [[ "$BUFFALO_DECRYTED" -ne 1 ]]; then
    print_output "[-] Decryption of Buffalo firmware file failed"
  fi
}

