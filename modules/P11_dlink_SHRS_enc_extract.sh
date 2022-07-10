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
# Contributor: Benedikt Kuehne

# Description: Extracts encrypted firmware images from D-Link
# (See https://github.com/0xricksanchez/dlink-decrypt)
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P11_dlink_SHRS_enc_extract() {
  module_log_init "${FUNCNAME[0]}"
  local NEG_LOG=0

  if [[ "$DLINK_ENC_DETECTED" -ne 0 ]]; then
    module_title "DLink encrypted firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"
    EXTRACTION_FILE="$LOG_DIR"/firmware/firmware_dlink_dec.bin

    if [[ "$DLINK_ENC_DETECTED" -eq 1 ]]; then
      dlink_SHRS_enc_extractor "$FIRMWARE_PATH" "$EXTRACTION_FILE"
    elif [[ "$DLINK_ENC_DETECTED" -eq 2 ]]; then
      dlink_enc_img_extractor "$FIRMWARE_PATH" "$EXTRACTION_FILE"
    fi

    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

dlink_SHRS_enc_extractor() {
  local DLINK_ENC_PATH_="${1:-}"
  local EXTRACTION_FILE_="${2:-}"
  if ! [[ -f "$DLINK_ENC_PATH_" ]]; then
    print_output "[-] No file for decryption provided"
    return
  fi

  sub_module_title "DLink encrypted firmware extractor"

  hexdump -C "$DLINK_ENC_PATH_" | head | tee -a "$LOG_FILE" || true

  print_output ""

  dd if="$DLINK_ENC_PATH_" skip=1756 iflag=skip_bytes|openssl aes-128-cbc -d -p -nopad -nosalt -K "c05fbf1936c99429ce2a0781f08d6ad8" -iv "67c6697351ff4aec29cdbaabf2fbe346" --nosalt -in /dev/stdin -out "$EXTRACTION_FILE_" 2>&1 || true | tee -a "$LOG_FILE"

  print_output ""
  if [[ -f "$EXTRACTION_FILE_" ]]; then
    print_output "[+] Decrypted D-Link firmware file to $ORANGE$EXTRACTION_FILE_$NC"
    print_output ""
    print_output "[*] Firmware file details: $ORANGE$(file "$EXTRACTION_FILE_")$NC"
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "DLink SHRS decryptor" "$DLINK_ENC_PATH_" "$EXTRACTION_FILE_" "1" "NA" "NA"
    export FIRMWARE_PATH="$EXTRACTION_FILE_"
    if [[ -z "${FW_VENDOR:-}" ]]; then
      FW_VENDOR="D-Link"
    fi
  else
    print_output "[-] Decryption of D-Link firmware file failed"
  fi
}

dlink_enc_img_extractor(){
  local TMP_DIR="$LOG_DIR""/tmp"
  local DLINK_ENC_PATH_="${1:-}"
  local EXTRACTION_FILE_="${2:-}"
  local TMP_IMAGE_FILE="$TMP_DIR/image.bin"
  if ! [[ -f "$DLINK_ENC_PATH_" ]]; then
    print_output "[-] No file for decryption provided"
    return
  fi
  local IMAGE_SIZE=0
  local OFFSET=0
  local ITERATION=0

  sub_module_title "DLink encrpted_image extractor"

  hexdump -C "$DLINK_ENC_PATH_" | head | tee -a "$LOG_FILE" || true
  dd if="$DLINK_ENC_PATH_" skip=16 iflag=skip_bytes of="$TMP_IMAGE_FILE" 2>&1 | tee -a "$LOG_FILE"

  IMAGE_SIZE=$(stat -c%s "$TMP_IMAGE_FILE")
  (( ROOF=IMAGE_SIZE/131072 ))
  for ((ITERATION=0; ITERATION<ROOF; ITERATION++)); do
    if [[ "$ITERATION" -eq 0 ]]; then
      OFFSET=0
    else
      (( OFFSET=131072*ITERATION ))
    fi
    dd if="$TMP_IMAGE_FILE" skip="$OFFSET" iflag=skip_bytes count=256| openssl aes-256-cbc -d -in /dev/stdin  -out /dev/stdout \
    -K "6865392d342b4d212964363d6d7e7765312c7132613364316e26322a5a5e2538" -iv "4a253169516c38243d6c6d2d3b384145" --nopad \
    --nosalt | dd if=/dev/stdin of="$EXTRACTION_FILE_" oflag=append conv=notrunc 2>&1 | tee -a "$LOG_FILE"
  done
  # Now it should be a .ubi file thats somewhat readable and extractable via ubireader
  print_output ""
  if [[ -f "$EXTRACTION_FILE_" ]]; then
    print_output "[+] Decrypted D-Link firmware file to $ORANGE$EXTRACTION_FILE_$NC"
    print_output ""
    print_output "[*] Firmware file details: $ORANGE$(file "$EXTRACTION_FILE_")$NC"
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "DLink enc_img decryptor" "$DLINK_ENC_PATH_" "$EXTRACTION_FILE_" "1" "NA" "NA"
    export FIRMWARE_PATH="$EXTRACTION_FILE_"
    if [[ -z "${FW_VENDOR:-}" ]]; then
      FW_VENDOR="D-Link"
    fi
  else
    print_output "[-] Decryption of D-Link firmware file failed"
  fi
}
