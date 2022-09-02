#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description: Extracts encrypted firmware images from EnGenius reported by @ryancdotorg
#              See https://twitter.com/ryancdotorg/status/1473807312242442240 and
#              https://gist.github.com/ryancdotorg/914f3ad05bfe0c359b79716f067eaa99
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P16_EnGenius_decryptor() {
  local NEG_LOG=0

  if [[ "$ENGENIUS_ENC_DETECTED" -ne 0 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "EnGenius encrypted firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_FILE="$LOG_DIR"/firmware/firmware_engenius_dec.bin

    engenius_enc_extractor "$FIRMWARE_PATH" "$EXTRACTION_FILE"

    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
  fi
}

engenius_enc_extractor() {
  local ENGENIUS_ENC_PATH_="${1:-}"
  local EXTRACTION_FILE_="${2:-}"

  if ! [[ -f "$ENGENIUS_ENC_PATH_" ]]; then
    print_output "[-] No file for decryption provided"
    return
  fi

  sub_module_title "EnGenius encrypted firmware extractor"

  hexdump -C "$ENGENIUS_ENC_PATH_" | head | tee -a "$LOG_FILE" || true

  if [[ -f "$EXT_DIR"/engenius-decrypt.py ]]; then
    python3 "$EXT_DIR"/engenius-decrypt.py "$ENGENIUS_ENC_PATH_" > "$EXTRACTION_FILE_"
  else
    print_output "[-] Decryptor not found - check your installation"
  fi

  print_ln
  if [[ -f "$EXTRACTION_FILE_" ]]; then
    print_output "[+] Decrypted EnGenius firmware file to $ORANGE$EXTRACTION_FILE_$NC"
    export FIRMWARE_PATH="$EXTRACTION_FILE_"
    MD5_DONE_DEEP+=( "$(md5sum "$ENGENIUS_ENC_PATH_" | awk '{print $1}')" )
    print_ln
    print_output "[*] Firmware file details: $ORANGE$(file "$EXTRACTION_FILE_")$NC"
    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
    write_csv_log "EnGenius decryptor" "$ENGENIUS_ENC_PATH_" "$EXTRACTION_FILE_" "1" "NA" "NA"
    if [[ -z "${FW_VENDOR:-}" ]]; then
      FW_VENDOR="EnGenius"
      backup_var "FW_VENDOR" "$FW_VENDOR"
    fi
  else
    print_output "[-] Decryption of EnGenius firmware file failed"
  fi
}
