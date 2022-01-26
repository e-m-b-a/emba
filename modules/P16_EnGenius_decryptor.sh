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

# Description: Extracts encrypted firmware images from EnGenius reported by @ryancdotorg
#              See https://twitter.com/ryancdotorg/status/1473807312242442240 and
#              https://gist.github.com/ryancdotorg/914f3ad05bfe0c359b79716f067eaa99
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P16_EnGenius_decryptor() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0

  if [[ "$ENGENIUS_ENC_DETECTED" -ne 0 ]]; then
    module_title "EnGenius encrypted firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_FILE="$LOG_DIR"/firmware/firmware_engenius_dec.bin

    engenius_enc_extractor "$FIRMWARE_PATH" "$EXTRACTION_FILE"

    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

engenius_enc_extractor() {
  local ENGENIUS_ENC_PATH_="$1"
  local EXTRACTION_FILE_="$2"
  sub_module_title "EnGenius encrypted firmware extractor"

  hexdump -C "$ENGENIUS_ENC_PATH_" | head | tee -a "$LOG_FILE"

  if [[ -f "$EXT_DIR"/engenius-decrypt.py ]]; then
    python3 "$EXT_DIR"/engenius-decrypt.py "$ENGENIUS_ENC_PATH_" > "$EXTRACTION_FILE_"
  else
    print_output "[-] Decryptor not found - check your installation"
  fi

  print_output ""
  if [[ -f "$EXTRACTION_FILE_" ]]; then
    print_output "[+] Decrypted EnGenius firmware file to $ORANGE$EXTRACTION_FILE_$NC"
    export FIRMWARE_PATH="$EXTRACTION_FILE_"
    print_output ""
    print_output "[*] Firmware file details: $ORANGE$(file "$EXTRACTION_FILE_")$NC"
    #export FIRMWARE_PATH="$LOG_DIR"/firmware
  else
    print_output "[-] Decryption of EnGenius firmware file failed"
  fi
}
