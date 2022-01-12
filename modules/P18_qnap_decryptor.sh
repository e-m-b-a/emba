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

# Description: Extracts encrypted firmware images from QNAP as shown here:
#              https://github.com/max-boehm/qnap-utils
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P18_qnap_decryptor() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0

  if [[ "$QNAP_ENC_DETECTED" -ne 0 ]]; then
    module_title "QNAP encrypted firmware extractor"
    EXTRACTION_FILE="$LOG_DIR"/firmware/firmware_qnap_dec.tgz

    qnap_enc_extractor "$FIRMWARE_PATH" "$EXTRACTION_FILE"

    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

qnap_enc_extractor() {
  local QNAP_ENC_PATH_="$1"
  local EXTRACTION_FILE_="$2"
  sub_module_title "QNAP encrypted firmware extractor"

  hexdump -C "$QNAP_ENC_PATH_" | head | tee -a "$LOG_FILE"

  if [[ -f "$EXT_DIR"/PC1 ]]; then
    print_output ""
    "$EXT_DIR"/PC1 d QNAPNASVERSION4 "$QNAP_ENC_PATH_" "$EXTRACTION_FILE_"
  else
    print_output "[-] QNAP decryptor not found - check your installation"
  fi

  print_output ""
  if [[ -f "$EXTRACTION_FILE_" && "$(file "$EXTRACTION_FILE_")" == *"gzip compressed data"* ]]; then
    print_output "[+] Decrypted QNAP firmware file to $ORANGE$EXTRACTION_FILE_$NC"
    export FIRMWARE_PATH="$EXTRACTION_FILE_"
    file "$EXTRACTION_FILE_"
    #export FIRMWARE_PATH="$LOG_DIR"/firmware
    print_output ""
  else
    print_output "[-] Decryption of QNAP firmware file failed"
  fi
}
