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

# Description:  Extracts gpg compressed (not encrypted) firmware images
#               This technique is used by Linksys/Belkin

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P17_gpg_decompress() {
  module_log_init "${FUNCNAME[0]}"
  NEG_LOG=0

  if [[ "$GPG_COMPRESS" -eq 1 ]]; then
    module_title "GPG compressed firmware extractor"
    EXTRACTION_FILE="$LOG_DIR"/firmware/firmware_gpg_dec.bin

    gpg_decompress_extractor "$FIRMWARE_PATH" "$EXTRACTION_FILE"

    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

gpg_decompress_extractor() {
  local GPG_FILE_PATH_="$1"
  local EXTRACTION_FILE_="$2"
  sub_module_title "GPG compressed firmware extractor"

  gpg --list-packets "$GPG_FILE_PATH_" 2>/dev/null | tee -a "$LOG_FILE"
  gpg --decrypt "$GPG_FILE_PATH_" > "$EXTRACTION_FILE_"

  print_output ""
  if [[ -f "$EXTRACTION_FILE_" ]]; then
    print_output "[+] Extracted GPG compressed firmware file to $ORANGE$EXTRACTION_FILE_$NC"
    export FIRMWARE_PATH="$EXTRACTION_FILE_"
  else
    print_output "[-] Extraction of GPG compressed firmware file failed"
  fi
}
