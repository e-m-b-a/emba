#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Gives some very basic information about the provided firmware binary.
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P02_firmware_bin_file_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware file analyzer"

  local FILE_BIN_OUT
  export VMDK_DETECTED=0
  export DLINK_ENC_DETECTED=0

  FILE_BIN_OUT=$(file "$FIRMWARE_PATH")
  DLINK_ENC_CHECK=$(hexdump -C "$FIRMWARE_PATH"| head -1)

  if [[ "$FILE_BIN_OUT" == *"VMware4 disk image"* ]]; then
    export VMDK_DETECTED=1
  fi
  if [[ "$DLINK_ENC_CHECK" == *"SHRS"* ]]; then
    export DLINK_ENC_DETECTED=1
  fi

  local FILE_LS_OUT
  FILE_LS_OUT=$(ls -lh "$FIRMWARE_PATH")

  # entropy checking on binary file
  ENTROPY=$(ent "$FIRMWARE_PATH" | grep Entropy)
  
  print_output "[*] Details of the binary file:"
  print_output "$(indent "$FILE_LS_OUT")"
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

  module_end_log "${FUNCNAME[0]}" 1
}
