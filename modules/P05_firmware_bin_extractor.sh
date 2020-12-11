#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

P05_firmware_bin_extractor() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware extractor"

  binwalking
  # probably we can do something more in the future
}

binwalking() {
  sub_module_title "Analyze binary firmware blob with binwalk"

  local MAIN_BINWALK
  print_output "[*] basic analysis with binwalk"
  MAIN_BINWALK=$(binwalk "$FIRMWARE_PATH")
  echo "$MAIN_BINWALK"

  echo
  print_output "[*] Entropy testing with binwalk ... "
  print_output "$(binwalk -E -F -J "$FIRMWARE_PATH")"
  mv "$(basename "$FIRMWARE_PATH".png)" "$LOG_DIR"/"$(basename "$FIRMWARE_PATH"_entropy.png)" 2> /dev/null
  if command -v xdg-open > /dev/null; then
    xdg-open "$LOG_DIR"/"$(basename "$FIRMWARE_PATH"_entropy.png)" 2> /dev/null
  fi

  # This test takes a long time and so I have removed it
  # we come back to this topic later on - leave it here for the future
  #print_output "\n[*] Architecture testing with binwalk ... could take a while"
  #binwalk -Y "$FIRMWARE_BIN_PATH"

  OUTPUT_DIR=$(basename "$FIRMWARE_PATH")
  OUTPUT_DIR="$LOG_DIR"/"$OUTPUT_DIR"_binwalk_emba

  echo
  print_output "[*] Extracting firmware to directory $OUTPUT_DIR"
  print_output "$(binwalk -e -M -C "$OUTPUT_DIR" "$FIRMWARE_PATH")"
}
