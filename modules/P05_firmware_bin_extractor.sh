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
  module_log_init "firmware_bin_extractor_log"
  module_title "Binary firmware extractor"

  binwalking
}

binwalking() {
  sub_module_title "Analyse binary firmware blob with binwalk"

  local MAIN_BINWALK
  print_output "[*] basic analysis with binwalk"
  MAIN_BINWALK=$(binwalk "$FIRMWARE_PATH")
  echo "$MAIN_BINWALK"

  echo
  print_output "[*] Entropy testing with binwalk ... "
  print_output "$(binwalk -E -F -J "$FIRMWARE_PATH")"
  mv "$(basename "$FIRMWARE_PATH".png)" "$LOG_DIR"/"$(basename "$FIRMWARE_PATH"_entropy.png)" 2> /dev/null

  # This test takes a long time and so I have removed it
  #print_output "\n[*] Architecture testing with binwalk ... could take a while"
  #binwalk -Y "$FIRMWARE_BIN_PATH"

  OUTPUT_DIR=$(basename "$FIRMWARE_PATH")
  OUTPUT_DIR="$LOG_DIR"/"$OUTPUT_DIR"_binwalk_emba

  echo
  print_output "[*] Extracting firmware to directory $OUTPUT_DIR"
  print_output "$(binwalk -e -M -C "$OUTPUT_DIR" "$FIRMWARE_PATH")"
}
