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

  filer
  binwalking
}

filer() {
  local FILE_BIN_OUT
  FILE_BIN_OUT=$(file "$FIRMWARE_PATH")
  
  print_output "[*] Output of the file command:"
  print_output "[*] $FILE_BIN_OUT"
}

binwalking() {
  sub_module_title "Analyse binary firmware blob with binwalk"

  local MAIN_BINWALK
  print_output "[*] basic analysis with binwalk"
  MAIN_BINWALK=$(binwalk "$FIRMWARE_PATH")

  local LINUX
  print_output "[*] Output of the binwalk command:\n$MAIN_BINWALK"
  # we have to extend the following check:
  LINUX=$(echo "$MAIN_BINWALK" | grep -i "linux\|squash")

  print_output "\n[*] Entropy testing with binwalk ... "
  print_output "$(binwalk -E -F -J "$FIRMWARE_PATH")"
  mv "$(basename "$FIRMWARE_PATH".png)" "$LOG_DIR"/"$(basename "$FIRMWARE_PATH"_entropy.png)" 2> /dev/null

  # This test takes a long time and so I have removed it
  #print_output "\n[*] Architecture testing with binwalk ... could take a while"
  #binwalk -Y "$FIRMWARE_BIN_PATH"

  OUTPUT_DIR=$(basename "$FIRMWARE_PATH")
  OUTPUT_DIR="$LOG_DIR"/"$OUTPUT_DIR"_binwalk_emba

  print_output "[*] Extracting firmware to directory $OUTPUT_DIR"
  print_output "$(binwalk -e -M -C "$OUTPUT_DIR" "$FIRMWARE_PATH")"

  local LINUX_PATH_COUNTER
  print_output "\n[*] Trying to identify a Linux root path in $OUTPUT_DIR"
  # just to ensure there is somewhere a linux filesystem in the extracted stuff
  # emba is able to handle the rest
  LINUX_PATH_COUNTER="$(find "$OUTPUT_DIR" "${EXCL_FIND[@]}" -type d -iname bin -o -type d -iname busybox -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"

  if [[ -n $LINUX && "$LINUX_PATH_COUNTER" -gt 0 ]]; then
    echo ""
    print_output "[+] A Linux system was identified and will be analysed with emba."
    export FIRMWARE=1
    export FIRMWARE_PATH="$OUTPUT_DIR"
  fi
}
