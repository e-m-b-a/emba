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

# Description:  Iterates through a static list with version details layout 
#               (e.g. busybox:binary:"BusyBox\ v[0-9]\.[0-9][0-9]\.[0-9]\ .*\ multi-call\ binary" ) of all executables and 
#               checks if these fit on a binary in the firmware. 

S09_firmware_base_version_check() {

  # this module check for version details statically.
  # this module is designed for *x based systems
  # for other systems (eg RTOS) we have the R09

  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware versions detection"

  EXTRACTOR_LOG="$LOG_DIR"/p05_firmware_bin_extractor.txt

  declare -a VERSIONS_DETECTED

  print_output "[*] Initial version detection running ..." | tr -d "\n"
  while read -r VERSION_LINE; do
    echo "." | tr -d "\n"

    STRICT="$(echo "$VERSION_LINE" | cut -d: -f2)"
    BIN_NAME="$(echo "$VERSION_LINE" | cut -d: -f1)"
    echo "VERSION_LINE: $VERSION_LINE"
    echo "STRICT: $STRICT"
    echo "BIN_NAME: $BIN_NAME"

    # as we do not have a typical linux executable we can't use strict version details
    # but to not exhaust the run time we only search for stuff that we know is possible to detect
    # on the other hand, if we do not use emulation for deeper detection we run all checks

    VERSION_IDENTIFIER="$(echo "$VERSION_LINE" | cut -d: -f3- | sed s/^\"// | sed s/\"$//)"

    if [[ $STRICT != "strict" ]]; then
      echo "." | tr -d "\n"

      # check binwalk files sometimes we can find kernel version information or something else in it
      VERSION_FINDER=$(grep -o -a -E "$VERSION_IDENTIFIER" "$EXTRACTOR_LOG" 2>/dev/null | head -1 2>/dev/null)
      if [[ -n $VERSION_FINDER ]]; then
        echo ""
        print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in binwalk logs."
        VERSIONS_DETECTED+=("$VERSION_FINDER")
        echo "." | tr -d "\n"
      fi
      
      echo "." | tr -d "\n"

      if [[ $FIRMWARE -eq 0 ]]; then
        VERSION_FINDER=$(find "$FIRMWARE_PATH" -xdev -type f -print0 2>/dev/null | xargs -0 strings | grep -o -a -E "$VERSION_IDENTIFIER" | head -1 2>/dev/null)

        if [[ -n $VERSION_FINDER ]]; then
          echo ""
          print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in original firmware file."
          VERSIONS_DETECTED+=("$VERSION_FINDER")
        fi  
        echo "." | tr -d "\n"
      fi  

      for BIN in "${BINARIES[@]}"; do
        VERSION_FINDER=$(strings "$BIN" | grep -o -a -E "$VERSION_IDENTIFIER" | head -1 2> /dev/null)
        if [[ -n $VERSION_FINDER ]]; then
          echo ""
          print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in binary $BIN."
          VERSIONS_DETECTED+=("$VERSION_FINDER")
        fi  
      done
      echo "." | tr -d "\n"
    else
      mapfile -t STRICT_BINS < <(find "$OUTPUT_DIR" -xdev -executable -type f -name "$BIN_NAME" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)
      for BIN in "${STRICT_BINS[@]}"; do
        VERSION_FINDER=$(strings "$BIN" | grep -E "$VERSION_IDENTIFIER" | sort -u)
        if [[ -n $VERSION_FINDER ]]; then
          echo ""
          print_output "[+] Version information found ${RED}""$BIN"" ""$VERSION_FINDER""${NC}${GREEN} in binary $BIN (strict)."
          VERSIONS_DETECTED+=("$VERSION_FINDER")
        fi
      done
      echo "." | tr -d "\n"
    fi

  done  < "$CONFIG_DIR"/bin_version_strings.cfg

  echo "." | tr -d "\n"

  module_end_log "${FUNCNAME[0]}" "${#VERSIONS_DETECTED[@]}"
}
