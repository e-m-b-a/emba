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

P09_firmware_base_version_check() {

  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware versions detection"

  declare -a VERSIONS_DETECTED

  print_output "[*] Initial version detection running on all firmware files ..." | tr -d "\n"
  while read -r VERSION_LINE; do
    echo "." | tr -d "\n"

    STRICT="$(echo "$VERSION_LINE" | cut -d: -f2)"

    # as we do not have a typical linux executable we can't use strict version details
    if [[ $STRICT == "binary" ]]; then
      #print_output "[*] $VERSION_LINE"
      VERSION_IDENTIFIER="$(echo "$VERSION_LINE" | cut -d: -f3- | sed s/^\"// | sed s/\"$//)"
      echo "." | tr -d "\n"

      # currently we only have binwalk files but sometimes we can find kernel version information or something else in it
      #VERSION_FINDER=$(find "$LOG_DIR"/*.txt -type f -exec grep -o -a -E "$VERSION_IDENTIFIER" {} \; 2>/dev/null | head -1 2>/dev/null)
      VERSION_FINDER=$(grep -o -a -E "$VERSION_IDENTIFIER" "$LOG_DIR"/p05_firmware_bin_extractor.txt 2>/dev/null | head -1 2>/dev/null)

      if [[ -n $VERSION_FINDER ]]; then
        echo ""
        print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in extraction logs."
        VERSIONS_DETECTED+=("$VERSION_FINDER")
      fi

      echo "." | tr -d "\n"

      VERSION_FINDER=$(find "$FIRMWARE_PATH" -type f -print0 2>/dev/null | xargs -0 strings | grep -o -a -E "$VERSION_IDENTIFIER" | head -1 2>/dev/null)

      if [[ -n $VERSION_FINDER ]]; then
        echo ""
        print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in original firmware file."
        VERSIONS_DETECTED+=("$VERSION_FINDER")
      fi

      echo "." | tr -d "\n"

      VERSION_FINDER=$(find "$OUTPUT_DIR" -type f -print0 2> /dev/null | xargs -0 strings | grep -o -a -E "$VERSION_IDENTIFIER" | head -1 2> /dev/null)

      if [[ -n $VERSION_FINDER ]]; then
        echo ""
        print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in extracted firmware files."
        VERSIONS_DETECTED+=("$VERSION_FINDER")
      fi
      echo "." | tr -d "\n"
    fi

  done  < "$CONFIG_DIR"/bin_version_strings.cfg
  echo "." | tr -d "\n"

  export TESTING_DONE=1
}
