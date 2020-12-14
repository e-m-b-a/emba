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

P09_firmware_base_version_chech() {

  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware versions detection"

  declare -a VERSIONS_DETECTED

  while read -r VERSION_LINE; do
    print_output "[*] Version detection running ..."

    VERSION_IDENTIFIER="$(echo "$VERSION_LINE" | cut -d: -f2 | sed s/^\"// | sed s/\"$//)"

    VERSION_FINDER=$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -a -e "$VERSION_IDENTIFIER" | head -1 2> /dev/null)
    VERSION_STRINGER=$(strings "$FIRMWARE_PATH" | grep -a -e "$VERSION_IDENTIFIER" | head -1 2> /dev/null)

    VERSIONS_DETECTED+=("$VERSION_FINDER")
    VERSIONS_DETECTED+=("$VERSION_STRINGER")

  done  < "$CONFIG_DIR"/bin_version_strings1.cfg

  for VERSION_DETECTED in "${VERSIONS_DETECTED[@]}"; do
    if [[ -n $VERSION_DETECTED ]]; then
      print_output "[+] Version information found ${RED}""$VERSION_DETECTED""${NC}${GREEN} found."
    fi
  done
}
