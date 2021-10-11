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

# Description: Identifies the main Linux distribution like Kali Linux, Debian, Fedora or OpenWRT

S06_distribution_identification()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Linux identification"

  OUTPUT=0
  while read -r LINE; do
    if echo "$LINE" | grep -q "^[^#*/;]"; then
      FILE="$(echo "$LINE" | cut -d\; -f2)"
      mapfile -t FILES < <(find "$FIRMWARE_PATH" -iwholename "*$FILE")
      for FILE in "${FILES[@]}"; do
        if [[ -f "$FILE" ]]; then
            PATTERN="$(echo "$LINE" | cut -d\; -f3 | sed s/^\"// | sed s/\"$//)"
            SED_COMMAND="$(echo "$LINE" | cut -d\; -f4)"
            # shellcheck disable=SC2086
            OUT1="$(grep $PATTERN "$FILE")"
            # echo "SED command: $SED_COMMAND"
            # echo "identified: $OUT1"
            IDENTIFIER=$(echo -e "$OUT1" | eval "$SED_COMMAND" | sed 's/  \+/ /g' | sed 's/ $//')

            if [[ $(basename "$FILE") == "image_sign" ]]; then
              # dlink image_sign file handling
              dlink_image_sign
            fi

            # check if not zero and not only spaces
            if [[ -n "${IDENTIFIER// }" ]]; then
              if [[ -n "$DLINK_FW_VER" ]]; then
                print_output "[+] Version information found $ORANGE$IDENTIFIER$GREEN in file $ORANGE$(print_path "$FILE")$GREEN for D-Link device."
              else
                print_output "[+] Version information found $ORANGE$IDENTIFIER$GREEN in file $ORANGE$(print_path "$FILE")$GREEN with Linux distribution detection"
              fi
              OUTPUT=1
            fi
        fi
      done
    fi
  done < "$CONFIG_DIR"/distri_id.cfg

  write_log ""
  module_end_log "${FUNCNAME[0]}" "$OUTPUT"
}

dlink_image_sign() {
  # the firmware version can be found in /config/buildver
  mapfile -t DLINK_BUILDVER < <(find "$FIRMWARE_PATH" -path "*config/buildver")
  for DLINK_BVER in "${DLINK_BUILDVER[@]}"; do
    DLINK_FW_VER=$(grep -E "^[0-9]+\.[0-9]+" "$DLINK_BVER")
    # -> 2.14
  done

  # probably we can use this in the future. Currently there is no need for it:
  mapfile -t DLINK_BUILDREV < <(find "$FIRMWARE_PATH" -path "*config/buildrev")
  for DLINK_BREV in "${DLINK_BUILDREV[@]}"; do
    DLINK_FW_VERx=$(grep -E "^[A-Z][0-9]+" "$DLINK_BREV")
    # -> B01
    DLINK_FW_VER="$DLINK_FW_VER""$DLINK_FW_VERx"
    # -> 2.14B01
  done

  if [[ -n "$DLINK_FW_VER" ]]; then
    IDENTIFIER="D-Link $IDENTIFIER"" v$DLINK_FW_VER"
    # -> D-Link dir-300 v2.14B01
  fi
}
