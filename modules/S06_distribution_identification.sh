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
  write_csv_log "file" "type" "identifier" "csv-rule"
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
                get_csv_rule_distri "$IDENTIFIER"
                write_csv_log "$FILE" "dlink" "$IDENTIFIER" "$CSV_RULE"
              else
                print_output "[+] Version information found $ORANGE$IDENTIFIER$GREEN in file $ORANGE$(print_path "$FILE")$GREEN with Linux distribution detection"
                get_csv_rule_distri "$IDENTIFIER"
                write_csv_log "$FILE" "Linux" "$IDENTIFIER" "$CSV_RULE"
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
    DLINK_FW_VER=$(grep -E "[0-9]+\.[0-9]+" "$DLINK_BVER")
    if ! [[ "$DLINK_FW_VER" =~ ^v.* ]]; then
      DLINK_FW_VER="v$DLINK_FW_VER"
    fi
    # -> v2.14
  done

  # probably we can use this in the future. Currently there is no need for it:
  mapfile -t DLINK_BUILDREV < <(find "$FIRMWARE_PATH" -path "*config/buildrev")
  for DLINK_BREV in "${DLINK_BUILDREV[@]}"; do
    DLINK_FW_VERx=$(grep -E "^[A-Z][0-9]+" "$DLINK_BREV")
    # -> B01
    DLINK_FW_VER="$DLINK_FW_VER""$DLINK_FW_VERx"
    # -> v2.14B01
  done

  if [[ -n "$DLINK_FW_VER" ]]; then
    IDENTIFIER="D-Link $IDENTIFIER"" $DLINK_FW_VER"
    # -> D-Link dir-300 v2.14B01
  fi
}

get_csv_rule_distri() {
  # this is a temp solution. If this list grows we are going to solve it via a configuration file
  VERSION_IDENTIFIER="$1"
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | tr '[:upper:]' '[:lower:]')"

  ### handle versions of linux distributions:
  # debian 9 (stretch) - installer build 20170615+deb9u5
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | sed -r 's/(debian) [0-9]+\ \([a-z]+\)\ -\ installer\ build\ [0-9]+\+deb([0-9]+)u([0-9])/\1:\1_linux:\2\.\3/')"
  # Fedora 17 (Beefy Miracle)
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | sed -r 's/(fedora)\ ([0-9]+).*/\1project:\1:\2/')"
  # Ubuntu
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | sed -r 's/(ubuntu)\ ([0-9]+\,[0-9]+).*/\1_linux:\1:\2/')"
  # OpenWRT KAMIKAZE r18* -> 8.09.2
  # see also: https://openwrt.org/about/history
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | sed -r 's/(openwrt)\ (kamikaze)\ r1[4-8][0-9][0-9][0-9].*/\1:\2:8.09/')"
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | sed -r 's/(openwrt)\ (backfire)\ r2[0-9][0-9][0-9][0-9].*/\1:\2:10.03/')"
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | sed -r 's/lede\ ([0-9]+\.[0-9]+\.[0-9]+)(-)?(rc[0-9])?.*/openwrt:\1:\3/')"
  # d-link dir-300 v2.14b01
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | sed -r 's/d-link\ (.*)\ v([0-9].[0-9]+[a-z][0-9]+)/dlink:\1_firmware:\2/')"
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | sed -r 's/d-link\ (.*)\ v([0-9].[0-9]+)/dlink:\1_firmware:\2/')"
  # dd-wrt v24-sp2
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | sed -r 's/dd-wrt\ v([0-9]+)-(sp[0-9])?/dd-wrt:dd-wrt:\1:\2/')"
  VERSION_IDENTIFIER="$(echo "$VERSION_IDENTIFIER" | sed -r 's/dd-wrt\ \#([0-9]+)/dd-wrt:dd-wrt:\1/')"
  CSV_RULE="$VERSION_IDENTIFIER"
}
