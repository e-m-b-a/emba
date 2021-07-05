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

# Description:  Searches for files with a specified password pattern inside.

S107_deep_password_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Deep analysis of files for password hashes"

  PW_HASH_CONFIG="$CONFIG_DIR"/password_regex.cfg

  find "$FIRMWARE_PATH" -xdev -type f -exec grep --color -n -a -E -H -f "$PW_HASH_CONFIG" {} \; > "$TMP"/pw_hashes.txt

  if [[ $(wc -l "$TMP"/pw_hashes.txt | awk '{print $1}') -gt 0 ]]; then
    print_output "[+] Found the following password hash values:"
    while read -r PW_HASH; do
      PW_PATH=$(echo "$PW_HASH" | cut -d: -f1)
      PW_HASH=$(echo "$PW_HASH" | cut -d: -f2- | sed -r "s/[[:blank:]]+/\ /g")
      print_output "[+] PATH: $ORANGE$(print_path "$PW_PATH")$GREEN\t-\tHash: $ORANGE$PW_HASH$GREEN."
      ((PW_COUNTER++))
    done < "$TMP"/pw_hashes.txt
  fi

  print_output ""
  print_output "[*] Found $ORANGE$PW_COUNTER$NC password hashes."
  write_log ""
  write_log "[*] Statistics:$PW_COUNTER"

  module_end_log "${FUNCNAME[0]}" "$PW_COUNTER"
}
