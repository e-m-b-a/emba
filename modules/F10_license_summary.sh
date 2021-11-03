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


F10_license_summary() {
  module_log_init "${FUNCNAME[0]}"
  module_title "License summary"
  COUNT_LIC=0

  mapfile -t LICENSE_DETECTION_STATIC < <(strip_color_codes "$(grep "Version information found" "$LOG_DIR"/s09_*.txt | grep -v "unknown" | sort -u)")
  eval "LICENSE_DETECTION_STATIC=($(for i in "${LICENSE_DETECTION_STATIC[@]}" ; do echo "\"$i\"" ; done | sort -u))"
  # [+] Version information found BusyBox v1.14.1  in binary /bin/busybox (-rwxr-xr-x root root) (license: gplv2) (static).

  mapfile -t LICENSE_DETECTION_DYN < <(strip_color_codes "$(grep "Version information found" "$LOG_DIR"/s115_*.txt | grep -v "unknown" | sort -u)")
  eval "LICENSE_DETECTION_DYN=($(for i in "${LICENSE_DETECTION_DYN[@]}" ; do echo "\"$i\"" ; done | sort -u))"
  # [+] Version information found BusyBox v1.14.1 (2012-10-10 12:06:47 CST) multi-call binary in binary /bin/busybox (license: gplv2) (emulation).

  # static version detection
  for ENTRY in "${LICENSE_DETECTION_STATIC[@]}"; do
    if [[ "$ENTRY" == *"in binary"* ]]; then
      BINARY="$(echo "$ENTRY" | sed 's/.*in binary //' | sed 's/ (license: .*//')"
      LICENSE="$(echo "$ENTRY" | sed 's/.*in binary //' | sed 's/.* (license: //' | sed 's/) (.*).*//')"
    elif [[ "$ENTRY" == *"binwalk logs"* ]]; then
      BINARY="$(echo "$ENTRY" | sed 's/.*Version information found //' | sed 's/ in binwalk logs.*//')"
      LICENSE="$(echo "$ENTRY" | sed 's/.*in binary //' | sed 's/.* (license: //' | sed 's/) (.*).*//')"
    else
      # shellcheck disable=SC2001
      BINARY="$(echo "$ENTRY" | sed 's/.*Version information found //')"
      LICENSE="$(echo "$ENTRY" | sed 's/.*Version information found //' | grep -o "license: .*)" | tr -d ")" | sed 's/license\:\ //')"
    fi
    print_output "[+] Binary: $ORANGE$BINARY$GREEN License: $ORANGE$LICENSE$NC"
    ((COUNT_LIC+=1))
  done

  # Qemu version detection
  for ENTRY in "${LICENSE_DETECTION_DYN[@]}"; do
    BINARY="$(echo "$ENTRY" | sed 's/.*in binary //' | sed 's/ (license: .*//')"
    LICENSE="$(echo "$ENTRY" | sed 's/.*in binary //' | sed 's/.* (license: //' | sed 's/) (.*).*//')"
    print_output "[+] Binary: $ORANGE$BINARY$GREEN License: $ORANGE$LICENSE$NC"
    ((COUNT_LIC+=1))
  done

  module_end_log "${FUNCNAME[0]}" "$COUNT_LIC"
}
