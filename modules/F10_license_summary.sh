#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Collects license details and gives a list with binaries, identified version and
#               the corresponding license (if available). The license details are maintained in the
#               configuration file config/bin_version_strings.cfg


F10_license_summary() {
  module_log_init "${FUNCNAME[0]}"
  module_title "License inventory"
  pre_module_reporter "${FUNCNAME[0]}"
  print_output ""

  COUNT_LIC=0

  mapfile -t LICENSE_DETECTION_STATIC < <(strip_color_codes "$(grep "Version information found" "$LOG_DIR"/s09_*.txt 2>/dev/null | grep -v "unknown" | sort -u)")
  mapfile -t LICENSE_DETECTION_DYN < <(strip_color_codes "$(grep "Version information found" "$LOG_DIR"/s116_*.txt 2>/dev/null | grep -v "unknown" | sort -u)")
  # TODO: Currently the final kernel details from s25 are missing

  # static version detection
  for ENTRY in "${LICENSE_DETECTION_STATIC[@]}"; do
    if [[ -z "$ENTRY" ]]; then
      continue
    fi

    if [[ "$ENTRY" == *"in binary"* ]]; then
      BINARY="$(echo "$ENTRY" | sed 's/.*in binary //' | sed 's/ (license: .*//')"
      VERSION="$(echo "$ENTRY" | sed 's/.*Version information found //' | sed 's/ in binary .*//')"
      LICENSE="$(echo "$ENTRY" | sed 's/.*in binary //' | sed 's/.* (license: //' | sed 's/) (.*).*//')"
    elif [[ "$ENTRY" == *"binwalk logs"* ]]; then
      BINARY="NA"
      VERSION="$(echo "$ENTRY" | sed 's/.*Version information found //' | sed 's/ in binwalk logs.*//')"
      LICENSE="$(echo "$ENTRY" | sed 's/.*in binary //' | sed 's/.* (license: //' | sed 's/) (.*).*//' | tr -d ")" | sed 's/\.$//')"
    else
      # shellcheck disable=SC2001
      BINARY="$(echo "$ENTRY" | sed 's/.*Version information found //')"
      VERSION="NA"
      LICENSE="$(echo "$ENTRY" | sed 's/.*Version information found //' | grep -o "license: .*)" | tr -d ")" | sed 's/license\:\ //')"
    fi

    print_output "[+] Binary: $ORANGE$(basename "$BINARY" | cut -d\  -f1)$GREEN / Version: $ORANGE$VERSION$GREEN / License: $ORANGE$LICENSE$NC"
    ((COUNT_LIC+=1))
  done

  # Qemu version detection
  for ENTRY in "${LICENSE_DETECTION_DYN[@]}"; do
    if [[ -z "$ENTRY" ]]; then
      continue
    fi

    if [[ "$ENTRY" == *"in binary"* ]]; then
      BINARY="$(echo "$ENTRY" | sed 's/.*in binary //' | sed 's/ (license: .*//')"
      VERSION="$(echo "$ENTRY" | sed 's/.*Version information found //' | sed 's/ in binary .*//')"
      LICENSE="$(echo "$ENTRY" | sed 's/.*in binary //' | sed 's/.* (license: //' | sed 's/) (.*).*//')"
    elif [[ "$ENTRY" == *"qemu log file"* ]]; then
      BINARY="$(echo "$ENTRY" | sed 's/.*in qemu log file //' | sed 's/ (license: .*//')"
      VERSION="$(echo "$ENTRY" | sed 's/.*Version information found //' | sed 's/ in qemu log file .*//')"
      LICENSE="$(echo "$ENTRY" | sed 's/.*in qemu log file //' | sed 's/.* (license: //' | sed 's/) (.*).*//')"
    fi

    print_output "[+] Binary: $ORANGE$(basename "$BINARY")$GREEN / Version: $ORANGE$VERSION$GREEN / License: $ORANGE$LICENSE$NC"
    ((COUNT_LIC+=1))
  done

  module_end_log "${FUNCNAME[0]}" "$COUNT_LIC"
}
