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

  #mapfile -t LICENSE_DETECTION_STATIC < <(strip_color_codes "$(grep "Version information found" "$LOG_DIR"/s09_*.txt 2>/dev/null | grep -v "unknown" | sort -u || true)")
  #mapfile -t LICENSE_DETECTION_DYN < <(strip_color_codes "$(grep "Version information found" "$LOG_DIR"/s116_*.txt 2>/dev/null | grep -v "unknown" | sort -u || true)")
  mapfile -t LICENSE_DETECTION_STATIC < <(grep -v "version_rule" "$LOG_DIR"/s09_*.csv 2>/dev/null | cut -d\; -f1,4,5 | sort -u || true)
  mapfile -t LICENSE_DETECTION_DYN < <(grep -v "version_rule" "$LOG_DIR"/s116_*.csv 2>/dev/null | cut -d\; -f1,4,5 |sort -u || true)
  # TODO: Currently the final kernel details from s25 are missing

  write_csv_log "binary/file" "version_rule" "version_detected" "csv_rule" "license" "static/emulation"
  VERSION_RULE="NA"
  CSV_RULE="NA"

  # static version detection
  if [[ "${#LICENSE_DETECTION_STATIC[@]}" -gt 0 ]]; then
    TYPE="static"
    for ENTRY in "${LICENSE_DETECTION_STATIC[@]}"; do
      if [[ -z "$ENTRY" ]]; then
        continue
      fi

      BINARY="$(echo "$ENTRY" | cut -d\; -f1)"
      VERSION="$(echo "$ENTRY" | cut -d\; -f2)" 
      LICENSE="$(echo "$ENTRY" |  cut -d\; -f3)"

      print_output "[+] Binary: $ORANGE$(basename "$BINARY" | cut -d\  -f1)$GREEN / Version: $ORANGE$VERSION$GREEN / License: $ORANGE$LICENSE$NC"
      write_csv_log "$BINARY" "$VERSION_RULE" "$VERSION" "$CSV_RULE" "$LICENSE" "$TYPE"
      ((COUNT_LIC+=1))
    done
  fi

  # Qemu version detection
  if [[ "${#LICENSE_DETECTION_DYN[@]}" -gt 0 ]]; then
    TYPE="emulation"
    for ENTRY in "${LICENSE_DETECTION_DYN[@]}"; do
      if [[ -z "$ENTRY" ]]; then
        continue
      fi

      BINARY="$(echo "$ENTRY" | cut -d\; -f1)"
      VERSION="$(echo "$ENTRY" | cut -d\; -f2)" 
      LICENSE="$(echo "$ENTRY" |  cut -d\; -f3)"

      print_output "[+] Binary: $ORANGE$(basename "$BINARY")$GREEN / Version: $ORANGE$VERSION$GREEN / License: $ORANGE$LICENSE$NC"
      write_csv_log "$BINARY" "$VERSION_RULE" "$VERSION" "$CSV_RULE" "$LICENSE" "$TYPE"
      ((COUNT_LIC+=1))
    done
  fi

  module_end_log "${FUNCNAME[0]}" "$COUNT_LIC"
}
