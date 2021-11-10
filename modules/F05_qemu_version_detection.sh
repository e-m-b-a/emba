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

# Description:  This module extracts version information from the results of S115

F05_qemu_version_detection() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Identified software components - via usermode emulation."

  LOG_PATH_S115="$LOG_DIR"/s115_usermode_emulator.txt
  if [[ -f "$LOG_PATH_S115" ]]; then
    LOG_PATH_MODULE_S115="$LOG_DIR"/s115_usermode_emulator/

    while read -r VERSION_LINE; do 
      if echo "$VERSION_LINE" | grep -v -q "^[^#*/;]"; then
        continue
      fi

      if [[ $THREADING -eq 1 ]]; then
        version_detection_thread &
        WAIT_PIDS_F05+=( "$!" )
      else
        version_detection_thread
      fi
    done < "$CONFIG_DIR"/bin_version_strings.cfg
    echo
    if [[ $THREADED -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS_F05[@]}"
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "$QEMULATION"
}

version_detection_thread() {
  BINARY="$(echo "$VERSION_LINE" | cut -d: -f1)"
  STRICT="$(echo "$VERSION_LINE" | cut -d: -f2)"
  LIC="$(echo "$VERSION_LINE" | cut -d: -f3)"

  VERSION_IDENTIFIER="$(echo "$VERSION_LINE" | cut -d: -f4- | sed s/^\"// | sed s/\"$//)"

  # if we have the key strict this version identifier only works for the defined binary and is not generic!
  if [[ $STRICT != "strict" ]]; then
    readarray -t VERSIONS_DETECTED < <(grep -a -o -H -E "$VERSION_IDENTIFIER" "$LOG_PATH_MODULE_S115"/qemu_*.txt | sort -u 2>/dev/null)
  else
    if [[ -f "$LOG_PATH_MODULE_S115"/qemu_"$BINARY".txt ]]; then
      VERSION_STRICT=$(grep -a -o -E "$VERSION_IDENTIFIER" "$LOG_PATH_MODULE_S115"/qemu_"$BINARY".txt | sort -u | head -1 2>/dev/null)
      BINARY_PATH=$(grep -a "Emulating binary:" "$LOG_PATH_MODULE_S115"/qemu_"$BINARY".txt | cut -d: -f2 | sed -e 's/^\ //' | sort -u | head -1 2>/dev/null)
      if [[ -n "$VERSION_STRICT" ]]; then
        if [[ "$BINARY" == "smbd" ]]; then
          # we log it as the original binary and the samba binary name
          VERSION_="$BINARY $VERSION_STRICT"
          VERSIONS_DETECTED+=("$VERSION_")
          BINARY="samba"
        fi
        VERSION_="$BINARY_PATH:$BINARY $VERSION_STRICT"
        VERSIONS_DETECTED+=("$VERSION_")
      fi
    fi
  fi

  if [[ ${#VERSIONS_DETECTED[@]} -ne 0 ]]; then
    for VERSION_DETECTED in "${VERSIONS_DETECTED[@]}"; do
      # if we have multiple detection of the same version details:
      if [ "$VERSION_DETECTED" != "$VERS_DET_OLD" ]; then
        VERS_DET_OLD="$VERSION_DETECTED"

        # first field is the path of the qemu log file
        LOG_PATH_="$(echo "$VERSION_DETECTED" | cut -d: -f1)"

        VERSION_DETECTED="$(echo "$VERSION_DETECTED" | cut -d: -f2-)"

        if [[ -n "$LOG_PATH_" ]]; then
          mapfile -t BINARY_PATHS < <(grep -a "Emulating binary:" "$LOG_PATH_" 2>/dev/null | cut -d: -f2 | sed -e 's/^\ //' | sort -u 2>/dev/null)
        fi

        if [[ ${#BINARY_PATHS[@]} -eq 0 ]]; then
          print_output "[+] Version information found ${RED}""$VERSION_DETECTED""${NC}${GREEN} in qemu log file $ORANGE$LOG_PATH_$GREEN (license: $ORANGE$LIC$GREEN) (${ORANGE}emulation$GREEN)." "" "$LOG_PATH_"
          continue
        else
          # binary path set in strict mode
          for BINARY_PATH in "${BINARY_PATHS[@]}"; do
            print_output "[+] Version information found ${RED}""$VERSION_DETECTED""${NC}${GREEN} in binary $ORANGE$BINARY_PATH$GREEN (license: $ORANGE$LIC$GREEN) (${ORANGE}emulation$GREEN)." "" "$LOG_PATH_"
          done
        fi
        BINARY_PATH=""
        BINARY_PATHS=()
      fi
    done
  fi
}
