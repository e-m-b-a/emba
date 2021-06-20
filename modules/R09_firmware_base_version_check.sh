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

# Description:  Searches for version strings in the extracted firmware, but this time without the strict version detail database, 
#               because these aren't Linux executables.
export THREAD_PRIO=1

R09_firmware_base_version_check() {

  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware versions detection"

  echo -e "\n"
  print_output "[*] Initial version detection running on all firmware files ..." | tr -d "\n"

  EXTRACTOR_LOG="$LOG_DIR"/p05_firmware_bin_extractor.txt

  if [[ "$THREADED" -eq 1 ]]; then
    MAX_THREADS_R09=$((7*"$(grep -c ^processor /proc/cpuinfo)"))
  fi

  while read -r VERSION_LINE; do
    echo "." | tr -d "\n"

    STRICT="$(echo "$VERSION_LINE" | cut -d: -f2)"

    # as we do not have a typical linux executable we can't use strict version details
    if [[ $STRICT != "strict" ]]; then

      #print_output "[*] $VERSION_LINE"
      VERSION_IDENTIFIER="$(echo "$VERSION_LINE" | cut -d: -f3- | sed s/^\"// | sed s/\"$//)"
      echo "." | tr -d "\n"

      if [[ "$THREADED" -eq 1 ]]; then
        R09_bin_string_checker &
        WAIT_PIDS_R09+=( "$!" )
      else
        R09_bin_string_checker
      fi
    fi

    if [[ "${#WAIT_PIDS_R09[@]}" -gt "$MAX_THREADS_R09" ]]; then
      recover_wait_pids_r09 "${WAIT_PIDS_R09[@]}"
      if [[ "${#WAIT_PIDS_R09[@]}" -gt "$MAX_THREADS_R09" ]]; then
        max_pids_protection "$MAX_THREADS_R09" "${WAIT_PIDS_R09[@]}"
      fi
    fi

  done  < "$CONFIG_DIR"/bin_version_strings.cfg
  echo "." | tr -d "\n"

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_R09[@]}"
  fi

  VERSIONS_DETECTED=$(grep -c "Version information found" "$( get_log_file )")

  module_end_log "${FUNCNAME[0]}" "$VERSIONS_DETECTED"
}

R09_bin_string_checker() {

  # currently we only have binwalk files but sometimes we can find kernel version information or something else in it
  VERSION_FINDER=$(grep -o -a -E "$VERSION_IDENTIFIER" "$EXTRACTOR_LOG" 2>/dev/null | head -1 2>/dev/null)

  if [[ -n $VERSION_FINDER ]]; then
    echo ""
    print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in extraction logs."
  fi

  echo "." | tr -d "\n"

  if [[ -f $FIRMWARE_PATH ]]; then
    VERSION_FINDER=$(find "$FIRMWARE_PATH" -type f -print0 2>/dev/null | xargs -0 strings | grep -o -a -E "$VERSION_IDENTIFIER" | head -1 2>/dev/null)

    if [[ -n $VERSION_FINDER ]]; then
      echo ""
      print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in original firmware file (static)."
    fi
    echo "." | tr -d "\n"
  fi

  VERSION_FINDER=$(find "$OUTPUT_DIR" -type f -print0 2> /dev/null | xargs -0 strings | grep -o -a -E "$VERSION_IDENTIFIER" | head -1 2> /dev/null)

  if [[ -n $VERSION_FINDER ]]; then
    echo ""
    print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in extracted firmware files (static)."
  fi
  echo "." | tr -d "\n"
}

recover_wait_pids_r09() {

  local TEMP_PIDS=()
  local PID
  # check for really running PIDs and re-create the array
  for PID in ${WAIT_PIDS_R09[*]}; do
    #print_output "[*] max pid protection: ${#WAIT_PIDS[@]}"
    if [[ -e /proc/"$PID" ]]; then
      TEMP_PIDS+=( "$PID" )
    fi
  done
  #print_output "[!] R09 - really running pids: ${#TEMP_PIDS[@]}"

  # recreate the arry with the current running PIDS
  WAIT_PIDS_R09=()
  WAIT_PIDS_R09=("${TEMP_PIDS[@]}")
}
