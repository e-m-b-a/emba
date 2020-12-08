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

P07_firmware_bin_base_analyser() {
  module_log_init "firmware_bin_base_analyser_log"
  module_title "Binary firmware OS detection"

  string_analyse
}

string_analyse() {
  COUNTER_Linux="$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -c Linux 2> /dev/null)"
  COUNTER_Linux_FW="$(strings "$FIRMWARE_PATH" | grep -c Linux 2> /dev/null)"
  COUNTER_Linux=$((COUNTER_Linux+COUNTER_Linux_FW))

  COUNTER_VxWorks="$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -c VxWorks 2> /dev/null)"
  COUNTER_VxWorks_FW="$(strings "$FIRMWARE_PATH" | grep -c VxWorks 2> /dev/null)"
  COUNTER_VxWorks=$((COUNTER_VxWorks+COUNTER_VxWorks_FW))

  COUNTER_FreeRTOS="$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -c FreeRTOS 2> /dev/null)"
  COUNTER_FreeRTOS_FW="$(strings "$FIRMWARE_PATH" | grep -c FreeRTOS 2> /dev/null)"
  COUNTER_FreeRTOS=$((COUNTER_FreeRTOS+COUNTER_FreeRTOS_FW))

  COUNTER_eCos="$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -c eCos 2> /dev/null)"
  COUNTER_eCos_FW="$(strings "$FIRMWARE_PATH" | grep -c eCos 2> /dev/null)"
  COUNTER_eCos=$((COUNTER_eCos+COUNTER_eCos_FW))

  if [[ $((COUNTER_VxWorks+COUNTER_FreeRTOS+COUNTER_eCos)) -gt 0 ]] ; then
    print_output "$(indent "$(orange "Operating system detection:")")" "no_log"
    if [[ $COUNTER_VxWorks -gt 0 ]] ; then print_output "$(indent "$(orange "VxWorks          ""$COUNTER_VxWorks")")" "no_log" ; fi
    if [[ $COUNTER_FreeRTOS -gt 0 ]] ; then print_output "$(indent "$(orange "FreeRTOS          ""$COUNTER_FreeRTOS")")" "no_log" ; fi
    if [[ $COUNTER_eCos -gt 0 ]] ; then print_output "$(indent "$(orange "eCos          ""$COUNTER_eCos")")" "no_log" ; fi
    if [[ $COUNTER_Linux -gt 0 ]] ; then print_output "$(indent "$(orange "Linux            ""$COUNTER_Linux")")" "no_log"; fi
  fi

  echo
  print_output "[*] Trying to identify a Linux root path in $OUTPUT_DIR"
  # just to check if there is somewhere a linux filesystem in the extracted stuff
  # emba is able to handle the rest
  LINUX_PATH_COUNTER="$(find "$OUTPUT_DIR" "${EXCL_FIND[@]}" -type d -iname bin -o -type d -iname busybox -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"
  if [[ $LINUX_PATH_COUNTER -gt 0 ]] ; then
    print_output "[+] Found possible Linux system in $OUTPUT_DIR"
    export FIRMWARE=1
    export FIRMWARE_PATH="$OUTPUT_DIR"
  fi
}
