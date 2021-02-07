#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

P07_firmware_bin_base_analyzer() {

  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware basic analyzer"

  os_identification

  # we only do this if we have not found a LInux filesystem
  if ! [[ -d "$FIRMWARE_PATH" ]]; then
    binary_architecture_detection
  fi
}

os_identification() {
  sub_module_title "OS detection"

  print_output "[*] Initial OS detection running " | tr -d "\n"
  echo "." | tr -d "\n"

  # We can improve this search stuff a lot in the future:
  COUNTER_Linux="$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -c Linux 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_Linux_FW="$(strings "$FIRMWARE_PATH" | grep -c Linux 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_Linux=$((COUNTER_Linux+COUNTER_Linux_FW))
  echo "." | tr -d "\n"

  COUNTER_VxWorks="$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -c VxWorks 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_VxWorks_FW="$(strings "$FIRMWARE_PATH" | grep -c VxWorks 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_VxWorks=$((COUNTER_VxWorks+COUNTER_VxWorks_FW))
  echo "." | tr -d "\n"

  COUNTER_FreeRTOS="$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -c FreeRTOS 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_FreeRTOS_FW="$(strings "$FIRMWARE_PATH" | grep -c FreeRTOS 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_FreeRTOS=$((COUNTER_FreeRTOS+COUNTER_FreeRTOS_FW))
  echo "." | tr -d "\n"

  COUNTER_eCos="$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -c eCos 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_eCos_FW="$(strings "$FIRMWARE_PATH" | grep -c eCos 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_eCos=$((COUNTER_eCos+COUNTER_eCos_FW))
  echo "." | tr -d "\n"

  # just a wild guess after looking at: https://i.blackhat.com/eu-19/Wednesday/eu-19-Abbasi-Doors-Of-Durin-The-Veiled-Gate-To-Siemens-S7-Silicon.pdf
  COUNTER_ADONIS="$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -i -c ADONIS 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_ADONIS_FW="$(strings "$FIRMWARE_PATH" | grep -c ADONIS 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_ADONIS=$((COUNTER_ADONIS+COUNTER_ADONIS_FW))
  echo "." | tr -d "\n"

  # Siemens SIPROTEC devices
  COUNTER_SIPROTEC="$(find "$OUTPUT_DIR" -type f -exec strings {} \; | grep -i -c siprotec 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_SIPROTEC_FW="$(strings "$FIRMWARE_PATH" | grep -i -c siprotec 2> /dev/null)"
  echo "." | tr -d "\n"
  COUNTER_SIPROTEC=$((COUNTER_SIPROTEC+COUNTER_SIPROTEC_FW))
  echo "." | tr -d "\n"

  print_output ""
  print_output "[*] Trying to identify a Linux root path in $(print_path "$OUTPUT_DIR")"
  # just to check if there is somewhere a linux filesystem in the extracted stuff
  # emba is able to handle the rest
  LINUX_PATH_COUNTER="$(find "$OUTPUT_DIR" "${EXCL_FIND[@]}" -type d -iname bin -o -type f -iname busybox -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"

  # gt 10 to avoid false positives
  if [[ $((COUNTER_Linux+COUNTER_VxWorks+COUNTER_FreeRTOS+COUNTER_eCos+COUNTER_ADONIS+COUNTER_SIPROTEC)) -gt 0 ]] ; then
    print_output ""
    print_output "$(indent "$(orange "Operating system detection:")")"
    if [[ $COUNTER_VxWorks -gt 10 ]] ; then print_output "$(indent "$(orange "VxWorks detected         ""$COUNTER_VxWorks")")"; fi
    if [[ $COUNTER_FreeRTOS -gt 0 ]] ; then print_output "$(indent "$(orange "FreeRTOS detected         ""$COUNTER_FreeRTOS")")"; fi
    if [[ $COUNTER_eCos -gt 0 ]] ; then print_output "$(indent "$(orange "eCos detected             ""$COUNTER_eCos")")"; fi
    if [[ $COUNTER_Linux -gt 5 && $LINUX_PATH_COUNTER -gt 1 ]] ; then 
      print_output "$(indent "$(green "Linux detected            ""$COUNTER_Linux""\t- verified Linux operating system detected")")"
    elif [[ $COUNTER_Linux -gt 5 ]] ; then 
      print_output "$(indent "$(orange "Linux detected           ""$COUNTER_Linux")")"
    fi
    if [[ $COUNTER_ADONIS -gt 10 ]] ; then print_output "$(indent "$(orange "Adonis detected          ""$COUNTER_ADONIS")")"; fi
    if [[ $COUNTER_SIPROTEC -gt 100 && $COUNTER_VxWorks -gt 20 ]] ; then
      print_output "$(indent "$(green "SIPROTEC detected        ""$COUNTER_SIPROTEC""\t- verified SIPROTEC system detected")")";
    elif [[ $COUNTER_SIPROTEC -gt 10 ]] ; then
      print_output "$(indent "$(orange "SIPROTEC detected         ""$COUNTER_SIPROTEC")")";
    fi
  fi

  echo
  if [[ $LINUX_PATH_COUNTER -gt 0 ]] ; then
    print_output "[+] Found possible Linux operating system in $(print_path "$OUTPUT_DIR")"
    export FIRMWARE=1
    export FIRMWARE_PATH="$OUTPUT_DIR"
  fi
}

binary_architecture_detection()
{
  sub_module_title "Architecture detection"
  print_output "[*] Architecture detection running on ""$FIRMWARE_PATH"""

  mapfile -t PRE_ARCH < <(binwalk -Y "$FIRMWARE_PATH" | grep "valid\ instructions" | awk '{print $3}' | sort -u)
  for PRE_ARCH_ in "${PRE_ARCH[@]}"; do
    print_output "[+] Possible architecture details found: $ORANGE$PRE_ARCH_"
  done
}
