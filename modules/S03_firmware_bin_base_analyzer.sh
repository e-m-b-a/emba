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

# Description:  A rough guess of the used operating system. Currently, it tries to identify VxWorks, eCos, Adonis, Siprotec, uC/OS and Linux.
#               If no Linux operating system is found, then it also tries to identify the target architecture (currently with binwalk only).
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
#export PRE_THREAD_ENA=1

S03_firmware_bin_base_analyzer() {

  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware basic analyzer"
  pre_module_reporter "${FUNCNAME[0]}"

  local NEG_LOG=0
  local WAIT_PIDS_S03=()

  if [[ -d "$FIRMWARE_PATH_CP" ]] ; then
    export OUTPUT_DIR="$FIRMWARE_PATH_CP"
    if [[ $THREADED -eq 1 ]]; then
      os_identification &
      WAIT_PIDS_S03+=( "$!" )
    else
      os_identification
    fi
  fi

  # we only do this if we have not found a Linux filesystem
  if ! [[ -d "$FIRMWARE_PATH" ]]; then
    if [[ $LINUX_PATH_COUNTER -eq 0 ]] ; then
      if [[ $THREADED -eq 1 ]]; then
        binary_architecture_detection &
        WAIT_PIDS_S03+=( "$!" )
      else
        binary_architecture_detection
      fi
    fi
  fi

  if [[ $THREADED -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_S03[@]}"
  fi

  if [[ "$(wc -l "$TMP_DIR"/s03.tmp | awk '{print $1}')" -gt 0 ]] ; then
    NEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

os_identification() {
  sub_module_title "OS detection"

  print_output "[*] Initial OS detection running ..." | tr -d "\n"
  OS_SEARCHER=("Linux" "FreeBSD" "VxWorks\|Wind" "FreeRTOS" "ADONIS" "eCos" "uC/OS" "SIPROTEC" "QNX" "CPU\ [34][12][0-9]-[0-9]" "CP443" "Sinamics")
  echo "." | tr -d "\n"
  declare -A OS_COUNTER=()
  local WAIT_PIDS_S03_1=()

  if [[ ${#ROOT_PATH[@]} -gt 1 || $LINUX_PATH_COUNTER -gt 2 ]] ; then
    echo "${#ROOT_PATH[@]}" >> "$TMP_DIR"/s03.tmp
    echo "$LINUX_PATH_COUNTER" >> "$TMP_DIR"/s03.tmp
  fi

  print_output ""
  print_output "$(indent "$(orange "Operating system detection:")")"

  for OS in "${OS_SEARCHER[@]}"; do
    if [[ $THREADED -eq 1 ]]; then
      os_detection_thread_per_os &
      WAIT_PIDS_S03_1+=( "$!" )
    else
      os_detection_thread_per_os
    fi
  done

  if [[ $THREADED -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_S03_1[@]}"
  fi
}

os_detection_thread_per_os() {
  local DETECTED=0
  OS_COUNTER[$OS]=0
  OS_COUNTER[$OS]=$(("${OS_COUNTER[$OS]}"+"$(find "$OUTPUT_DIR" -xdev -type f -exec strings {} \; | grep -i -c "$OS" 2> /dev/null || true)"))
  OS_COUNTER[$OS]=$(("${OS_COUNTER[$OS]}"+"$(find "$LOG_DIR" -maxdepth 1 -xdev -type f -name "p60_firmware*" -exec grep -i -c "$OS" {} \; 2> /dev/null || true)" ))
  OS_COUNTER[$OS]=$(("${OS_COUNTER[$OS]}"+"$(strings "$FIRMWARE_PATH" 2>/dev/null | grep -i -c "$OS" || true)" ))

  if [[ $OS == "VxWorks\|Wind" ]]; then
    OS_COUNTER_VxWorks="${OS_COUNTER[$OS]}"
  fi
  if [[ $OS == *"CPU "* || $OS == "ADONIS" || $OS == "CP443" ]]; then
    OS_COUNTER[$OS]=$(("${OS_COUNTER[$OS]}"+"$(strings "$FIRMWARE_PATH" 2>/dev/null | grep -i -c "Original Siemens Equipment" || true)" ))
  fi

  if [[ $OS == "Linux" && ${OS_COUNTER[$OS]} -gt 5 && ${#ROOT_PATH[@]} -gt 1 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified Linux operating system detected (root filesystem)${NC}\n" "$OS detected" "${OS_COUNTER[$OS]}" | tee -a "$LOG_FILE"
    DETECTED=1
  elif [[ $OS == "Linux" && ${OS_COUNTER[$OS]} -gt 5 && $LINUX_PATH_COUNTER -gt 2 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified Linux operating system detected (root filesystem)${NC}\n" "$OS detected" "${OS_COUNTER[$OS]}" | tee -a "$LOG_FILE"
    DETECTED=1
  elif [[ $OS == "Linux" && ${OS_COUNTER[$OS]} -gt 5 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "$OS detected" "${OS_COUNTER[$OS]}" | tee -a "$LOG_FILE"
    DETECTED=1
  fi

  if [[ $OS == "SIPROTEC" && ${OS_COUNTER[$OS]} -gt 100 && $OS_COUNTER_VxWorks -gt 20 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified SIPROTEC system detected${NC}\n" "$OS detected" "${OS_COUNTER[$OS]}" | tee -a "$LOG_FILE"
    DETECTED=1
  elif [[ $OS == "SIPROTEC" && ${OS_COUNTER[$OS]} -gt 10 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "SIPROTEC detected" "${OS_COUNTER[$OS]}" | tee -a "$LOG_FILE"
    DETECTED=1
  fi
  if [[ $OS == "CP443" && ${OS_COUNTER[$OS]} -gt 100 && $OS_COUNTER_VxWorks -gt 20 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified S7-CP443 system detected${NC}\n" "$OS detected" "${OS_COUNTER[$OS]}" | tee -a "$LOG_FILE"
    DETECTED=1
  elif [[ $OS == "CP443" && ${OS_COUNTER[$OS]} -gt 10 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "S7-CP443 detected" "${OS_COUNTER[$OS]}" | tee -a "$LOG_FILE"
    DETECTED=1
  fi

  if [[ ${OS_COUNTER[$OS]} -gt 5 ]] ; then
    if [[ $OS == "VxWorks\|Wind" ]]; then
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "VxWorks detected" "${OS_COUNTER[$OS]}" | tee -a "$LOG_FILE"
    elif [[ $OS == "CPU\ [34][12][0-9]-[0-9]" ]]; then
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "S7-CPU400 detected" "${OS_COUNTER[$OS]}" | tee -a "$LOG_FILE"
    elif [[ $DETECTED -eq 0 ]]; then
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "$OS detected" "${OS_COUNTER[$OS]}" | tee -a "$LOG_FILE"
    fi
  fi

  if [[ "${OS_COUNTER[$OS]}" -gt 0 ]]; then
    echo "${OS_COUNTER[$OS]}" >> "$TMP_DIR"/s03.tmp
  fi
}

binary_architecture_detection()
{
  sub_module_title "Architecture detection"
  print_output "[*] Architecture detection running on ""$FIRMWARE_PATH"

  # as Thumb is usually false positive we remove it from the results
  mapfile -t PRE_ARCH_Y < <(binwalk -Y "$FIRMWARE_PATH" | grep "valid\ instructions" | grep -v "Thumb" | awk '{print $3}' | sort -u || true)
  mapfile -t PRE_ARCH_A < <(binwalk -A "$FIRMWARE_PATH" | grep "\ instructions," | awk '{print $3}' | uniq -c | sort -n | tail -1 | awk '{print $2}' || true)
  for PRE_ARCH_ in "${PRE_ARCH_Y[@]}"; do
    print_output ""
    print_output "[+] Possible architecture details found: $ORANGE$PRE_ARCH_$NC"
    echo "$PRE_ARCH_" >> "$TMP_DIR"/s03.tmp
  done
  for PRE_ARCH_ in "${PRE_ARCH_A[@]}"; do
    print_output ""
    print_output "[+] Possible architecture details found: $ORANGE$PRE_ARCH_$NC"
    echo "$PRE_ARCH_" >> "$TMP_DIR"/s03.tmp
  done
}
