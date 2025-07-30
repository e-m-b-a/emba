#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  A rough guess of the used operating system. Currently, it tries to
#               identify VxWorks, eCos, Adonis, Siprotec, uC/OS and Linux.
#               If no Linux operating system is found, then it also tries to identify
#               the target architecture (currently with binwalk only).
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# export PRE_THREAD_ENA=1

S03_firmware_bin_base_analyzer() {

  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware basic analyzer"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0
  local lWAIT_PIDS_S03_ARR=()

  if [[ -d "${FIRMWARE_PATH_CP}" ]] ; then
    export OUTPUT_DIR="${FIRMWARE_PATH_CP}"
    if [[ ${THREADED} -eq 1 ]]; then
      os_identification &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S03_ARR+=( "${lTMP_PID}" )
    else
      os_identification
    fi
  fi

  # we only do this if we have not found a Linux filesystem
  if [[ -f "${FIRMWARE_PATH_BAK}" ]]; then
    export PRE_ARCH_Y_ARR=()
    export PRE_ARCH_A_ARR=()
    export PRE_ARCH_CPU_REC=""
    if [[ ${RTOS} -eq 1 ]] ; then
      print_output "[*] INFO: S03 Architecture detection mechanism is currently not available"

      # if [[ ${THREADED} -eq 1 ]]; then
      #  binary_architecture_detection "${FIRMWARE_PATH_BAK}" &
      #  local lTMP_PID="$!"
      #  store_kill_pids "${lTMP_PID}"
      #  lWAIT_PIDS_S03_ARR+=( "${lTMP_PID}" )
      # else
      #  binary_architecture_detection "${FIRMWARE_PATH_BAK}"
      # fi
    fi
  fi

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S03_ARR[@]}"

  [[ -f "${TMP_DIR}"/s03_arch.tmp ]] && binary_architecture_reporter

  if [[ -f "${TMP_DIR}"/s03.tmp ]]; then
    [[ "$(wc -l < "${TMP_DIR}"/s03.tmp)" -gt 0 ]] && lNEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

os_identification() {
  sub_module_title "OS detection"
  local lOS=""
  local lOS_SEARCHER_ARR=()
  export OS_COUNTER_VxWorks=0

  print_output "[*] Initial OS guessing running ..." "no_log" | tr -d "\n"
  write_log "[*] Initial OS guessing:"
  write_csv_log "Guessed OS" "confidential rating" "verified" "Linux root filesystems found"

  lOS_SEARCHER_ARR=("Linux" "FreeBSD" "VxWorks\|Wind" "FreeRTOS" "ADONIS" "eCos" "uC/OS" "SIPROTEC" "QNX" "CPU\ [34][12][0-9]-[0-9]" "CP443" "Sinamics" "UEFI" "HelenOS" "Windows\ CE" "Android")
  print_dot
  declare -A OS_COUNTER=()
  local lWAIT_PIDS_S03_1_ARR=()

  if [[ ${#ROOT_PATH[@]} -gt 1 || ${LINUX_PATH_COUNTER} -gt 2 ]] ; then
    safe_echo "${#ROOT_PATH[@]}" >> "${TMP_DIR}"/s03.tmp
    safe_echo "${LINUX_PATH_COUNTER}" >> "${TMP_DIR}"/s03.tmp
  fi

  print_ln
  print_output "$(indent "$(orange "Operating system detection:")")"

  strings "${FIRMWARE_PATH}" 2>/dev/null > "${LOG_PATH_MODULE}/strings_firmware.txt" || true &
  lWAIT_PIDS_S03_1_ARR+=( "${!}" )
  find "${OUTPUT_DIR}" -xdev -type f -print0|xargs -0 -P 16 -I % sh -c 'strings "%" | uniq >> '"${LOG_PATH_MODULE}/all_strings_firmware.txt"' 2> /dev/null' || true &
  lWAIT_PIDS_S03_1_ARR+=( "${!}" )
  wait_for_pid "${lWAIT_PIDS_S03_1_ARR[@]}"

  local lWAIT_PIDS_S03_1_ARR=()

  for lOS in "${lOS_SEARCHER_ARR[@]}"; do
    if [[ ${THREADED} -eq 1 ]]; then
      os_detection_thread_per_os "${lOS}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S03_1_ARR+=( "${lTMP_PID}" )
    else
      os_detection_thread_per_os "${lOS}"
    fi
  done

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S03_1_ARR[@]}"

  if grep -q "Identified Android APK package - performing APK checks" "${P02_LOG}"; then
    lOS_="Android APK"
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${lOS_} detected" "NA" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS_}" "NA" "APK verified" "NA"
  fi

  if [[ -f "${LOG_PATH_MODULE}/strings_firmware.txt" ]]; then
    rm "${LOG_PATH_MODULE}/strings_firmware.txt" || true
  fi
  if [[ -f "${LOG_PATH_MODULE}/all_strings_firmware.txt" ]]; then
    rm "${LOG_PATH_MODULE}/all_strings_firmware.txt" || true
  fi
}

os_detection_thread_per_os() {
  local lOS="${1:-}"
  local lDETECTED=0
  local lOS_=""

  OS_COUNTER[${lOS}]=0
  if [[ -f "${LOG_PATH_MODULE}/strings_firmware.txt" ]]; then
    OS_COUNTER[${lOS}]=$(("${OS_COUNTER[${lOS}]}"+"$(grep -a -i -c "${lOS}" "${LOG_PATH_MODULE}/strings_firmware.txt" || true)" ))
  fi
  if [[ -f "${LOG_PATH_MODULE}/all_strings_firmware.txt" ]]; then
    OS_COUNTER[${lOS}]=$(("${OS_COUNTER[${lOS}]}"+"$(grep -a -i -c "${lOS}" "${LOG_PATH_MODULE}/all_strings_firmware.txt" 2>/dev/null || true)"))
  fi
  if [[ -f "${LOG_DIR}"/p60_firmware_bin_extractor.txt ]]; then
    OS_COUNTER[${lOS}]=$(("${OS_COUNTER[${lOS}]}"+"$(grep -a -i -c "${lOS}" "${LOG_DIR}"/p60_firmware_bin_extractor.txt 2>/dev/null || true)" ))
  fi
  if [[ -f "${LOG_PATH_MODULE}/strings_firmware.txt" ]]; then
    OS_COUNTER[${lOS}]=$(("${OS_COUNTER[${lOS}]}"+"$(grep -a -i -c "${lOS}" "${LOG_PATH_MODULE}/strings_firmware.txt" 2>/dev/null || true)" ))
  fi

  if [[ ${lOS} == "VxWorks\|Wind" ]]; then
    OS_COUNTER_VxWorks="${OS_COUNTER[${lOS}]}"
  fi
  if [[ ${lOS} == *"CPU "* || ${lOS} == "ADONIS" || ${lOS} == "CP443" ]] && [[ -f "${LOG_PATH_MODULE}/strings_firmware.txt" ]]; then
    OS_COUNTER[${lOS}]=$(("${OS_COUNTER[${lOS}]}"+"$(grep -a -i -c "Original Siemens Equipment" "${LOG_PATH_MODULE}/strings_firmware.txt" || true)" ))
  fi

  if [[ ${lOS} == "Linux" && ${OS_COUNTER[${lOS}]} -gt 5 && ${#ROOT_PATH[@]} -gt 1 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified Linux operating system detected (root filesystem)${NC}\n" "${lOS} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "verified" "${#ROOT_PATH[@]}"
    lDETECTED=1
  elif [[ ${lOS} == "Linux" && ${OS_COUNTER[${lOS}]} -gt 5 && ${LINUX_PATH_COUNTER} -gt 2 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified Linux operating system detected (root filesystem)${NC}\n" "${lOS} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "verified" "${#ROOT_PATH[@]}"
    lDETECTED=1
  elif [[ ${lOS} == "Linux" && ${OS_COUNTER[${lOS}]} -gt 5 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${lOS} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "not verified" "${#ROOT_PATH[@]}"
    lDETECTED=1
  fi

  if [[ ${lOS} == "SIPROTEC" && ${OS_COUNTER[${lOS}]} -gt 100 && ${OS_COUNTER_VxWorks} -gt 20 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified SIPROTEC system detected${NC}\n" "${lOS} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "verified" "NA"
    lDETECTED=1
  elif [[ ${lOS} == "SIPROTEC" && ${OS_COUNTER[${lOS}]} -gt 10 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "SIPROTEC detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "not verified" "NA"
    lDETECTED=1
  fi
  if [[ ${lOS} == "CP443" && ${OS_COUNTER[${lOS}]} -gt 100 && ${OS_COUNTER_VxWorks} -gt 20 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified S7-CP443 system detected${NC}\n" "${lOS} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "verified" "NA"
    lDETECTED=1
  elif [[ ${lOS} == "CP443" && ${OS_COUNTER[${lOS}]} -gt 10 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "S7-CP443 detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${lOS}" "${OS_COUNTER[${lOS}]}" "not verified" "NA"
    lDETECTED=1
  fi

  if [[ ${OS_COUNTER[${lOS}]} -gt 5 ]] ; then
    if [[ ${lOS} == "VxWorks\|Wind" ]]; then
      lOS_="VxWorks"
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${lOS_} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
      write_csv_log "${lOS_}" "${OS_COUNTER[${lOS}]}" "not verified" "NA"
    elif [[ ${lOS} == "CPU\ [34][12][0-9]-[0-9]" ]]; then
      lOS_="S7-CPU400"
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${lOS_} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
      write_csv_log "${lOS_}" "${OS_COUNTER[${lOS}]}" "not verified" "NA"
    elif [[ ${lDETECTED} -eq 0 ]]; then
      lOS_="${lOS}"
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${lOS_} detected" "${OS_COUNTER[${lOS}]}" | tee -a "${LOG_FILE}"
      write_csv_log "${lOS_}" "${OS_COUNTER[${lOS}]}" "not verified" "NA"
    fi
  fi

  [[ "${OS_COUNTER[${lOS}]}" -gt 0 ]] && safe_echo "${OS_COUNTER[${lOS}]}" >> "${TMP_DIR}"/s03.tmp
}

binary_architecture_detection() {
  # sub_module_title "Architecture detection for RTOS based systems"

  local lFILE_TO_CHECK="${1:-}"
  if ! [[ -f "${lFILE_TO_CHECK}" ]]; then
    return
  fi

  local lPRE_ARCH_=""
  print_output "[*] Architecture detection running on ""${lFILE_TO_CHECK}"

  # as Thumb is usually false positive we remove it from the results
  mapfile -t PRE_ARCH_Y_ARR < <(binwalk -Y "${lFILE_TO_CHECK}" | grep "valid\ instructions" | grep -v "Thumb" | \
    awk '{print $3}' | sort -u || true)
  mapfile -t PRE_ARCH_A_ARR < <(binwalk -A "${lFILE_TO_CHECK}" | grep "\ instructions," | awk '{print $3}' | \
    uniq -c | sort -n | tail -1 | awk '{print $2}' || true)

  if [[ -f "${HOME}"/.config/binwalk/modules/cpu_rec.py ]]; then
    # entropy=0.9xxx is typically encrypted or compressed -> we just remove these entries:
    PRE_ARCH_CPU_REC=$(binwalk -% "${lFILE_TO_CHECK}"  | grep -v "DESCRIPTION\|None\|-----------" | grep -v "entropy=0.9" \
      | awk '{print $3}' | grep -v -e "^$" | sort | uniq -c | head -1 | awk '{print $2}' || true)
  fi

  for lPRE_ARCH_ in "${PRE_ARCH_Y_ARR[@]}"; do
    echo "binwalk -Y;${lPRE_ARCH_}" >> "${TMP_DIR}"/s03_arch.tmp
  done
  for lPRE_ARCH_ in "${PRE_ARCH_A_ARR[@]}"; do
    echo "binwalk -A;${lPRE_ARCH_}" >> "${TMP_DIR}"/s03_arch.tmp
  done
  if [[ -n "${PRE_ARCH_CPU_REC}" ]]; then
    echo "cpu_rec;${PRE_ARCH_CPU_REC}" >> "${TMP_DIR}"/s03_arch.tmp
  fi
}

binary_architecture_reporter() {
  sub_module_title "Architecture detection for RTOS based systems"
  local lPRE_ARCH_=""
  local lSOURCE=""

  while read -r lPRE_ARCH_; do
    lSOURCE=$(echo "${lPRE_ARCH_}" | cut -d\; -f1)
    lPRE_ARCH_=$(echo "${lPRE_ARCH_}" | cut -d\; -f2)
    print_ln
    print_output "[+] Possible architecture details found (${ORANGE}${lSOURCE}${GREEN}): ${ORANGE}${lPRE_ARCH_}${NC}"
    echo "${lPRE_ARCH_}" >> "${TMP_DIR}"/s03.tmp
  done < "${TMP_DIR}"/s03_arch.tmp
}
