#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
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

  local NEG_LOG=0
  local WAIT_PIDS_S03=()

  if [[ -d "${FIRMWARE_PATH_CP}" ]] ; then
    export OUTPUT_DIR="${FIRMWARE_PATH_CP}"
    if [[ ${THREADED} -eq 1 ]]; then
      os_identification &
      local TMP_PID="$!"
      store_kill_pids "${TMP_PID}"
      WAIT_PIDS_S03+=( "${TMP_PID}" )
    else
      os_identification
    fi
  fi

  # we only do this if we have not found a Linux filesystem
  if [[ -f "${FIRMWARE_PATH_BAK}" ]]; then
    export PRE_ARCH_Y=()
    export PRE_ARCH_A=()
    export PRE_ARCH_CPU_REC=""
    if [[ ${RTOS} -eq 1 ]] ; then
      if [[ ${THREADED} -eq 1 ]]; then
        binary_architecture_detection "${FIRMWARE_PATH_BAK}" &
        local TMP_PID="$!"
        store_kill_pids "${TMP_PID}"
        WAIT_PIDS_S03+=( "${TMP_PID}" )
      else
        binary_architecture_detection "${FIRMWARE_PATH_BAK}"
      fi
    fi
  fi

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S03[@]}"

  [[ -f "${TMP_DIR}"/s03_arch.tmp ]] && binary_architecture_reporter

  [[ "$(wc -l "${TMP_DIR}"/s03.tmp | awk '{print $1}')" -gt 0 ]] && NEG_LOG=1

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

os_identification() {
  sub_module_title "OS detection"
  local OS=""
  local OS_SEARCHER=()
  export OS_COUNTER_VxWorks=0

  print_output "[*] Initial OS guessing running ..." "no_log" | tr -d "\n"
  write_log "[*] Initial OS guessing:"
  write_csv_log "Guessed OS" "confidential rating" "verified" "Linux root filesystems found"

  OS_SEARCHER=("Linux" "FreeBSD" "VxWorks\|Wind" "FreeRTOS" "ADONIS" "eCos" "uC/OS" "SIPROTEC" "QNX" "CPU\ [34][12][0-9]-[0-9]" "CP443" "Sinamics" "UEFI" "HelenOS" "Windows\ CE")
  print_dot
  declare -A OS_COUNTER=()
  local WAIT_PIDS_S03_1=()

  if [[ ${#ROOT_PATH[@]} -gt 1 || ${LINUX_PATH_COUNTER} -gt 2 ]] ; then
    safe_echo "${#ROOT_PATH[@]}" >> "${TMP_DIR}"/s03.tmp
    safe_echo "${LINUX_PATH_COUNTER}" >> "${TMP_DIR}"/s03.tmp
  fi

  print_ln
  print_output "$(indent "$(orange "Operating system detection:")")"

  for OS in "${OS_SEARCHER[@]}"; do
    if [[ ${THREADED} -eq 1 ]]; then
      os_detection_thread_per_os "${OS}" &
      local TMP_PID="$!"
      store_kill_pids "${TMP_PID}"
      WAIT_PIDS_S03_1+=( "${TMP_PID}" )
    else
      os_detection_thread_per_os "${OS}"
    fi
  done

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S03_1[@]}"
}

os_detection_thread_per_os() {
  local OS="${1:-}"
  local DETECTED=0
  local OS_=""

  OS_COUNTER[${OS}]=0
  OS_COUNTER[${OS}]=$(("${OS_COUNTER[${OS}]}"+"$(find "${OUTPUT_DIR}" -xdev -type f -exec strings {} \; | grep -i -c "${OS}" 2> /dev/null || true)"))
  if [[ -f "${LOG_DIR}"/p60_firmware_bin_extractor.txt ]]; then
    OS_COUNTER[${OS}]=$(("${OS_COUNTER[${OS}]}"+"$(find "${LOG_DIR}" -maxdepth 1 -xdev -type f -name "p60_firmware_bin_extractor.txt" -exec grep -i -c "${OS}" {} \; 2> /dev/null || true)" ))
  fi
  OS_COUNTER[${OS}]=$(("${OS_COUNTER[${OS}]}"+"$(strings "${FIRMWARE_PATH}" 2>/dev/null | grep -i -c "${OS}" || true)" ))

  if [[ ${OS} == "VxWorks\|Wind" ]]; then
    OS_COUNTER_VxWorks="${OS_COUNTER[${OS}]}"
  fi
  if [[ ${OS} == *"CPU "* || ${OS} == "ADONIS" || ${OS} == "CP443" ]]; then
    OS_COUNTER[${OS}]=$(("${OS_COUNTER[${OS}]}"+"$(strings "${FIRMWARE_PATH}" 2>/dev/null | grep -i -c "Original Siemens Equipment" || true)" ))
  fi

  if [[ ${OS} == "Linux" && ${OS_COUNTER[${OS}]} -gt 5 && ${#ROOT_PATH[@]} -gt 1 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified Linux operating system detected (root filesystem)${NC}\n" "${OS} detected" "${OS_COUNTER[${OS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${OS}" "${OS_COUNTER[${OS}]}" "verified" "${#ROOT_PATH[@]}"
    DETECTED=1
  elif [[ ${OS} == "Linux" && ${OS_COUNTER[${OS}]} -gt 5 && ${LINUX_PATH_COUNTER} -gt 2 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified Linux operating system detected (root filesystem)${NC}\n" "${OS} detected" "${OS_COUNTER[${OS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${OS}" "${OS_COUNTER[${OS}]}" "verified" "${#ROOT_PATH[@]}"
    DETECTED=1
  elif [[ ${OS} == "Linux" && ${OS_COUNTER[${OS}]} -gt 5 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${OS} detected" "${OS_COUNTER[${OS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${OS}" "${OS_COUNTER[${OS}]}" "not verified" "${#ROOT_PATH[@]}"
    DETECTED=1
  fi

  if [[ ${OS} == "SIPROTEC" && ${OS_COUNTER[${OS}]} -gt 100 && ${OS_COUNTER_VxWorks} -gt 20 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified SIPROTEC system detected${NC}\n" "${OS} detected" "${OS_COUNTER[${OS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${OS}" "${OS_COUNTER[${OS}]}" "verified" "NA"
    DETECTED=1
  elif [[ ${OS} == "SIPROTEC" && ${OS_COUNTER[${OS}]} -gt 10 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "SIPROTEC detected" "${OS_COUNTER[${OS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${OS}" "${OS_COUNTER[${OS}]}" "not verified" "NA"
    DETECTED=1
  fi
  if [[ ${OS} == "CP443" && ${OS_COUNTER[${OS}]} -gt 100 && ${OS_COUNTER_VxWorks} -gt 20 ]] ; then
    printf "${GREEN}\t%-20.20s\t:\t%-15s\t:\tverified S7-CP443 system detected${NC}\n" "${OS} detected" "${OS_COUNTER[${OS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${OS}" "${OS_COUNTER[${OS}]}" "verified" "NA"
    DETECTED=1
  elif [[ ${OS} == "CP443" && ${OS_COUNTER[${OS}]} -gt 10 ]] ; then
    printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "S7-CP443 detected" "${OS_COUNTER[${OS}]}" | tee -a "${LOG_FILE}"
    write_csv_log "${OS}" "${OS_COUNTER[${OS}]}" "not verified" "NA"
    DETECTED=1
  fi

  if [[ ${OS_COUNTER[${OS}]} -gt 5 ]] ; then
    if [[ ${OS} == "VxWorks\|Wind" ]]; then
      OS_="VxWorks"
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${OS_} detected" "${OS_COUNTER[${OS}]}" | tee -a "${LOG_FILE}"
      write_csv_log "${OS_}" "${OS_COUNTER[${OS}]}" "not verified" "NA"
    elif [[ ${OS} == "CPU\ [34][12][0-9]-[0-9]" ]]; then
      OS_="S7-CPU400"
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${OS_} detected" "${OS_COUNTER[${OS}]}" | tee -a "${LOG_FILE}"
      write_csv_log "${OS_}" "${OS_COUNTER[${OS}]}" "not verified" "NA"
    elif [[ ${DETECTED} -eq 0 ]]; then
      OS_="${OS}"
      printf "${ORANGE}\t%-20.20s\t:\t%-15s${NC}\n" "${OS_} detected" "${OS_COUNTER[${OS}]}" | tee -a "${LOG_FILE}"
      write_csv_log "${OS_}" "${OS_COUNTER[${OS}]}" "not verified" "NA"
    fi
  fi

  [[ "${OS_COUNTER[${OS}]}" -gt 0 ]] && safe_echo "${OS_COUNTER[${OS}]}" >> "${TMP_DIR}"/s03.tmp
}

binary_architecture_detection() {
  # sub_module_title "Architecture detection for RTOS based systems"

  local FILE_TO_CHECK="${1:-}"
  if ! [[ -f "${FILE_TO_CHECK}" ]]; then
    return
  fi

  print_output "[*] Architecture detection running on ""${FILE_TO_CHECK}"


  # as Thumb is usually false positive we remove it from the results
  mapfile -t PRE_ARCH_Y < <(binwalk -Y "${FILE_TO_CHECK}" | grep "valid\ instructions" | grep -v "Thumb" | \
    awk '{print $3}' | sort -u || true)
  mapfile -t PRE_ARCH_A < <(binwalk -A "${FILE_TO_CHECK}" | grep "\ instructions," | awk '{print $3}' | \
    uniq -c | sort -n | tail -1 | awk '{print $2}' || true)

  if [[ -f "${HOME}"/.config/binwalk/modules/cpu_rec.py ]]; then
    # entropy=0.9xxx is typically encrypted or compressed -> we just remove these entries:
    PRE_ARCH_CPU_REC=$(binwalk -% "${FILE_TO_CHECK}"  | grep -v "DESCRIPTION\|None\|-----------" | grep -v "entropy=0.9" \
      | awk '{print $3}' | grep -v -e "^$" | sort | uniq -c | head -1 | awk '{print $2}' || true)
  fi

  for PRE_ARCH_ in "${PRE_ARCH_Y[@]}"; do
    echo "binwalk -Y;${PRE_ARCH_}" >> "${TMP_DIR}"/s03_arch.tmp
  done
  for PRE_ARCH_ in "${PRE_ARCH_A[@]}"; do
    echo "binwalk -A;${PRE_ARCH_}" >> "${TMP_DIR}"/s03_arch.tmp
  done
  if [[ -n "${PRE_ARCH_CPU_REC}" ]]; then
    echo "cpu_rec;${PRE_ARCH_CPU_REC}" >> "${TMP_DIR}"/s03_arch.tmp
  fi
}

binary_architecture_reporter() {
  sub_module_title "Architecture detection for RTOS based systems"
  local PRE_ARCH_=""
  local SOURCE=""

  while read -r PRE_ARCH_; do
    SOURCE=$(echo "${PRE_ARCH_}" | cut -d\; -f1)
    PRE_ARCH_=$(echo "${PRE_ARCH_}" | cut -d\; -f2)
    print_ln
    print_output "[+] Possible architecture details found (${ORANGE}${SOURCE}${GREEN}): ${ORANGE}${PRE_ARCH_}${NC}"
    echo "${PRE_ARCH_}" >> "${TMP_DIR}"/s03.tmp
  done < "${TMP_DIR}"/s03_arch.tmp
}
