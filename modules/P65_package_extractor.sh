#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Identification and extraction of typical package archives like deb, apk, ipk

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# This module extracts the firmware and is blocking modules that needs executed before the following modules can run
export PRE_THREAD_ENA=0

P65_package_extractor() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Package extractor module"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ "${DISABLE_DEEP:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lDISK_SPACE_CRIT=0
  local lNEG_LOG=0
  export FILES_PRE_PACKAGE=0
  local lFILES_POST_PACKAGE_ARR=()
  export WAIT_PIDS_P20=()

  if [[ "${#ROOT_PATH[@]}" -gt 0 && "${RTOS}" -eq 0 ]]; then
    FILES_PRE_PACKAGE=$(find "${FIRMWARE_PATH_CP}" -type f ! -name "*.raw" | wc -l)
    if [[ "${lDISK_SPACE_CRIT}" -ne 1 ]]; then
      deb_extractor
    else
      print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
      print_output "[!] $(print_date) - Ending extraction processes - no deb extraction performed" "main"
      lDISK_SPACE_CRIT=1
    fi
    if [[ "${lDISK_SPACE_CRIT}" -ne 1 ]]; then
      ipk_extractor
    else
      print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
      print_output "[!] $(print_date) - Ending extraction processes - no ipk extraction performed" "main"
      lDISK_SPACE_CRIT=1
    fi
    if [[ "${lDISK_SPACE_CRIT}" -ne 1 ]]; then
      apk_extractor
    else
      print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
      print_output "[!] $(print_date) - Ending extraction processes - no apk extraction performed" "main"
      lDISK_SPACE_CRIT=1
    fi
    if [[ "${lDISK_SPACE_CRIT}" -ne 1 ]]; then
      rpm_extractor
    else
      print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
      print_output "[!] $(print_date) - Ending extraction processes - no rpm extraction performed" "main"
      lDISK_SPACE_CRIT=1
    fi

    mapfile -t lFILES_POST_PACKAGE_ARR < <(find "${FIRMWARE_PATH_CP}" -type f ! -name "*.raw")

    if [[ "${#lFILES_POST_PACKAGE_ARR[@]}" -gt "${FILES_PRE_PACKAGE}" ]]; then
      sub_module_title "Firmware package extraction details"
      print_ln
      print_output "[*] Found ${ORANGE}${#lFILES_POST_PACKAGE_ARR[@]}${NC} files."

      print_output "[*] Adjusting the backend with ${ORANGE}${#lFILES_POST_PACKAGE_ARR[@]}${NC} files ... take a break" "no_log"

      for lBINARY in "${lFILES_POST_PACKAGE_ARR[@]}" ; do
        binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
      done

      local lLINUX_PATH_COUNTER_PCK=0
      lLINUX_PATH_COUNTER_PCK=$(linux_basic_identification "${FIRMWARE_PATH_CP}")

      wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

      print_output "[*] Additionally the Linux path counter is ${ORANGE}${lLINUX_PATH_COUNTER_PCK}${NC}."
      print_ln
      tree -csh "${FIRMWARE_PATH_CP}" | tee -a "${LOG_FILE}"
      print_output "[*] Before package extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after package extraction we have now ${ORANGE}${#lFILES_POST_PACKAGE_ARR[@]}${NC} files extracted."
      lNEG_LOG=1
    fi
  else
    print_output "[*] As there is no root directory detected it is not possible to process package archives"
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

rpm_extractor() {
  sub_module_title "RPM archive extraction mode"

  local lRPM_ARCHIVES_ARR=()
  local lRPM_NAME=""
  local lFILES_AFTER_RPM=0
  local lR_PATH=""
  local lRPM=""

  print_output "[*] Identify RPM archives and extracting it to the root directories ..."
  mapfile -t lRPM_ARCHIVES_ARR < <(find "${FIRMWARE_PATH_CP}" -xdev -type f -name "*.rpm" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)

  if [[ "${#lRPM_ARCHIVES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Identified ${ORANGE}${#lRPM_ARCHIVES_ARR[@]}${NC} RPM archives - extracting archives to the root directories ..."
    for lR_PATH in "${ROOT_PATH[@]}"; do
      for lRPM in "${lRPM_ARCHIVES_ARR[@]}"; do
        lRPM_NAME=$(basename "${lRPM}")
        print_output "[*] Extracting ${ORANGE}${lRPM_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
        rpm2cpio "${lRPM}" | cpio -D "${lR_PATH}" -idm || true
      done
    done

    lFILES_AFTER_RPM=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
    print_ln "no_log"
    print_output "[*] Before deep extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after RPM extraction we have ${ORANGE}${lFILES_AFTER_RPM}${NC} files extracted."
  else
    print_output "[-] No rpm packages extracted."
  fi
}

apk_extractor() {
  sub_module_title "Android APK archive extraction mode"

  local lAPK_ARCHIVES_ARR=()
  local lAPK_NAME=""
  local lFILES_AFTER_APK=0
  local lR_PATH=""
  local lAPK=""

  print_output "[*] Identify apk archives and extracting it to the root directories ..."
  mapfile -t lAPK_ARCHIVES_ARR < <(find "${FIRMWARE_PATH_CP}" -xdev -type f -name "*.apk" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)

  if [[ "${#lAPK_ARCHIVES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Found ${ORANGE}${#lAPK_ARCHIVES_ARR[@]}${NC} APK archives - extracting them to the root directories ..."
    for lR_PATH in "${ROOT_PATH[@]}"; do
      for lAPK in "${lAPK_ARCHIVES_ARR[@]}"; do
        lAPK_NAME=$(basename "${lAPK}")
        print_output "[*] Extracting ${ORANGE}${lAPK_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
        unzip -o -d "${lR_PATH}" "${lAPK}" || true
      done
    done

    lFILES_AFTER_APK=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
    print_ln "no_log"
    print_output "[*] Before apk extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${lFILES_AFTER_APK}${NC} files extracted."
  else
    print_output "[-] No apk packages extracted."
  fi
}

ipk_extractor() {
  sub_module_title "IPK archive extraction mode"
  local lIPK_ARCHIVES_ARR=()
  local lIPK_NAME=""
  local lFILES_AFTER_IPK=0
  local lR_PATH=""
  local lIPK=""

  print_output "[*] Identify ipk archives and extracting it to the root directories ..."
  mapfile -t lIPK_ARCHIVES_ARR < <(find "${FIRMWARE_PATH_CP}" -xdev -type f -name "*.ipk" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)

  if [[ "${#lIPK_ARCHIVES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Found ${ORANGE}${#lIPK_ARCHIVES_ARR[@]}${NC} IPK archives - extracting them to the root directories ..."
    mkdir "${LOG_DIR}"/ipk_tmp
    for lR_PATH in "${ROOT_PATH[@]}"; do
      for lIPK in "${lIPK_ARCHIVES_ARR[@]}"; do
        lIPK_NAME=$(basename "${lIPK}")
        if [[ $(file -b "${lIPK}") == *"gzip"* ]]; then
          print_output "[*] Extracting ${ORANGE}${lIPK_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
          tar zxpf "${lIPK}" --directory "${LOG_DIR}"/ipk_tmp || true
        else
          print_output "[-] Is ${ORANGE}${lIPK_NAME}${NC} a valid ipk (tgz) archive?"
        fi
        if [[ -f "${LOG_DIR}"/ipk_tmp/data.tar.gz ]]; then
          tar xzf "${LOG_DIR}"/ipk_tmp/data.tar.gz --directory "${lR_PATH}" || true
        fi
        if [[ -d "${LOG_DIR}"/ipk_tmp/ ]]; then
          rm -r "${LOG_DIR}"/ipk_tmp/* 2>/dev/null || true
        fi
      done
    done

    lFILES_AFTER_IPK=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
    print_ln "no_log"
    print_output "[*] Before ipk extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${lFILES_AFTER_IPK}${NC} files extracted."
    if [[ -d "${LOG_DIR}"/ipk_tmp/ ]]; then
      rm -r "${LOG_DIR}"/ipk_tmp/* 2>/dev/null || true
    fi
  else
    print_output "[-] No ipk packages extracted."
  fi
}

deb_extractor() {
  sub_module_title "Debian archive extraction mode"

  local lDEB_ARCHIVES_ARR=()
  local lFILES_AFTER_DEB=0
  local lR_PATH=""
  local lDEB=""

  print_output "[*] Identify debian archives and extracting it to the root directories ..."
  mapfile -t lDEB_ARCHIVES_ARR < <(find "${FIRMWARE_PATH_CP}" -xdev -type f \( -name "*.deb" -o -name "*.udeb" \) -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)

  if [[ "${#lDEB_ARCHIVES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Found ${ORANGE}${#lDEB_ARCHIVES_ARR[@]}${NC} debian archives - extracting them to the root directories ..."
    for lR_PATH in "${ROOT_PATH[@]}"; do
      for lDEB in "${lDEB_ARCHIVES_ARR[@]}"; do
        if [[ "${THREADED}" -eq 1 ]]; then
          extract_deb_extractor_helper "${lDEB}" "${lR_PATH}" &
          WAIT_PIDS_P20+=( "$!" )
        else
          extract_deb_extractor_helper "${lDEB}" "${lR_PATH}"
        fi
      done
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_P20[@]}"

    lFILES_AFTER_DEB=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
    print_ln "no_log"
    print_output "[*] Before deb extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${lFILES_AFTER_DEB}${NC} files extracted."
  else
    print_output "[-] No deb packages extracted."
  fi
}

extract_deb_extractor_helper() {
  local lDEB="${1:-}"
  local lR_PATH="${2:-}"
  local lDEB_NAME=""

  lDEB_NAME=$(basename "${lDEB}")
  print_output "[*] Extracting ${ORANGE}${lDEB_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
  dpkg-deb --extract "${lDEB}" "${lR_PATH}" || true
}

