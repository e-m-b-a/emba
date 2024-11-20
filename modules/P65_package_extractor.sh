#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
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
  module_title "Package extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ "${DISABLE_DEEP:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lDISK_SPACE_CRIT=0
  local lNEG_LOG=0
  export FILES_PRE_PACKAGE=0
  local lFILES_POST_PACKAGE=0
  local lBINS=0
  local lDIRS_EXT=0
  local lFILES_EXT=0
  local lUNIQUE_FILES=0
  export WAIT_PIDS_P20=()

  if [[ "${#ROOT_PATH[@]}" -gt 0 && "${RTOS}" -eq 0 ]]; then
    FILES_PRE_PACKAGE=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
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
      print_output "[!] $(print_date) - Ending extraction processes - apk extraction performed" "main"
      lDISK_SPACE_CRIT=1
    fi

    lFILES_POST_PACKAGE=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )

    if [[ "${lFILES_POST_PACKAGE}" -gt "${FILES_PRE_PACKAGE}" ]]; then
      # we need to update these numbers:
      lFILES_EXT=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
      lUNIQUE_FILES=$(find "${FIRMWARE_PATH_CP}" "${EXCL_FIND[@]}" -xdev -type f -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum % 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 | wc -l )
      lDIRS_EXT=$(find "${FIRMWARE_PATH_CP}" -xdev -type d | wc -l )
      lBINS=$(find "${FIRMWARE_PATH_CP}" "${EXCL_FIND[@]}" -xdev -type f -print0|xargs -r -0 -P 16 -I % sh -c 'file %' | grep -c "ELF" || true)

      if [[ "${lBINS}" -gt 0 || "${lUNIQUE_FILES}" -gt 0 ]]; then
        sub_module_title "Firmware package extraction details"
        linux_basic_identification_helper "${FIRMWARE_PATH_CP}"
        print_ln
        print_output "[*] Found ${ORANGE}${lFILES_EXT}${NC} files (${ORANGE}${lUNIQUE_FILES}${NC} unique files) and ${ORANGE}${lDIRS_EXT}${NC} directories at all."
        print_output "[*] Found ${ORANGE}${lBINS}${NC} binaries."
        print_output "[*] Additionally the Linux path counter is ${ORANGE}${LINUX_PATH_COUNTER}${NC}."
        print_ln
        tree -csh "${FIRMWARE_PATH_CP}" | tee -a "${LOG_FILE}"
        print_output "[*] Before package extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after package extraction we have now ${ORANGE}${lFILES_POST_PACKAGE}${NC} files extracted."
        lNEG_LOG=1
      fi
      backup_var "FILES_EXT" "${lFILES_EXT}"
    fi
  else
    print_output "[*] As there is no root directory detected it is not possible to process package archives"
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

apk_extractor() {
  sub_module_title "APK archive extraction mode"

  local lAPK_ARCHIVES=0
  local lAPK_NAME=""
  local lFILES_AFTER_APK=0
  local lR_PATH=""
  local lAPK=""

  print_output "[*] Identify apk archives and extracting it to the root directories ..."
  extract_apk_helper &
  WAIT_PIDS_ARR+=( "$!" )
  wait_for_extractor
  export WAIT_PIDS_ARR=( )

  if [[ -f "${TMP_DIR}"/apk_db.txt ]] ; then
    lAPK_ARCHIVES=$(wc -l "${TMP_DIR}"/apk_db.txt | awk '{print $1}')
    if [[ "${lAPK_ARCHIVES}" -gt 0 ]]; then
      print_output "[*] Found ${ORANGE}${lAPK_ARCHIVES}${NC} APK archives - extracting them to the root directories ..."
      for lR_PATH in "${ROOT_PATH[@]}"; do
        while read -r lAPK; do
          lAPK_NAME=$(basename "${lAPK}")
          print_output "[*] Extracting ${ORANGE}${lAPK_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
          # tar xpf "${lAPK}" --directory "${lR_PATH}" || true
          unzip -o -d "${lR_PATH}" "${lAPK}" || true
        done < "${TMP_DIR}"/apk_db.txt
      done

      lFILES_AFTER_APK=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
      print_ln "no_log"
      print_output "[*] Before apk extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${lFILES_AFTER_APK}${NC} files extracted."
    fi
    check_disk_space
  else
    print_output "[-] No apk packages extracted."
  fi
}

ipk_extractor() {
  sub_module_title "IPK archive extraction mode"
  local lIPK_ARCHIVES=0
  local lIPK_NAME=""
  local lFILES_AFTER_IPK=0
  local lR_PATH=""

  print_output "[*] Identify ipk archives and extracting it to the root directories ..."
  extract_ipk_helper &
  WAIT_PIDS_ARR+=( "$!" )
  wait_for_extractor
  WAIT_PIDS_ARR=( )

  if [[ -f "${TMP_DIR}"/ipk_db.txt ]] ; then
    lIPK_ARCHIVES=$(wc -l "${TMP_DIR}"/ipk_db.txt | awk '{print $1}')
    if [[ "${lIPK_ARCHIVES}" -gt 0 ]]; then
      print_output "[*] Found ${ORANGE}${lIPK_ARCHIVES}${NC} IPK archives - extracting them to the root directories ..."
      mkdir "${LOG_DIR}"/ipk_tmp
      for lR_PATH in "${ROOT_PATH[@]}"; do
        while read -r IPK; do
          lIPK_NAME=$(basename "${IPK}")
          if [[ $(file "${IPK}") == *"gzip"* ]]; then
            print_output "[*] Extracting ${ORANGE}${lIPK_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
            tar zxpf "${IPK}" --directory "${LOG_DIR}"/ipk_tmp || true
          else
            print_output "[-] Is ${ORANGE}${lIPK_NAME}${NC} a valid ipk (tgz) archive?"
          fi
          if [[ -f "${LOG_DIR}"/ipk_tmp/data.tar.gz ]]; then
            tar xzf "${LOG_DIR}"/ipk_tmp/data.tar.gz --directory "${lR_PATH}" || true
          fi
          if [[ -d "${LOG_DIR}"/ipk_tmp/ ]]; then
            rm -r "${LOG_DIR}"/ipk_tmp/* 2>/dev/null || true
          fi
        done < "${TMP_DIR}"/ipk_db.txt
      done

      lFILES_AFTER_IPK=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
      print_ln "no_log"
      print_output "[*] Before ipk extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${lFILES_AFTER_IPK}${NC} files extracted."
      if [[ -d "${LOG_DIR}"/ipk_tmp/ ]]; then
        rm -r "${LOG_DIR}"/ipk_tmp/* 2>/dev/null || true
      fi
    fi
    check_disk_space
  else
    print_output "[-] No ipk packages extracted."
  fi
}

deb_extractor() {
  sub_module_title "Debian archive extraction mode"

  local lDEB_ARCHIVES=0
  local lFILES_AFTER_DEB=0
  local lR_PATH=""
  local lDEB=""

  print_output "[*] Identify debian archives and extracting it to the root directories ..."
  extract_deb_helper &
  WAIT_PIDS_ARR+=( "$!" )
  wait_for_extractor
  export WAIT_PIDS_ARR=( )

  if [[ -f "${TMP_DIR}"/deb_db.txt ]] ; then
    lDEB_ARCHIVES=$(wc -l "${TMP_DIR}"/deb_db.txt | awk '{print $1}')
    if [[ "${lDEB_ARCHIVES}" -gt 0 ]]; then
      print_output "[*] Found ${ORANGE}${lDEB_ARCHIVES}${NC} debian archives - extracting them to the root directories ..."
      for lR_PATH in "${ROOT_PATH[@]}"; do
        while read -r lDEB; do
          if [[ "${THREADED}" -eq 1 ]]; then
            extract_deb_extractor_helper "${lDEB}" "${lR_PATH}" &
            WAIT_PIDS_P20+=( "$!" )
          else
            extract_deb_extractor_helper "${lDEB}" "${lR_PATH}"
          fi
        done < "${TMP_DIR}"/deb_db.txt
      done

      [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_P20[@]}"

      lFILES_AFTER_DEB=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
      print_ln "no_log"
      print_output "[*] Before deb extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${lFILES_AFTER_DEB}${NC} files extracted."
    fi
    check_disk_space
  else
    print_output "[-] No deb packages extracted."
  fi
}

extract_ipk_helper() {
  find "${FIRMWARE_PATH_CP}" -xdev -type f -name "*.ipk" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 >> "${TMP_DIR}"/ipk_db.txt
}

extract_apk_helper() {
  find "${FIRMWARE_PATH_CP}" -xdev -type f -name "*.apk" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 >> "${TMP_DIR}"/apk_db.txt
}

extract_deb_helper() {
  find "${FIRMWARE_PATH_CP}" -xdev -type f \( -name "*.deb" -o -name "*.udeb" \) -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 >> "${TMP_DIR}"/deb_db.txt
}

extract_deb_extractor_helper() {
  local lDEB="${1:-}"
  local lR_PATH="${2:-}"
  local lDEB_NAME=""

  lDEB_NAME=$(basename "${lDEB}")
  print_output "[*] Extracting ${ORANGE}${lDEB_NAME}${NC} package to the root directory ${ORANGE}${lR_PATH}${NC}."
  dpkg-deb --extract "${lDEB}" "${lR_PATH}" || true
}

