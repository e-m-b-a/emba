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

  local DISK_SPACE_CRIT=0
  local NEG_LOG=0
  export FILES_PRE_PACKAGE=0
  local FILES_POST_PACKAGE=0
  local BINS=0
  local DIRS_EXT=0
  local FILES_EXT=0
  local UNIQUE_FILES=0
  export WAIT_PIDS_P20=()

  if [[ "${#ROOT_PATH[@]}" -gt 0 && "${RTOS}" -eq 0 ]]; then
    FILES_PRE_PACKAGE=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
    if [[ "${DISK_SPACE_CRIT}" -ne 1 ]]; then
      deb_extractor
    else
      print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
      print_output "[!] $(print_date) - Ending extraction processes - no deb extraction performed" "main"
      DISK_SPACE_CRIT=1
    fi
    if [[ "${DISK_SPACE_CRIT}" -ne 1 ]]; then
      ipk_extractor
    else
      print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
      print_output "[!] $(print_date) - Ending extraction processes - no ipk extraction performed" "main"
      DISK_SPACE_CRIT=1
    fi
    if [[ "${DISK_SPACE_CRIT}" -ne 1 ]]; then
      apk_extractor
    else
      print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
      print_output "[!] $(print_date) - Ending extraction processes - apk extraction performed" "main"
      DISK_SPACE_CRIT=1
    fi

    FILES_POST_PACKAGE=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )

    if [[ "${FILES_POST_PACKAGE}" -gt "${FILES_PRE_PACKAGE}" ]]; then
      # we need to update these numbers:
      FILES_EXT=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
      UNIQUE_FILES=$(find "${FIRMWARE_PATH_CP}" "${EXCL_FIND[@]}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
      DIRS_EXT=$(find "${FIRMWARE_PATH_CP}" -xdev -type d | wc -l )
      BINS=$(find "${FIRMWARE_PATH_CP}" "${EXCL_FIND[@]}" -xdev -type f -exec file {} \; | grep -c "ELF" || true)

      if [[ "${BINS}" -gt 0 || "${UNIQUE_FILES}" -gt 0 ]]; then
        sub_module_title "Firmware package extraction details"
        linux_basic_identification_helper "${FIRMWARE_PATH_CP}"
        print_ln
        print_output "[*] Found ${ORANGE}${FILES_EXT}${NC} files (${ORANGE}${UNIQUE_FILES}${NC} unique files) and ${ORANGE}${DIRS_EXT}${NC} directories at all."
        print_output "[*] Found ${ORANGE}${BINS}${NC} binaries."
        print_output "[*] Additionally the Linux path counter is ${ORANGE}${LINUX_PATH_COUNTER}${NC}."
        print_ln
        tree -csh "${FIRMWARE_PATH_CP}" | tee -a "${LOG_FILE}"
        print_output "[*] Before package extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after package extraction we have now ${ORANGE}${FILES_POST_PACKAGE}${NC} files extracted."
        NEG_LOG=1
      fi
      backup_var "FILES_EXT" "${FILES_EXT}"
    fi
  else
    print_output "[*] As there is no root directory detected it is not possible to process package archives"
  fi

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

apk_extractor() {
  sub_module_title "APK archive extraction mode"
  local APK_ARCHIVES=0
  local APK_NAME=""
  local FILES_AFTER_APK=0
  local R_PATH=""

  print_output "[*] Identify apk archives and extracting it to the root directories ..."
  extract_apk_helper &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  export WAIT_PIDS=( )

  if [[ -f "${TMP_DIR}"/apk_db.txt ]] ; then
    APK_ARCHIVES=$(wc -l "${TMP_DIR}"/apk_db.txt | awk '{print $1}')
    if [[ "${APK_ARCHIVES}" -gt 0 ]]; then
      print_output "[*] Found ${ORANGE}${APK_ARCHIVES}${NC} APK archives - extracting them to the root directories ..."
      for R_PATH in "${ROOT_PATH[@]}"; do
        while read -r APK; do
          APK_NAME=$(basename "${APK}")
          print_output "[*] Extracting ${ORANGE}${APK_NAME}${NC} package to the root directory ${ORANGE}${R_PATH}${NC}."
          # tar xpf "${APK}" --directory "${R_PATH}" || true
          unzip -o -d "${R_PATH}" "${APK}" || true
        done < "${TMP_DIR}"/apk_db.txt
      done

      FILES_AFTER_APK=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
      print_ln "no_log"
      print_output "[*] Before apk extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${FILES_AFTER_APK}${NC} files extracted."
    fi
    check_disk_space
  else
    print_output "[-] No apk packages extracted."
  fi
}

ipk_extractor() {
  sub_module_title "IPK archive extraction mode"
  local IPK_ARCHIVES=0
  local IPK_NAME=""
  local FILES_AFTER_IPK=0
  local R_PATH=""

  print_output "[*] Identify ipk archives and extracting it to the root directories ..."
  extract_ipk_helper &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  WAIT_PIDS=( )

  if [[ -f "${TMP_DIR}"/ipk_db.txt ]] ; then
    IPK_ARCHIVES=$(wc -l "${TMP_DIR}"/ipk_db.txt | awk '{print $1}')
    if [[ "${IPK_ARCHIVES}" -gt 0 ]]; then
      print_output "[*] Found ${ORANGE}${IPK_ARCHIVES}${NC} IPK archives - extracting them to the root directories ..."
      mkdir "${LOG_DIR}"/ipk_tmp
      for R_PATH in "${ROOT_PATH[@]}"; do
        while read -r IPK; do
          IPK_NAME=$(basename "${IPK}")
          if [[ $(file "${IPK}") == *"gzip"* ]]; then
            print_output "[*] Extracting ${ORANGE}${IPK_NAME}${NC} package to the root directory ${ORANGE}${R_PATH}${NC}."
            tar zxpf "${IPK}" --directory "${LOG_DIR}"/ipk_tmp || true
          else
            print_output "[-] Is ${ORANGE}${IPK_NAME}${NC} a valid ipk (tgz) archive?"
          fi
          if [[ -f "${LOG_DIR}"/ipk_tmp/data.tar.gz ]]; then
            tar xzf "${LOG_DIR}"/ipk_tmp/data.tar.gz --directory "${R_PATH}" || true
          fi
          if [[ -d "${LOG_DIR}"/ipk_tmp/ ]]; then
            rm -r "${LOG_DIR}"/ipk_tmp/* 2>/dev/null || true
          fi
        done < "${TMP_DIR}"/ipk_db.txt
      done

      FILES_AFTER_IPK=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
      print_ln "no_log"
      print_output "[*] Before ipk extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${FILES_AFTER_IPK}${NC} files extracted."
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
  local DEB_ARCHIVES=0
  local FILES_AFTER_DEB=0

  print_output "[*] Identify debian archives and extracting it to the root directories ..."
  extract_deb_helper &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  export WAIT_PIDS=( )

  if [[ -f "${TMP_DIR}"/deb_db.txt ]] ; then
    DEB_ARCHIVES=$(wc -l "${TMP_DIR}"/deb_db.txt | awk '{print $1}')
    if [[ "${DEB_ARCHIVES}" -gt 0 ]]; then
      print_output "[*] Found ${ORANGE}${DEB_ARCHIVES}${NC} debian archives - extracting them to the root directories ..."
      for R_PATH in "${ROOT_PATH[@]}"; do
        while read -r DEB; do
          if [[ "${THREADED}" -eq 1 ]]; then
            extract_deb_extractor_helper "${DEB}" &
            WAIT_PIDS_P20+=( "$!" )
          else
            extract_deb_extractor_helper "${DEB}"
          fi
        done < "${TMP_DIR}"/deb_db.txt
      done

      [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_P20[@]}"

      FILES_AFTER_DEB=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
      print_ln "no_log"
      print_output "[*] Before deb extraction we had ${ORANGE}${FILES_PRE_PACKAGE}${NC} files, after deep extraction we have ${ORANGE}${FILES_AFTER_DEB}${NC} files extracted."
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
  local DEB="${1:-}"
  local DEB_NAME=""
  DEB_NAME=$(basename "${DEB}")
  print_output "[*] Extracting ${ORANGE}${DEB_NAME}${NC} package to the root directory ${ORANGE}${R_PATH}${NC}."
  dpkg-deb --extract "${DEB}" "${R_PATH}" || true
}

