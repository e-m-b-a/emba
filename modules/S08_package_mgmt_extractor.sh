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

# Description:  Searches known locations for package management information
# shellcheck disable=SC2094

S08_package_mgmt_extractor()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Non binary SBOM module"
  pre_module_reporter "${FUNCNAME[0]}"

  local NEG_LOG=0
  local lWAIT_PIDS_S08_ARR=()

  if [[ ${THREADED} -eq 1 ]]; then
    debian_status_files_analysis &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    openwrt_control_files_analysis &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    rpm_package_mgmt_analysis &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    rpm_package_check &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    deb_package_check &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    bsd_pkg_check &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    python_pip_packages &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    python_requirements &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    python_poetry_lock_parser &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    java_archives_check &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    ruby_gem_archive_check &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    alpine_apk_package_check &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    windows_exifparser &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    rust_cargo_lock_parser &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    wait_for_pid "${lWAIT_PIDS_S08_ARR[@]}"
  else
    debian_status_files_analysis
    openwrt_control_files_analysis
    rpm_package_mgmt_analysis
    rpm_package_check
    deb_package_check
    bsd_pkg_check
    python_pip_packages
    python_requirements
    python_poetry_lock_parser
    java_archives_check
    ruby_gem_archive_check
    alpine_apk_package_check
    windows_exifparser
    rust_cargo_lock_parser
  fi

  # shellcheck disable=SC2153
  [[ -s "${S08_CSV_LOG}" ]] && NEG_LOG=1
  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

check_for_csv_log() {
  lS08_CSV_LOG="${1:-}"
  if [[ ! -f "${lS08_CSV_LOG}" ]]; then
    # using write_log as this always works
    write_log "Packaging system;package file;MD5/SHA-256/SHA-512;package;original version;stripped version;license;maintainer;architecture;CPE identifier;PURL;Description" "${lS08_CSV_LOG}"
  fi
}

distri_check() {
  # check for distribution
  local lOS_RELEASE_ARR=()
  local lOS_RELEASE_FILE=""
  local lOS_IDENTIFIED=""
  local lOS_VERS_IDENTIFIED=""

  mapfile -t lOS_RELEASE_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -type f -iwholename "*/etc/os-release")
  for lOS_RELEASE_FILE in "${lOS_RELEASE_ARR[@]}"; do
    lOS_IDENTIFIED=$(grep "^ID=" "${lOS_RELEASE_FILE}")
    lOS_IDENTIFIED=${lOS_IDENTIFIED//ID=}
    lOS_VERS_IDENTIFIED=$(grep "^VERSION_ID=" "${lOS_RELEASE_FILE}")
    lOS_VERS_IDENTIFIED=${lOS_VERS_IDENTIFIED//VERSION_ID=}
    lOS_IDENTIFIED+="-${lOS_VERS_IDENTIFIED}"
    lOS_IDENTIFIED=${lOS_IDENTIFIED//\"}
    lOS_IDENTIFIED=${lOS_IDENTIFIED,,}
    # if it looks like an os then we are happy for now :)
    # for the future we can do some further checks if it is some debian for debs and some rpm based for rpm systems
    if [[ "${lOS_IDENTIFIED}" =~ ^[a-z]+-[a-z]+$ ]]; then
      break
    fi
  done
  echo "${lOS_IDENTIFIED}"
}

deb_package_check() {
  # └─$ ar x liblzma5_5.6.1-1_amd64.deb --output dirname
  # └─$ tar xvf control.tar.xz
  # └─$ cat control
  #
  # Package: liblzma5
  # Source: xz-utils
  # Version: 5.6.1-1
  # Architecture: amd64
  # Maintainer: Sebastian Andrzej Siewior <sebastian@breakpoint.cc>
  # Installed-Size: 401
  # Depends: libc6 (>= 2.34)
  local lPACKAGING_SYSTEM="debian_deb"

  sub_module_title "Debian deb package parser" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lDEB_ARCHIVES_ARR=()
  local lDEB_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM=""
  local lSHA256_CHECKSUM=""
  local lSHA512_CHECKSUM=""
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lDEB_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -type f -name "*.deb")

  if [[ -v lDEB_ARCHIVES_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lDEB_ARCHIVES_ARR[@]}${NC} Debian deb files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lDEB_ARCHIVE in "${lDEB_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lDEB_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lDEB_ARCHIVES_ARR[@]}${NC} Debian deb files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    lOS_IDENTIFIED=$(distri_check)

    for lDEB_ARCHIVE in "${lDEB_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lDEB_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"Debian binary package"* ]]; then
        continue
      fi
      mkdir "${TMP_DIR}/deb_package/"
      ar x "${lDEB_ARCHIVE}" --output "${TMP_DIR}/deb_package/"

      if [[ ! -f "${TMP_DIR}/deb_package/control.tar.xz" ]]; then
        write_log "[-] No debian control.tar.xz found for ${lDEB_ARCHIVE}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      fi

      tar xf "${TMP_DIR}/deb_package/control.tar.xz" -C "${TMP_DIR}/deb_package/"

      if [[ ! -f "${TMP_DIR}/deb_package/control" ]]; then
        write_log "[-] No debian control extracted for ${lDEB_ARCHIVE}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      fi

      lAPP_NAME=$(grep "Package: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_NAME=${lAPP_NAME/*:\ }
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_ARCH=$(grep "Architecture: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_ARCH=${lAPP_ARCH/*:\ }
      lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")

      lAPP_MAINT=$(grep "Maintainer: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_MAINT=${lAPP_MAINT/*:\ }
      lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")

      lAPP_DESC=$(grep "Description: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_DESC=${lAPP_DESC/*:\ }
      lAPP_DESC=$(clean_package_details "${lAPP_DESC}")

      lAPP_LIC=$(grep "License: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_LIC=${lAPP_LIC/*:\ }
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lAPP_VERS=$(grep "Version: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_VERS=${lAPP_VERS/*:\ }
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lDEB_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lDEB_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lDEB_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      lPURL_IDENTIFIER="pkg:deb/${lOS_IDENTIFIED/-*}/${lAPP_NAME}@${lAPP_VERS}?arch=${lAPP_ARCH}&distro=${lOS_IDENTIFIED}"

      # Todo: Company Name, Copyright, Mime-Type

      write_log "[*] Debian deb package details: ${ORANGE}${lDEB_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lDEB_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
      lPOS_RES=1
      rm -r "${TMP_DIR}/deb_package/" || true
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Debian deb archives found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Debian deb archives found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Debian archives SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Debian archives SBOM results available"
  fi
}

windows_exifparser() {
  local lPACKAGING_SYSTEM="windows_exe"

  sub_module_title "Windows Exif parser" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lEXE_ARCHIVES_ARR=()
  local lEXE_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lEXE_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -type f \( -name "*.exe" -o -name "*.dll" \))

  if [[ -v lEXE_ARCHIVES_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lEXE_ARCHIVES_ARR[@]}${NC} Windows exe files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lEXE_ARCHIVE in "${lEXE_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lEXE_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lEXE_ARCHIVES_ARR[@]}${NC} Windows exe files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lEXE_ARCHIVE in "${lEXE_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lEXE_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"PE32 executable"* ]] && [[ "${lR_FILE}" == *"PE32+ executable"* ]]; then
        continue
      fi
      exiftool "${lEXE_ARCHIVE}" > "${TMP_DIR}/windows_exe_exif_data.txt" || true

      lAPP_NAME=$(grep "Product Name" "${TMP_DIR}/windows_exe_exif_data.txt" || true)
      lAPP_NAME=${lAPP_NAME/*:\ }
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      if [[ -z "${lAPP_NAME}" ]]; then
        lAPP_NAME=$(grep "Internal Name" "${TMP_DIR}/windows_exe_exif_data.txt" || true)
        lAPP_NAME=${lAPP_NAME/*:\ }
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
      fi

      if [[ -z "${lAPP_NAME}" ]]; then
        lAPP_NAME=$(grep "File Name" "${TMP_DIR}/windows_exe_exif_data.txt" || true)
        lAPP_NAME=${lAPP_NAME/*:\ }
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
      fi

      lAPP_LIC="NA"

      lAPP_VERS=$(grep "Product Version" "${TMP_DIR}/windows_exe_exif_data.txt" || true)
      lAPP_VERS=${lAPP_VERS/*:\ }
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lEXE_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lEXE_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lEXE_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      # Todo: Company Name, Copyright, Mime-Type

      write_log "[*] Windows EXE details: ${ORANGE}${lEXE_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lEXE_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
      lPOS_RES=1
      rm -f "${TMP_DIR}/windows_exe_exif_data.txt"
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Windows executables found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Windows executables found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Windows executables SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Rust Windows executables SBOM results available"
  fi
}

python_poetry_lock_parser() {
  local lPACKAGING_SYSTEM="python_poetry_lock"

  sub_module_title "Python poetry lock identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPY_LCK_ARCHIVES_ARR=()
  local lPY_LCK_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lPY_LCK_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "poetry.lock" -type f)

  if [[ -v lPY_LCK_ARCHIVES_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lPY_LCK_ARCHIVES_ARR[@]}${NC} Python poetry.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPY_LCK_ARCHIVE in "${lPY_LCK_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPY_LCK_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPY_LCK_ARCHIVES_ARR[@]}${NC} Python poetry.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPY_LCK_ARCHIVE in "${lPY_LCK_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lPY_LCK_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"ASCII text"* ]]; then
        continue
      fi

      lSHA512_CHECKSUM="$(sha512sum "${lPY_LCK_ARCHIVE}" | awk '{print $1}')"
      lMD5_CHECKSUM="$(md5sum "${lPY_LCK_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lPY_LCK_ARCHIVE}" | awk '{print $1}')"

      sed ':a;N;$!ba;s/\"\n/\"|/g' "${lPY_LCK_ARCHIVE}" | grep name > "${TMP_DIR}/poetry.lock.tmp" || true

      while read -r lPOETRY_ENTRY; do
        lAPP_NAME=${lPOETRY_ENTRY/|*}
        lAPP_NAME=${lAPP_NAME/name\ =\ }
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_LIC="NA"

        lAPP_VERS=$(echo "${lPOETRY_ENTRY}" | cut -d\| -f2)
        lAPP_VERS=${lAPP_VERS/version\ =\ }
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lAPP_DESC=$(echo "${lPOETRY_ENTRY}" | cut -d\| -f3)
        lAPP_DESC=${lAPP_DESC/description\ =\ }
        lAPP_DESC=$(clean_package_details "${lAPP_DESC}")

        # lSHA512_CHECKSUM=$(echo "${lPOETRY_ENTRY}" | cut -d\| -f4)
        # lSHA512_CHECKSUM=${lSHA512_CHECKSUM/checksum\ =\ }
        # lSHA512_CHECKSUM=$(clean_package_versions "${lSHA512_CHECKSUM}")

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        # Todo: checksum

        write_log "[*] Python poetry.lock archive details: ${ORANGE}${lPY_LCK_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPY_LCK_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH:-NA}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
        lPOS_RES=1
      done < "${TMP_DIR}/poetry.lock.tmp"
      rm -f "${TMP_DIR}/poetry.lock.tmp"
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Python poetry.lock packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Python poetry.lock package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Python poetry.lock SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Python poetry.lock SBOM results available"
  fi
}

rust_cargo_lock_parser() {
  local lPACKAGING_SYSTEM="rust_cargo_lock"

  sub_module_title "Rust cargo lock identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lRST_ARCHIVES_ARR=()
  local lRST_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lRST_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "Cargo.lock" -type f)

  if [[ -v lRST_ARCHIVES_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lRST_ARCHIVES_ARR[@]}${NC} Rust Cargo.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lRST_ARCHIVE in "${lRST_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lRST_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lRST_ARCHIVES_ARR[@]}${NC} Rust Cargo.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lRST_ARCHIVE in "${lRST_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lRST_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"ASCII text"* ]]; then
        continue
      fi
      # we start with the following file structure:
      # [[package]]
      # name = "windows-sys"
      # version = "0.42.0"
      # source = "registry+https://github.com/rust-lang/crates.io-index"
      # checksum = "5a3e1820f08b8513f676f7ab6c1f99ff312fb97b553d30ff4dd86f9f15728aa7"
      # dependencies = [
      #  "windows_aarch64_gnullvm",
      #
      #  and transform it to a one liner like the following:
      #  name = "windows_x86_64_msvc" -- version = "0.42.0" -- source = "registry+https://github.com/rust-lang/crates.io-index" -- checksum = "f40009d85759725a34da6d89a94e63d7bdc50a862acf0dbc7c8e488f1edcb6f5" --

      sed ':a;N;$!ba;s/\"\n/\"|/g' "${lRST_ARCHIVE}" | grep name | sed 's/|dependencies = \[//' > "${TMP_DIR}/Cargo.lock.tmp"

      while read -r lCARGO_ENTRY; do
        lAPP_NAME=${lCARGO_ENTRY/|*}
        lAPP_NAME=${lAPP_NAME/name\ =\ }
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_LIC="NA"

        lAPP_VERS=$(echo "${lCARGO_ENTRY}" | cut -d\| -f2)
        lAPP_VERS=${lAPP_VERS/version\ =\ }
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lSHA256_CHECKSUM=$(echo "${lCARGO_ENTRY}" | cut -d\| -f4)
        lSHA256_CHECKSUM=${lSHA256_CHECKSUM/checksum\ =\ }
        lSHA256_CHECKSUM=$(clean_package_versions "${lSHA256_CHECKSUM}")

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        # Todo: source

        write_log "[*] Rust Cargo.lock archive details: ${ORANGE}${lRST_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lRST_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
        lPOS_RES=1
      done < "${TMP_DIR}/Cargo.lock.tmp"
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Rust Cargo.lock packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Rust Cargo.lock package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Rust Cargo.lock SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Rust Cargo.lock SBOM results available"
  fi
}

alpine_apk_package_check() {
  local lPACKAGING_SYSTEM="alpine_apk"

  sub_module_title "Alpine apk archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lAPK_ARCHIVES_ARR=()
  local lAPK_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lAPK_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.apk" -type f)

  if [[ -v lAPK_ARCHIVES_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lAPK_ARCHIVES_ARR[@]}${NC} Alpine apk archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lAPK_ARCHIVE in "${lAPK_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lAPK_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lAPK_ARCHIVES_ARR[@]}${NC} Alpine apk archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lAPK_ARCHIVE in "${lAPK_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lAPK_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"gzip compressed data"* ]]; then
        continue
      fi

      mkdir "${TMP_DIR}"/apk
      tar -xzf "${lAPK_ARCHIVE}" -C "${TMP_DIR}"/apk 2>/dev/null || print_error "[-] Extraction of APK package file ${lAPK_ARCHIVE} failed"

      if ! [[ -f "${TMP_DIR}"/apk/.PKGINFO ]]; then
        continue
      fi

      lAPP_NAME=$(grep '^pkgname = ' "${TMP_DIR}"/apk/.PKGINFO || true)
      lAPP_NAME=${lAPP_NAME/pkgname\ =\ }
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_LIC=$(grep '^license = ' "${TMP_DIR}"/apk/.PKGINFO || true)
      lAPP_LIC=${lAPP_LIC/license\ =\ }
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lAPP_VERS=$(grep '^pkgver = ' "${TMP_DIR}"/apk/.PKGINFO || true)
      lAPP_VERS=${lAPP_VERS/pkgver\ =\ }
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lAPK_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lAPK_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lAPK_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      write_log "[*] Alpine apk archive details: ${ORANGE}${lAPK_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lAPK_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
      lPOS_RES=1
      rm -rf "${TMP_DIR}"/apk || true
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Alpine apk packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Alpine apk package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Alpine APK archives SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Alpine APK archives SBOM results available"
  fi
}

ruby_gem_archive_check() {
  local lPACKAGING_SYSTEM="ruby_gem"

  sub_module_title "Ruby gem archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lGEM_ARCHIVES_ARR=()
  local lGEM_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lGEM_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.gem" -type f)

  if [[ -v lGEM_ARCHIVES_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lGEM_ARCHIVES_ARR[@]}${NC} Ruby gem archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lGEM_ARCHIVE in "${lGEM_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lGEM_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lGEM_ARCHIVES_ARR[@]}${NC} Ruby gem archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lGEM_ARCHIVE in "${lGEM_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lGEM_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"POSIX tar archive"* ]]; then
        continue
      fi

      mkdir "${TMP_DIR}"/gems
      tar -x -f "${lGEM_ARCHIVE}" -C "${TMP_DIR}"/gems || print_error "[-] Extraction of FreeBSD package file ${lPKG_ARCHIVE} failed"
      # └─$ gunzip -k metadata.gz
      # └─$ cat metadata
      # -> name, version
      if ! [[ -f "${TMP_DIR}"/gems/metadata.gz ]]; then
        write_log "[-] No metadata.gz extracted from ${lGEM_ARCHIVE}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        continue
      fi
      gunzip -k -c "${TMP_DIR}"/gems/metadata.gz > "${TMP_DIR}"/gems/metadata

      if ! [[ -f "${TMP_DIR}"/gems/metadata ]]; then
        write_log "[-] No metadata extracted from ${lGEM_ARCHIVE}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        continue
      fi

      lAPP_NAME=$(grep '^name: ' "${TMP_DIR}"/gems/metadata || true)
      lAPP_NAME=${lAPP_NAME/name:\ }
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_LIC="NA"
      # lAPP_LIC=$(grep '^licenses' "${TMP_DIR}"/gems/metadata || true)
      # lAPP_LIC=$(safe_echo "${lAPP_LIC}" | tr -dc '[:print:]')

      # grep -A1 "^version: " metadata | grep "[0-9]\."
      lAPP_VERS=$(grep -A1 '^version' "${TMP_DIR}"/gems/metadata | grep "[0-9]" || true)
      lAPP_VERS=${lAPP_VERS/*version:\ }
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lGEM_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lGEM_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lGEM_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      write_log "[*] Ruby gems archive details: ${ORANGE}${lGEM_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lGEM_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
      lPOS_RES=1
      rm -rf "${TMP_DIR}"/gems || true
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Ruby gems packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Ruby gems package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Ruby gems package files SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Ruby gemx package SBOM results available"
  fi
}

bsd_pkg_check() {
  # └─$ file boost-libs-1.84.0.pkg
  #     boost-libs-1.84.0.pkg: Zstandard compressed data (v0.8+), Dictionary ID: None
  # tar --zstd -x -f ./boost-libs-1.84.0.pkg +COMPACT_MANIFEST
  local lPACKAGING_SYSTEM="freebsd_pkg"

  sub_module_title "FreeBSD pkg archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPKG_ARCHIVES_ARR=()
  local lPKG_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lPKG_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.pkg" -type f)

  if [[ -v lPKG_ARCHIVES_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lPKG_ARCHIVES_ARR[@]}${NC} FreeBSD pkg archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPKG_ARCHIVE in "${lPKG_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPKG_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPKG_ARCHIVES_ARR[@]}${NC} FreeBSD pkg archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPKG_ARCHIVE in "${lPKG_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lPKG_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"Zstandard"* ]]; then
        continue
      fi

      tar --zstd -x -f "${lPKG_ARCHIVE}" -C "${TMP_DIR}" +COMPACT_MANIFEST || print_error "[-] Extraction of FreeBSD package file ${lPKG_ARCHIVE} failed"
      if ! [[ -f "${TMP_DIR}"/+COMPACT_MANIFEST ]]; then
        continue
      fi
      # jq -r '.' "${TMP_DIR}"/+COMPACT_MANIFEST
      # jq -r '.name' "${TMP_DIR}"/+COMPACT_MANIFEST
      # boost-libs
      #
      # jq -r '.version' "${TMP_DIR}"/+COMPACT_MANIFEST
      # 1.84.0
      #
      # jq -cr '.licenses' "${TMP_DIR}"/+COMPACT_MANIFEST
      # ["BSL"]

      lAPP_NAME=$(jq -r '.name' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_LIC=$(jq -cr '.licenses' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lAPP_VERS=$(jq -r '.version' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lPKG_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lPKG_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lPKG_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      write_log "[*] FreeBSD pkg archive details: ${ORANGE}${lPKG_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lPKG_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
      lPOS_RES=1
      rm -f "${TMP_DIR}"/+COMPACT_MANIFEST || true
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No FreeBSD pkg packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No FreeBSD pkg package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] FreeBSD pkg package files SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No FreeBSD pkg package SBOM results available"
  fi
}

rpm_package_check() {
  local lPACKAGING_SYSTEM="rpm_package"

  sub_module_title "RPM archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lRPM_ARCHIVES_ARR=()
  local lRPM_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lRPM_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.rpm" -type f)

  if [[ -v lRPM_ARCHIVES_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lRPM_ARCHIVES_ARR[@]}${NC} RPM archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lRPM_ARCHIVE in "${lRPM_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lRPM_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lRPM_ARCHIVES_ARR[@]}${NC} RPM archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lRPM_ARCHIVE in "${lRPM_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lRPM_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"RPM"* ]]; then
        continue
      fi

      lAPP_NAME=$(rpm -qipl "${lRPM_ARCHIVE}" 2>/dev/null | grep "Name" || true)
      lAPP_NAME=${lAPP_NAME/*:\ /}
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_LIC=$(rpm -qipl "${lRPM_ARCHIVE}" 2>/dev/null | grep "License" || true)
      lAPP_LIC=${lAPP_LIC/*:\ /}
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lAPP_VERS=$(rpm -qipl "${lRPM_ARCHIVE}" 2>/dev/null | grep "Version" || true)
      lAPP_VERS=${lAPP_VERS/*:\ /}
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lRPM_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lRPM_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lRPM_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      write_log "[*] RPM archive details: ${ORANGE}${lRPM_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lRPM_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
      lPOS_RES=1
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No RPM packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No RPM package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] RPM packages SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No RPM package SBOM results available"
  fi
}

python_requirements() {
  local lPACKAGING_SYSTEM="python_requirements"

  sub_module_title "Python requirements identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPY_REQUIREMENTS_ARR=()
  local lPY_REQ_FILE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lPOS_RES=0
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lRES_ENTRY="NA"
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lPY_REQUIREMENTS_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "requirements*.txt" -type f)

  if [[ -v lPY_REQUIREMENTS_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lPY_REQUIREMENTS_ARR[@]}${NC} python requirement files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPY_REQ_FILE in "${lPY_REQUIREMENTS_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPY_REQ_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPY_REQUIREMENTS_ARR[@]}${NC} python requirement files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPY_REQ_FILE in "${lPY_REQUIREMENTS_ARR[@]}" ; do
      lR_FILE=$(file "${lPY_REQ_FILE}")
      if [[ ! "${lR_FILE}" == *"ASCII text"* ]]; then
        continue
      fi

      # read entry line by line
      while read -r lRES_ENTRY; do
        if [[ "${lRES_ENTRY}" =~ ^#.*$ ]]; then
          continue
        fi
        if [[ "${lRES_ENTRY}" == *"=="* ]]; then
          lAPP_NAME=${lRES_ENTRY/==*}
          lAPP_VERS=${lRES_ENTRY/*==}
        elif [[ "${lRES_ENTRY}" == *">="* ]]; then
          lAPP_NAME=${lRES_ENTRY/>=*}
          lAPP_VERS=${lRES_ENTRY/*>=}
          lAPP_VERS='>='"${lAPP_VERS}"
        elif [[ "${lRES_ENTRY}" == *"<"* ]]; then
          lAPP_NAME=${lRES_ENTRY/<*}
          lAPP_VERS=${lRES_ENTRY/*<}
          lAPP_VERS='<'"${lAPP_VERS}"
        elif [[ "${lRES_ENTRY}" == *"=~"* ]]; then
          lAPP_NAME=${lRES_ENTRY/=~*}
          lAPP_VERS=${lRES_ENTRY/*=~}
          lAPP_VERS='=~'"${lAPP_VERS}"
        else
          lAPP_NAME=${lRES_ENTRY}
          lAPP_VERS="NA"
        fi
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lMD5_CHECKSUM="$(md5sum "${lPY_REQ_FILE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPY_REQ_FILE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPY_REQ_FILE}" | awk '{print $1}')"

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        # with internet we can query further details
        # └─$ curl -sH "accept: application/json" https://pypi.org/pypi/"${lAPP_NAME}"/json | jq '.info.author, .info.classifiers'
        # "Chris P"
        # [
        #   "Development Status :: 5 - Production/Stable",
        #   "License :: OSI Approved :: MIT License",

        write_log "[*] Python requirement details: ${ORANGE}${lPY_REQ_FILE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPY_REQ_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
        lPOS_RES=1
      done < "${lPY_REQ_FILE}"
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No python requirements!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No python requirement files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Python requirements SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Python requirements SBOM results available"
  fi
}

python_pip_packages() {
  local lPACKAGING_SYSTEM="python_pip"

  sub_module_title "Python PIP package identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPIP_PACKAGES_SITE_ARR=()
  local lPIP_PACKAGES_DIST_ARR=()
  local lPIP_DIST_DIR=""
  local lPIP_SITE_DIR=""
  local lPIP_DIST_INSTALLED_PACKAGES_ARR=()
  local lPIP_SITE_INSTALLED_PACKAGES_ARR=()
  local lPIP_DIST_META_PACKAGE=""
  local lPIP_SITE_META_PACKAGE=""
  local lAPP_LIC="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  # pip packages are in site-packages or in dist-packages directories installed
  # metadata can be found in METADATA of in PKG-INFO
  mapfile -t lPIP_PACKAGES_SITE_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "site-packages" -type d)
  mapfile -t lPIP_PACKAGES_DIST_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "dist-packages" -type d)

  if [[ -v lPIP_PACKAGES_DIST_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lPIP_PACKAGES_DIST_ARR[@]}${NC} PIP dist-packages directories:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPIP_DIST_DIR in "${lPIP_PACKAGES_DIST_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPIP_DIST_DIR}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPIP_PACKAGES_DIST_ARR[@]}${NC} PIP dist-packages directories:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPIP_DIST_DIR in "${lPIP_PACKAGES_DIST_ARR[@]}" ; do
      mapfile -t lPIP_DIST_INSTALLED_PACKAGES_ARR < <(find "${lPIP_DIST_DIR}" -name "METADATA" -type f)
      for lPIP_DIST_META_PACKAGE in "${lPIP_DIST_INSTALLED_PACKAGES_ARR[@]}" ; do
        lPIP_PACKAGE_NAME=$(grep "^Name: " "${lPIP_DIST_META_PACKAGE}" || true)
        lPIP_PACKAGE_NAME=${lPIP_PACKAGE_NAME/*:\ }
        lPIP_PACKAGE_NAME=$(clean_package_details "${lPIP_PACKAGE_NAME}")

        lPIP_PACKAGE_VERSION=$(grep "^Version: " "${lPIP_DIST_META_PACKAGE}" || true)
        lPIP_PACKAGE_VERSION=${lPIP_PACKAGE_VERSION/*:\ }
        lPIP_PACKAGE_VERSION=$(clean_package_details "${lPIP_PACKAGE_VERSION}")
        lPIP_PACKAGE_VERSION=$(clean_package_versions "${lPIP_PACKAGE_VERSION}")

        lMD5_CHECKSUM="$(md5sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"

        lAPP_VENDOR="${lPIP_PACKAGE_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lPIP_PACKAGE_NAME}:${lPIP_PACKAGE_VERSION}:*:*:*:*:*:*"

        write_log "[*] Found PIP package ${ORANGE}${lPIP_PACKAGE_NAME}${NC} - Version ${ORANGE}${lPIP_PACKAGE_VERSION}${NC} in PIP dist-packages directory ${ORANGE}${lPIP_DIST_META_PACKAGE}${NC} - Source ${ORANGE}METADATA${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_DIST_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lPIP_PACKAGE_NAME}" "${lPIP_PACKAGE_VERSION}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
        lPOS_RES=1
      done

      mapfile -t lPIP_DIST_INSTALLED_PACKAGES_ARR < <(find "${lPIP_DIST_DIR}" -name "PKG-INFO" -type f)
      for lPIP_DIST_META_PACKAGE in "${lPIP_DIST_INSTALLED_PACKAGES_ARR[@]}" ; do
        lPIP_PACKAGE_NAME=$(grep "^Name: " "${lPIP_DIST_META_PACKAGE}" || true)
        lPIP_PACKAGE_NAME=${lPIP_PACKAGE_NAME/*:\ }
        lPIP_PACKAGE_NAME=$(clean_package_details "${lPIP_PACKAGE_NAME}")

        lPIP_PACKAGE_VERSION=$(grep "^Version: " "${lPIP_DIST_META_PACKAGE}" || true)
        lPIP_PACKAGE_VERSION=${lPIP_PACKAGE_VERSION/*:\ }
        lPIP_PACKAGE_VERSION=$(clean_package_details "${lPIP_PACKAGE_VERSION}")
        lPIP_PACKAGE_VERSION=$(clean_package_versions "${lPIP_PACKAGE_VERSION}")

        lMD5_CHECKSUM="$(md5sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"

        lAPP_VENDOR="${lPIP_PACKAGE_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lPIP_PACKAGE_NAME}:${lPIP_PACKAGE_VERSION}:*:*:*:*:*:*"

        write_log "[*] Found PIP package ${ORANGE}${lPIP_PACKAGE_NAME}${NC} - Version ${ORANGE}${lPIP_PACKAGE_VERSION}${NC} in PIP dist-packages directory ${ORANGE}${lPIP_DIST_META_PACKAGE}${NC} - Source ${ORANGE}PKG-INFO${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_DIST_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lPIP_PACKAGE_NAME}" "${lPIP_PACKAGE_VERSION}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
        lPOS_RES=1
      done
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No PIP dist packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No PIP dist package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  if [[ -v lPIP_PACKAGES_SITE_ARR[@] ]] ; then
    if [[ ! -f "${S08_CSV_LOG}" ]]; then
      write_csv_log "Packaging system" "package file" "SHA-512" "package" "original version" "stripped version" "license" "maintainer" "architecture" "Description"
    fi

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Found ${ORANGE}${#lPIP_PACKAGES_SITE_ARR[@]}${NC} PIP site-packages directories:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPIP_SITE_DIR in "${lPIP_PACKAGES_SITE_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPIP_SITE_DIR}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPIP_PACKAGES_SITE_ARR[@]}${NC} PIP site-packages directories:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPIP_SITE_DIR in "${lPIP_PACKAGES_SITE_ARR[@]}" ; do
      mapfile -t lPIP_SITE_INSTALLED_PACKAGES_ARR < <(find "${lPIP_SITE_DIR}" -name "METADATA" -type f)
      for lPIP_SITE_META_PACKAGE in "${lPIP_SITE_INSTALLED_PACKAGES_ARR[@]}" ; do
        lPIP_PACKAGE_NAME=$(grep "^Name: " "${lPIP_SITE_META_PACKAGE}" || true)
        lPIP_PACKAGE_NAME=${lPIP_PACKAGE_NAME/*:\ }
        lPIP_PACKAGE_NAME=$(clean_package_details "${lPIP_PACKAGE_NAME}")

        lPIP_PACKAGE_VERSION=$(grep "^Version: " "${lPIP_SITE_META_PACKAGE}" || true)
        lPIP_PACKAGE_VERSION=${lPIP_PACKAGE_VERSION/*:\ }
        lPIP_PACKAGE_VERSION=$(clean_package_details "${lPIP_PACKAGE_VERSION}")
        lPIP_PACKAGE_VERSION=$(clean_package_versions "${lPIP_PACKAGE_VERSION}")

        lMD5_CHECKSUM="$(md5sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"

        lAPP_VENDOR="${lPIP_PACKAGE_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lPIP_PACKAGE_NAME}:${lPIP_PACKAGE_VERSION}:*:*:*:*:*:*"

        write_log "[*] Found PIP package ${ORANGE}${lPIP_PACKAGE_NAME}${NC} - Version ${ORANGE}${lPIP_PACKAGE_VERSION}${NC} in PIP dist-packages directory ${ORANGE}${lPIP_SITE_META_PACKAGE}${NC} - Source ${ORANGE}METADATA${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_SITE_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lPIP_PACKAGE_NAME}" "${lPIP_PACKAGE_VERSION}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
        lPOS_RES=1
      done

      mapfile -t lPIP_SITE_INSTALLED_PACKAGES_ARR < <(find "${lPIP_SITE_DIR}" -name "PKG-INFO" -type f)
      for lPIP_SITE_META_PACKAGE in "${lPIP_SITE_INSTALLED_PACKAGES_ARR[@]}" ; do
        lPIP_PACKAGE_NAME=$(grep "^Name: " "${lPIP_SITE_META_PACKAGE}" || true)
        lPIP_PACKAGE_NAME=${lPIP_PACKAGE_NAME/*:\ }
        lPIP_PACKAGE_NAME=$(clean_package_details "${lPIP_PACKAGE_NAME}")

        lPIP_PACKAGE_VERSION=$(grep "^Version: " "${lPIP_SITE_META_PACKAGE}" || true)
        lPIP_PACKAGE_VERSION=${lPIP_PACKAGE_VERSION/*:\ }
        lPIP_PACKAGE_VERSION=$(clean_package_details "${lPIP_PACKAGE_VERSION}")
        lPIP_PACKAGE_VERSION=$(clean_package_versions "${lPIP_PACKAGE_VERSION}")

        lMD5_CHECKSUM="$(md5sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"

        lAPP_VENDOR="${lPIP_PACKAGE_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lPIP_PACKAGE_NAME}:${lPIP_PACKAGE_VERSION}:*:*:*:*:*:*"

        write_log "[*] Found PIP package ${ORANGE}${lPIP_PACKAGE_NAME}${NC} - Version ${ORANGE}${lPIP_PACKAGE_VERSION}${NC} in PIP dist-packages directory ${ORANGE}${lPIP_SITE_META_PACKAGE}${NC} - Source ${ORANGE}PKG-INFO${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_SITE_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lPIP_PACKAGE_NAME}" "${lPIP_PACKAGE_VERSION}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
        lPOS_RES=1
      done
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No PIP site packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No PIP site package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Python PIP database SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Python PIP SBOM results available"
  fi
}

java_archives_check() {
  local lPACKAGING_SYSTEM="java_archive"

  sub_module_title "Java archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lJAVA_ARCHIVES_ARR=()
  local lJAVA_ARCHIVES_JAR_ARR=()
  local lJAVA_ARCHIVES_WAR_ARR=()
  local lJAVA_ARCHIVE=""
  local lJ_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lIMPLEMENT_TITLE="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lJAVA_ARCHIVES_JAR_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.jar" -type f)
  mapfile -t lJAVA_ARCHIVES_WAR_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.war" -type f)
  lJAVA_ARCHIVES_ARR=( "${lJAVA_ARCHIVES_JAR_ARR[@]}" "${lJAVA_ARCHIVES_WAR_ARR[@]}" )

  if [[ -v lJAVA_ARCHIVES_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lJAVA_ARCHIVES_ARR[@]}${NC} Java archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lJAVA_ARCHIVE in "${lJAVA_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lJAVA_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lJAVA_ARCHIVES_ARR[@]}${NC} Java archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lJAVA_ARCHIVE in "${lJAVA_ARCHIVES_ARR[@]}" ; do
      lJ_FILE=$(file "${lJAVA_ARCHIVE}")
      if [[ ! "${lJ_FILE}" == *"Java archive data"* && ! "${lJ_FILE}" == *"Zip archive"* ]]; then
        continue
      fi

      lAPP_NAME=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Application-Name" || true)
      lAPP_NAME=${lAPP_NAME/*:\ /}
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_LIC=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "License" || true)
      lAPP_LIC=${lAPP_LIC/*:\ /}
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lIMPLEMENT_TITLE=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Implementation-Title" || true)
      lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE/*:/}
      lIMPLEMENT_TITLE=$(clean_package_details "${lIMPLEMENT_TITLE}")

      lAPP_VERS=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Implementation-Version" || true)
      lAPP_VERS=${lAPP_VERS/*:\ /}
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"

      if [[ -z "${lAPP_NAME}" && -z "${lAPP_LIC}" && -z "${lIMPLEMENT_TITLE}" && -z "${lAPP_VERS}" ]]; then
        continue
      fi
      if [[ -z "${lAPP_NAME}" && -n "${lIMPLEMENT_TITLE}" ]]; then
        # in case APP_NAME is not set but we have an lIMPLEMENT_TITLE we use this
        lAPP_NAME="${lIMPLEMENT_TITLE}"
      fi

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      write_log "[*] Java archive details: ${ORANGE}${lJAVA_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA} / ${lIMPLEMENT_TITLE:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lJAVA_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
      lPOS_RES=1
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No JAVA packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No JAVA package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Java package SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Java package SBOM results available"
  fi
}

debian_status_files_analysis() {
  local lPACKAGING_SYSTEM="debian_pkg_mgmt"

  sub_module_title "Debian package management identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lDEBIAN_MGMT_STATUS_ARR=()
  local lPACKAGE_FILE=""
  local lDEBIAN_PACKAGES_ARR=()
  local lPACKAGE_VERSION=""
  local lPACKAGE=""
  local lVERSION=""
  local lINSTALL_STATE=""
  local lAPP_LIC="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lDEBIAN_MGMT_STATUS_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -path "*dpkg/status" -type f)

  if [[ -v lDEBIAN_MGMT_STATUS_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lDEBIAN_MGMT_STATUS_ARR[@]}${NC} debian package management files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lDEBIAN_MGMT_STATUS_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPACKAGE_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    lOS_IDENTIFIED=$(distri_check)

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lDEBIAN_MGMT_STATUS_ARR[@]}${NC} debian package management files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lDEBIAN_MGMT_STATUS_ARR[@]}" ; do
      if grep -q "Package: " "${lPACKAGE_FILE}"; then
        mapfile -t lDEBIAN_PACKAGES_ARR < <(grep "^Package: \|^Status: \|^Version: \|^Maintainer: \|^Architecture: \|^Description: " "${lPACKAGE_FILE}" | sed -z 's/\nVersion: / - Version: /g' \
          | sed -z 's/\nStatus: / - Status: /g' | sed -z 's/\nMaintainer: / - Maintainer: /g' | sed -z 's/\nDescription: / - Description: /g' | sed -z 's/\nArchitecture: / - Architecture: /g')
        write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_log "[*] Found debian package details in ${ORANGE}${lPACKAGE_FILE}${NC}:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

        lMD5_CHECKSUM="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPACKAGE_FILE}" | awk '{print $1}')"

        for lPACKAGE_VERSION in "${lDEBIAN_PACKAGES_ARR[@]}" ; do
          # Package: dbus - Status: install ok installed - Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com> - Version: 1.12.16-2ubuntu2.1 - Description: simple interprocess messaging system (daemon and utilities)
          lPACKAGE=$(safe_echo "${lPACKAGE_VERSION}" | awk '{print $2}')
          lPACKAGE=$(clean_package_details "${lPACKAGE}")

          lAPP_MAINT=${lPACKAGE_VERSION/*Maintainer:\ /}
          lAPP_MAINT=${lAPP_MAINT/- Architecture:\ */}
          lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")
          lAPP_MAINT=$(clean_package_versions "${lAPP_MAINT}")

          lVERSION=${lPACKAGE_VERSION/*Version:\ /}
          lVERSION=${lVERSION/ - Description:\ */}
          lVERSION=$(clean_package_details "${lVERSION}")
          lVERSION=$(clean_package_versions "${lVERSION}")

          lAPP_ARCH=${lPACKAGE_VERSION/*Architecture:\ /}
          lAPP_ARCH=${lAPP_ARCH/ - Version:\ */}
          lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")
          lAPP_ARCH=$(clean_package_versions "${lAPP_ARCH}")

          lAPP_DESC=${lPACKAGE_VERSION/*Description:\ /}
          lAPP_DESC=$(clean_package_details "${lAPP_DESC}")
          lAPP_DESC=$(clean_package_versions "${lAPP_DESC}")

          lINSTALL_STATE=$(safe_echo "${lPACKAGE_VERSION}" | cut -d: -f3)
          if [[ "${lINSTALL_STATE}" == *"deinstall ok"* ]]; then
            write_log "[*] Debian package details: ${ORANGE}${lPACKAGE_FILE}${NC} - ${ORANGE}${lPACKAGE}${NC} - ${ORANGE}${lVERSION}${NC} - ${RED}STATE: Not installed${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
            continue
          fi

          lAPP_VENDOR="${lPACKAGE}"
          lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lPACKAGE}:${lVERSION}:*:*:*:*:*:*"
          lPURL_IDENTIFIER="pkg:deb/${lOS_IDENTIFIED/-*}/${lPACKAGE}@${lVERSION}?arch=${lAPP_ARCH}&distro=${lOS_IDENTIFIED}"

          write_log "[*] Debian package details: ${ORANGE}${lPACKAGE_FILE}${NC} - ${ORANGE}${lPACKAGE}${NC} - ${ORANGE}${lVERSION}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          write_csv_log "${lPACKAGING_SYSTEM}" "${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lPACKAGE}" "${lVERSION}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
          lPOS_RES=1
        done
      fi
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No debian packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No debian package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Debian packages SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Debian packages SBOM results available"
  fi
}

openwrt_control_files_analysis() {
  local lPACKAGING_SYSTEM="OpenWRT"

  sub_module_title "OpenWRT package management identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPACKAGE_FILE=""
  local lOPENWRT_PACKAGES_ARR=()
  local lPACKAGE_VERSION=""
  local lPACKAGE=""
  local lVERSION=""
  local lAPP_LIC="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lOPENWRT_MGMT_CONTROL_ARR=()
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lOS_IDENTIFIED="NA"
  local lPURL_IDENTIFIER="NA"

  mapfile -t lOPENWRT_MGMT_CONTROL_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -path "*opkg/info/*.control" -type f)

  if [[ -v lOPENWRT_MGMT_CONTROL_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lOPENWRT_MGMT_CONTROL_ARR[@]}${NC} OpenWRT package management files." "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lOPENWRT_MGMT_CONTROL_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPACKAGE_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lOPENWRT_MGMT_CONTROL_ARR[@]}${NC} OpenWRT package management files." "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lOPENWRT_MGMT_CONTROL_ARR[@]}" ; do
      if grep -q "Package: " "${lPACKAGE_FILE}"; then
        lMD5_CHECKSUM="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        mapfile -t lOPENWRT_PACKAGES_ARR < <(grep "^Package: \|^Version: " "${lPACKAGE_FILE}" | sed -z 's/\nVersion: / - Version: /g')
        for lPACKAGE_VERSION in "${lOPENWRT_PACKAGES_ARR[@]}" ; do
          lPACKAGE=$(safe_echo "${lPACKAGE_VERSION}" | awk '{print $2}' | tr -dc '[:print:]')
          lPACKAGE=$(clean_package_details "${lPACKAGE}")

          lVERSION=${lPACKAGE_VERSION/*Version:\ /}
          lVERSION=$(clean_package_details "${lVERSION}")
          lVERSION=$(clean_package_versions "${lVERSION}")

          lAPP_VENDOR="${lPACKAGE}"
          lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lPACKAGE}:${lVERSION}:*:*:*:*:*:*"

          write_log "[*] OpenWRT package details: ${ORANGE}${lPACKAGE_FILE}${NC} - ${ORANGE}${lPACKAGE}${NC} - ${ORANGE}${lVERSION}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          write_csv_log "${lPACKAGING_SYSTEM}" "${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lPACKAGE}" "${lVERSION}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
          lPOS_RES=1
        done
      fi
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No OpenWRT packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No OpenWRT package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] OpenWRT packages SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No OpenWRT packages SBOM results available"
  fi
}

rpm_package_mgmt_analysis() {
  local lPACKAGING_SYSTEM="RPM_pkg_mgmt"

  sub_module_title "RPM package management identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if ! command -v rpm > /dev/null; then
    write_log "[-] RPM command not found ... not executing RPM test module" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    return
  fi

  local lRPM_PACKAGE_DBS_ARR=()
  local lPACKAGE_FILE=""
  local lRPM_PACKAGES_ARR=()
  local lRPM_DIR=""
  local lPACKAGE_VERSION=""
  local lPACKAGE_NAME=""
  local lPACKAGE_AND_VERSION=""
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"

  mapfile -t lRPM_PACKAGE_DBS_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -path "*rpm/Packages" -type f)

  if [[ -v lRPM_PACKAGE_DBS_ARR[@] ]] ; then
    check_for_csv_log "${S08_CSV_LOG}"

    write_log "[*] Found ${ORANGE}${#lRPM_PACKAGE_DBS_ARR[@]}${NC} RPM package management directories." "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lRPM_PACKAGE_DBS_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPACKAGE_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lRPM_PACKAGE_DBS_ARR[@]}${NC} RPM package management directories." "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lRPM_PACKAGE_DBS_ARR[@]}" ; do
      lMD5_CHECKSUM="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lPACKAGE_FILE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lPACKAGE_FILE}" | awk '{print $1}')"

      lRPM_DIR="$(dirname "${lPACKAGE_FILE}" || true)"
      # not sure this works on an offline system - we need further tests on this:
      mapfile -t lRPM_PACKAGES_ARR < <(rpm -qa --dbpath "${lRPM_DIR}" || print_error "[-] Failed to identify RPM packages in ${lRPM_DIR}")
      for lPACKAGE_AND_VERSION in "${lRPM_PACKAGES_ARR[@]}" ; do
        write_log "[*] Testing RPM directory ${lRPM_DIR} with PACKAGE_AND_VERSION: ${lPACKAGE_AND_VERSION}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        lPACKAGE_VERSION=$(rpm -qi --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" | grep "^Version" || true)
        lPACKAGE_VERSION="${lPACKAGE_VERSION/*:\ }"
        lPACKAGE_VERSION=$(clean_package_details "${lPACKAGE_VERSION}")

        lPACKAGE_NAME=$(rpm -qi --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" | grep "^Name" || true)
        lPACKAGE_NAME="${lPACKAGE_NAME/*:\ }"
        lPACKAGE_NAME=$(clean_package_details "${lPACKAGE_NAME}")

        # just for output the details
        rpm -qi --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" || true

        if [[ -z "${lPACKAGE_NAME}" ]]; then
          continue
        fi

        lAPP_VENDOR="${lPACKAGE_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lPACKAGE_NAME}:${lPACKAGE_VERSION}:*:*:*:*:*:*"

        write_log "[*] RPM package details: ${ORANGE}${lPACKAGE_NAME}${NC} - ${ORANGE}${lPACKAGE_VERSION:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lRPM_DIR} / ${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lPACKAGE_NAME}" "${lPACKAGE_VERSION}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${lAPP_DESC}"
        lPOS_RES=1
      done
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No RPM packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No RPM package management database found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] RPM package managment database SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No RPM package management database SBOM results available"
  fi
}

clean_package_details() {
  local lCLEAN_ME_UP="${1}"

  lCLEAN_ME_UP=$(safe_echo "${lCLEAN_ME_UP}" | tr -dc '[:print:]')
  lCLEAN_ME_UP=${lCLEAN_ME_UP/\"}
  # Turn on extended globbing
  shopt -s extglob
  lCLEAN_ME_UP=${lCLEAN_ME_UP//+([\[\'\"\(\)\]])}
  lCLEAN_ME_UP=${lCLEAN_ME_UP##+( )}
  lCLEAN_ME_UP=${lCLEAN_ME_UP%%+( )}
  # Turn off extended globbing
  shopt -u extglob
  lCLEAN_ME_UP=${lCLEAN_ME_UP,,}
  lCLEAN_ME_UP=${lCLEAN_ME_UP//,/ }
  echo "${lCLEAN_ME_UP}"
}

clean_package_versions() {
  local lVERSION="${1:-}"
  local STRIPPED_VERSION=""

  # usually we get a version like 1.2.3-4 or 1.2.3-0kali1bla or 1.2.3-unknown
  # this is a quick approach to clean this version identifier
  # there is a lot of room for future improvement
  STRIPPED_VERSION=$(safe_echo "${lVERSION}" | sed -r 's/-[0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-unknown$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+kali[0-9]+.*$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+ubuntu[0-9]+.*$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+build[0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+\.[0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+\.[a-d][0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/:[0-9]:/:/g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/^[0-9]://g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | tr -dc '[:print:]')
  STRIPPED_VERSION=${STRIPPED_VERSION//,\ /\.}
  echo "${STRIPPED_VERSION}"
}
