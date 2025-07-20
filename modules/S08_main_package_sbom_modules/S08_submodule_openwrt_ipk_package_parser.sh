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

# Description:  Searches known locations for package management information
# shellcheck disable=SC2094

S08_submodule_openwrt_ipk_package_parser() {
  # └─$ tar zxpf package.ipk --directory dirname
  # └─$ tar xvf control.tar.xz
  # └─$ cat control
  #
  #
  # Package: downloadmaster
  # Architecture: mipsel
  # Priority: optional
  # Section: net
  # Version: 3.1.0.78
  # OptionalUtility: 1.0.0.1+
  # Maintainer: ASUS
  # Source: http://127.0.0.1/
  # URL: http://www.asusnetwork.net:8081/downloadmaster/index.asp
  # Description: Download tools
  # Depends:  asuslighttpd,wxbase,readline
  # Suggests:
  # Conflicts:
  # Enabled: yes

  local lPACKAGING_SYSTEM="openwrt_ipk_pkg"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "OpenWrt ipk package parser" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lIPK_ARCHIVES_ARR=()
  local lIPK_ARCHIVE=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""
  local lPOS_RES=0

  mapfile -t lIPK_ARCHIVES_ARR < <(grep "\.ipk;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lIPK_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lIPK_ARCHIVES_ARR[@]}${NC} OpenWRT ipk files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lIPK_ARCHIVE in "${lIPK_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lIPK_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lIPK_ARCHIVES_ARR[@]}${NC} OpenWRT ipk files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lIPK_ARCHIVE in "${lIPK_ARCHIVES_ARR[@]}" ; do
      ipk_package_parser_threader "${lPACKAGING_SYSTEM}" "${lOS_IDENTIFIED}" "${lIPK_ARCHIVE}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S08_ARR_LCK+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_ARR_LCK
      lPOS_RES=1
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No OpenWRT ipk archives found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No OpenWRT ipk archives found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  wait_for_pid "${lWAIT_PIDS_S08_ARR_LCK[@]}"
  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] OpenWRT IPK archives SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No OpenWRT archives SBOM results available"
  fi
}

ipk_package_parser_threader() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lOS_IDENTIFIED="${2:-}"
  local lIPK_ARCHIVE="${3:-}"

  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS=""
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM=""
  local lSHA256_CHECKSUM=""
  local lSHA512_CHECKSUM=""
  local lPURL_IDENTIFIER="NA"
  local lIPK_FILES_ARR=()
  local lIPK_FILE_ID=""
  local lIPK_FILE=""
  local lAPP_DEPS_ARR=()
  local lIPK_DEP_ID=""
  local lAPP_DEP=""

  lR_FILE=$(file "${lIPK_ARCHIVE}")
  if [[ ! "${lR_FILE}" == *"gzip"* ]]; then
    return
  fi

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  lPKG_MD5="$(md5sum "${lIPK_ARCHIVE}" | awk '{print $1}')"
  if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
    print_output "[*] ${ORANGE}${lIPK_ARCHIVE}${NC} already analyzed" "no_log"
    return
  fi
  lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

  local lIPK_LOG_PATH="${TMP_DIR}/ipk_package_${lPKG_MD5}"
  if ! [[ -d "${lIPK_LOG_PATH}" ]]; then
    mkdir "${lIPK_LOG_PATH}" || true
  fi
  tar zxpf "${lIPK_ARCHIVE}" -C "${lIPK_LOG_PATH}" || print_error "[-] Extraction error for OpenWRT archive ${lIPK_ARCHIVE}"

  if [[ -f "${lIPK_LOG_PATH}/control.tar.gz" ]]; then
    tar zxpf "${lIPK_LOG_PATH}/control.tar.gz" -C "${lIPK_LOG_PATH}" || print_error "[-] Can't process ${lIPK_ARCHIVE}"
  else
    write_log "[-] No OpenWRT control.tar.gz found for ${lIPK_ARCHIVE}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    return
  fi

  if [[ ! -f "${lIPK_LOG_PATH}/control" ]]; then
    write_log "[-] No OpenWRT control extracted for ${lIPK_ARCHIVE}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    return
  fi

  lAPP_NAME=$(grep "Package: " "${lIPK_LOG_PATH}/control" || true)
  lAPP_NAME=${lAPP_NAME/*:\ }
  lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

  lAPP_ARCH=$(grep "Architecture: " "${lIPK_LOG_PATH}/control" || true)
  lAPP_ARCH=${lAPP_ARCH/*:\ }
  lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")

  lAPP_MAINT=$(grep "Maintainer: " "${lIPK_LOG_PATH}/control" || true)
  lAPP_MAINT=${lAPP_MAINT/*:\ }
  lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")

  lAPP_DESC=$(grep "Description: " "${lIPK_LOG_PATH}/control" || true)
  lAPP_DESC=${lAPP_DESC/*:\ }
  lAPP_DESC=$(clean_package_details "${lAPP_DESC}")

  lAPP_LIC=$(grep "License: " "${lIPK_LOG_PATH}/control" || true)
  lAPP_LIC=${lAPP_LIC/*:\ }
  lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

  lAPP_VERS=$(grep "Version: " "${lIPK_LOG_PATH}/control" || true)
  lAPP_VERS=${lAPP_VERS/*:\ }
  lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
  lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

  mapfile -t lAPP_DEPS_ARR < <(grep "Depends: " "${lIPK_LOG_PATH}/control" | sed 's/Depends: //' | tr ',' '\n' | sed 's/\.\ /\n/g' | sort -u || true)

  lMD5_CHECKSUM="$(md5sum "${lIPK_ARCHIVE}" | awk '{print $1}')"
  lSHA256_CHECKSUM="$(sha256sum "${lIPK_ARCHIVE}" | awk '{print $1}')"
  lSHA512_CHECKSUM="$(sha512sum "${lIPK_ARCHIVE}" | awk '{print $1}')"

  lAPP_VENDOR="${lAPP_NAME}"
  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

  if [[ -z "${lOS_IDENTIFIED}" ]]; then
    lOS_IDENTIFIED="openwrt-based"
  fi
  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "deb" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
  local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

  # add deb path information to our properties array:
  local lPROP_ARRAY_INIT_ARR=()
  lPROP_ARRAY_INIT_ARR+=( "source_path:${lIPK_ARCHIVE}" )
  lPROP_ARRAY_INIT_ARR+=( "source_arch:${lAPP_ARCH}" )
  lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
  lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
  lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
  lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

  # Add dependencies to properties
  for lIPK_DEP_ID in "${!lAPP_DEPS_ARR[@]}"; do
    lAPP_DEP="${lAPP_DEPS_ARR["${lIPK_DEP_ID}"]}"
    lPROP_ARRAY_INIT_ARR+=( "dependency:${lAPP_DEP#\ }" )
  done

  # add package files to properties
  if [[ -f "${lIPK_LOG_PATH}/data.tar.xz" ]]; then
    mapfile -t lIPK_FILES_ARR < <(tar -tvf "${lIPK_LOG_PATH}/data.tar.xz" | awk '{print $6}')
    for lIPK_FILE_ID in "${!lIPK_FILES_ARR[@]}"; do
      lIPK_FILE="${lIPK_FILES_ARR["${lIPK_FILE_ID}"]}"
      lPROP_ARRAY_INIT_ARR+=( "path:${lIPK_FILE#\.}" )
      # we limit the logging of the package files to 500 files per package
      if [[ "${lIPK_FILE_ID}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
        lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
        break
      fi
    done
  fi

  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
  # final array with all hash values
  if ! build_sbom_json_hashes_arr "${lIPK_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
    write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
    return
  fi

  # create component entry - this allows adding entries very flexible:
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

  write_log "[*] OpenWRT ipk package details: ${ORANGE}${lIPK_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  write_csv_log "${lPACKAGING_SYSTEM}" "${lIPK_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
  lPOS_RES=1
  rm -r "${lIPK_LOG_PATH}" || true
}
