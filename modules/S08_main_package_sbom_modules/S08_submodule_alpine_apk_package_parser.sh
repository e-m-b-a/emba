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

S08_submodule_alpine_apk_package_parser() {
  local lPACKAGING_SYSTEM="alpine_apk"
  local lOS_IDENTIFIED="${1:-}"

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
  local lPURL_IDENTIFIER="NA"
  local lAPK_FILES_ARR=()
  local lAPK_FILE=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  # mapfile -t lAPK_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.apk" -type f)
  mapfile -t lAPK_ARCHIVES_ARR < <(grep "\.apk;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lAPK_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
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

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lAPK_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lAPK_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      if ! [[ -d "${TMP_DIR}"/apk ]]; then
        mkdir "${TMP_DIR}"/apk || true
      fi
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

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="generic"
      fi
      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "apk" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

      local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

      # add deb path information to our properties array:
      local lPROP_ARRAY_INIT_ARR=()
      lPROP_ARRAY_INIT_ARR+=( "source_path:${lAPK_ARCHIVE}" )
      lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
      lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
      lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
      lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

      mapfile -t lAPK_FILES_ARR < <(find "${TMP_DIR}"/apk)
      # add package files to properties
      if [[ "${#lAPK_FILES_ARR[@]}" -gt 0 ]]; then
        for lAPK_FILE_ID in "${!lAPK_FILES_ARR[@]}"; do
          lAPK_FILE="${lAPK_FILES_ARR["${lAPK_FILE_ID}"]}"
          lPROP_ARRAY_INIT_ARR+=( "path:${lAPK_FILE#*apk}" )
          # we limit the logging of the package files to 500 files per package
          if [[ "${lAPK_FILE_ID}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
            lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
            break
          fi
        done
      fi

      build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

      # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
      # final array with all hash values
      if ! build_sbom_json_hashes_arr "${lAPK_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
        write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
        continue
      fi

      # create component entry - this allows adding entries very flexible:
      build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

      write_log "[*] Alpine apk archive details: ${ORANGE}${lAPK_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lAPK_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
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

