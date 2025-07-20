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

S08_submodule_bsd_package_parser() {
  # └─$ file boost-libs-1.84.0.pkg
  #     boost-libs-1.84.0.pkg: Zstandard compressed data (v0.8+), Dictionary ID: None
  # tar --zstd -x -f ./boost-libs-1.84.0.pkg +COMPACT_MANIFEST
  local lPACKAGING_SYSTEM="freebsd_pkg"
  local lOS_IDENTIFIED="${1:-}"

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
  local lAPP_DEPS_ARR=()
  local lPKG_DEP_ID=""
  local lAPP_DEP=""
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"
  local lPKG_FILES_ARR=()
  local lPKG_FILE=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  # mapfile -t lPKG_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.pkg" -type f)
  mapfile -t lPKG_ARCHIVES_ARR < <(grep "\.pkg;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lPKG_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
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

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPKG_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lPKG_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

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

      lAPP_ARCH=$(jq -cr '.arch' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")

      lAPP_MAINT=$(jq -cr '.maintainer' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")

      lAPP_DESC=$(jq -cr '.comment' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_DESC=$(clean_package_details "${lAPP_DESC}")

      lAPP_LIC=$(jq -cr '.licenses' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lAPP_VERS=$(jq -r '.version' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      mapfile -t lAPP_DEPS_ARR < <(jq -r '.deps[].origin' "${TMP_DIR}"/+COMPACT_MANIFEST || true)

      # └─$ jq -r '.deps'  /home/m1k3/Downloads/pkg_tmp/+COMPACT_MANIFEST
      # {
      #   "icu": {
      #     "origin": "devel/icu",
      #     "version": "74.2_1,1"
      #   }
      # }

      lMD5_CHECKSUM="$(md5sum "${lPKG_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lPKG_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lPKG_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="generic"
      fi
      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pkg" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

      local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

      # add deb path information to our properties array:
      local lPROP_ARRAY_INIT_ARR=()
      lPROP_ARRAY_INIT_ARR+=( "source_path:${lPKG_ARCHIVE}" )
      lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
      lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
      lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
      lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

      if ! [[ -d "${TMP_DIR}"/pkg_tmp ]]; then
        mkdir "${TMP_DIR}"/pkg_tmp || true
      fi

      tar --zstd -x -f "${lPKG_ARCHIVE}" -C "${TMP_DIR}"/pkg_tmp || print_error "[-] Extraction of FreeBSD package file ${lPKG_ARCHIVE} failed"

      mapfile -t lPKG_FILES_ARR < <(find "${TMP_DIR}"/pkg_tmp)
      # add package files to properties
      if [[ "${#lPKG_FILES_ARR[@]}" -gt 0 ]]; then
        for lPKG_FILE_ID in "${!lPKG_FILES_ARR[@]}"; do
          lPKG_FILE="${lPKG_FILES_ARR["${lPKG_FILE_ID}"]}"
          lPROP_ARRAY_INIT_ARR+=( "path:${lPKG_FILE#*pkg_tmp}" )
          # we limit the logging of the package files to 500 files per package
          if [[ "${lPKG_FILE_ID}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
            lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
            break
          fi
        done
      fi

      # Add dependencies to properties
      for lPKG_DEP_ID in "${!lAPP_DEPS_ARR[@]}"; do
        lAPP_DEP="${lAPP_DEPS_ARR["${lPKG_DEP_ID}"]}"
        lPROP_ARRAY_INIT_ARR+=( "dependency:${lAPP_DEP#\ }" )
      done

      [[ -d "${TMP_DIR}"/pkg_tmp ]] && rm -rf "${TMP_DIR}"/pkg_tmp

      build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

      # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
      # final array with all hash values
      if ! build_sbom_json_hashes_arr "${lPKG_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
        write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
        continue
      fi

      # create component entry - this allows adding entries very flexible:
      build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

      write_log "[*] FreeBSD pkg archive details: ${ORANGE}${lPKG_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lPKG_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
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
