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

S08_submodule_ruby_gem_archive_parser() {
  local lPACKAGING_SYSTEM="ruby_gem"
  local lOS_IDENTIFIED="${1:-}"

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
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"
  local lGEM_FILES_ARR=()
  local lGEM_FILE=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lGEM_ARCHIVES_ARR < <(grep "\.gem;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lGEM_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
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

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lGEM_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lGEM_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      if ! [[ -d "${TMP_DIR}"/gems ]]; then
        mkdir "${TMP_DIR}"/gems || true
      fi
      tar -x -f "${lGEM_ARCHIVE}" -C "${TMP_DIR}"/gems || print_error "[-] Extraction of Ruby gem file ${lGEM_ARCHIVE} failed"
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

      # grep -A1 "^version: " metadata | grep "[0-9]\."
      lAPP_VERS=$(grep -A1 '^version' "${TMP_DIR}"/gems/metadata | grep "[0-9]" || true)
      lAPP_VERS=${lAPP_VERS/*version:\ }
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lSHA256_CHECKSUM="$(sha256sum "${lGEM_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lGEM_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="generic"
      fi
      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "gem" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

      local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

      # add deb path information to our properties array:
      local lPROP_ARRAY_INIT_ARR=()
      lPROP_ARRAY_INIT_ARR+=( "source_path:${lGEM_ARCHIVE}" )
      lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
      lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
      lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
      lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

      # add package files to properties
      if [[ -f "${TMP_DIR}/gems/data.tar.gz" ]]; then
        mapfile -t lGEM_FILES_ARR < <(tar -tvf "${TMP_DIR}/gems/data.tar.gz" | awk '{print $6}' || print_error "[-] Extraction of Ruby gem file ${lGEM_ARCHIVE} failed")
        for lGEM_FILE_ID in "${!lGEM_FILES_ARR[@]}"; do
          lGEM_FILE="${lGEM_FILES_ARR["${lGEM_FILE_ID}"]}"
          lPROP_ARRAY_INIT_ARR+=( "path:${lGEM_FILE#\.}" )
          # we limit the logging of the package files to 500 files per package
          if [[ "${lGEM_FILE_ID}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
            lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
            break
          fi
        done
      fi

      build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

      # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
      # final array with all hash values
      if ! build_sbom_json_hashes_arr "${lGEM_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
        write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
        continue
      fi

      # create component entry - this allows adding entries very flexible:
      build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

      write_log "[*] Ruby gems archive details: ${ORANGE}${lGEM_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lGEM_ARCHIVE}" "${lPKG_MD5:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
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

