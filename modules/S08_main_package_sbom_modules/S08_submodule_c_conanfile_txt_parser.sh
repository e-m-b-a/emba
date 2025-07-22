#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2025-2025 Siemens Energy AG
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

S08_submodule_c_conanfile_txt_parser() {
  local lPACKAGING_SYSTEM="conanfile_txt"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "C/C++ conanfile.txt identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lCONAN_ARCHIVES_ARR=()
  local lCONAN_ARCHIVE=""
  local lC_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS=""
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lCONAN_ARCHIVES_ARR < <(grep "conanfile.txt" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lCONAN_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lCONAN_ARCHIVES_ARR[@]}${NC} C/C++ conanfile.txt package files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lCONAN_ARCHIVE in "${lCONAN_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lCONAN_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lCONAN_ARCHIVES_ARR[@]}${NC} Rust Cargo.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lCONAN_ARCHIVE in "${lCONAN_ARCHIVES_ARR[@]}" ; do
      lC_FILE=$(file "${lCONAN_ARCHIVE}")
      if [[ ! "${lC_FILE}" == *"ASCII text"* ]]; then
        continue
      fi
      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lCONAN_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lCONAN_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )
      # we start with the following file structure:
      # [requires]
      # zlib/1.2.11
      # poco/[>1.0 <1.9]
      # mylib/1.16.0@demo/testing
      #
      # [tool_requires]
      # cmake/3.22.6
      #
      # [generators]
      # CMakeDeps
      # CMakeToolchain
      #
      # and we build something like this
      # [requires]ASDFzlib/1.2.11ASDFpoco/[>1.0 <1.9]ASDFboost/1.70.0#revision2ASDFmylib/1.16.0@demo/testing
      # [tool_requires]ASDFcmake/3.22.6
      # [generators]ASDFCMakeDepsASDFCMakeToolchainASDF

      mapfile -t lCONAN_PKG_ARR < <(sed ':a;N;$!ba;s/\n/ASDF/g' "${lCONAN_ARCHIVE}" | sed 's/ASDFASDF/\n/g' | grep -E "\[(tool_)?requires\]" | sed 's/ASDF/\n/g')

      lMD5_CHECKSUM="$(md5sum "${lCONAN_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lCONAN_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lCONAN_ARCHIVE}" | awk '{print $1}')"

      for lCONAN_ENTRY in "${lCONAN_PKG_ARR[@]}"; do
        # on requires entries we skip them, all others are requirements
        if [[ "${lCONAN_ENTRY}" == *"[requires]"* ]]; then
          # we found relevant entries
          continue
        elif [[ "${lCONAN_ENTRY}" == *"[tool_requires]"* ]]; then
          continue
        fi
        lAPP_NAME=${lCONAN_ENTRY/\/*}
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_LIC="NA"

        lAPP_VERS=$(echo "${lCONAN_ENTRY}" | cut -d '/' -f2-)
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "conan" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

        local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # add deb path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lCONAN_ARCHIVE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
        lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
        lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lCONAN_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM:-NA}" "${S08_DUPLICATES_LOG}"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

        write_log "[*] Rust Cargo.lock archive details: ${ORANGE}${lCONAN_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lCONAN_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No C/C++ conanfile.txt found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No C/C++ conanfile.txt found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] C/C++ conanfile.txt SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No C/C++ conanfile.tx SBOM results available"
  fi
}
