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

S08_submodule_rust_cargo_lock_parser() {
  local lPACKAGING_SYSTEM="rust_cargo_lock"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Rust cargo lock identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lRST_ARCHIVES_ARR=()
  local lRST_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS=""
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lAPP_SOURCE="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lRST_ARCHIVES_ARR < <(grep "Cargo.lock" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lRST_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
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
      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lRST_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lRST_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )
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

        lAPP_SOURCE=$(echo "${lCARGO_ENTRY}" | cut -d\| -f3)
        lAPP_SOURCE=${lAPP_SOURCE/source\ =\ }
        lAPP_SOURCE=$(clean_package_details "${lAPP_SOURCE}")
        lAPP_SOURCE=$(clean_package_versions "${lAPP_SOURCE}")
        # lAPP_SOURCE should be added to the properties: name: EMBA:cargo:source

        lSHA256_CHECKSUM=$(echo "${lCARGO_ENTRY}" | cut -d\| -f4)
        lSHA256_CHECKSUM=${lSHA256_CHECKSUM/checksum\ =\ }
        lSHA256_CHECKSUM=$(clean_package_details "${lSHA256_CHECKSUM}")
        lSHA256_CHECKSUM=$(clean_package_versions "${lSHA256_CHECKSUM}")

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "cargo" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

        local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # add deb path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lRST_ARCHIVE}" )
        lPROP_ARRAY_INIT_ARR+=( "source:${lAPP_SOURCE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
        lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
        lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        export HASHES_ARR=()
        local lHASHES_ARRAY_INIT=("alg=SHA-256")
        lHASHES_ARRAY_INIT+=("content=${lSHA256_CHECKSUM}")
        HASHES_ARR+=( "$(jo "${lHASHES_ARRAY_INIT[@]}")" )

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

        write_log "[*] Rust Cargo.lock archive details: ${ORANGE}${lRST_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lRST_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
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
