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

S08_submodule_python_poetry_lock_parser() {
  local lPACKAGING_SYSTEM="python_poetry_lock"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Python poetry lock identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPY_LCK_ARCHIVES_ARR=()
  local lPY_LCK_ARCHIVE=""
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
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"
  local lAPP_FILES_ARR=()
  local lPOETRY_FILE_ENTRY=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lPY_LCK_ARCHIVES_ARR < <(grep "poetry.lock" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lPY_LCK_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
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
      if [[ ! "${lR_FILE}" == *"text"* ]]; then
        continue
      fi

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPY_LCK_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lPY_LCK_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      lSHA512_CHECKSUM="$(sha512sum "${lPY_LCK_ARCHIVE}" | awk '{print $1}')"
      lMD5_CHECKSUM="$(md5sum "${lPY_LCK_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lPY_LCK_ARCHIVE}" | awk '{print $1}')"

      # source file:
      # [[package]]
      # name = "wheel"
      # version = "0.43.0"
      # description = "A built-package format for Python"
      # optional = false
      # python-versions = ">=3.8"
      # files = [
      #     {file = "wheel-0.43.0-py3-none-any.whl", hash = "sha256:55c570405f142630c6b9f72fe09d9b67cf1477fcf543ae5b8dcb1f5b7377da81"},
      #     {file = "wheel-0.43.0.tar.gz", hash = "sha256:465ef92c69fa5c5da2d1cf8ac40559a8c940886afcef87dcf14b9470862f1d85"},
      # ]
      sed ':a;N;$!ba;s/\"\n/\"|/g' "${lPY_LCK_ARCHIVE}" | sed 's/.*files = //g' | sed ':a;N;$!ba;s/,\n/ -/g' | sed ':a;N;$!ba;s/\n\[\n/|/g' | grep "^name" > "${TMP_DIR}/poetry.lock.tmp" || true
      # results in
      # name = "zipp"|version = "3.17.0"|description = "Backport of pathlib-compatible object wrapper for zip files"|optional = false|    {file = "zipp-3.17.0-py3-none-any.whl", hash = "sha256:0e923e726174922dce09c53c59ad483ff7bbb8e572e00c7f7c46b88556409f31"} -    {file = "zipp-3.17.0.tar.gz", hash = "sha256:84e64a1c28cf7e91ed2078bb8cc8c259cb19b76942096c8d7b84947690cabaf0"} -]

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

        mapfile -t lAPP_FILES_ARR < <(echo "${lPOETRY_ENTRY}" | cut -d\| -f5 | sed 's/ - /\n/g')

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pypi" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

        local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # Todo: checksum

        # add deb path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lPY_LCK_ARCHIVE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
        lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
        lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
        lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

        local lCNT=0
        for lPOETRY_FILE_ENTRY in "${lAPP_FILES_ARR[@]}"; do
          lPOETRY_FILE_ENTRY=$(echo "${lPOETRY_FILE_ENTRY}" | cut -d '"' -f2)
          lPROP_ARRAY_INIT_ARR+=( "path:${lPOETRY_FILE_ENTRY}" )
          # we limit the logging of the package files to 500 files per package
          if [[ "${lCNT}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
            lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
            break
          fi
        done

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lPY_LCK_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
          write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

        write_log "[*] Python poetry.lock archive details: ${ORANGE}${lPY_LCK_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPY_LCK_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH:-NA}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
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

