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

S08_submodule_openwrt_pkg_mgmt_parser() {
  local lPACKAGING_SYSTEM="OpenWRT"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "OpenWRT package management identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPACKAGE_FILE=""
  local lAPP_NAME=""
  local lAPP_VERS=""
  local lAPP_LIC="NA"
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lAPP_DEPS_ARR=()
  local lAPP_DEP=""
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lOPENWRT_MGMT_CONTROL_ARR=()
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lOPENWRT_MGMT_CONTROL_ARR < <(grep "opkg/info/.*.control" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lOPENWRT_MGMT_CONTROL_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lOPENWRT_MGMT_CONTROL_ARR[@]}${NC} OpenWRT package management files." "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lOPENWRT_MGMT_CONTROL_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPACKAGE_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lOPENWRT_MGMT_CONTROL_ARR[@]}${NC} OpenWRT package management files." "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lPACKAGE_FILE in "${lOPENWRT_MGMT_CONTROL_ARR[@]}" ; do
      # echo "lPACKAGE_FILE: ${lPACKAGE_FILE}"
      if ! [[ -f "${lPACKAGE_FILE}" ]]; then
        print_output "[-] WARNING: ${FUNCNAME[0]} - package file ${lPACKAGE_FILE} not available ... skipping"
      fi
      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lPACKAGE_FILE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      if grep -q "Package: " "${lPACKAGE_FILE}"; then
        lMD5_CHECKSUM="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPACKAGE_FILE}" | awk '{print $1}')"

        lAPP_NAME=$(grep "^Package: " "${lPACKAGE_FILE}" | awk '{print $2}' || true)
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_VERS=$(grep "^Version: " "${lPACKAGE_FILE}" | awk '{print $2}' || true)
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lAPP_MAINT=$(grep "^Maintainer: " "${lPACKAGE_FILE}" | cut -d ':' -f2- || true)
        lAPP_MAINT=${lAPP_MAINT#\ }
        lAPP_MAINT=${lAPP_MAINT//[![:print:]]/}
        # lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")
        # lAPP_MAINT=$(clean_package_versions "${lAPP_MAINT}")

        lAPP_DESC=$(grep "^Description: " "${lPACKAGE_FILE}" | cut -d ':' -f2- || true)
        lAPP_DESC=${lAPP_DESC#\ }
        lAPP_DESC=$(clean_package_details "${lAPP_DESC}")
        lAPP_DESC=$(clean_package_versions "${lAPP_DESC}")

        mapfile -t lAPP_DEPS_ARR < <(grep "^Depends: " "${lPACKAGE_FILE}" | cut -d ':' -f2- | tr ',' '\n' | sort -u || true)

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="openwrt"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "opkg" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
        local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS}"

        # add the python requirement path information to our properties array:
        # Todo: in the future we should check for the package, package hashes and which files
        # are in the package
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lPACKAGE_FILE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
        lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
        lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
        lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

        if [[ "${#lAPP_DEPS_ARR[@]}" -gt 0 ]]; then
          for lAPP_DEP in "${lAPP_DEPS_ARR[@]}"; do
            lAPP_DEP=${lAPP_DEP//[![:print:]]/}
            lPROP_ARRAY_INIT_ARR+=( "dependency:${lAPP_DEP#\ }" )
          done
        fi

        # if we have the list file also we can add all the paths provided by the package
        if [[ -f "${lPACKAGE_FILE/\.control/\.list}" ]]; then
          # echo "lPACKAGE_FILE: ${lPACKAGE_FILE} / ${lPACKAGE_FILE/\.control/\.list}"
          local lPKG_LIST_ENTRY=""
          local lCNT=0
          while IFS= read -r lPKG_LIST_ENTRY; do
            lCNT=$((lCNT+1))
            lPROP_ARRAY_INIT_ARR+=( "path:${lPKG_LIST_ENTRY}" )
            # we limit the logging of the package files to 500 files per package
            if [[ "${lCNT}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
              lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
              break
            fi
          done < "${lPACKAGE_FILE/\.control/\.list}"
        fi

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lPACKAGE_FILE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
          write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

        write_log "[*] OpenWRT package details: ${ORANGE}${lPACKAGE_FILE}${NC} - ${ORANGE}${lAPP_NAME}${NC} - ${ORANGE}${lAPP_VERS}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
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
