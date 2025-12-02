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

# Description:  Searches for Siemens Sinamics VERSIONS.XML files and builds needed SBOM details
# shellcheck disable=SC2094

S08_submodule_sinamics_version_xml_parser() {
  local lPACKAGING_SYSTEM="sinamics_version_xml"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Siemens Sinamics VERSIONS.XML identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lXMLLINT_OPTS_ARR=()
  lXMLLINT_OPTS_ARR+=("--noent" "--recover" "--nonet")

  local lVERSION_XML_ARR=()
  local lVERSION_XML_FILE=""

  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
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
  local lXML_CHECKED_ARR=()
  local lXML_MD5=""

  mapfile -t lVERSION_XML_ARR < <(grep "VERSIONS\.XML;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lVERSION_XML_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lVERSION_XML_ARR[@]}${NC} Sinamics VERSIONS.XML files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lVERSION_XML_FILE in "${lVERSION_XML_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lVERSION_XML_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lVERSION_XML_ARR[@]}${NC} Sinamics VERSIONS.XML files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lVERSION_XML_FILE in "${lVERSION_XML_ARR[@]}"; do
      lR_FILE=$(file -b "${lVERSION_XML_FILE}")
      if [[ ! "${lR_FILE}" == *"XML"* ]]; then
        # print_output "[!] NOT Testing ${lVERSION_XML_FILE} - ${lR_FILE}"
        continue
      fi
      # print_output "[*] Testing ${lVERSION_XML_FILE} - ${lR_FILE}"

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lXML_MD5="$(md5sum "${lVERSION_XML_FILE}" | awk '{print $1}')"
      if [[ "${lXML_CHECKED_ARR[*]}" == *"${lXML_MD5}"* ]]; then
        print_output "[*] Sinamics ${ORANGE}${lVERSION_XML_FILE}${NC} already analyzed" "no_log"
        continue
      fi
      lXML_CHECKED_ARR+=( "${lXML_MD5}" )

      if ! validate_xml "${lVERSION_XML_FILE}"; then
        continue
      fi

      lXML_CHECK=$(xmllint "${lXMLLINT_OPTS_ARR[@]}" --xpath versions/Component/FirmwareBasis/ComponentContainer "${lVERSION_XML_FILE}" 2>/dev/null | grep -c "<Component category=")
      # print_output "[*] Identified ${lXML_CHECK} XML nodes" "no_log"
      [[ "${lXML_CHECK}" -lt 1 ]] && continue

      for lCNT in $(seq "${lXML_CHECK}"); do
        # print_output "[*] Testing XML node: ${lCNT}" "no_log"
        lAPP_NAME=$(xmllint "${lXMLLINT_OPTS_ARR[@]}" --xpath versions/Component/FirmwareBasis/ComponentContainer/Component["${lCNT}"] "${lVERSION_XML_FILE}" 2>/dev/null | grep "\<Component\ category=\"" | cut -d '"' -f2 || true)
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
        [[ -z "${lAPP_NAME}" ]] && continue

        lAPP_VERS=$(xmllint "${lXMLLINT_OPTS_ARR[@]}" --xpath versions/Component/FirmwareBasis/ComponentContainer/Component["${lCNT}"]/IntVersion//text\(\) "${lVERSION_XML_FILE}" 2>/dev/null || true)
        if [[ -z "${lAPP_VERS}" ]]; then
          lAPP_VERS=$(xmllint "${lXMLLINT_OPTS_ARR[@]}" --xpath versions/Component/FirmwareBasis/ComponentContainer/Component["${lCNT}"]/ExtVersion//text\(\) "${lVERSION_XML_FILE}" 2>/dev/null || true)
        fi
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")
        [[ -z "${lAPP_VERS}" ]] && continue

        lMD5_CHECKSUM="$(md5sum "${lVERSION_XML_FILE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lVERSION_XML_FILE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lVERSION_XML_FILE}" | awk '{print $1}')"

        lAPP_VENDOR="Siemens"
        lAPP_MAINT="${lAPP_VENDOR}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="Sinamics"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "sinamics" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${ARCH:-NA}")

        local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # add path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lVERSION_XML_FILE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
        lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
        lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
        lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lVERSION_XML_FILE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
          write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

        write_log "[*] Siemens Sinamics VERSIONS.XML details: ${ORANGE}${lVERSION_XML_FILE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lVERSION_XML_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done
    done
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Siemens Sinamics VERSIONS.XML SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Siemens Sinamics VERSIONS.XML SBOM results available"
  fi
}

