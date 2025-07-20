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

S08_submodule_java_archives_parser() {
  local lPACKAGING_SYSTEM="java_archive"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Java archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lJAVA_ARCHIVES_ARR=()
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
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lJAVA_ARCHIVES_ARR < <(grep "\.jar;\|\.war;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lJAVA_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
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

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lJAVA_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      # the complete naming in the manifest files is a big mess
      # probably we need some dictionary to parse the names somehow and generate something
      # that is usable for CVE queries
      lAPP_NAME=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Application-Name" | head -1 || true)
      lAPP_NAME=${lAPP_NAME/*:\ /}

      lAPP_LIC=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "License" | head -1 || true)
      lAPP_LIC=${lAPP_LIC/*:\ /}
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lAPP_VENDOR_CLEAR=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Vendor: " | sort -u | head -1 || true)
      lAPP_VENDOR_CLEAR=${lAPP_VENDOR_CLEAR#*:\ }
      lAPP_VENDOR_CLEAR=${lAPP_VENDOR_CLEAR//[![:print:]]/}
      lAPP_VENDOR=$(clean_package_details "${lAPP_VENDOR_CLEAR}")
      # we need some translation:
      # e.g.: The Apache Software Foundation -> apache

      # we check for the deprecated vendor id:
      lAPP_VENDOR_ID=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Implementation-Vendor-Id: " | sort -u | head -1 || true)
      lAPP_VENDOR_ID=${lAPP_VENDOR_ID#*:\ }
      # we have seen some vendor ids like org.apache.shiro -> should end up in apache:shiro:version
      lAPP_VENDOR_ID=${lAPP_VENDOR_ID#org\.}
      lAPP_VENDOR_ID=${lAPP_VENDOR_ID#com\.}
      lAPP_VENDOR_ID=${lAPP_VENDOR_ID//\./:}
      lAPP_VENDOR_ID=$(clean_package_details "${lAPP_VENDOR_ID}")

      # alternative package names
      lIMPLEMENT_TITLE=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Implementation-Title" | head -1 || true)
      lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE#*:\ }
      lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE//\ }
      lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE//::/_}
      lIMPLEMENT_TITLE=$(clean_package_details "${lIMPLEMENT_TITLE}")
      lBUNDLE_NAME=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Bundle-Name:" | head -1 || true)
      lBUNDLE_NAME=${lBUNDLE_NAME#*:\ }
      lBUNDLE_NAME=${lBUNDLE_NAME//::/_}
      lBUNDLE_NAME=$(clean_package_details "${lBUNDLE_NAME}")

      lAPP_VERS=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Implementation-Version" | head -1 || true)
      lAPP_VERS=${lAPP_VERS#*:\ }
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")
      lAPP_VERS_ALT=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Bundle-Version" | head -1 || true)
      lAPP_VERS_ALT=${lAPP_VERS_ALT#*:\ }
      lAPP_VERS_ALT=$(clean_package_details "${lAPP_VERS_ALT}")
      lAPP_VERS_ALT=$(clean_package_versions "${lAPP_VERS_ALT}")

      lMD5_CHECKSUM="$(md5sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"

      if [[ -z "${lAPP_NAME}" && -n "${lIMPLEMENT_TITLE}" ]]; then
        # print_output "[*] Using lIMPLEMENT_TITLE (${lIMPLEMENT_TITLE}) as name for ${lJAVA_ARCHIVE}" "no_log"
        # in case APP_NAME is not set but we have an lIMPLEMENT_TITLE we use this
        lAPP_NAME="${lIMPLEMENT_TITLE}"
      fi
      if [[ -z "${lAPP_NAME}" && -n "${lBUNDLE_NAME}" ]]; then
        # print_output "[*] Using lBUNDLE_NAME (${lBUNDLE_NAME}) as name for ${lJAVA_ARCHIVE}" "no_log"
        # in case APP_NAME is not set but we have an lIMPLEMENT_TITLE we use this
        lAPP_NAME="${lBUNDLE_NAME}"
      fi
      if [[ -z "${lAPP_VERS}" && -n "${lAPP_VERS_ALT}" ]]; then
        # print_output "[*] Using lAPP_VERS_ALT (${lAPP_VERS_ALT}) as version for ${lJAVA_ARCHIVE}" "no_log"
        # in case APP_NAME is not set but we have an lIMPLEMENT_TITLE we use this
        lAPP_VERS="${lAPP_VERS_ALT}"
      fi

      local lPOM_XML=""
      lPOM_XML=$(unzip -l "${lJAVA_ARCHIVE}" | awk '{print $4}' | grep pom.xml || true)
      if [[ -n "${lPOM_XML}" ]]; then
        lAPP_VERS_POM_XML=$(unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" | xpath -e project/version//text\(\) 2>/dev/null)
        if [[ -z "${lAPP_VERS_POM_XML}" ]]; then
          # for the dependencies we can check for pom.xml
          write_log "============================================" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}-notes.txt"
          write_log "[*] Found pom.xml metadata in ${lJAVA_ARCHIVE}. Further dependency analysis is currently not supported" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}-notes.txt"
          write_log "[*] Please open an issue at https://github.com/e-m-b-a/emba/issues and provide the Java package" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}-notes.txt"
          write_log "[*] Further details:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}-notes.txt"
          unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" >> "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}-notes.txt"
          # We could do something like the following to extract the dependencies
            # unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" | xpath -e project/dependencies
            # unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" | xpath -e project/dependencies/dependency
            # unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" | xpath -e project/dependencies/dependency[1]/version
        elif [[ -z "${lAPP_VERS}" ]]; then
          # if we have extracted some version from pom.xml and we have not extracted something from META-INF/MANIFEST.MF
          # then we are going to use the pom.xml version
          # we have also seen multiple versions 1.2.3.release which we are going to cleanup a bit
          lAPP_VERS="${lAPP_VERS_POM_XML}"
          lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
          lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")
        fi
      fi

      if [[ -z "${lAPP_NAME}" ]]; then
        # last fallback -> we use the basename of the archive
        lAPP_NAME="$(basename -s .jar "${lJAVA_ARCHIVE}")"
      fi
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
      # if we have a vendor id but no app_vendor we are going to use the deprecated id:
      if [[ -z "${lAPP_VENDOR}" && -n "${lAPP_VENDOR_ID}" ]]; then
        # print_output "[*] Using lAPP_VENDOR_ID (${lAPP_VENDOR_ID}) as vendor for ${lJAVA_ARCHIVE}" "no_log"
        lAPP_VENDOR="${lAPP_VENDOR_ID}"
      fi
      if [[ -z "${lAPP_NAME}" && -z "${lAPP_LIC}" && -z "${lIMPLEMENT_TITLE}" && -z "${lAPP_VERS}" && -z "${lBUNDLE_NAME}" ]]; then
        # print_output "[-] skipping ... lJAVA_ARCHIVE: ${lJAVA_ARCHIVE} // lAPP_NAME: ${lAPP_NAME} / lAPP_LIC: ${lAPP_LIC} / lIMPLEMENT_TITLE: ${lIMPLEMENT_TITLE} / lAPP_VERS: ${lAPP_VERS} / lBUNDLE_NAME: ${lBUNDLE_NAME}" "no_log"
        continue
      fi
      lAPP_VERS="${lAPP_VERS/\.release}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="generic"
      fi
      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "java" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
      local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

      # add the python requirement path information to our properties array:
      # Todo: in the future we should check for the package, package hashes and which files
      # are in the package
      local lPROP_ARRAY_INIT_ARR=()
      lPROP_ARRAY_INIT_ARR+=( "source_path:${lJAVA_ARCHIVE}" )
      lPROP_ARRAY_INIT_ARR+=( "vendor_clear:${lAPP_VENDOR_CLEAR}" )
      lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
      lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
      lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
      lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

      build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

      # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
      # final array with all hash values
      if ! build_sbom_json_hashes_arr "${lJAVA_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
        write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
        continue
      fi

      # create component entry - this allows adding entries very flexible:
      build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_VENDOR:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

      write_log "[*] Java archive details: ${ORANGE}${lJAVA_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA} / ${lIMPLEMENT_TITLE:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lJAVA_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
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
