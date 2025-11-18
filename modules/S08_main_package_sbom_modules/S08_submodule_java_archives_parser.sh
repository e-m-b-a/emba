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
  export POS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""
  local lJ_JAVA_FILE_NAME=""
  local lPOM_CHECKED_ARR=()

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
      lJ_JAVA_FILE_NAME=$(basename "${lJAVA_ARCHIVE}")

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lJAVA_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      # Check the MANIFEST file
      if unzip -l "${lJAVA_ARCHIVE}" -- *META-INF/MANIFEST.MF &>/dev/null; then
        local lJAVA_MANIFEST_FILE="${LOG_PATH_MODULE}/Java_${lJ_JAVA_FILE_NAME}_MANIFEST.MF"
        unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF > "${lJAVA_MANIFEST_FILE}"
        if [[ -s "${lJAVA_MANIFEST_FILE}" ]]; then
          S08_java_manifest_handling "${lPACKAGING_SYSTEM}" "${lJAVA_ARCHIVE}" "${lJAVA_MANIFEST_FILE}"
        fi
      fi

      # check for pom.xml meta files
      if unzip -l "${lJAVA_ARCHIVE}" -- *pom.xml &>/dev/null ; then
        local lPOM_XML_ARR=()
        local lPOM_XML=""
        local lPOM_MD5=""
        # extract all the pom.xml meta files
        mapfile -t lPOM_XML_ARR < <(unzip -l "${lJAVA_ARCHIVE}" | awk '{print $4}' | grep pom.xml || true)
        if [[ "${#lPOM_XML_ARR[@]}" -gt 0 ]]; then
          write_log "[*] Found ${ORANGE}${#lPOM_XML_ARR[@]}${NC} Java pom.xml:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          for lPOM_XML in "${lPOM_XML_ARR[@]}" ; do
            write_log "$(indent "$(orange "$(print_path "${lPOM_XML}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          done

          write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          write_log "[*] Analyzing ${ORANGE}${#lPOM_XML_ARR[@]}${NC} Java pom.xml:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

          # lets analyse every pom.xml for versions and names:
          for lPOM_XML in "${lPOM_XML_ARR[@]}"; do
            local lJAVA_POM_XML_FILE="${LOG_PATH_MODULE}/Java_${lJ_JAVA_FILE_NAME}_POM_${RANDOM}.xml"
            unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" > "${lJAVA_POM_XML_FILE}"

            # if we have found multiple status files but all are the same -> we do not need to test duplicates
            lPOM_MD5="$(md5sum "${lJAVA_POM_XML_FILE}" | awk '{print $1}')"
            if [[ "${lPOM_CHECKED_ARR[*]}" == *"${lPOM_MD5}"* ]]; then
              print_output "[*] ${ORANGE}${lJAVA_POM_XML_FILE}${NC} already analyzed" "no_log"
              continue
            fi
            lPOM_CHECKED_ARR+=( "${lPOM_MD5}" )

            if [[ -s "${lJAVA_POM_XML_FILE}" ]]; then
              S08_java_pom_xml_handling "${lPACKAGING_SYSTEM}" "${lJAVA_ARCHIVE}" "${lJAVA_POM_XML_FILE}"
            fi
          done
        fi
      fi
    done

    if [[ "${POS_RES}" -eq 0 ]]; then
      write_log "[-] No JAVA packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No JAVA package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  # our first attempt was to extract the pom.xml files directly from the java files
  # the following approach is using already available pom.xml files (we can see this in source code repos)
  mapfile -t lJAVA_POM_XML_ARR < <(grep "pom\.xml;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lJAVA_POM_XML_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lJAVA_POM_XML_ARR[@]}${NC} Java pom.xml:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lJAVA_POM in "${lJAVA_POM_XML_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lJAVA_POM}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lJAVA_POM_XML_ARR[@]}${NC} Java pom.xml:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lJAVA_POM_XML in "${lJAVA_POM_XML_ARR[@]}" ; do
      S08_java_pom_xml_handling "${lPACKAGING_SYSTEM}" "${lJAVA_POM_XML}" "${lJAVA_POM_XML}"
    done
    if [[ "${POS_RES}" -eq 0 ]]; then
      write_log "[-] No JAVA pom.xml found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${POS_RES}" -eq 1 ]]; then
    print_output "[+] Java package SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Java package SBOM results available"
  fi
}

S08_java_manifest_handling() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lJAVA_ARCHIVE="${2:-}"
  local lJAVA_MANIFEST_FILE="${3:-}"

  local lAPP_NAME=""
  local lAPP_LIC=""
  local lAPP_VENDOR_CLEAR=""
  local lAPP_VENDOR=""
  local lAPP_VENDOR_ID=""
  local lBUNDLE_NAME=""
  local lIMPLEMENT_TITLE=""
  local lAPP_VERS=""
  local lAPP_VERS_ALT=""

  # the complete naming in the manifest files is a big mess
  # probably we need some dictionary to parse the names somehow and generate something
  # that is usable for CVE queries
  lAPP_NAME=$(grep "Application-Name" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lAPP_NAME=${lAPP_NAME/*:\ /}

  lAPP_LIC=$(grep "License" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lAPP_LIC=${lAPP_LIC/*:\ /}
  lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

  lAPP_VENDOR_CLEAR=$(grep "Vendor: " "${lJAVA_MANIFEST_FILE}" | sort -u | head -1 || true)
  lAPP_VENDOR_CLEAR=${lAPP_VENDOR_CLEAR#*:\ }
  lAPP_VENDOR_CLEAR=${lAPP_VENDOR_CLEAR//[![:print:]]/}
  lAPP_VENDOR=$(clean_package_details "${lAPP_VENDOR_CLEAR}")
  # we need some translation:
  # e.g.: The Apache Software Foundation -> apache

  # we check for the deprecated vendor id:
  lAPP_VENDOR_ID=$(grep "Implementation-Vendor-Id: " "${lJAVA_MANIFEST_FILE}" | sort -u | head -1 || true)
  lAPP_VENDOR_ID=${lAPP_VENDOR_ID#*:\ }
  # we have seen some vendor ids like org.apache.shiro -> should end up in apache:shiro:version
  lAPP_VENDOR_ID=${lAPP_VENDOR_ID#org\.}
  lAPP_VENDOR_ID=${lAPP_VENDOR_ID#com\.}
  lAPP_VENDOR_ID=${lAPP_VENDOR_ID//\./:}
  lAPP_VENDOR_ID=$(clean_package_details "${lAPP_VENDOR_ID}")

  # alternative package names
  lIMPLEMENT_TITLE=$(grep "Implementation-Title" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE#*:\ }
  lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE//\ }
  lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE//::/_}
  lIMPLEMENT_TITLE=$(clean_package_details "${lIMPLEMENT_TITLE}")
  lBUNDLE_NAME=$(grep "Bundle-Name:" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lBUNDLE_NAME=${lBUNDLE_NAME#*:\ }
  lBUNDLE_NAME=${lBUNDLE_NAME//::/_}
  lBUNDLE_NAME=$(clean_package_details "${lBUNDLE_NAME}")

  lAPP_VERS=$(grep "Implementation-Version" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lAPP_VERS=${lAPP_VERS#*:\ }
  lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
  lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")
  lAPP_VERS_ALT=$(grep "Bundle-Version" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lAPP_VERS_ALT=${lAPP_VERS_ALT#*:\ }
  lAPP_VERS_ALT=$(clean_package_details "${lAPP_VERS_ALT}")
  lAPP_VERS_ALT=$(clean_package_versions "${lAPP_VERS_ALT}")

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

  if [[ -z "${lAPP_NAME}" ]]; then
    # last fallback -> we use the basename of the archive
    lAPP_NAME="$(basename -s .jar "${lJAVA_ARCHIVE}")"
  fi
  lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
  [[ -z "${lAPP_NAME}" ]] && return

  # if we have a vendor id but no app_vendor we are going to use the deprecated id:
  if [[ -z "${lAPP_VENDOR}" && -n "${lAPP_VENDOR_ID}" ]]; then
    # print_output "[*] Using lAPP_VENDOR_ID (${lAPP_VENDOR_ID}) as vendor for ${lJAVA_ARCHIVE}" "no_log"
    lAPP_VENDOR="${lAPP_VENDOR_ID}"
  fi
  if [[ -z "${lAPP_NAME}" && -z "${lAPP_LIC}" && -z "${lIMPLEMENT_TITLE}" && -z "${lAPP_VERS}" && -z "${lBUNDLE_NAME}" ]]; then
    # print_output "[-] skipping ... lJAVA_ARCHIVE: ${lJAVA_ARCHIVE} // lAPP_NAME: ${lAPP_NAME} / lAPP_LIC: ${lAPP_LIC} / lIMPLEMENT_TITLE: ${lIMPLEMENT_TITLE} / lAPP_VERS: ${lAPP_VERS} / lBUNDLE_NAME: ${lBUNDLE_NAME}" "no_log"
    return
  fi
  lAPP_VERS="${lAPP_VERS/\.release}"
  write_log "[*] Java MANIFEST details: ${ORANGE}${lJAVA_ARCHIVE}${NC} - name ${ORANGE}${lAPP_NAME:-NA}${NC} - version ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  S08_java_generate_sbom_entry "${lJAVA_ARCHIVE}" "${lPACKAGING_SYSTEM}-manifest" "${lAPP_VENDOR}" "${lAPP_NAME}" "${lAPP_VERS}" "${lAPP_DESC:-NA}" "${lAPP_LIC}"
  POS_RES=1
}

S08_java_pom_xml_handling() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lJAVA_ARCHIVE="${2:-}"
  local lJAVA_POM_XML="${3:-}"

  local lPOM_XML_ARR=()
  local lPOM_XML=""
  local lAPP_VERS_POM_XML=""
  local lAPP_NAME_POM_XML=""
  local lAPP_NAME_CLEAR_POM_XML=""
  local lAPP_NAME_DESC_POM_XML=""
  local lAPP_NAME_LIC_POM_XML=""
  local lAPP_VERS=""
  local lAPP_NAME=""
  local lAPP_VENDOR=""
  local lAPP_NAME_PROPERTIES_VERSION=""
  local lAPP_NAME_PROPERTIES_NAME=""

  # main version detection in pom.xml -> project->version:
  lAPP_VERS_POM_XML=$(xpath -e project/version//text\(\) "${lJAVA_POM_XML}" 2>/dev/null)
  lAPP_NAME_POM_XML=$(xpath -e project/artifactId//text\(\) "${lJAVA_POM_XML}" 2>/dev/null)
  lAPP_NAME_CLEAR_POM_XML=$(xpath -e project/name//text\(\) "${lJAVA_POM_XML}" 2>/dev/null)
  lAPP_NAME_DESC_POM_XML=$(xpath -e project/description//text\(\) "${lJAVA_POM_XML}" 2>/dev/null | tr '\n' ' ')
  lAPP_NAME_LIC_POM_XML=$(xpath -e project/licenses/license/name//text\(\) "${lJAVA_POM_XML}" 2>/dev/null)
  if [[ -n "${lAPP_VERS_POM_XML}" ]]; then
    # for the dependencies we can check for pom.xml
    # We could do something like the following to extract the dependencies
      # unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" | xpath -e project/dependencies
      # unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" | xpath -e project/dependencies/dependency
      # unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" | xpath -e project/dependencies/dependency[1]/version
    lAPP_VERS="${lAPP_VERS_POM_XML}"
    lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
    lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")
    lAPP_NAME="${lAPP_NAME_POM_XML}"

    write_log "[*] Java pom.xml details: ${ORANGE}${lJAVA_ARCHIVE}${NC} - ${lJAVA_POM_XML} - version ${lAPP_VERS} / name ${lAPP_NAME} / ${lAPP_NAME_CLEAR_POM_XML:-NA} / ${lAPP_NAME_DESC_POM_XML:-NA} / license ${lAPP_NAME_LIC_POM_XML:-NA}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    S08_java_generate_sbom_entry "${lJAVA_ARCHIVE}" "${lPACKAGING_SYSTEM}-pom_xml" "${lAPP_VENDOR:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lAPP_NAME_DESC_POM_XML:-NA}" "${lAPP_NAME_LIC_POM_XML}"
    POS_RES=1
  fi

  # lets check also versions in properties:
  # xpath -e "project/properties/*[contains(name(),'version')]"
  local lAPP_NAME_PROPERTIES_VERS_POM_XML=()
  mapfile -t lAPP_NAME_PROPERTIES_VERS_POM_XML < <(xpath -e "project/properties/*[contains(name(),'.version')]" "${lJAVA_POM_XML}" 2>/dev/null)
  for lAPP_NAME_PROPERTIES_VERSION in "${lAPP_NAME_PROPERTIES_VERS_POM_XML[@]}"; do
    # e.g.: <spotbugs.version>4.8.6.0</spotbugs.version>
    lAPP_NAME_PROPERTIES_NAME=${lAPP_NAME_PROPERTIES_VERSION/\.version*}
    # e.g.: <spotbugs
    lAPP_NAME_PROPERTIES_NAME=${lAPP_NAME_PROPERTIES_NAME//<}
    lAPP_NAME_PROPERTIES_VERSION=${lAPP_NAME_PROPERTIES_VERSION/<\/*\.version>/}
    lAPP_NAME_PROPERTIES_VERSION=${lAPP_NAME_PROPERTIES_VERSION/*\.version>}
    lAPP_VERS=$(clean_package_versions "${lAPP_NAME_PROPERTIES_VERSION}")
    lAPP_NAME="${lAPP_NAME_PROPERTIES_NAME}"
    local lAPP_LIC="NA"
    local lAPP_DESC="NA"

    write_log "[*] Java pom.xml details: ${ORANGE}${lJAVA_ARCHIVE}${NC} - ${lJAVA_POM_XML} - version ${lAPP_VERS} / name ${lAPP_NAME}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    S08_java_generate_sbom_entry "${lJAVA_ARCHIVE}" "${lPACKAGING_SYSTEM}-pom_xml" "${lAPP_VENDOR:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lAPP_DESC}" "${lAPP_LIC}"
    POS_RES=1
  done
}

S08_java_generate_sbom_entry() {
  local lJAVA_ARCHIVE="${1:-}"
  local lPACKAGING_SYSTEM="${2:-}"
  local lAPP_VENDOR="${3:-}"
  local lAPP_NAME="${4:-}"
  local lAPP_VERS="${5:-}"
  local lAPP_DESC="${6:-}"
  local lAPP_LIC="${7:-}"

  local lOS_IDENTIFIED="generic"
  local lAPP_MAINT=""
  local lAPP_ARCH=""

  if [[ -f "${lJAVA_ARCHIVE}" ]]; then
    lMD5_CHECKSUM="$(md5sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
    lSHA256_CHECKSUM="$(sha256sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
    lSHA512_CHECKSUM="$(sha512sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
  fi

  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "java" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
  local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

  # add the java archive path information to our properties array:
  # Todo: in the future we should check for the package, package hashes and which files
  # are in the package
  local lPROP_ARRAY_INIT_ARR=()
  if [[ -f "${lJAVA_ARCHIVE}" ]]; then
    lPROP_ARRAY_INIT_ARR+=( "source_path:${lJAVA_ARCHIVE}" )
  fi
  lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
  lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
  lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
  lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
  # final array with all hash values
  if ! build_sbom_json_hashes_arr "${lJAVA_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM}"; then
    write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
    return
  fi

  # create component entry - this allows adding entries very flexible:
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_VENDOR:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

  write_csv_log "${lPACKAGING_SYSTEM}" "${lJAVA_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
}


