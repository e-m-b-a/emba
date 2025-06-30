#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description: Helper functions for SBOM building
#

# first: build the properties path array
# This can be used for the binary path (souce_path) and for paths extracted from a
# package like deb or rpm (path). Additionally, it is commonly used for the architecture
# and further meta data like the version identifier
# parameter: array with all the properties in the form
#   "path:the_path_to_log"
#   "other_propertie:the_property_to_log"
# returns global array PROPERTIES_JSON_ARR
build_sbom_json_properties_arr() {
  local lPROPERTIES_ARRAY_INIT_ARR=("$@")

  local lPROPERTIES_ELEMENT_ID=""
  local lPROPERTIES_ELEMENT=""
  # PROPERTIES_JSON_ARR is used in the caller
  export PROPERTIES_JSON_ARR=()
  local lPROPERTIES_ELEMENT_1=""
  local lPROPERTIES_ELEMENT_2=""
  local lINIT_ELEMENT=""

  for lPROPERTIES_ELEMENT_ID in "${!lPROPERTIES_ARRAY_INIT_ARR[@]}"; do
    lPROPERTIES_ELEMENT="${lPROPERTIES_ARRAY_INIT_ARR["${lPROPERTIES_ELEMENT_ID}"]}"
    # lPROPERTIES_ELEMENT_1 -> path, source or something else
    lPROPERTIES_ELEMENT_1=$(echo "${lPROPERTIES_ELEMENT}" | cut -d ':' -f1)
    # lPROPERTIES_ELEMENT_2 -> the real value
    lPROPERTIES_ELEMENT_2=$(echo "${lPROPERTIES_ELEMENT}" | cut -d ':' -f2-)
    if [[ -z "${lPROPERTIES_ELEMENT_2}" ]]; then
      continue
    fi
    # jo is looking for a file if our entry starts with : -> lets pseudo escape it for jo
    if [[ "${lPROPERTIES_ELEMENT_2:0:1}" == ":" ]]; then
      # shellcheck disable=SC1003
      lPROPERTIES_ELEMENT_2='\'"${lPROPERTIES_ELEMENT_2}"
    fi

    # default value
    lINIT_ELEMENT="EMBA:sbom"
    # dedicated rules -> path -> location
    [[ "${lPROPERTIES_ELEMENT_1}" == "path" ]] && lINIT_ELEMENT="EMBA:sbom:location"
    [[ "${lPROPERTIES_ELEMENT_1}" == "source_path" ]] && lINIT_ELEMENT="EMBA:sbom:source_location"

    local lPROPERTIES_ARRAY_TMP=()
    lPROPERTIES_ARRAY_TMP+=("-s" "name=${lINIT_ELEMENT}:$((lPROPERTIES_ELEMENT_ID+1)):${lPROPERTIES_ELEMENT_1}")
    [[ "${lPROPERTIES_ELEMENT_2}" == "NA" ]] && continue
    lPROPERTIES_ARRAY_TMP+=("-s" "value=${lPROPERTIES_ELEMENT_2@Q}")
    PROPERTIES_JSON_ARR+=( "$(jo -n -- "${lPROPERTIES_ARRAY_TMP[@]}")")
  done
  # lPROPERTIES_PATH_JSON=$(jo -p -a "${lPROPERTIES_PATH_ARR_TMP[@]}")
}

# 2nd: build the checksum array
# We currently build md5, sha256 and sha512
# parameter: binary/file to check
# returns global array HASHES_ARR
build_sbom_json_hashes_arr() {
  local lBINARY="${1:-}"
  local lAPP_NAME="${2:-}"
  local lAPP_VERS="${3:-}"
  local lPACKAGING_SYSTEM="${4:-NA}"
  local lCONFIDENCE_LEVEL="${5:-NA}"

  # HASHES_ARR is used in the caller
  export HASHES_ARR=()
  local lMD5_CHECKSUM=""
  local lSHA256_CHECKSUM=""
  local lSHA512_CHECKSUM=""
  local lDUP_CHECK_FILE_ARR=()
  local lDUP_CHECK_FILE=""
  local lDUP_CHECK_NAME=""
  local lDUP_CHECK_VERS=""

  if [[ ! -d "${SBOM_LOG_PATH}" ]]; then
    mkdir "${SBOM_LOG_PATH}" 2>/dev/null || true
  fi

  # hashes of the source file that is currently tested:
  lMD5_CHECKSUM="$(md5sum "${lBINARY}" | awk '{print $1}')"
  lSHA256_CHECKSUM="$(sha256sum "${lBINARY}" | awk '{print $1}')"
  lSHA512_CHECKSUM="$(sha512sum "${lBINARY}" | awk '{print $1}')"

  # temp array with only one set of hash values
  local lHASHES_ARRAY_INIT=("alg=MD5")
  lHASHES_ARRAY_INIT+=("content=${lMD5_CHECKSUM}")
  HASHES_ARR+=( "$(jo "${lHASHES_ARRAY_INIT[@]}")" )

  lHASHES_ARRAY_INIT=("alg=SHA-256")
  lHASHES_ARRAY_INIT+=("content=${lSHA256_CHECKSUM}")
  HASHES_ARR+=( "$(jo "${lHASHES_ARRAY_INIT[@]}")" )

  lHASHES_ARRAY_INIT=("alg=SHA-512")
  lHASHES_ARRAY_INIT+=("content=${lSHA512_CHECKSUM}")
  HASHES_ARR+=( "$(jo "${lHASHES_ARRAY_INIT[@]}")" )

  # check if we already have results which are duplicates and does not need to be logged
  # we check all SBOM results for the same file hash and afterwards for name and version
  # if all are matching this is duplicate and we do not need to log it
  # we return 1 if we already found something and the caller needs to handle it
  if [[ -d "${SBOM_LOG_PATH}" ]] && [[ "${lAPP_NAME}" != "NA" && "${lAPP_VERS}" != "NA" && "${lAPP_VERS}" != "null" ]]; then
    # first check is for same hash, same name, same version:
    if grep -qr '"alg":"SHA-512","content":"'"${lSHA512_CHECKSUM}" "${SBOM_LOG_PATH}"; then
      # if we have found some sbom log file with the matching sha512 checksum, we then check if
      # it is the same name and version. If so, we will skip it in the caller
      mapfile -t lDUP_CHECK_FILE_ARR < <(grep -lr '"alg":"SHA-512","content":"'"${lSHA512_CHECKSUM}" "${SBOM_LOG_PATH}" || true)
      for lDUP_CHECK_FILE in "${lDUP_CHECK_FILE_ARR[@]}"; do
        lDUP_CHECK_NAME=$(jq -r .name "${lDUP_CHECK_FILE}")
        lDUP_CHECK_VERS=$(jq -r .version "${lDUP_CHECK_FILE}")
        if [[ "${lDUP_CHECK_NAME}" == "${lAPP_NAME}" ]] && [[ "${lDUP_CHECK_VERS}" == "${lAPP_VERS}" ]]; then
          return 1
        fi
      done
    fi

    # 2nd test is now for same name and same version but other hash (new file with the same name/version detected)
    # this results in the need to merge the new path of the binary into the already available component json
    # mapfile -t lDUP_CHECK_FILE_ARR < <(find "${SBOM_LOG_PATH}" -type f -name "${lPACKAGING_SYSTEM:-*}_${lAPP_NAME}_*" || true)
    mapfile -t lDUP_CHECK_FILE_ARR < <(find "${SBOM_LOG_PATH}" -type f -name "*_${lAPP_NAME}_*.json" || true)
    # print_output "[*] Duplicate check for ${lAPP_NAME} - ${lAPP_VERS} reached - ${lDUP_CHECK_FILE_ARR[*]}"
    for lDUP_CHECK_FILE in "${lDUP_CHECK_FILE_ARR[@]}"; do
      # write_log "[*] Testing for duplicates ${lAPP_NAME}-${lAPP_VERS} / ${lDUP_CHECK_FILE}" "${SBOM_LOG_PATH}"/duplicates.txt
      lDUP_CHECK_NAME=$(jq -r .name "${lDUP_CHECK_FILE}")
      lDUP_CHECK_VERS=$(jq -r .version "${lDUP_CHECK_FILE}")
      lDUP_RAND_ID="${RANDOM}"
      # we test the current version against the stored version. But as we often have a version from a package manager like
      # 1.2.3-deb-123abc and from the binary level we have only 1.2.3
      # To handle these cases we check against the version ^1.2.3*
      if [[ "${lDUP_CHECK_NAME}" == "${lAPP_NAME}" ]] && { [[ "${lAPP_VERS}" =~ ^"${lDUP_CHECK_VERS}".* ]] || [[ "${lDUP_CHECK_VERS}" =~ ^"${lAPP_VERS}".* ]]; }; then
        # write_log "[*] Duplicate detected - merge needed for ${lAPP_NAME}-${lAPP_VERS} / ${lDUP_CHECK_FILE}" "${SBOM_LOG_PATH}"/duplicates.txt
        write_log "[*] Duplicate detected - merging ${lAPP_NAME} - ${lAPP_VERS} / ${lDUP_CHECK_VERS}" "${SBOM_LOG_PATH}"/duplicates.txt
        lJQ_ELEMENTS=$(jq '.properties | length' "${lDUP_CHECK_FILE}")
        jq '.properties[.properties| length] |= . + { "name": "EMBA:sbom:source_location:'"$((lJQ_ELEMENTS+1))"':additional_source_path", "value": "'"${lBINARY}"'" }' "${lDUP_CHECK_FILE}" > "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp"
        if ! [[ -f "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp" ]]; then
          continue
        fi

        # with the following check we find out if we have the same version or some extended version
        # on the 2nd case we also add this different version to the properties
        if [[ "${lAPP_VERS}" != "${lDUP_CHECK_VERS}" ]]; then
          write_log "[*] Version difference detected - merging ${lAPP_NAME} - ${lAPP_VERS} / ${lDUP_CHECK_VERS}" "${SBOM_LOG_PATH}"/duplicates.txt
          jq '.properties[.properties| length] |= . + { "name": "EMBA:sbom:version:'"$((lJQ_ELEMENTS+2))"':additional_version_identified", "value": "'"${lAPP_VERS}"'" }' "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp" > "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp1"
          mv "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp1" "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp" 2>/dev/null || true
        fi

        # extract the confidence level from the json and compare it to our current level:
        lCONFIDENCE_LEVEL_JSON=$(jq -r '.properties[] | select(.name | endswith(":confidence")).value' "${lDUP_CHECK_FILE}" || true)
        if [[ "${lCONFIDENCE_LEVEL}" != "NA" ]] && [[ "${lCONFIDENCE_LEVEL_JSON:-NA}" != "NA" ]]; then
          write_log "[*] lCONFIDENCE_LEVEL: ${lCONFIDENCE_LEVEL} / lCONFIDENCE_LEVEL_JSON: $(get_confidence_value "${lCONFIDENCE_LEVEL_JSON}")" "${SBOM_LOG_PATH}"/duplicates.txt
          if [[ "${lCONFIDENCE_LEVEL:-0}" -gt "$(get_confidence_value "${lCONFIDENCE_LEVEL_JSON:-undef}")" ]]; then
            # if our current level is higher as the level from the json we need to adjust it now
            write_log "[*] Duplicate handling - Confidence level needs to be adjusted for ${lDUP_CHECK_FILE} -> from ${lCONFIDENCE_LEVEL_JSON:-NA} -> to $(get_confidence_string "${lCONFIDENCE_LEVEL:-NA}")" "${SBOM_LOG_PATH}"/duplicates.txt
            # very dirty :-D
            jq . "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp" | sed 's/"value": "'"${lCONFIDENCE_LEVEL_JSON:-NA}"'"/"value": "'"$(get_confidence_string "${lCONFIDENCE_LEVEL:-NA}")"'"/' > "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp1" || true
            mv "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp1" "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp" 2>/dev/null || true
            # Todo: adjust json
          fi
        fi
        mv "${lDUP_CHECK_FILE/\.json/}_${lDUP_RAND_ID}.tmp" "${lDUP_CHECK_FILE}" 2>/dev/null || true
        return 1
      fi
    done
  fi

  if [[ "${lPACKAGING_SYSTEM}" != "unhandled_file" && -d "${SBOM_LOG_PATH}" ]]; then
    # Finally, we check if there is another "unhandled_file_*.json" with the same hash. If we find such a file we can remove it now
    mapfile -t lDUP_CHECK_FILE_ARR < <(grep -lr '"alg":"SHA-512","content":"'"${lSHA512_CHECKSUM}" "${SBOM_LOG_PATH}"/unhandled_file_*.json 2>/dev/null || true)
    for lDUP_CHECK_FILE in "${lDUP_CHECK_FILE_ARR[@]}"; do
      print_output "[*] Duplicate unhandled_file sbom entry detected for ${lAPP_NAME} - ${lDUP_CHECK_FILE}" "no_log"
      if ! grep -q "${lDUP_CHECK_FILE}" "${SBOM_LOG_PATH}"/duplicates_to_delete.txt 2>/dev/null; then
        echo "${lDUP_CHECK_FILE}" >> "${SBOM_LOG_PATH}"/duplicates_to_delete.txt
      fi
    done
  fi

  return 0

  # lhashes=$(jo -p -a "${HASHES_ARR[@]}")
}

# 3rd: build and store the component sbom as json
# paramters: multiple
# return: nothing -> writes json to SBOM directory
build_sbom_json_component_arr() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lAPP_TYPE="${2:-}"
  local lAPP_NAME="${3:-}"
  local lAPP_VERS="${4:-}"
  # lAPP_MAINT is used as supplier
  local lAPP_MAINT="${5:-}"
  local lAPP_LIC="${6:-}"
  local lCPE_IDENTIFIER="${7:-}"
  local lPURL_IDENTIFIER="${8:-}"
  local lAPP_DESC="${9:-}"
  # we need the bom-ref in the caller to include it in our EMBA csv log for further references
  export SBOM_COMP_BOM_REF=""
  SBOM_COMP_BOM_REF="$(uuidgen)"

  local lAPP_LIC_ARR=()

  # detected component is always required
  local lAPP_SCOPE="required"

  if [[ -n "${lAPP_MAINT}" ]] && { [[ "${lAPP_MAINT}" == "NA" ]] || [[ "${lAPP_MAINT}" == "-" ]]; }; then
    lAPP_MAINT="Unknown"
  fi
  [[ -n "${lAPP_MAINT}" ]] && lAPP_MAINT=$(translate_vendor "${lAPP_MAINT}")

  if [[ -n "${lAPP_VERS}" ]] && [[ "${lAPP_VERS}" == "NA" ]]; then
    lAPP_VERS=""
  fi
  if [[ -n "${lAPP_LIC}" ]] && [[ "${lAPP_LIC}" == "NA" || "${lAPP_LIC}" == "null" || "${lAPP_LIC}" == "unknown" ]]; then
    lAPP_LIC_ARR=()
  else
    lAPP_LIC_ARR+=( "name=${lAPP_LIC}" )
  fi
  if [[ -n "${lCPE_IDENTIFIER}" ]] && [[ "${lCPE_IDENTIFIER}" == "NA" ]]; then
    lCPE_IDENTIFIER=""
  fi
  if [[ -n "${lPURL_IDENTIFIER}" ]] && [[ "${lPURL_IDENTIFIER}" == "NA" ]]; then
    lPURL_IDENTIFIER=""
  fi

  local lAPP_DESC_NEW="EMBA SBOM-group: ${lPACKAGING_SYSTEM} - name: ${lAPP_NAME}"
  if [[ -n "${lAPP_VERS}" ]] && [[ "${lAPP_VERS}" != "NA" ]]; then
    lAPP_DESC_NEW+=" - version: ${lAPP_VERS}"
  fi
  if [[ -n "${lAPP_DESC}" ]] && [[ "${lAPP_DESC}" != "NA" ]]; then
    lAPP_DESC_NEW+=" - description: ${lAPP_DESC}"
  fi

  local lCOMPONENT_ARR=()

  lCOMPONENT_ARR+=( "type=${lAPP_TYPE}" )
  lCOMPONENT_ARR+=( "name=${lAPP_NAME:-NA}" )
  lCOMPONENT_ARR+=( "-s" "version=${lAPP_VERS}" )
  if [[ -n "${lAPP_MAINT}" ]]; then
    lCOMPONENT_ARR+=( "supplier=$(jo name="${lAPP_MAINT}")" )
    # lCOMPONENT_ARR+=( "author=${lAPP_MAINT}" )
  fi
  lCOMPONENT_ARR+=( "group=${lPACKAGING_SYSTEM}" )
  lCOMPONENT_ARR+=( "bom-ref=${SBOM_COMP_BOM_REF}" )
  if [[ "${#lAPP_LIC_ARR[@]}" -gt 0 ]]; then
    local lTMP_IDENTIFIER="${RANDOM}"
    # we should not work with the tmp file trick but otherwise jo does not handle our json correctly
    jo -p license="$(jo -n "${lAPP_LIC_ARR[@]}")" > "${TMP_DIR}"/sbom_lic_"${lAPP_NAME}"_"${lTMP_IDENTIFIER}".json
    lCOMPONENT_ARR+=( "licenses=$(jo -a :"${TMP_DIR}"/sbom_lic_"${lAPP_NAME}"_"${lTMP_IDENTIFIER}".json)" )
    rm "${TMP_DIR}"/sbom_lic_"${lAPP_NAME}"_"${lTMP_IDENTIFIER}".json || true
  fi
  lCOMPONENT_ARR+=( "scope=${lAPP_SCOPE}" )
  lCOMPONENT_ARR+=( "cpe=${lCPE_IDENTIFIER}" )
  lCOMPONENT_ARR+=( "purl=${lPURL_IDENTIFIER}" )
  lCOMPONENT_ARR+=( "properties=$(jo -a "${PROPERTIES_JSON_ARR[@]}")" )
  if [[ -v HASHES_ARR ]] && [[ "${#HASHES_ARR[@]}" -gt 0 ]]; then
    lCOMPONENT_ARR+=( "hashes=$(jo -a "${HASHES_ARR[@]}")" )
  fi
  lCOMPONENT_ARR+=( "description=${lAPP_DESC_NEW//\ /%SPACE%}" )

  if [[ ! -d "${SBOM_LOG_PATH}" ]]; then
    mkdir "${SBOM_LOG_PATH}" 2>/dev/null || true
  fi

  jo -n -- "${lCOMPONENT_ARR[@]}" > "${SBOM_LOG_PATH}/${lPACKAGING_SYSTEM}_${lAPP_NAME}_${SBOM_COMP_BOM_REF:-NA}.json"

  # we can unset it here again
  unset HASHES_ARR
  unset PROPERTIES_PATH_JSON_ARR
}

# translate known vendors from short variant to the long variant:
#   dlink -> D'Link
#   kernel -> kernel.org
translate_vendor() {
  local lAPP_MAINT="${1:-}"
  local lAPP_MAINT_NEW=""

  if [[ -f "${CONFIG_DIR}"/vendor_list.cfg ]]; then
    lAPP_MAINT_NEW="$(grep "^${lAPP_MAINT};" "${CONFIG_DIR}"/vendor_list.cfg | cut -d ';' -f2- || true)"
    lAPP_MAINT_NEW="${lAPP_MAINT_NEW//\"}"
  fi

  [[ -z "${lAPP_MAINT_NEW}" ]] && lAPP_MAINT_NEW="${lAPP_MAINT}"
  echo "${lAPP_MAINT_NEW}"
}

check_for_s08_csv_log() {
  lS08_CSV_LOG="${1:-}"
  if [[ ! -f "${lS08_CSV_LOG}" ]]; then
    # using write_log as this always works
    write_log "Packaging system;package file;MD5/SHA-256/SHA-512;package;original version;stripped version;license;maintainer;architecture;CPE identifier;PURL;SBOM comoponent reference;Description" "${lS08_CSV_LOG}"
  fi
}

build_purl_identifier() {
  local lOS_IDENTIFIED="${1:-}"
  local lPKG_TYPE="${2:-}"
  local lAPP_NAME="${3:-}"
  local lAPP_VERS="${4:-}"
  local lAPP_ARCH="${5:-}"

  local lPURL_IDENTIFIER=""

  if [[ "${lOS_IDENTIFIED}" == "NA" ]]; then
    lOS_IDENTIFIED="generic"
  fi
  lPURL_IDENTIFIER="pkg:${lPKG_TYPE}/${lOS_IDENTIFIED/-*}/${lAPP_NAME}"
  if [[ -n "${lAPP_VERS}" ]]; then
    lPURL_IDENTIFIER+="@${lAPP_VERS}"
  fi
  if [[ -n "${lAPP_ARCH}" && "${lAPP_ARCH}" != "NA" ]]; then
    lPURL_IDENTIFIER+="?arch=${lAPP_ARCH//\ /-}"
  fi
  if [[ "${lOS_IDENTIFIED}" != "generic" && "${lOS_IDENTIFIED}" != *"-based" ]]; then
    if [[ -n "${lAPP_ARCH}" ]]; then
      lPURL_IDENTIFIER+="&"
    else
      lPURL_IDENTIFIER+="?"
    fi
    lPURL_IDENTIFIER+="distro=${lOS_IDENTIFIED}"
  fi
  echo "${lPURL_IDENTIFIER}"
}

distri_check() {
  # quick check for distribution
  local lOS_RELEASE_ARR=()
  local lOS_RELEASE_FILE=""
  local lOS_IDENTIFIED=""
  local lOS_VERS_IDENTIFIED=""

  # currently this is a weak check via /etc/os-release
  # Todo: If this check failes we can use further tests like lsb-release or motd
  mapfile -t lOS_RELEASE_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -iwholename "*/etc/os-release" || true)
  for lOS_RELEASE_FILE in "${lOS_RELEASE_ARR[@]}"; do
    lOS_IDENTIFIED=$(grep "^ID=" "${lOS_RELEASE_FILE}" || true)
    lOS_IDENTIFIED=${lOS_IDENTIFIED//ID=}
    lOS_VERS_IDENTIFIED=$(grep "^VERSION_ID=" "${lOS_RELEASE_FILE}" || true)
    lOS_VERS_IDENTIFIED=${lOS_VERS_IDENTIFIED//VERSION_ID=}
    lOS_IDENTIFIED+="-${lOS_VERS_IDENTIFIED}"
    lOS_IDENTIFIED=${lOS_IDENTIFIED//\"}
    lOS_IDENTIFIED=${lOS_IDENTIFIED,,}
    # if it looks like an os then we are happy for now :)
    # for the future we can do some further checks if it is some debian for debs and some rpm based for rpm systems
    if [[ "${lOS_IDENTIFIED}" =~ ^[a-z]+-[a-z]+$ ]]; then
      break
    fi
  done
  echo "${lOS_IDENTIFIED}"
}

get_confidence_string() {
  local lCONFIDENCE_LEVEL="${1:-3}"
  # 1 -> very-low
  # 2 -> low
  # 3 -> medium
  # 4 -> high
  if [[ "${lCONFIDENCE_LEVEL}" -eq 1 ]]; then
    echo "very-low"
  elif [[ "${lCONFIDENCE_LEVEL}" -eq 2 ]]; then
    echo "low"
  elif [[ "${lCONFIDENCE_LEVEL}" -eq 3 ]]; then
    echo "medium"
  elif [[ "${lCONFIDENCE_LEVEL}" -eq 4 ]]; then
    echo "high"
  else
    echo "NA"
  fi
}

get_confidence_value() {
  local lCONFIDENCE_LEVEL="${1:-NA}"
  # 1 -> very-low
  # 2 -> low
  # 3 -> medium
  # 4 -> high
  if [[ "${lCONFIDENCE_LEVEL}" == "very-low" ]]; then
    echo "1"
  elif [[ "${lCONFIDENCE_LEVEL}" == "low" ]]; then
    echo "2"
  elif [[ "${lCONFIDENCE_LEVEL}" == "medium" ]]; then
    echo "3"
  elif [[ "${lCONFIDENCE_LEVEL}" == "high" ]]; then
    echo "4"
  else
    echo "99"
  fi
}

