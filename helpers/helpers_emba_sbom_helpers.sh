#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2024 Siemens Energy AG
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

# first: build the properaties path array
# This is used for the binary path and for paths extracted from a
# package like deb or rpm
# parameter: array with all the paths
# returns global array PROPERTIES_PATH_JSON_ARR
build_sbom_json_path_properties_arr() {
  local lPATH_ARRAY_INIT_ARR=("$@")

  local lPATH_ELEMENT_ID=""
  local lPATH_ELEMENT=""
  # PROPERTIES_PATH_JSON_ARR is used in the caller
  export PROPERTIES_PATH_JSON_ARR=()

  for lPATH_ELEMENT_ID in "${!lPATH_ARRAY_INIT_ARR[@]}"; do
    lPATH_ELEMENT="${lPATH_ARRAY_INIT_ARR["${lPATH_ELEMENT_ID}"]}"
    local lPATH_ARRAY_TMP=()
    lPATH_ARRAY_TMP+=("name="EMBA:location:$((lPATH_ELEMENT_ID+1)):path"")
    lPATH_ARRAY_TMP+=("value=${lPATH_ELEMENT}")
    PROPERTIES_PATH_JSON_ARR+=( "$(jo "${lPATH_ARRAY_TMP[@]}")")
  done
  # lPROPERTIES_PATH_JSON=$(jo -p -a "${lPROPERTIES_PATH_ARR_TMP[@]}")
}

# 2nd: build the checksum array
# We currently build md5, sha256 and sha512
# parameter: binary/file to check
# returns global array HASHES_ARR
build_sbom_json_hashes_arr() {
  local lBINARY="${1:-}"

  local lMD5_CHECKSUM=""
  local lSHA256_CHECKSUM=""
  local lSHA512_CHECKSUM=""
  # HASHES_ARR is used in the caller
  export HASHES_ARR=()

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
  local lAPP_MAINT="${5:-}"
  local lAPP_LIC="${6:-}"
  local lCPE_IDENTIFIER="${7:-}"
  local lPURL_IDENTIFIER="${8:-}"
  local lAPP_ARCH="${9:-}"
  local lAPP_DESC="${10:-}"
  # we need the bom-ref in the caller to include it in our EMBA csv log for further references
  export SBOM_COMP_BOM_REF=""
  SBOM_COMP_BOM_REF="$(uuidgen)"

  if [[ -n "${lAPP_MAINT}" ]] && ( [[ "${lAPP_MAINT}" == "NA" ]] || [[ "${lAPP_MAINT}" == "-" ]] ); then
    lAPP_MAINT=""
  fi
  if [[ -n "${lAPP_VERS}" ]] && [[ "${lAPP_VERS}" == "NA" ]]; then
    lAPP_VERS=""
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
  if [[ -n "${lAPP_ARCH}" ]] && [[ "${lAPP_ARCH}" != "NA" ]]; then
    lAPP_DESC_NEW+=" - architecture: ${lAPP_ARCH}"
  fi
  if [[ -n "${lAPP_DESC}" ]] && [[ "${lAPP_DESC}" != "NA" ]]; then
    lAPP_DESC_NEW+=" - description: ${lAPP_DESC}"
  fi

  local lCOMPONENT_ARR=()

  lCOMPONENT_ARR+=( "type=${lAPP_TYPE}" )
  lCOMPONENT_ARR+=( "name=${lAPP_NAME:-NA}" )
  lCOMPONENT_ARR+=( "version=${lAPP_VERS}" )
  lCOMPONENT_ARR+=( "author=${lAPP_MAINT}" )
  lCOMPONENT_ARR+=( "group=${lPACKAGING_SYSTEM}" )
  lCOMPONENT_ARR+=( "bom-ref=${SBOM_COMP_BOM_REF}" )
  lCOMPONENT_ARR+=( "license=$(jo name="${lAPP_LIC}")" )
  lCOMPONENT_ARR+=( "cpe=${lCPE_IDENTIFIER}" )
  lCOMPONENT_ARR+=( "purl=${lPURL_IDENTIFIER}" )
  lCOMPONENT_ARR+=( "properties=$(jo -a "${PROPERTIES_PATH_JSON_ARR[@]}")" )
  lCOMPONENT_ARR+=( "hashes=$(jo -a "${HASHES_ARR[@]}")" )
  lCOMPONENT_ARR+=( "description=${lAPP_DESC_NEW//\ /%SPACE%}" )

  if [[ ! -d "${SBOM_LOG_PATH}" ]]; then
    mkdir "${SBOM_LOG_PATH}"
  fi

  jo -n -- "${lCOMPONENT_ARR[@]}" > "${SBOM_LOG_PATH}/${lPACKAGING_SYSTEM}_${lAPP_NAME}_${SBOM_COMP_BOM_REF:-NA}.json"

  # we can unset it here again
  unset HASHES_ARR
  unset PROPERTIES_PATH_JSON_ARR
}


