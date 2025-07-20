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

S08_submodule_python_requirements_parser() {
  local lPACKAGING_SYSTEM="python_requirements"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Python requirements identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPY_REQUIREMENTS_ARR=()
  local lPY_REQ_FILE=""
  local lR_FILE=""
  local lRES_ENTRY="NA"
  local lPOS_RES=0

  local lWAIT_PIDS_S08_ARR_LCK=()

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lPY_REQUIREMENTS_ARR < <(grep "requirements.*\.txt" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lPY_REQUIREMENTS_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lPY_REQUIREMENTS_ARR[@]}${NC} python requirement files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPY_REQ_FILE in "${lPY_REQUIREMENTS_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPY_REQ_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPY_REQUIREMENTS_ARR[@]}${NC} python requirement files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lPY_REQ_FILE in "${lPY_REQUIREMENTS_ARR[@]}" ; do
      lR_FILE=$(file "${lPY_REQ_FILE}")
      if [[ ! "${lR_FILE}" == *"ASCII text"* ]]; then
        continue
      fi

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPY_REQ_FILE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lPY_REQ_FILE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      # read entry line by line
      while read -r lRES_ENTRY; do
        if [[ -z "${lRES_ENTRY}" ]]; then
          continue
        fi
        if [[ "${lRES_ENTRY}" =~ ^[[:space:]]*\#.*$ ]]; then
          continue
        fi
        python_requirements_threader "${lPACKAGING_SYSTEM}" "${lOS_IDENTIFIED}" "${lPY_REQ_FILE}" "${lRES_ENTRY}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S08_ARR_LCK+=( "${lTMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_ARR_LCK

        lPOS_RES=1
      done < "${lPY_REQ_FILE}"
    done
    wait_for_pid "${lWAIT_PIDS_S08_ARR_LCK[@]}"

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No python requirements!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No python requirement files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Python requirements SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Python requirements SBOM results available"
  fi
}

python_requirements_threader() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lOS_IDENTIFIED="${2:-}"
  local lPY_REQ_FILE="${3:-}"
  local lRES_ENTRY="${4:-}"

  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lPOS_RES=0
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"

  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"
  local lCPE_IDENTIFIER="NA"

  if [[ "${lRES_ENTRY}" == *"=="* ]]; then
    lAPP_NAME=${lRES_ENTRY/==*}
    lAPP_VERS=${lRES_ENTRY/*==}
  elif [[ "${lRES_ENTRY}" == *">="* ]]; then
    lAPP_NAME=${lRES_ENTRY/>=*}
    lAPP_VERS=${lRES_ENTRY/*>=}
    lAPP_VERS='>='"${lAPP_VERS}"
  elif [[ "${lRES_ENTRY}" == *"<"* ]]; then
    lAPP_NAME=${lRES_ENTRY/<*}
    lAPP_VERS=${lRES_ENTRY/*<}
    lAPP_VERS='<'"${lAPP_VERS}"
  elif [[ "${lRES_ENTRY}" == *"~="* ]]; then
    lAPP_NAME=${lRES_ENTRY/~=*}
    lAPP_VERS=${lRES_ENTRY/*~=}
    lAPP_VERS='~='"${lAPP_VERS}"
  else
    lAPP_NAME=${lRES_ENTRY}
    lAPP_VERS=""
  fi
  lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
  lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
  lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

  lMD5_CHECKSUM="$(md5sum "${lPY_REQ_FILE}" | awk '{print $1}')"
  lSHA256_CHECKSUM="$(sha256sum "${lPY_REQ_FILE}" | awk '{print $1}')"
  lSHA512_CHECKSUM="$(sha512sum "${lPY_REQ_FILE}" | awk '{print $1}')"

  lAPP_VENDOR="${lAPP_NAME}"
  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

  if [[ -z "${lOS_IDENTIFIED}" ]]; then
    lOS_IDENTIFIED="generic"
  fi
  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pypi" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

  local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # with internet we can query further details
        # └─$ curl -sH "accept: application/json" https://pypi.org/pypi/"${lAPP_NAME}"/json | jq '.info.author, .info.classifiers'
        # "Chris P"
        # [
        #   "Development Status :: 5 - Production/Stable",
        #   "License :: OSI Approved :: MIT License",

  # add the python requirement path information to our properties array:
  # Todo: in the future we should check for the package, package hashes and which files
  # are in the package
  local lPROP_ARRAY_INIT_ARR=()
  lPROP_ARRAY_INIT_ARR+=( "source_path:${lPY_REQ_FILE}" )
  lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
  lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
  lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
  lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
  # final array with all hash values
  if ! build_sbom_json_hashes_arr "${lPY_REQ_FILE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
    write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
    return
  fi

  # create component entry - this allows adding entries very flexible:
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

  write_log "[*] Python requirement details: ${ORANGE}${lPY_REQ_FILE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  write_csv_log "${lPACKAGING_SYSTEM}" "${lPY_REQ_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
}
