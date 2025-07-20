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

S08_submodule_python_pipfile_lock() {
  local lOS_IDENTIFIED="${1:-}"
  local lPACKAGING_SYSTEM="python_pipfile_lock"

  sub_module_title "Python pipfile.lock SBOM analysis" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPIPFILE_LCK_ARCHIVES_ARR=()
  local lPIPFILE_LCK_ARCHIVE=""
  local lPIP_LOCK_ENTRIES_ARR=()
  local lPIP_LOCK_ENTRY=""

  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS=""
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lPOS_RES=0

  # if we have found multiple lock files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""
  local lWAIT_PIDS_S08_ARR_LCK=()

  mapfile -t lPIPFILE_LCK_ARCHIVES_ARR < <(grep -i "/Pipfile.*\.lock;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lPIPFILE_LCK_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lPIPFILE_LCK_ARCHIVES_ARR[@]}${NC} Python pipfile.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPIPFILE_LCK_ARCHIVE in "${lPIPFILE_LCK_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPIPFILE_LCK_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPIPFILE_LCK_ARCHIVES_ARR[@]}${NC} Python pipfile.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lPIPFILE_LCK_ARCHIVE in "${lPIPFILE_LCK_ARCHIVES_ARR[@]}"; do
      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPIPFILE_LCK_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lPIPFILE_LCK_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      lR_FILE=$(file "${lPIPFILE_LCK_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"JSON text"* ]]; then
        continue
      fi

      mapfile -t lPIP_LOCK_ENTRIES_ARR < <(jq -rc '.default | to_entries[] | "\(.key),\(.value)"' "${lPIPFILE_LCK_ARCHIVE}")

      # shellcheck disable=SC2034
      for lPIP_LOCK_ENTRY in "${lPIP_LOCK_ENTRIES_ARR[@]}"; do
        python_pipfile_lock_threader "${lPACKAGING_SYSTEM}" "${lOS_IDENTIFIED}" "${lPIPFILE_LCK_ARCHIVE}" "${lPIP_LOCK_ENTRY}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S08_ARR_LCK+=( "${lTMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_ARR_LCK
        lPOS_RES=1
      done
      wait_for_pid "${lWAIT_PIDS_S08_ARR_LCK[@]}"
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Python pipfile.log packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Python pipfile.logk package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Python pipfile.lock SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Python pipfile.lock SBOM results available"
  fi
}

python_pipfile_lock_threader() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lOS_IDENTIFIED="${2:-}"
  local lPIPFILE_LCK_ARCHIVE="${3:-}"
  local lPIPFILE_LCK_ENTRY="${4:-}"

  local lAPP_NAME=""
  local lAPP_VERS=""
  local lAPP_VENDOR=""
  local lCPE_IDENTIFIER=""
  local lPURL_IDENTIFIER=""

  # our entry looks like
  # Entry: urllib3,{"hashes":["sha256:1cee9ad369867bfdbbb48b7dd50374c0967a0bb7710050facf0dd6911440e3df","sha256:f8c5449b3cf0861679ce7e0503c7b44b5ec981bec0d1d3795a07f1ba96f0204d"],"markers":"python_version >= '3.9'","version":"==2.3.0"}
  lAPP_NAME="${lPIPFILE_LCK_ENTRY/,*}"
  lAPP_VERS=$(jq -r .version <<< "${lPIPFILE_LCK_ENTRY#*,}")

  lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
  # version outcome from compose is mostly ==1.2.3 -> 1.2.3
  lAPP_VERS=$(clean_package_details "${lAPP_VERS#==}")
  [[ -z "${lAPP_NAME}" ]] && return

  lAPP_VENDOR="${lAPP_NAME}"
  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

  if [[ -z "${lOS_IDENTIFIED}" ]]; then
    lOS_IDENTIFIED="generic"
  fi
  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "python" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
  local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

  # add the node lock path information to our properties array:
  # Todo: in the future we should check for the package, package hashes and which files
  # are in the package
  local lPROP_ARRAY_INIT_ARR=()
  lPROP_ARRAY_INIT_ARR+=( "source_path:${lPIPFILE_LCK_ARCHIVE}" )
  lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
  lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
  lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
  lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
  # final array with all hash values
  if ! build_sbom_json_hashes_arr "${lPIPFILE_LCK_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
    write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
    return
  fi

  # create component entry - this allows adding entries very flexible:
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

  write_log "[*] Python pipfile.lock archive details: ${ORANGE}${lPIPFILE_LCK_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  write_csv_log "${lPACKAGING_SYSTEM}" "${lPIPFILE_LCK_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_ARCH:-NA}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC:-NA}"
}

