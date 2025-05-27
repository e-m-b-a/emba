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

S08_submodule_node_js_package_lock_parser() {
  local lOS_IDENTIFIED="${1:-}"
  local lPACKAGING_SYSTEM="node_js_lock"

  sub_module_title "Node.js package lock identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lNODE_LCK_ARCHIVES_ARR=()
  local lNODE_LCK_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS=""
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lPOS_RES=0

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""
  local lWAIT_PIDS_S08_ARR_LCK=()

  mapfile -t lNODE_LCK_ARCHIVES_ARR < <(grep "/package.*json;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lNODE_LCK_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lNODE_LCK_ARCHIVES_ARR[@]}${NC} Node.js npm lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lNODE_LCK_ARCHIVE in "${lNODE_LCK_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lNODE_LCK_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lNODE_LCK_ARCHIVES_ARR[@]}${NC} node.js npm lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lNODE_LCK_ARCHIVE in "${lNODE_LCK_ARCHIVES_ARR[@]}" ; do
      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lNODE_LCK_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lNODE_LCK_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      lR_FILE=$(file "${lNODE_LCK_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"JSON text"* ]]; then
        continue
      fi

      jq -r '"\(.name);\(.version);\(.license);\(.integrity);\(.dependencies)"' "${lNODE_LCK_ARCHIVE}" > "${TMP_DIR}/node.lock.tmp" || true
      jq -r '.packages | keys[] as $k | "\($k);\(.[$k] | "\(.version);\(.license);\(.integrity);\(.dependencies)")"' "${lNODE_LCK_ARCHIVE}" >> "${TMP_DIR}/node.lock.tmp" || true

      # shellcheck disable=SC2034
      while IFS=";" read -r lAPP_NAME lAPP_VERS lAPP_LIC lAPP_CHECKSUM lAPP_DEPS; do
        node_js_package_lock_threader "${lPACKAGING_SYSTEM}" "${lOS_IDENTIFIED}" "${lNODE_LCK_ARCHIVE}" "${lAPP_NAME}" "${lAPP_VERS:-NA}" "${lAPP_LIC:-NA}" "${lAPP_DEPS:-NA}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S08_ARR_LCK+=( "${lTMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_ARR_LCK
        lPOS_RES=1
      done < "${TMP_DIR}/node.lock.tmp"
      wait_for_pid "${lWAIT_PIDS_S08_ARR_LCK[@]}"
      rm -f "${TMP_DIR}/node.lock.tmp"
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Node.js lock packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Node.js lock package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Node.js lock SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Node.js lock SBOM results available"
  fi

}

node_js_package_lock_threader() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lOS_IDENTIFIED="${2:-}"
  local lNODE_LCK_ARCHIVE="${3:-}"
  local lAPP_NAME="${4:-}"
  local lAPP_VERS="${5:-}"
  local lAPP_LIC="${6:-}"
  local lAPP_DEPS="${7:-}"

  local lAPP_VENDOR=""
  local lCPE_IDENTIFIER=""
  local lPURL_IDENTIFIER=""

  local lAPP_DEPS_ARR=()
  local lJS_DEP_ID=""
  local lAPP_DEP=""

  lAPP_NAME=$(echo "${lAPP_NAME}" | rev | cut -d '/' -f1 | rev)
  [[ -z "${lAPP_NAME}" ]] && return
  lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
  lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
  lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

  lAPP_VENDOR="${lAPP_NAME}"
  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

  if [[ -z "${lOS_IDENTIFIED}" ]]; then
    lOS_IDENTIFIED="generic"
  fi
  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "npm" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
  local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

  if [[ "${lAPP_DEPS}" != "null" ]]; then
    # extract the dependencies lAPP_DEPS from '{"ansi-styles":"^4.0.0","string-width":"^4.1.0","strip-ansi":"^6.0.0"}'
    mapfile -t lAPP_DEPS_ARR < <(echo "${lAPP_DEPS}" | jq -r '. | to_entries[] | "\(.key)(\(.value))"' || true)
  fi

  # add the node lock path information to our properties array:
  # Todo: in the future we should check for the package, package hashes and which files
  # are in the package
  local lPROP_ARRAY_INIT_ARR=()
  lPROP_ARRAY_INIT_ARR+=( "source_path:${lNODE_LCK_ARCHIVE}" )
  lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
  lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

  # Add dependencies to properties
  for lJS_DEP_ID in "${!lAPP_DEPS_ARR[@]}"; do
    lAPP_DEP="${lAPP_DEPS_ARR["${lJS_DEP_ID}"]}"
    lPROP_ARRAY_INIT_ARR+=( "dependency:${lAPP_DEP#\ }" )
  done

  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
  # final array with all hash values
  if ! build_sbom_json_hashes_arr "${lNODE_LCK_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
    write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
    return
  fi

  # create component entry - this allows adding entries very flexible:
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

  write_log "[*] Node.js npm lock archive details: ${ORANGE}${lNODE_LCK_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  write_csv_log "${lPACKAGING_SYSTEM}" "${lNODE_LCK_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_ARCH:-NA}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC:-NA}"
}

