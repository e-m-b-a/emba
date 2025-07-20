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

S08_submodule_rpm_pkg_mgmt_parser() {
  local lPACKAGING_SYSTEM="rpm_package_mgmt"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "RPM package management identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lWAIT_PIDS_S08_ARR_LCK=()
  local lRPM_PACKAGE_DBS_BRK_ARR=()
  local lRPM_PACKAGE_DBS_SQLITE_ARR=()
  local lRPM_PACKAGE_DBS_ARR=()
  local lPACKAGE_FILE=""
  local lRPM_PACKAGES_ARR=()
  local lPACKAGE_AND_VERSION=""
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lRPM_DIR=""
  local lPOS_RES=0

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  # this handles the Berkley database
  mapfile -t lRPM_PACKAGE_DBS_BRK_ARR < <(grep "rpm/Packages;" "${P99_CSV_LOG}" | cut -d ';'  -f2 || true)
  # this handles the sqlite database
  mapfile -t lRPM_PACKAGE_DBS_SQLITE_ARR < <(grep "rpm/rpmdb.sqlite;" "${P99_CSV_LOG}" | cut -d ';'  -f2 || true)
  lRPM_PACKAGE_DBS_ARR=( "${lRPM_PACKAGE_DBS_BRK_ARR[@]}" "${lRPM_PACKAGE_DBS_SQLITE_ARR[@]}" )

  if [[ "${#lRPM_PACKAGE_DBS_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lRPM_PACKAGE_DBS_ARR[@]}${NC} RPM package management directories." "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lRPM_PACKAGE_DBS_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPACKAGE_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lRPM_PACKAGE_DBS_ARR[@]}${NC} RPM package management directories." "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lPACKAGE_FILE in "${lRPM_PACKAGE_DBS_ARR[@]}" ; do
      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lPACKAGE_FILE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      lMD5_CHECKSUM="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lPACKAGE_FILE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lPACKAGE_FILE}" | awk '{print $1}')"

      lRPM_DIR="$(dirname "${lPACKAGE_FILE}" || true)"
      # not sure this works on an offline system - we need further tests on this:
      mapfile -t lRPM_PACKAGES_ARR < <(rpm -qa --dbpath "${lRPM_DIR}" || print_error "[-] Failed to identify RPM packages in ${lRPM_DIR}")
      for lPACKAGE_AND_VERSION in "${lRPM_PACKAGES_ARR[@]}" ; do
        rpm_pkg_mgmt_analysis_threader "${lPACKAGING_SYSTEM}" "${lOS_IDENTIFIED}" "${lPACKAGE_FILE}" "${lPACKAGE_AND_VERSION}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S08_ARR_LCK+=( "${lTMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_ARR_LCK
        lPOS_RES=1
      done
    done

    wait_for_pid "${lWAIT_PIDS_S08_ARR_LCK[@]}"

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No RPM packages found (based on RPM package management database)!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No RPM package management database found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] RPM package managment database SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No RPM package management database SBOM results available"
  fi
}

rpm_pkg_mgmt_analysis_threader() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lOS_IDENTIFIED="${2:-}"
  local lPACKAGE_FILE="${3:-}"
  local lPACKAGE_AND_VERSION="${4:-}"

  local lAPP_NAME=""
  local lAPP_VERS=""
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lAPP_DEPS_ARR=()
  local lAPP_DEP=""
  local lAPP_FILE=""
  local lAPP_FILE_ID=""
  local lAPP_FILES_ARR=()

  local lRPM_DIR=""
  lRPM_DIR="$(dirname "${lPACKAGE_FILE}" || true)"
  # print_output "[*] Testing RPM directory ${lRPM_DIR} with PACKAGE_AND_VERSION: ${lPACKAGE_AND_VERSION}" "no_log"

  lAPP_VERS=$(rpm -qi --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" | grep "^Version" || true)
  lAPP_VERS="${lAPP_VERS/*:\ }"
  lAPP_VERS=$(clean_package_details "${lAPP_VERS}")

  lAPP_NAME=$(rpm -qi --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" | grep "^Name" || true)
  lAPP_NAME="${lAPP_NAME/*:\ }"
  lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

  if [[ -z "${lAPP_NAME}" ]]; then
    return
  fi

  lAPP_LIC=$(rpm -qi --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" | grep "^License" || true)
  lAPP_LIC="${lAPP_LIC/*:\ }"
  lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

  lAPP_ARCH=$(rpm -qi --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" | grep "^Architecture" || true)
  lAPP_ARCH="${lAPP_ARCH/*:\ }"
  lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")

  mapfile -t lAPP_DEPS_ARR < <(rpm -qR --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" || true)
  mapfile -t lAPP_FILES_ARR < <(rpm -ql --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" || true)

  lAPP_VENDOR="${lAPP_NAME}"
  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

  if [[ -z "${lOS_IDENTIFIED}" ]]; then
    lOS_IDENTIFIED="rpm-based"
  fi
  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "rpm" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
  local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

  # add the rpm database path information to our properties array:
  # Todo: in the future we should check for the package, package hashes and which files
  # are in the package
  local lPROP_ARRAY_INIT_ARR=()
  lPROP_ARRAY_INIT_ARR+=( "source_path:${lPACKAGE_FILE}" )
  lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
  lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )

  if [[ "${#lAPP_DEPS_ARR[@]}" -gt 0 ]]; then
    for lAPP_DEP in "${lAPP_DEPS_ARR[@]}"; do
      lPROP_ARRAY_INIT_ARR+=( "dependency:${lAPP_DEP#\ }" )
    done
  fi

  # add package files to properties
  if [[ "${#lAPP_FILES_ARR[@]}" -gt 0  ]]; then
    for lAPP_FILE_ID in "${!lAPP_FILES_ARR[@]}"; do
      lAPP_FILE="${lAPP_FILES_ARR["${lAPP_FILE_ID}"]}"
      lPROP_ARRAY_INIT_ARR+=( "path:${lAPP_FILE#\.}" )
      # we limit the logging of the package files to 500 files per package
      if [[ "${lAPP_FILE_ID}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
        lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
        break
      fi
    done
  fi

  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
  # final array with all hash values
  if ! build_sbom_json_hashes_arr "${lPACKAGE_FILE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
    write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
    return
  fi

  # create component entry - this allows adding entries very flexible:
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

  write_log "[*] RPM package details (based on package management): ${ORANGE}${lAPP_NAME}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  write_csv_log "${lPACKAGING_SYSTEM}" "${lRPM_DIR} / ${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
}
