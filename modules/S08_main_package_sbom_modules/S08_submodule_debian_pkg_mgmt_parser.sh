#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
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

S08_submodule_debian_pkg_mgmt_parser() {
  local lPACKAGING_SYSTEM="debian_pkg_mgmt"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Debian package management identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lDEBIAN_MGMT_STATUS_ARR=()
  local lPACKAGE_FILE=""
  local lDEBIAN_PACKAGES_ARR=()
  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""
  local lPACKAGE_DIR=""
  local lPOS_RES=0

  local lWAIT_PIDS_S08_ARR_LCK=()

  mapfile -t lDEBIAN_MGMT_STATUS_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -path "*dpkg/status" -type f)

  if [[ "${#lDEBIAN_MGMT_STATUS_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lDEBIAN_MGMT_STATUS_ARR[@]}${NC} debian package management files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lDEBIAN_MGMT_STATUS_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPACKAGE_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lDEBIAN_MGMT_STATUS_ARR[@]}${NC} debian package management files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lDEBIAN_MGMT_STATUS_ARR[@]}" ; do

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lPACKAGE_FILE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )
      lPACKAGE_DIR="$(dirname "${lPACKAGE_FILE}")"

      if grep -q "Package: " "${lPACKAGE_FILE}"; then
        mapfile -t lDEBIAN_PACKAGES_ARR < <(grep "^Package: \|^Status: \|^Version: \|^Maintainer: \|^Architecture: \|^Description: \|^Depends: " "${lPACKAGE_FILE}" | sed -z 's/\nVersion: / - Version: /g' \
          | sed -z 's/\nStatus: / - Status: /g' | sed -z 's/\nMaintainer: / - Maintainer: /g' | sed -z 's/\nDescription: / - Description: /g' | sed -z 's/\nArchitecture: / - Architecture: /g' \
          | sed -z 's/\nDepends: / - Depends: /g')
        write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_log "[*] Found debian package details in ${ORANGE}${lPACKAGE_FILE}${NC}:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

        for lPACKAGE_VERSION in "${lDEBIAN_PACKAGES_ARR[@]}" ; do
          debian_status_files_analysis_threader "${lPACKAGING_SYSTEM}" "${lOS_IDENTIFIED}" "${lPACKAGE_FILE}" "${lPACKAGE_VERSION}" &
          local lTMP_PID="$!"
          store_kill_pids "${lTMP_PID}"
          lWAIT_PIDS_S08_ARR_LCK+=( "${lTMP_PID}" )
          max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_S08_ARR_LCK[@]}"
          lPOS_RES=1
        done
      fi
    done
    wait_for_pid "${lWAIT_PIDS_S08_ARR_LCK[@]}"

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No debian packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No debian package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Debian packages SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Debian packages SBOM results available"
  fi
}

debian_status_files_analysis_threader() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lOS_IDENTIFIED="${2:-}"
  local lPACKAGE_FILE="${3:-}"
  local lPACKAGE_VERSION="${4:-}"

  local lPACKAGE=""
  local lVERSION=""
  local lINSTALL_STATE=""
  local lAPP_LIC="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"
  local lAPP_DEPS=""
  local lAPP_DEPS_ARR=()

  # Package: dbus - Status: install ok installed - Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com> - Version: 1.12.16-2ubuntu2.1 - Description: simple interprocess messaging system (daemon and utilities)
  lPACKAGE=$(safe_echo "${lPACKAGE_VERSION}" | awk '{print $2}')
  lPACKAGE=$(clean_package_details "${lPACKAGE}")

  lAPP_MAINT=${lPACKAGE_VERSION/*Maintainer:\ /}
  lAPP_MAINT=${lAPP_MAINT/- Architecture:\ */}
  lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")
  lAPP_MAINT=$(clean_package_versions "${lAPP_MAINT}")

  lVERSION=${lPACKAGE_VERSION/*Version:\ /}
  lVERSION=${lVERSION/ - Depends:\ */}
  # if we have not dependencies:
  lVERSION=${lVERSION/ - Description:\ */}
  lVERSION=$(clean_package_details "${lVERSION}")
  lVERSION=$(clean_package_versions "${lVERSION}")

  lAPP_ARCH=${lPACKAGE_VERSION/*Architecture:\ /}
  lAPP_ARCH=${lAPP_ARCH/ - Version:\ */}
  lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")
  lAPP_ARCH=$(clean_package_versions "${lAPP_ARCH}")

  if [[ "${lPACKAGE_VERSION}" == *"Depends:"* ]]; then
    lAPP_DEPS=${lPACKAGE_VERSION/*Depends:\ /}
    lAPP_DEPS=${lAPP_DEPS/ - Description:\ */}
    # lAPP_DEPS=$(clean_package_details "${lAPP_DEPS}")
    lAPP_DEPS=$(clean_package_versions "${lAPP_DEPS}")
    mapfile -t lAPP_DEPS_ARR < <(echo "${lAPP_DEPS}" | tr ',' '\n' | sed 's/\.\ /\n/g' | sort -u)
  fi

  lAPP_DESC=${lPACKAGE_VERSION/*Description:\ /}
  lAPP_DESC=$(clean_package_details "${lAPP_DESC}")
  lAPP_DESC=$(clean_package_versions "${lAPP_DESC}")

  lINSTALL_STATE=$(safe_echo "${lPACKAGE_VERSION}" | cut -d: -f3)
  if [[ "${lINSTALL_STATE}" == *"deinstall ok"* ]]; then
    write_log "[*] Debian package details: ${ORANGE}${lPACKAGE_FILE}${NC} - ${ORANGE}${lPACKAGE}${NC} - ${ORANGE}${lVERSION}${NC} - ${RED}STATE: Not installed${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    return
  fi

  if [[ -z "${lOS_IDENTIFIED}" ]]; then
    lOS_IDENTIFIED="debian-based"
  fi
  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "deb" "${lPACKAGE:-NA}" "${lVERSION:-NA}" "${lAPP_ARCH:-NA}")
  lAPP_VENDOR="${lPACKAGE}"
  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lPACKAGE}:${lVERSION}:*:*:*:*:*:*"
  local lSTRIPPED_VERSION="::${lPACKAGE}:${lVERSION:-NA}"

  # add source file path information to our properties array:
  local lPROP_ARRAY_INIT_ARR=()
  lPROP_ARRAY_INIT_ARR+=( "source_path:${lPACKAGE_FILE}" )
  lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
  if [[ "${#lAPP_DEPS_ARR[@]}" -gt 0 ]]; then
    for lAPP_DEP in "${lAPP_DEPS_ARR[@]}"; do
      lPROP_ARRAY_INIT_ARR+=( "dependency:${lAPP_DEP#\ }" )
    done
  fi

  # if we have the list file also we can add all the paths provided by the package
  if [[ -f "${lPACKAGE_DIR%\/}/info/${lPACKAGE}.list" ]]; then
    local lPKG_LIST_ENTRY=""
    local lCNT=0
    while IFS= read -r lPKG_LIST_ENTRY; do
      # exclude the root directory entry as this will confuse people
      [[ "${lPKG_LIST_ENTRY}" == "/." ]] && continue
      lCNT=$((lCNT+1))
      lPROP_ARRAY_INIT_ARR+=( "path:${lPKG_LIST_ENTRY}" )
      # we limit the logging of the package files to 500 files per package
      if [[ "${lCNT}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
        lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
        break
      fi
    done < "${lPACKAGE_DIR%\/}/info/${lPACKAGE}.list"
  fi

  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
  # final array with all hash values
  if ! build_sbom_json_hashes_arr "${lPACKAGE_FILE}" "${lPACKAGE:-NA}" "${lVERSION:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
    print_output "[*] Already found results for ${lPACKAGE} / ${lVERSION}" "no_log"
    return
  fi

  # create component entry - this allows adding entries very flexible:
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lPACKAGE:-NA}" "${lVERSION:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

  write_log "[*] Debian package details: ${ORANGE}${lPACKAGE_FILE}${NC} - ${ORANGE}${lPACKAGE}${NC} - ${ORANGE}${lVERSION}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  write_csv_log "${lPACKAGING_SYSTEM}" "${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lPACKAGE}" "${lVERSION}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
}
