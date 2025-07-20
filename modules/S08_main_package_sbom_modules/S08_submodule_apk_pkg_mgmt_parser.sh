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

S08_submodule_apk_pkg_mgmt_parser() {
  local lPACKAGING_SYSTEM="apk_pkg_mgmt"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "APK package management identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lAPK_MGMT_STATUS_ARR=()
  local lPACKAGE_FILE=""
  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""
  local lPOS_RES=0
  local lAPK_PACKAGE_FILES_ARR=()
  local lAPK_PACKAGE_FILE_TMP=""

  local lWAIT_PIDS_S08_ARR_LCK=()

  mapfile -t lAPK_MGMT_STATUS_ARR < <(grep "apk/db/installed" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)

  if [[ "${#lAPK_MGMT_STATUS_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lAPK_MGMT_STATUS_ARR[@]}${NC} APK package management databases:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lAPK_MGMT_STATUS_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPACKAGE_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lAPK_MGMT_STATUS_ARR[@]}${NC} APK package management databases:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lAPK_MGMT_STATUS_ARR[@]}" ; do
      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] APK database ${ORANGE}${lPACKAGE_FILE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      if [[ ! -d "${LOG_PATH_MODULE}"/apk_tmp_db ]]; then
        mkdir "${LOG_PATH_MODULE}"/apk_tmp_db
      fi
      if grep -q "^C:" "${lPACKAGE_FILE}" 2>/dev/null; then
        # split lPACKAGE_FILE on empty lines into separate package entry files for further processing
        awk -v RS= '{print > ("'"${LOG_PATH_MODULE}"/apk_tmp_db/apk-'" NR ".txt")}' "${lPACKAGE_FILE}"
        write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_log "[*] Found APK package details in ${ORANGE}${lPACKAGE_FILE}${NC}:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

        mapfile -t lAPK_PACKAGE_FILES_ARR < <(find "${LOG_PATH_MODULE}"/apk_tmp_db -name "apk-*")
        for lAPK_PACKAGE_FILE_TMP in "${lAPK_PACKAGE_FILES_ARR[@]}"; do
          apk_pkg_analysis_threader "${lPACKAGING_SYSTEM}" "${lOS_IDENTIFIED}" "${lPACKAGE_FILE}" "${lAPK_PACKAGE_FILE_TMP}" &
          local lTMP_PID="$!"
          lWAIT_PIDS_S08_ARR_LCK+=( "${lTMP_PID}" )
          max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_ARR_LCK
          lPOS_RES=1
        done
      fi
    done
    wait_for_pid "${lWAIT_PIDS_S08_ARR_LCK[@]}"

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No aPK packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No APK package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] APK packages SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No APK packages SBOM results available"
  fi
}

apk_pkg_analysis_threader() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lOS_IDENTIFIED="${2:-}"
  local lPACKAGE_FILE="${3:-}"
  local lAPK_PACKAGE_FILE_TMP="${4:-}"

  local lAPP_NAME=""
  local lAPP_VERS=""
  local lAPP_LIC="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lAPP_URL="NA"
  local lCPE_IDENTIFIER="NA"
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"
  local lAPP_DEPS_ARR=()

  lAPP_NAME=$(grep "^P:" "${lAPK_PACKAGE_FILE_TMP}" || true)
  lAPP_NAME=$(clean_package_details "${lAPP_NAME/P:}")

  lAPP_VERS=$(grep "^V:" "${lAPK_PACKAGE_FILE_TMP}" || true)
  lAPP_VERS=${lAPP_VERS/V:}
  lAPP_VERS=$(clean_package_details "${lAPP_VERS}" || true)
  lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

  lAPP_MAINT=$(grep "^m:" "${lAPK_PACKAGE_FILE_TMP}" || true)
  lAPP_MAINT=${lAPP_MAINT/m:}
  lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")
  lAPP_MAINT=$(clean_package_versions "${lAPP_MAINT}")

  lAPP_ARCH=$(grep "^A:" "${lAPK_PACKAGE_FILE_TMP}" || true)
  lAPP_ARCH=${lAPP_ARCH/A:}
  lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")
  lAPP_ARCH=$(clean_package_versions "${lAPP_ARCH}")

  lAPP_DESC=$(grep "^T:" "${lAPK_PACKAGE_FILE_TMP}" || true)
  lAPP_DESC=${lAPP_DESC/T:}
  lAPP_DESC=$(clean_package_details "${lAPP_DESC}")
  lAPP_DESC=$(clean_package_versions "${lAPP_DESC}")

  lAPP_LIC=$(grep "^L:" "${lAPK_PACKAGE_FILE_TMP}" || true)
  lAPP_LIC=${lAPP_LIC/L:}

  # currently not further used -> probably this can be used for externalReferences
  lAPP_URL=$(grep "^U:" "${lAPK_PACKAGE_FILE_TMP}" || true)
  lAPP_URL=${lAPP_URL/U:}

  if [[ -z "${lOS_IDENTIFIED}" ]]; then
    lOS_IDENTIFIED="alpine-based"
  fi
  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "apk" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
  lAPP_VENDOR="${lAPP_NAME}"
  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"
  local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

  # add source file path information to our properties array:
  local lPROP_ARRAY_INIT_ARR=()
  lPROP_ARRAY_INIT_ARR+=( "source_path:${lPACKAGE_FILE}" )
  lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
  lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
  lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
  lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

  mapfile -t lAPP_DEPS_ARR < <(grep "^D:" "${lAPK_PACKAGE_FILE_TMP}" | tr ' ' '\n' | sort -u || true)
  if [[ "${#lAPP_DEPS_ARR[@]}" -gt 0 ]]; then
    for lAPP_DEP in "${lAPP_DEPS_ARR[@]}"; do
      lPROP_ARRAY_INIT_ARR+=( "dependency:${lAPP_DEP/D:}" )
    done
  fi

  # extract the list file name from the package details
  local lAPP_LIST_FILE=""
  lAPP_LIST_FILE=$(grep "^R:" "${lAPK_PACKAGE_FILE_TMP}" || true)
  # get the list file path
  if [[ -n "${lAPP_LIST_FILE}" ]]; then
    lAPP_LIST_FILE=$(grep "apk/packages/${lAPP_LIST_FILE/R:};" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
  fi

  # if we have the list file also we can add all the paths provided by the package
  if [[ -f "${lAPP_LIST_FILE}" ]]; then
    local lPKG_LIST_ENTRY=""
    local lCNT=0
    while IFS= read -r lPKG_LIST_ENTRY; do
      lCNT=$((lCNT+1))
      lPROP_ARRAY_INIT_ARR+=( "path:${lPKG_LIST_ENTRY}" )
      # we limit the logging of the package files to 500 files per package
      if [[ "${lCNT}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
        lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
        break
      fi
    done < "${lAPP_LIST_FILE}"
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

  write_log "[*] Alpine APK package details: ${ORANGE}${lPACKAGE_FILE}${NC} - ${ORANGE}${lAPP_NAME}${NC} - ${ORANGE}${lAPP_VERS}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  write_csv_log "${lPACKAGING_SYSTEM}" "${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
}
