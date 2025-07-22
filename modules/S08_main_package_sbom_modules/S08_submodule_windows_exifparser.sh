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


S08_submodule_windows_exifparser() {
  local lPACKAGING_SYSTEM="windows_exe"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Windows Exif parser" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lEXE_ARCHIVES_ARR=()
  local lEXE_ARCHIVE=""
  local lPOS_RES=0
  local lWAIT_PIDS_S08_ARR_LCK=()

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lEXE_ARCHIVES_ARR < <(grep "PE32\|MSI" "${P99_CSV_LOG}" | grep -v "ASCII text\|Unicode text" | cut -d ';' -f2 || true)

  if [[ "${#lEXE_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lEXE_ARCHIVES_ARR[@]}${NC} Windows exe files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lEXE_ARCHIVE in "${lEXE_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lEXE_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lEXE_ARCHIVES_ARR[@]}${NC} Windows exe files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lEXE_ARCHIVE in "${lEXE_ARCHIVES_ARR[@]}" ; do
      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lEXE_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lEXE_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      windows_exifparser_threader "${lPACKAGING_SYSTEM}" "${lOS_IDENTIFIED}" "${lEXE_ARCHIVE}" &

      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S08_ARR_LCK+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_ARR_LCK
      lPOS_RES=1
    done
    wait_for_pid "${lWAIT_PIDS_S08_ARR_LCK[@]}"
    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Windows executables found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Windows executables found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Windows executables SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Windows executables SBOM results available"
  fi
}

windows_exifparser_threader() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lOS_IDENTIFIED="${2:-}"
  local lEXE_ARCHIVE="${3:-}"

  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"
  local lPKG_MD5=""

  lR_FILE=$(file -b "${lEXE_ARCHIVE}")
  if [[ ! "${lR_FILE}" == *"PE32 executable"* ]] && [[ ! "${lR_FILE}" == *"PE32+ executable"* ]]; then
    return
  fi

  lEXE_NAME=$(basename -s .exe "${lEXE_ARCHIVE}")
  lPKG_MD5="$(md5sum "${lEXE_ARCHIVE}" | awk '{print $1}')"
  lEXIF_LOG="${LOG_PATH_MODULE}/windows_exe_exif_data_${lEXE_NAME}_${lPKG_MD5}.txt"

  exiftool "${lEXE_ARCHIVE}" > "${lEXIF_LOG}" || true
  if ! [[ -f "${lEXIF_LOG}" ]]; then
    return
  fi

  lAPP_NAME=$(grep "Product Name" "${lEXIF_LOG}" || true)
  lAPP_NAME=${lAPP_NAME/*:\ }
  lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
  lAPP_NAME=$(clean_package_versions "${lAPP_NAME}")

  if [[ -z "${lAPP_NAME}" ]]; then
    lAPP_NAME=$(grep "Internal Name" "${lEXIF_LOG}" || true)
    lAPP_NAME=${lAPP_NAME/*:\ }
    lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
  fi

  if [[ -z "${lAPP_NAME}" ]]; then
    lAPP_NAME=$(grep "File Name" "${lEXIF_LOG}" || true)
    lAPP_NAME=${lAPP_NAME/*:\ }
    lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
  fi

  lAPP_VENDOR=$(grep "Company Name" "${lEXIF_LOG}" || true)
  lAPP_VENDOR=${lAPP_VENDOR/*:\ }
  lAPP_VENDOR=$(clean_package_details "${lAPP_VENDOR}")
  lAPP_VENDOR=$(clean_package_versions "${lAPP_VENDOR}")

  if [[ -z "${lAPP_VENDOR}" ]]; then
    lAPP_VENDOR="${lAPP_NAME}"
  fi

  lAPP_DESC=$(grep "File Description" "${lEXIF_LOG}" || true)
  lAPP_DESC=${lAPP_DESC/*:\ }
  lAPP_DESC=$(clean_package_details "${lAPP_DESC}")

  lAPP_LIC="NA"

  lAPP_VERS=$(grep "Product Version Number" "${lEXIF_LOG}" || true)
  if [[ -z "${lAPP_VERS}" ]]; then
    # backup
    lAPP_VERS=$(grep "Product Version" "${lEXIF_LOG}" || true)
  fi
  lAPP_VERS=${lAPP_VERS/*:\ }
  lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
  lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")
  if [[ -z "${lAPP_VERS}" ]]; then
    return
  fi

  lAPP_ARCH=$(grep "Machine Type" "${lEXIF_LOG}" || true)
  lAPP_ARCH=${lAPP_ARCH/*:\ }
  lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")

  if [[ "${lAPP_ARCH}" == *"intel_386_or_later"* ]]; then
    lAPP_ARCH="x86"
  fi
  if [[ -z "${lAPP_ARCH}" ]]; then
    if [[ "${lR_FILE}" == *"Intel 80386"* ]]; then
      lAPP_ARCH="x86"
    else
      lAPP_ARCH="${lR_FILE//\ /-}"
      lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")
    fi
  fi

  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR%.exe}:${lAPP_NAME%.exe}:${lAPP_VERS:-*}:*:*:*:*:*:*"

  if [[ -z "${lOS_IDENTIFIED}" ]]; then
    lOS_IDENTIFIED="windows-based"
  fi

  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "exe" "${lAPP_NAME%.exe}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

  local lSTRIPPED_VERSION="::${lAPP_NAME//\.exe}:${lAPP_VERS:-NA}"

  # add EXE path information to our properties array:
  local lPROP_ARRAY_INIT_ARR=()
  lPROP_ARRAY_INIT_ARR+=( "source_path:${lEXE_ARCHIVE}" )
  [[ -n "${lAPP_ARCH}" ]] && lPROP_ARRAY_INIT_ARR+=( "source_arch:${lAPP_ARCH}" )
  lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
  lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR%.exe}" )
  lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME%.exe}" )
  lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
  # final array with all hash values
  if ! build_sbom_json_hashes_arr "${lEXE_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
    write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
    return
  fi

  # create component entry - this allows adding entries very flexible:
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

  write_log "[*] Windows EXE details: ${ORANGE}${lEXE_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  write_link "${lEXIF_LOG}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  write_csv_log "${lPACKAGING_SYSTEM}" "${lEXE_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
}

