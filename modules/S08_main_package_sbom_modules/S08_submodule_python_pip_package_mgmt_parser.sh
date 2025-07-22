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

S08_submodule_python_pip_package_mgmt_parser() {
  local lPACKAGING_SYSTEM="python_pip"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Python PIP package identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPIP_PACKAGES_SITE_ARR=()
  local lPIP_PACKAGES_DIST_ARR=()
  local lPIP_DIST_DIR=""
  local lPIP_SITE_DIR=""
  local lPIP_DIST_INSTALLED_PACKAGES_ARR=()
  local lPIP_SITE_INSTALLED_PACKAGES_ARR=()
  local lPIP_DIST_META_PACKAGE=""
  local lPIP_SITE_META_PACKAGE=""
  local lAPP_LIC="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # pip packages are in site-packages or in dist-packages directories installed
  # metadata can be found in METADATA of in PKG-INFO
  mapfile -t lPIP_PACKAGES_SITE_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "site-packages" -type d)
  mapfile -t lPIP_PACKAGES_DIST_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "dist-packages" -type d)

  if [[ "${#lPIP_PACKAGES_DIST_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lPIP_PACKAGES_DIST_ARR[@]}${NC} PIP dist-packages directories:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPIP_DIST_DIR in "${lPIP_PACKAGES_DIST_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPIP_DIST_DIR}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPIP_PACKAGES_DIST_ARR[@]}${NC} PIP dist-packages directories:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lPIP_DIST_DIR in "${lPIP_PACKAGES_DIST_ARR[@]}" ; do
      mapfile -t lPIP_DIST_INSTALLED_PACKAGES_ARR < <(find "${lPIP_DIST_DIR}" -name "METADATA" -type f)
      for lPIP_DIST_META_PACKAGE in "${lPIP_DIST_INSTALLED_PACKAGES_ARR[@]}" ; do
        lAPP_NAME=$(grep "^Name: " "${lPIP_DIST_META_PACKAGE}" || true)
        lAPP_NAME=${lAPP_NAME/*:\ }
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_VERS=$(grep "^Version: " "${lPIP_DIST_META_PACKAGE}" || true)
        lAPP_VERS=${lAPP_VERS/*:\ }
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lAPP_LIC=$(grep "^License: " "${lPIP_DIST_META_PACKAGE}" || true)
        lAPP_LIC=${lAPP_LIC/*:\ }

        lAPP_DESC=$(grep "^Summary: " "${lPIP_DIST_META_PACKAGE}" || true)
        lAPP_DESC=${lAPP_DESC/*:\ }
        lAPP_DESC=$(clean_package_details "${lAPP_DESC}")
        lAPP_DESC=$(clean_package_versions "${lAPP_DESC}")

        lAPP_MAINT=$(grep "^Author: " "${lPIP_DIST_META_PACKAGE}" || true)
        lAPP_MAINT=${lAPP_MAINT/*:\ }
        lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")
        lAPP_MAINT=$(clean_package_versions "${lAPP_MAINT}")

        # Todo: from METADATA we also get "^Requires-Dist: "

        lMD5_CHECKSUM="$(md5sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pypi" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
        local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # add the python requirement path information to our properties array:
        # Todo: in the future we should check for the package, package hashes and which files
        # are in the package
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lPIP_DIST_META_PACKAGE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
        lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
        lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
        lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lPIP_DIST_META_PACKAGE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
          write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

        write_log "[*] Found PIP package ${ORANGE}${lAPP_NAME}${NC} - Version ${ORANGE}${lAPP_VERS}${NC} in PIP dist-packages directory ${ORANGE}${lPIP_DIST_META_PACKAGE}${NC} - Source ${ORANGE}METADATA${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_DIST_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done

      mapfile -t lPIP_DIST_INSTALLED_PACKAGES_ARR < <(find "${lPIP_DIST_DIR}" -name "PKG-INFO" -type f)
      for lPIP_DIST_META_PACKAGE in "${lPIP_DIST_INSTALLED_PACKAGES_ARR[@]}" ; do
        lAPP_NAME=$(grep "^Name: " "${lPIP_DIST_META_PACKAGE}" || true)
        lAPP_NAME=${lAPP_NAME/*:\ }
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_VERS=$(grep "^Version: " "${lPIP_DIST_META_PACKAGE}" || true)
        lAPP_VERS=${lAPP_VERS/*:\ }
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lAPP_LIC=$(grep "^License: " "${lPIP_DIST_META_PACKAGE}" || true)
        lAPP_LIC=${lAPP_LIC/*:\ }

        lAPP_DESC=$(grep "^Summary: " "${lPIP_DIST_META_PACKAGE}" || true)
        lAPP_DESC=${lAPP_DESC/*:\ }
        lAPP_DESC=$(clean_package_details "${lAPP_DESC}")
        lAPP_DESC=$(clean_package_versions "${lAPP_DESC}")

        lAPP_MAINT=$(grep "^Author: " "${lPIP_DIST_META_PACKAGE}" || true)
        lAPP_MAINT=${lAPP_MAINT/*:\ }
        lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")
        lAPP_MAINT=$(clean_package_versions "${lAPP_MAINT}")

        lMD5_CHECKSUM="$(md5sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPIP_DIST_META_PACKAGE}" | awk '{print $1}')"

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pypi" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
        local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # add the python requirement path information to our properties array:
        # Todo: in the future we should check for the package, package hashes and which files
        # are in the package
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lPIP_DIST_META_PACKAGE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
        lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
        lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
        lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lPIP_DIST_META_PACKAGE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

        write_log "[*] Found PIP package ${ORANGE}${lAPP_NAME}${NC} - Version ${ORANGE}${lAPP_VERS}${NC} in PIP dist-packages directory ${ORANGE}${lPIP_DIST_META_PACKAGE}${NC} - Source ${ORANGE}PKG-INFO${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_DIST_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No PIP dist packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No PIP dist package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  if [[ "${#lPIP_PACKAGES_SITE_ARR[@]}" -gt 0 ]] ; then
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Found ${ORANGE}${#lPIP_PACKAGES_SITE_ARR[@]}${NC} PIP site-packages directories:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPIP_SITE_DIR in "${lPIP_PACKAGES_SITE_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPIP_SITE_DIR}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPIP_PACKAGES_SITE_ARR[@]}${NC} PIP site-packages directories:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPIP_SITE_DIR in "${lPIP_PACKAGES_SITE_ARR[@]}" ; do
      mapfile -t lPIP_SITE_INSTALLED_PACKAGES_ARR < <(find "${lPIP_SITE_DIR}" -name "METADATA" -type f)
      for lPIP_SITE_META_PACKAGE in "${lPIP_SITE_INSTALLED_PACKAGES_ARR[@]}" ; do
        lAPP_NAME=$(grep "^Name: " "${lPIP_SITE_META_PACKAGE}" || true)
        lAPP_NAME=${lAPP_NAME/*:\ }
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_VERS=$(grep "^Version: " "${lPIP_SITE_META_PACKAGE}" || true)
        lAPP_VERS=${lAPP_VERS/*:\ }
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lAPP_LIC=$(grep "^License: " "${lPIP_SITE_META_PACKAGE}" || true)
        lAPP_LIC=${lAPP_LIC/*:\ }

        lAPP_DESC=$(grep "^Summary: " "${lPIP_SITE_META_PACKAGE}" || true)
        lAPP_DESC=${lAPP_DESC/*:\ }
        lAPP_DESC=$(clean_package_details "${lAPP_DESC}")
        lAPP_DESC=$(clean_package_versions "${lAPP_DESC}")

        lAPP_MAINT=$(grep "^Author: " "${lPIP_SITE_META_PACKAGE}" || true)
        lAPP_MAINT=${lAPP_MAINT/*:\ }
        lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")
        lAPP_MAINT=$(clean_package_versions "${lAPP_MAINT}")

        lMD5_CHECKSUM="$(md5sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pypi" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
        local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # add the python requirement path information to our properties array:
        # Todo: in the future we should check for the package, package hashes and which files
        # are in the package
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lPIP_SITE_META_PACKAGE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
        lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
        lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
        lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lPIP_SITE_META_PACKAGE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

        write_log "[*] Found PIP package ${ORANGE}${lAPP_NAME}${NC} - Version ${ORANGE}${lAPP_VERS}${NC} in PIP site-packages directory ${ORANGE}${lPIP_SITE_META_PACKAGE}${NC} - Source ${ORANGE}METADATA${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_SITE_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done

      mapfile -t lPIP_SITE_INSTALLED_PACKAGES_ARR < <(find "${lPIP_SITE_DIR}" -name "PKG-INFO" -type f)
      for lPIP_SITE_META_PACKAGE in "${lPIP_SITE_INSTALLED_PACKAGES_ARR[@]}" ; do
        lAPP_NAME=$(grep "^Name: " "${lPIP_SITE_META_PACKAGE}" || true)
        lAPP_NAME=${lAPP_NAME/*:\ }
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_VERS=$(grep "^Version: " "${lPIP_SITE_META_PACKAGE}" || true)
        lAPP_VERS=${lAPP_VERS/*:\ }
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lAPP_LIC=$(grep "^License: " "${lPIP_SITE_META_PACKAGE}" || true)
        lAPP_LIC=${lAPP_LIC/*:\ }

        lAPP_DESC=$(grep "^Summary: " "${lPIP_SITE_META_PACKAGE}" || true)
        lAPP_DESC=${lAPP_DESC/*:\ }
        lAPP_DESC=$(clean_package_details "${lAPP_DESC}")
        lAPP_DESC=$(clean_package_versions "${lAPP_DESC}")

        lAPP_MAINT=$(grep "^Author: " "${lPIP_SITE_META_PACKAGE}" || true)
        lAPP_MAINT=${lAPP_MAINT/*:\ }
        lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")
        lAPP_MAINT=$(clean_package_versions "${lAPP_MAINT}")

        lMD5_CHECKSUM="$(md5sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pypi" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
        local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # add the python requirement path information to our properties array:
        # Todo: in the future we should check for the package, package hashes and which files
        # are in the package
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lPIP_SITE_META_PACKAGE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
        lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
        lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
        lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lPIP_SITE_META_PACKAGE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

        write_log "[*] Found PIP package ${ORANGE}${lAPP_NAME}${NC} - Version ${ORANGE}${lAPP_VERS}${NC} in PIP site-packages directory ${ORANGE}${lPIP_SITE_META_PACKAGE}${NC} - Source ${ORANGE}PKG-INFO${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_SITE_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No PIP site packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No PIP site package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Python PIP database SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Python PIP SBOM results available"
  fi
}
