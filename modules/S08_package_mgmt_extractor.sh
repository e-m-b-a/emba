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

S08_package_mgmt_extractor()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "EMBA central SBOM environment"
  pre_module_reporter "${FUNCNAME[0]}"

  local NEG_LOG=0
  local lWAIT_PIDS_S08_ARR=()
  local lOS_IDENTIFIED=""
  # we limit the maximal file log
  export SBOM_MAX_FILE_LOG=200

  # shellcheck disable=SC2153
  check_for_s08_csv_log "${S08_CSV_LOG}"

  lOS_IDENTIFIED=$(distri_check)

  if [[ ${THREADED} -eq 1 ]]; then
    debian_status_files_analysis "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    openwrt_control_files_analysis "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    rpm_package_mgmt_analysis "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    rpm_package_check "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    deb_package_check "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    bsd_pkg_check "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    python_pip_packages "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    python_requirements "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    python_poetry_lock_parser "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    java_archives_check "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    ruby_gem_archive_check "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    alpine_apk_package_check "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    windows_exifparser "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    rust_cargo_lock_parser "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    node_js_package_lock_parser "${lOS_IDENTIFIED}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )

    wait_for_pid "${lWAIT_PIDS_S08_ARR[@]}"
  else
    debian_status_files_analysis "${lOS_IDENTIFIED}"
    openwrt_control_files_analysis "${lOS_IDENTIFIED}"
    rpm_package_mgmt_analysis "${lOS_IDENTIFIED}"
    rpm_package_check "${lOS_IDENTIFIED}"
    deb_package_check "${lOS_IDENTIFIED}"
    bsd_pkg_check "${lOS_IDENTIFIED}"
    python_pip_packages "${lOS_IDENTIFIED}"
    python_requirements "${lOS_IDENTIFIED}"
    python_poetry_lock_parser "${lOS_IDENTIFIED}"
    java_archives_check "${lOS_IDENTIFIED}"
    ruby_gem_archive_check "${lOS_IDENTIFIED}"
    alpine_apk_package_check "${lOS_IDENTIFIED}"
    windows_exifparser "${lOS_IDENTIFIED}"
    rust_cargo_lock_parser "${lOS_IDENTIFIED}"
    node_js_package_lock_parser "${lOS_IDENTIFIED}"
  fi

  build_dependency_tree

  # shellcheck disable=SC2153
  [[ -s "${S08_CSV_LOG}" ]] && NEG_LOG=1
  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

build_dependency_tree() {
  sub_module_title "SBOM dependency tree build" "${SBOM_LOG_PATH}/SBOM_dependencies.txt"

  local lSBOM_COMPONENT_FILES_ARR=()
  local lSBOM_COMP=""

  local lWAIT_PIDS_S08_ARR=()

  mapfile -t lSBOM_COMPONENT_FILES_ARR < <(find "${SBOM_LOG_PATH}" -maxdepth 1 -type f)

  for lSBOM_COMP in "${lSBOM_COMPONENT_FILES_ARR[@]}"; do
    [[ ! -f "${lSBOM_COMP}" ]] && continue
    # to speed up the dep tree we are working threaded for every componentfile and write into dedicated json files
    # "${SBOM_LOG_PATH}/SBOM_deps/SBOM_dependency_${lSBOM_COMP_REF}".json which we can put together in f15
    create_comp_dep_tree_threader "${lSBOM_COMP}" &
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_S08_ARR[@]}"
  done
  wait_for_pid "${lWAIT_PIDS_S08_ARR[@]}"

  if [[ -d "${SBOM_LOG_PATH}/SBOM_deps" ]]; then
    print_output "[+] SBOM dependency results" "" "${SBOM_LOG_PATH}/SBOM_dependencies.txt"
  else
    print_output "[*] No SBOM dependency results available"
  fi
}

create_comp_dep_tree_threader() {
  # lSBOM_COMP -> current sbom json file under analysis
  local lSBOM_COMP="${1:-}"

  local lSBOM_COMP_DEPS_ARR=()
  local lSBOM_COMP_DEPS_FILES_ARR=()
  local lSBOM_COMP_NAME=""
  local lSBOM_COMP_REF=""
  local lSBOM_COMP_VERS=""
  local lSBOM_COMP_SOURCE=""
  local lSBOM_COMP_DEP=""
  local lSBOM_DEP_SOURCE_FILES_ARR=()
  local lSBOM_COMP_SOURCE_FILE=""
  local lSBOM_COMP_SOURCE_REF=""

  # extract needed metadata (VERS not really needed but nice to show)
  lSBOM_COMP_NAME=$(jq -r .name "${lSBOM_COMP}" || true)
  lSBOM_COMP_REF=$(jq -r '."bom-ref"' "${lSBOM_COMP}" || true)
  lSBOM_COMP_VERS=$(jq -r .version "${lSBOM_COMP}" || true)
  # Source is only used to ensure we check only matching sources (eg. check debian packages against debian sources)
  lSBOM_COMP_SOURCE=$(jq -r .group "${lSBOM_COMP}" || true)

  print_output "[*] Source file: ${lSBOM_COMP}" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"
  print_output "[*] Component: ${lSBOM_COMP_NAME} / ${lSBOM_COMP_VERS} / ${lSBOM_COMP_SOURCE} / ${lSBOM_COMP_REF}" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"

  # lets search for dependencies in every SBOM component file we have and store it in lSBOM_COMP_DEPS_ARR
  mapfile -t lSBOM_COMP_DEPS_FILES_ARR < <(jq -rc '.properties[] | select(.name | endswith(":dependency")).value' "${lSBOM_COMP}" || true)
  if [[ "${#lSBOM_COMP_DEPS_FILES_ARR[@]}" -eq 0 ]]; then
    return
  fi

  [[ ! -d "${SBOM_LOG_PATH}/SBOM_deps" ]] && mkdir "${SBOM_LOG_PATH}/SBOM_deps"

  # now we check every dependency for the current component
  for lSBOM_COMP_DEP in "${lSBOM_COMP_DEPS_FILES_ARR[@]}"; do
    # lets extract the name of the dependency
    lSBOM_COMP_DEP="${lSBOM_COMP_DEP/\ *}"
    lSBOM_COMP_DEP="${lSBOM_COMP_DEP/\(*}"

    # check all sbom component files from this group (e.g. debian_pkg_mgmt) for the dependency as name:
    mapfile -t lSBOM_DEP_SOURCE_FILES_ARR < <(grep -l "name\":\"${lSBOM_COMP_DEP}" "${SBOM_LOG_PATH}"/"${lSBOM_COMP_SOURCE}"_* || true)

    # if we have the dependency in our components we can log it via the UUID
    # if we do not have the dependency installed and available via a UUID we log an indicator that this component is not available
    if [[ "${#lSBOM_DEP_SOURCE_FILES_ARR[@]}" -gt 0 ]]; then
      for lSBOM_COMP_SOURCE_FILE in "${lSBOM_DEP_SOURCE_FILES_ARR[@]}"; do
        # get the  bom-ref from the dependency
        lSBOM_COMP_SOURCE_REF=$(jq -r '."bom-ref"' "${lSBOM_COMP_SOURCE_FILE}" || true)
        print_output "[*] Component dependency found: ${lSBOM_COMP_NAME} / ${lSBOM_COMP_REF} -> ${lSBOM_COMP_DEP} / ${lSBOM_COMP_SOURCE_REF:-NA}" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"
        lSBOM_COMP_DEPS_ARR+=("-s" "${lSBOM_COMP_SOURCE_REF}")
      done
    else
      print_output "[*] Component dependency without reference found: ${lSBOM_COMP_NAME} / ${lSBOM_COMP_REF} -> ${lSBOM_COMP_DEP} / No reference available" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"
      lSBOM_COMP_DEPS_ARR+=("-s" "NO_VALID_REF-${lSBOM_COMP_DEP}")
    fi
  done
  print_output "" "${SBOM_LOG_PATH}/SBOM_dependencies.txt"

  cat "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt" >> "${SBOM_LOG_PATH}/SBOM_dependencies.txt"
  rm "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt" || true

  jo -p ref="${lSBOM_COMP_REF}" dependsOn="$(jo -a -- "${lSBOM_COMP_DEPS_ARR[@]}")" | tee -a "${SBOM_LOG_PATH}/SBOM_deps/SBOM_dependency_${lSBOM_COMP_REF}".json
}


node_js_package_lock_parser() {
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
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lNODE_LCK_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "package*json" -type f)

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

      jq -r '.packages | keys[] as $k | "\($k);\(.[$k] | "\(.version);\(.license);\(.integrity);\(.dependencies)")"' "${lNODE_LCK_ARCHIVE}" > "${TMP_DIR}/node.lock.tmp" || true

      while IFS=";" read -r lAPP_NAME lAPP_VERS lAPP_LIC lAPP_CHECKSUM lAPP_DEPS; do
        lAPP_NAME=$(echo "${lAPP_NAME}" | rev | cut -d '/' -f1 | rev)
        [[ -z "${lAPP_NAME}" ]] && continue
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_LIC=$(clean_package_details "${lAPP_LIC}")
        lAPP_CHECKSUM=$(clean_package_details "${lAPP_CHECKSUM}")
        lAPP_DEPS=$(clean_package_details "${lAPP_DEPS}")

        [[ "${lAPP_CHECKSUM}" == "md5-"* ]] && lMD5_CHECKSUM=${lAPP_CHECKSUM}
        [[ "${lAPP_CHECKSUM}" == "sha256-"* ]] && lSHA256_CHECKSUM=${lAPP_CHECKSUM}
        [[ "${lAPP_CHECKSUM}" == "sha512-"* ]] && lSHA512_CHECKSUM=${lAPP_CHECKSUM}

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "npm" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
        STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        if command -v jo >/dev/null; then
          # add the node lock path information to our properties array:
          # Todo: in the future we should check for the package, package hashes and which files
          # are in the package
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${lNODE_LCK_ARCHIVE}" )
          lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

          build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

          # usuall build_json_hashes_arr sets HASHES_ARR globally and we unset it afterwards
          # as we have the hashes from the lock file we do it here
          export HASHES_ARR=()
          local lHASH_ALG="NA"
          [[ "${lAPP_CHECKSUM}" == "md5-"* ]] && lHASH_ALG="MD5"
          [[ "${lAPP_CHECKSUM}" == "sha256-"* ]] && lHASH_ALG="SHA-256"
          [[ "${lAPP_CHECKSUM}" == "sha512-"* ]] && lHASH_ALG="SHA-512"
          if ! [[ "${lHASH_ALG}" == "NA" ]]; then
            local lHASHES_ARRAY_INIT=("alg=${lHASH_ALG}")
            lHASHES_ARRAY_INIT+=("content=${lAPP_CHECKSUM/*-}")
            HASHES_ARR+=( "$(jo "${lHASHES_ARRAY_INIT[@]}")" )

            # create component entry - this allows adding entries very flexible:
            build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
          else
            print_output "[-] ${lPACKAGING_SYSTEM} - No hashes detected for ${lAPP_NAME} - ${lAPP_VERS} - ${lAPP_LIC} - ${lAPP_CHECKSUM} - ${lAPP_DEPS}" "no_log"
          fi
        fi

        write_log "[*] Node.js npm lock archive details: ${ORANGE}${lNODE_LCK_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lNODE_LCK_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH:-NA}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done < "${TMP_DIR}/node.lock.tmp"
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

deb_package_check() {
  # └─$ ar x liblzma5_5.6.1-1_amd64.deb --output dirname
  # └─$ tar xvf control.tar.xz
  # └─$ cat control
  #
  # Package: liblzma5
  # Source: xz-utils
  # Version: 5.6.1-1
  # Architecture: amd64
  # Maintainer: Sebastian Andrzej Siewior <sebastian@breakpoint.cc>
  # Installed-Size: 401
  # Depends: libc6 (>= 2.34)
  local lPACKAGING_SYSTEM="debian_deb"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Debian deb package parser" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lDEB_ARCHIVES_ARR=()
  local lDEB_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS=""
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM=""
  local lSHA256_CHECKSUM=""
  local lSHA512_CHECKSUM=""
  local lPURL_IDENTIFIER="NA"
  local lDEB_FILES_ARR=()
  local lDEB_FILE_ID=""
  local lDEB_FILE=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lDEB_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -type f -name "*.deb")

  if [[ "${#lDEB_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lDEB_ARCHIVES_ARR[@]}${NC} Debian deb files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lDEB_ARCHIVE in "${lDEB_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lDEB_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lDEB_ARCHIVES_ARR[@]}${NC} Debian deb files:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lDEB_ARCHIVE in "${lDEB_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lDEB_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"Debian binary package"* ]]; then
        continue
      fi

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lDEB_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lDEB_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      mkdir "${TMP_DIR}/deb_package/"
      ar x "${lDEB_ARCHIVE}" --output "${TMP_DIR}/deb_package/"

      if [[ ! -f "${TMP_DIR}/deb_package/control.tar.xz" ]]; then
        write_log "[-] No debian control.tar.xz found for ${lDEB_ARCHIVE}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      fi

      tar xf "${TMP_DIR}/deb_package/control.tar.xz" -C "${TMP_DIR}/deb_package/"

      if [[ ! -f "${TMP_DIR}/deb_package/control" ]]; then
        write_log "[-] No debian control extracted for ${lDEB_ARCHIVE}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      fi

      lAPP_NAME=$(grep "Package: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_NAME=${lAPP_NAME/*:\ }
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_ARCH=$(grep "Architecture: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_ARCH=${lAPP_ARCH/*:\ }
      lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")

      lAPP_MAINT=$(grep "Maintainer: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_MAINT=${lAPP_MAINT/*:\ }
      lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")

      lAPP_DESC=$(grep "Description: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_DESC=${lAPP_DESC/*:\ }
      lAPP_DESC=$(clean_package_details "${lAPP_DESC}")

      lAPP_LIC=$(grep "License: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_LIC=${lAPP_LIC/*:\ }
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lAPP_VERS=$(grep "Version: " "${TMP_DIR}/deb_package/control" || true)
      lAPP_VERS=${lAPP_VERS/*:\ }
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lDEB_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lDEB_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lDEB_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="debian-based"
      fi
      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "deb" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
      STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

      if command -v jo >/dev/null; then
        # add deb path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lDEB_ARCHIVE}" )
        lPROP_ARRAY_INIT_ARR+=( "source_arch:${lAPP_ARCH}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

        # add package files to properties
        if [[ ! -f "${TMP_DIR}/deb_package/data.tar.xz" ]]; then
          mapfile -t lDEB_FILES_ARR < <(tar -tvf "${TMP_DIR}/deb_package/data.tar.xz" | awk '{print $6}')
          for lDEB_FILE_ID in "${!lDEB_FILES_ARR[@]}"; do
            lDEB_FILE="${lDEB_FILES_ARR["${lDEB_FILE_ID}"]}"
            lPROP_ARRAY_INIT_ARR+=( "path:${lDEB_FILE#\.}" )
            # we limit the logging of the package files to 500 files per package
            if [[ "${lDEB_FILE_ID}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
              lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
              break
            fi
          done
        fi

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lDEB_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
      fi

      write_log "[*] Debian deb package details: ${ORANGE}${lDEB_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lDEB_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
      lPOS_RES=1
      rm -r "${TMP_DIR}/deb_package/" || true
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Debian deb archives found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Debian deb archives found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Debian archives SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Debian archives SBOM results available"
  fi
}

windows_exifparser() {
  local lPACKAGING_SYSTEM="windows_exe"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Windows Exif parser" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lEXE_ARCHIVES_ARR=()
  local lEXE_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  if [[ "${WINDOWS_EXE:-0}" -eq 1 ]]; then
    # if we already know that we have a windows binary to analyze we can check every file with the file command
    # to ensure we do not miss anything
    mapfile -t lEXE_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -type f -exec file {} \; | grep "PE32\|MSI" | cut -d ':' -f1)
  else
    # if we just search through an unknwon environment we search for exe, dll and msi files
    mapfile -t lEXE_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -type f \( -name "*.exe" -o -name "*.dll" -o -name "*.msi" \))
  fi

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
      lR_FILE=$(file -b "${lEXE_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"PE32 executable"* ]] && [[ ! "${lR_FILE}" == *"PE32+ executable"* ]]; then
        continue
      fi

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lEXE_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lEXE_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      lEXE_NAME=$(basename -s .exe "${lEXE_ARCHIVE}")
      lEXIF_LOG="${LOG_PATH_MODULE}/windows_exe_exif_data_${lEXE_NAME}.txt"

      exiftool "${lEXE_ARCHIVE}" > "${lEXIF_LOG}" || true

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

      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR//\.exe}:${lAPP_NAME//\.exe}:${lAPP_VERS:-*}:*:*:*:*:*:*"

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="windows-based"
      fi

      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "exe" "${lAPP_NAME//\.exe}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

      STRIPPED_VERSION="::${lAPP_NAME//\.exe}:${lAPP_VERS:-NA}"

      ### new SBOM json testgenerator
      if command -v jo >/dev/null; then
        # add EXE path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lEXE_ARCHIVE}" )
        [[ -n "${lAPP_ARCH}" ]] && lPROP_ARRAY_INIT_ARR+=( "source_arch:${lAPP_ARCH}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lEXE_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
      fi

      write_log "[*] Windows EXE details: ${ORANGE}${lEXE_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_link "${lEXIF_LOG}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lEXE_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
      lPOS_RES=1
      rm -f "${TMP_DIR}/windows_exe_exif_data.txt"
    done

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

python_poetry_lock_parser() {
  local lPACKAGING_SYSTEM="python_poetry_lock"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Python poetry lock identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPY_LCK_ARCHIVES_ARR=()
  local lPY_LCK_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS=""
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"
  local lAPP_FILES_ARR=()
  local lPOETRY_FILE_ENTRY=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lPY_LCK_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "poetry.lock" -type f)

  if [[ "${#lPY_LCK_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lPY_LCK_ARCHIVES_ARR[@]}${NC} Python poetry.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPY_LCK_ARCHIVE in "${lPY_LCK_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPY_LCK_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPY_LCK_ARCHIVES_ARR[@]}${NC} Python poetry.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lPY_LCK_ARCHIVE in "${lPY_LCK_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lPY_LCK_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"text"* ]]; then
        continue
      fi

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lEXE_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lEXE_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      lSHA512_CHECKSUM="$(sha512sum "${lPY_LCK_ARCHIVE}" | awk '{print $1}')"
      lMD5_CHECKSUM="$(md5sum "${lPY_LCK_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lPY_LCK_ARCHIVE}" | awk '{print $1}')"

      # source file:
      # [[package]]
      # name = "wheel"
      # version = "0.43.0"
      # description = "A built-package format for Python"
      # optional = false
      # python-versions = ">=3.8"
      # files = [
      #     {file = "wheel-0.43.0-py3-none-any.whl", hash = "sha256:55c570405f142630c6b9f72fe09d9b67cf1477fcf543ae5b8dcb1f5b7377da81"},
      #     {file = "wheel-0.43.0.tar.gz", hash = "sha256:465ef92c69fa5c5da2d1cf8ac40559a8c940886afcef87dcf14b9470862f1d85"},
      # ]
      sed ':a;N;$!ba;s/\"\n/\"|/g' "${lPY_LCK_ARCHIVE}" | sed 's/.*files = //g' | sed ':a;N;$!ba;s/,\n/ -/g' | sed ':a;N;$!ba;s/\n\[\n/|/g' | grep "^name" > "${TMP_DIR}/poetry.lock.tmp" || true
      # results in
      # name = "zipp"|version = "3.17.0"|description = "Backport of pathlib-compatible object wrapper for zip files"|optional = false|    {file = "zipp-3.17.0-py3-none-any.whl", hash = "sha256:0e923e726174922dce09c53c59ad483ff7bbb8e572e00c7f7c46b88556409f31"} -    {file = "zipp-3.17.0.tar.gz", hash = "sha256:84e64a1c28cf7e91ed2078bb8cc8c259cb19b76942096c8d7b84947690cabaf0"} -]

      while read -r lPOETRY_ENTRY; do
        lAPP_NAME=${lPOETRY_ENTRY/|*}
        lAPP_NAME=${lAPP_NAME/name\ =\ }
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_LIC="NA"

        lAPP_VERS=$(echo "${lPOETRY_ENTRY}" | cut -d\| -f2)
        lAPP_VERS=${lAPP_VERS/version\ =\ }
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lAPP_DESC=$(echo "${lPOETRY_ENTRY}" | cut -d\| -f3)
        lAPP_DESC=${lAPP_DESC/description\ =\ }
        lAPP_DESC=$(clean_package_details "${lAPP_DESC}")

        # lSHA512_CHECKSUM=$(echo "${lPOETRY_ENTRY}" | cut -d\| -f4)
        # lSHA512_CHECKSUM=${lSHA512_CHECKSUM/checksum\ =\ }
        # lSHA512_CHECKSUM=$(clean_package_versions "${lSHA512_CHECKSUM}")

        mapfile -t lAPP_FILES_ARR < <(echo "${lPOETRY_ENTRY}" | cut -d\| -f5 | sed 's/ - /\n/g')

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pypi" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

        STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # Todo: checksum

        if command -v jo >/dev/null; then
          # add deb path information to our properties array:
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${lPY_LCK_ARCHIVE}" )
          lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

          local lCNT=0
          for lPOETRY_FILE_ENTRY in "${lAPP_FILES_ARR[@]}"; do
            lPOETRY_FILE_ENTRY=$(echo "${lPOETRY_FILE_ENTRY}" | cut -d '"' -f2)
            lPROP_ARRAY_INIT_ARR+=( "path:${lPOETRY_FILE_ENTRY}" )
            # we limit the logging of the package files to 500 files per package
            if [[ "${lCNT}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
              lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
              break
            fi
          done

          build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

          # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
          # final array with all hash values
          if ! build_sbom_json_hashes_arr "${lPY_LCK_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
            print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
            continue
          fi

          # create component entry - this allows adding entries very flexible:
          build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
        fi

        write_log "[*] Python poetry.lock archive details: ${ORANGE}${lPY_LCK_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPY_LCK_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH:-NA}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done < "${TMP_DIR}/poetry.lock.tmp"
      rm -f "${TMP_DIR}/poetry.lock.tmp"
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Python poetry.lock packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Python poetry.lock package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Python poetry.lock SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Python poetry.lock SBOM results available"
  fi
}

rust_cargo_lock_parser() {
  local lPACKAGING_SYSTEM="rust_cargo_lock"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Rust cargo lock identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lRST_ARCHIVES_ARR=()
  local lRST_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS=""
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lAPP_SOURCE="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lRST_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "Cargo.lock" -type f)

  if [[ "${#lRST_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lRST_ARCHIVES_ARR[@]}${NC} Rust Cargo.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lRST_ARCHIVE in "${lRST_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lRST_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lRST_ARCHIVES_ARR[@]}${NC} Rust Cargo.lock archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lRST_ARCHIVE in "${lRST_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lRST_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"ASCII text"* ]]; then
        continue
      fi
      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lRST_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lRST_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )
      # we start with the following file structure:
      # [[package]]
      # name = "windows-sys"
      # version = "0.42.0"
      # source = "registry+https://github.com/rust-lang/crates.io-index"
      # checksum = "5a3e1820f08b8513f676f7ab6c1f99ff312fb97b553d30ff4dd86f9f15728aa7"
      # dependencies = [
      #  "windows_aarch64_gnullvm",
      #
      #  and transform it to a one liner like the following:
      #  name = "windows_x86_64_msvc" -- version = "0.42.0" -- source = "registry+https://github.com/rust-lang/crates.io-index" -- checksum = "f40009d85759725a34da6d89a94e63d7bdc50a862acf0dbc7c8e488f1edcb6f5" --

      sed ':a;N;$!ba;s/\"\n/\"|/g' "${lRST_ARCHIVE}" | grep name | sed 's/|dependencies = \[//' > "${TMP_DIR}/Cargo.lock.tmp"

      while read -r lCARGO_ENTRY; do
        lAPP_NAME=${lCARGO_ENTRY/|*}
        lAPP_NAME=${lAPP_NAME/name\ =\ }
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_LIC="NA"

        lAPP_VERS=$(echo "${lCARGO_ENTRY}" | cut -d\| -f2)
        lAPP_VERS=${lAPP_VERS/version\ =\ }
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lAPP_SOURCE=$(echo "${lCARGO_ENTRY}" | cut -d\| -f3)
        lAPP_SOURCE=${lAPP_SOURCE/source\ =\ }
        lAPP_SOURCE=$(clean_package_details "${lAPP_SOURCE}")
        lAPP_SOURCE=$(clean_package_versions "${lAPP_SOURCE}")
        # lAPP_SOURCE should be added to the properties: name: EMBA:cargo:source

        lSHA256_CHECKSUM=$(echo "${lCARGO_ENTRY}" | cut -d\| -f4)
        lSHA256_CHECKSUM=${lSHA256_CHECKSUM/checksum\ =\ }
        lSHA256_CHECKSUM=$(clean_package_details "${lSHA256_CHECKSUM}")
        lSHA256_CHECKSUM=$(clean_package_versions "${lSHA256_CHECKSUM}")

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "cargo" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

        STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        if command -v jo >/dev/null; then
          # add deb path information to our properties array:
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${lRST_ARCHIVE}" )
          lPROP_ARRAY_INIT_ARR+=( "source:${lAPP_SOURCE}" )
          lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

          build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

          # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
          # final array with all hash values
          export HASHES_ARR=()
          local lHASHES_ARRAY_INIT=("alg=SHA-256")
          lHASHES_ARRAY_INIT+=("content=${lSHA256_CHECKSUM}")
          HASHES_ARR+=( "$(jo "${lHASHES_ARRAY_INIT[@]}")" )

          # create component entry - this allows adding entries very flexible:
          build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
        fi


        write_log "[*] Rust Cargo.lock archive details: ${ORANGE}${lRST_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lRST_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done < "${TMP_DIR}/Cargo.lock.tmp"
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Rust Cargo.lock packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Rust Cargo.lock package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Rust Cargo.lock SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Rust Cargo.lock SBOM results available"
  fi
}

alpine_apk_package_check() {
  local lPACKAGING_SYSTEM="alpine_apk"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Alpine apk archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lAPK_ARCHIVES_ARR=()
  local lAPK_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
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
  local lAPK_FILES_ARR=()
  local lAPK_FILE=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lAPK_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.apk" -type f)

  if [[ "${#lAPK_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lAPK_ARCHIVES_ARR[@]}${NC} Alpine apk archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lAPK_ARCHIVE in "${lAPK_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lAPK_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lAPK_ARCHIVES_ARR[@]}${NC} Alpine apk archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lAPK_ARCHIVE in "${lAPK_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lAPK_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"gzip compressed data"* ]]; then
        continue
      fi

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lAPK_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lAPK_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      mkdir "${TMP_DIR}"/apk
      tar -xzf "${lAPK_ARCHIVE}" -C "${TMP_DIR}"/apk 2>/dev/null || print_error "[-] Extraction of APK package file ${lAPK_ARCHIVE} failed"

      if ! [[ -f "${TMP_DIR}"/apk/.PKGINFO ]]; then
        continue
      fi

      lAPP_NAME=$(grep '^pkgname = ' "${TMP_DIR}"/apk/.PKGINFO || true)
      lAPP_NAME=${lAPP_NAME/pkgname\ =\ }
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_LIC=$(grep '^license = ' "${TMP_DIR}"/apk/.PKGINFO || true)
      lAPP_LIC=${lAPP_LIC/license\ =\ }
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lAPP_VERS=$(grep '^pkgver = ' "${TMP_DIR}"/apk/.PKGINFO || true)
      lAPP_VERS=${lAPP_VERS/pkgver\ =\ }
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lAPK_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lAPK_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lAPK_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="generic"
      fi
      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "apk" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

      STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

      if command -v jo >/dev/null; then
        # add deb path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lAPK_ARCHIVE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

        mapfile -t lAPK_FILES_ARR < <(find "${TMP_DIR}"/apk)
        # add package files to properties
        if [[ "${#lAPK_FILES_ARR[@]}" -gt 0 ]]; then
          for lAPK_FILE_ID in "${!lAPK_FILES_ARR[@]}"; do
            lAPK_FILE="${lAPK_FILES_ARR["${lAPK_FILE_ID}"]}"
            lPROP_ARRAY_INIT_ARR+=( "path:${lAPK_FILE#*apk}" )
            # we limit the logging of the package files to 500 files per package
            if [[ "${lAPK_FILE_ID}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
              lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
              break
            fi
          done
        fi

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lAPK_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
      fi

      write_log "[*] Alpine apk archive details: ${ORANGE}${lAPK_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lAPK_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
      lPOS_RES=1
      rm -rf "${TMP_DIR}"/apk || true
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Alpine apk packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Alpine apk package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Alpine APK archives SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Alpine APK archives SBOM results available"
  fi
}

ruby_gem_archive_check() {
  local lPACKAGING_SYSTEM="ruby_gem"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Ruby gem archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lGEM_ARCHIVES_ARR=()
  local lGEM_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
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
  local lGEM_FILES_ARR=()
  local lGEM_FILE=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lGEM_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.gem" -type f)

  if [[ "${#lGEM_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lGEM_ARCHIVES_ARR[@]}${NC} Ruby gem archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lGEM_ARCHIVE in "${lGEM_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lGEM_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lGEM_ARCHIVES_ARR[@]}${NC} Ruby gem archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lGEM_ARCHIVE in "${lGEM_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lGEM_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"POSIX tar archive"* ]]; then
        continue
      fi

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lGEM_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lGEM_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      mkdir "${TMP_DIR}"/gems
      tar -x -f "${lGEM_ARCHIVE}" -C "${TMP_DIR}"/gems || print_error "[-] Extraction of Ruby gem file ${lGEM_ARCHIVE} failed"
      # └─$ gunzip -k metadata.gz
      # └─$ cat metadata
      # -> name, version
      if ! [[ -f "${TMP_DIR}"/gems/metadata.gz ]]; then
        write_log "[-] No metadata.gz extracted from ${lGEM_ARCHIVE}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        continue
      fi
      gunzip -k -c "${TMP_DIR}"/gems/metadata.gz > "${TMP_DIR}"/gems/metadata

      if ! [[ -f "${TMP_DIR}"/gems/metadata ]]; then
        write_log "[-] No metadata extracted from ${lGEM_ARCHIVE}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        continue
      fi

      lAPP_NAME=$(grep '^name: ' "${TMP_DIR}"/gems/metadata || true)
      lAPP_NAME=${lAPP_NAME/name:\ }
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_LIC="NA"
      # lAPP_LIC=$(grep '^licenses' "${TMP_DIR}"/gems/metadata || true)
      # lAPP_LIC=$(safe_echo "${lAPP_LIC}" | tr -dc '[:print:]')

      # grep -A1 "^version: " metadata | grep "[0-9]\."
      lAPP_VERS=$(grep -A1 '^version' "${TMP_DIR}"/gems/metadata | grep "[0-9]" || true)
      lAPP_VERS=${lAPP_VERS/*version:\ }
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lGEM_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lGEM_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lGEM_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="generic"
      fi
      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "gem" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

      STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

      if command -v jo >/dev/null; then
        # add deb path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lGEM_ARCHIVE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

        # add package files to properties
        if [[ ! -f "${TMP_DIR}/gems/data.tar.xz" ]]; then
          mapfile -t lGEM_FILES_ARR < <(tar -tvf "${TMP_DIR}/gems/data.tar.gz" | awk '{print $6}' || print_error "[-] Extraction of Ruby gem file ${lGEM_ARCHIVE} failed")
          for lGEM_FILE_ID in "${!lGEM_FILES_ARR[@]}"; do
            lGEM_FILE="${lGEM_FILES_ARR["${lGEM_FILE_ID}"]}"
            lPROP_ARRAY_INIT_ARR+=( "path:${lGEM_FILE#\.}" )
            # we limit the logging of the package files to 500 files per package
            if [[ "${lGEM_FILE_ID}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
              lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
              break
            fi
          done
        fi

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lGEM_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
      fi

      write_log "[*] Ruby gems archive details: ${ORANGE}${lGEM_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lGEM_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
      lPOS_RES=1
      rm -rf "${TMP_DIR}"/gems || true
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No Ruby gems packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No Ruby gems package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Ruby gems package files SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Ruby gemx package SBOM results available"
  fi
}

bsd_pkg_check() {
  # └─$ file boost-libs-1.84.0.pkg
  #     boost-libs-1.84.0.pkg: Zstandard compressed data (v0.8+), Dictionary ID: None
  # tar --zstd -x -f ./boost-libs-1.84.0.pkg +COMPACT_MANIFEST
  local lPACKAGING_SYSTEM="freebsd_pkg"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "FreeBSD pkg archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPKG_ARCHIVES_ARR=()
  local lPKG_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
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
  local lPKG_FILES_ARR=()
  local lPKG_FILE=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lPKG_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.pkg" -type f)

  if [[ "${#lPKG_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lPKG_ARCHIVES_ARR[@]}${NC} FreeBSD pkg archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPKG_ARCHIVE in "${lPKG_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPKG_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lPKG_ARCHIVES_ARR[@]}${NC} FreeBSD pkg archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lPKG_ARCHIVE in "${lPKG_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lPKG_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"Zstandard"* ]]; then
        continue
      fi

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPKG_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lPKG_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      tar --zstd -x -f "${lPKG_ARCHIVE}" -C "${TMP_DIR}" +COMPACT_MANIFEST || print_error "[-] Extraction of FreeBSD package file ${lPKG_ARCHIVE} failed"
      if ! [[ -f "${TMP_DIR}"/+COMPACT_MANIFEST ]]; then
        continue
      fi
      # jq -r '.' "${TMP_DIR}"/+COMPACT_MANIFEST
      # jq -r '.name' "${TMP_DIR}"/+COMPACT_MANIFEST
      # boost-libs
      #
      # jq -r '.version' "${TMP_DIR}"/+COMPACT_MANIFEST
      # 1.84.0
      #
      # jq -cr '.licenses' "${TMP_DIR}"/+COMPACT_MANIFEST
      # ["BSL"]

      lAPP_NAME=$(jq -r '.name' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_LIC=$(jq -cr '.licenses' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lAPP_VERS=$(jq -r '.version' "${TMP_DIR}"/+COMPACT_MANIFEST || true)
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lPKG_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lPKG_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lPKG_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="generic"
      fi
      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pkg" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

      STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

      if command -v jo >/dev/null; then
        # add deb path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lPKG_ARCHIVE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )
        mkdir "${TMP_DIR}"/pkg_tmp
        tar --zstd -x -f "${lPKG_ARCHIVE}" -C "${TMP_DIR}"/pkg_tmp || print_error "[-] Extraction of FreeBSD package file ${lPKG_ARCHIVE} failed"
        mapfile -t lPKG_FILES_ARR < <(find "${TMP_DIR}"/pkg_tmp)
        # add package files to properties
        if [[ "${#lPKG_FILES_ARR[@]}" -gt 0 ]]; then
          for lPKG_FILE_ID in "${!lPKG_FILES_ARR[@]}"; do
            lPKG_FILE="${lPKG_FILES_ARR["${lPKG_FILE_ID}"]}"
            lPROP_ARRAY_INIT_ARR+=( "path:${lPKG_FILE#*pkg_tmp}" )
            # we limit the logging of the package files to 500 files per package
            if [[ "${lPKG_FILE_ID}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
              lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
              break
            fi
          done
        fi
        [[ -d "${TMP_DIR}"/pkg_tmp ]] && rm -rf "${TMP_DIR}"/pkg_tmp

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lPKG_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
      fi

      write_log "[*] FreeBSD pkg archive details: ${ORANGE}${lPKG_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lPKG_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
      lPOS_RES=1
      rm -f "${TMP_DIR}"/+COMPACT_MANIFEST || true
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No FreeBSD pkg packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No FreeBSD pkg package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] FreeBSD pkg package files SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No FreeBSD pkg package SBOM results available"
  fi
}

rpm_package_check() {
  local lPACKAGING_SYSTEM="rpm_package"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "RPM archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lRPM_ARCHIVES_ARR=()
  local lRPM_ARCHIVE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
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
  local lRPM_FILES_ARR=()
  local lRPM_FILE=""

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lRPM_ARCHIVES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.rpm" -type f)

  if [[ "${#lRPM_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lRPM_ARCHIVES_ARR[@]}${NC} RPM archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lRPM_ARCHIVE in "${lRPM_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lRPM_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lRPM_ARCHIVES_ARR[@]}${NC} RPM archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lRPM_ARCHIVE in "${lRPM_ARCHIVES_ARR[@]}" ; do
      lR_FILE=$(file "${lRPM_ARCHIVE}")
      if [[ ! "${lR_FILE}" == *"RPM"* ]]; then
        continue
      fi

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lRPM_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lRPM_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      lAPP_NAME=$(rpm -qipl "${lRPM_ARCHIVE}" 2>/dev/null | grep "^Name" || true)
      lAPP_NAME=${lAPP_NAME/*:\ /}
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_LIC=$(rpm -qipl "${lRPM_ARCHIVE}" 2>/dev/null | grep "^License" || true)
      lAPP_LIC=${lAPP_LIC/*:\ /}
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lAPP_VERS=$(rpm -qipl "${lRPM_ARCHIVE}" 2>/dev/null | grep "^Version" || true)
      lAPP_VERS=${lAPP_VERS/*:\ /}
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lAPP_MAINT=$(rpm -qipl "${lRPM_ARCHIVE}" 2>/dev/null | grep "^Vendor" || true)
      lAPP_MAINT=${lAPP_MAINT/*:\ /}
      lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")

      lAPP_ARCH=$(rpm -qipl "${lRPM_ARCHIVE}" 2>/dev/null | grep "^Architecture" || true)
      lAPP_ARCH=${lAPP_ARCH/*:\ /}
      lAPP_ARCH=$(clean_package_details "${lAPP_ARCH}")

      lAPP_DESC=$(rpm -qipl "${lRPM_ARCHIVE}" 2>/dev/null | grep "^Summary" || true)
      lAPP_DESC=${lAPP_DESC/*:\ /}
      lAPP_DESC=$(clean_package_details "${lAPP_DESC}")

      lMD5_CHECKSUM="$(md5sum "${lRPM_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lRPM_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lRPM_ARCHIVE}" | awk '{print $1}')"

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="rpm-based"
      fi
      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "rpm" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")

      STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

      mapfile -t lRPM_FILES_ARR < <(rpm -qlp "${lRPM_ARCHIVE}" 2>/dev/null || true)

      if command -v jo >/dev/null; then
        # add rpm path information to our properties array:
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lRPM_ARCHIVE}" )
        lPROP_ARRAY_INIT_ARR+=( "source_arch:${lAPP_ARCH}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

        # add package files to properties
        if [[ "${#lRPM_FILES_ARR[@]}" -gt 0 ]]; then
          for lRPM_FILE_ID in "${!lRPM_FILES_ARR[@]}"; do
            lRPM_FILE="${lRPM_FILES_ARR["${lRPM_FILE_ID}"]}"
            lPROP_ARRAY_INIT_ARR+=( "path:${lRPM_FILE}" )
            # we limit the logging of the package files to 500 files per package
            if [[ "${lRPM_FILE_ID}" -gt "${SBOM_MAX_FILE_LOG}" ]]; then
              lPROP_ARRAY_INIT_ARR+=( "path:limit-to-${SBOM_MAX_FILE_LOG}-results" )
              break
            fi
          done
        fi

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lRPM_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
      fi

      write_log "[*] RPM archive details: ${ORANGE}${lRPM_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lRPM_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
      lPOS_RES=1
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No RPM packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No RPM package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] RPM packages SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No RPM package SBOM results available"
  fi
}

python_requirements() {
  local lPACKAGING_SYSTEM="python_requirements"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Python requirements identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPY_REQUIREMENTS_ARR=()
  local lPY_REQ_FILE=""
  local lR_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lPOS_RES=0
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lRES_ENTRY="NA"
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lPY_REQUIREMENTS_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "requirements*.txt" -type f)

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
        if [[ "${lRES_ENTRY}" =~ ^#.*$ ]]; then
          continue
        fi
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

        STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        # with internet we can query further details
        # └─$ curl -sH "accept: application/json" https://pypi.org/pypi/"${lAPP_NAME}"/json | jq '.info.author, .info.classifiers'
        # "Chris P"
        # [
        #   "Development Status :: 5 - Production/Stable",
        #   "License :: OSI Approved :: MIT License",

        if command -v jo >/dev/null; then
          # add the python requirement path information to our properties array:
          # Todo: in the future we should check for the package, package hashes and which files
          # are in the package
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${lPY_REQ_FILE}" )
          lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

          build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

          # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
          # final array with all hash values
          if ! build_sbom_json_hashes_arr "${lPY_REQ_FILE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
            print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
            continue
          fi

          # create component entry - this allows adding entries very flexible:
          build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
        fi

        write_log "[*] Python requirement details: ${ORANGE}${lPY_REQ_FILE}${NC} - ${ORANGE}${lAPP_NAME:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPY_REQ_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done < "${lPY_REQ_FILE}"
    done

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

python_pip_packages() {
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
        STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        if command -v jo >/dev/null; then
          # add the python requirement path information to our properties array:
          # Todo: in the future we should check for the package, package hashes and which files
          # are in the package
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${lPIP_DIST_META_PACKAGE}" )
          lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

          build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

          # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
          # final array with all hash values
          if ! build_sbom_json_hashes_arr "${lPIP_DIST_META_PACKAGE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
            print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
            continue
          fi

          # create component entry - this allows adding entries very flexible:
          build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
        fi

        write_log "[*] Found PIP package ${ORANGE}${lAPP_NAME}${NC} - Version ${ORANGE}${lAPP_VERS}${NC} in PIP dist-packages directory ${ORANGE}${lPIP_DIST_META_PACKAGE}${NC} - Source ${ORANGE}METADATA${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_DIST_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
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
        STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        if command -v jo >/dev/null; then
          # add the python requirement path information to our properties array:
          # Todo: in the future we should check for the package, package hashes and which files
          # are in the package
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${lPIP_DIST_META_PACKAGE}" )
          lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

          build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

          # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
          # final array with all hash values
          if ! build_sbom_json_hashes_arr "${lPIP_DIST_META_PACKAGE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
            print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
            continue
          fi

          # create component entry - this allows adding entries very flexible:
          build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
        fi

        write_log "[*] Found PIP package ${ORANGE}${lAPP_NAME}${NC} - Version ${ORANGE}${lAPP_VERS}${NC} in PIP dist-packages directory ${ORANGE}${lPIP_DIST_META_PACKAGE}${NC} - Source ${ORANGE}PKG-INFO${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_DIST_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
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

        lMD5_CHECKSUM="$(md5sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pypi" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
        STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        if command -v jo >/dev/null; then
          # add the python requirement path information to our properties array:
          # Todo: in the future we should check for the package, package hashes and which files
          # are in the package
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${lPIP_SITE_META_PACKAGE}" )
          lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

          build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

          # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
          # final array with all hash values
          if ! build_sbom_json_hashes_arr "${lPIP_SITE_META_PACKAGE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
            print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
            continue
          fi

          # create component entry - this allows adding entries very flexible:
          build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
        fi

        write_log "[*] Found PIP package ${ORANGE}${lAPP_NAME}${NC} - Version ${ORANGE}${lAPP_VERS}${NC} in PIP dist-packages directory ${ORANGE}${lPIP_SITE_META_PACKAGE}${NC} - Source ${ORANGE}METADATA${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_SITE_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
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

        lMD5_CHECKSUM="$(md5sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPIP_SITE_META_PACKAGE}" | awk '{print $1}')"

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="generic"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "pypi" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
        STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        if command -v jo >/dev/null; then
          # add the python requirement path information to our properties array:
          # Todo: in the future we should check for the package, package hashes and which files
          # are in the package
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${lPIP_SITE_META_PACKAGE}" )
          lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

          build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

          # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
          # final array with all hash values
          if ! build_sbom_json_hashes_arr "${lPIP_SITE_META_PACKAGE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
            print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
            continue
          fi

          # create component entry - this allows adding entries very flexible:
          build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
        fi

        write_log "[*] Found PIP package ${ORANGE}${lAPP_NAME}${NC} - Version ${ORANGE}${lAPP_VERS}${NC} in PIP dist-packages directory ${ORANGE}${lPIP_SITE_META_PACKAGE}${NC} - Source ${ORANGE}PKG-INFO${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPIP_SITE_META_PACKAGE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
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

java_archives_check() {
  local lPACKAGING_SYSTEM="java_archive"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Java archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lJAVA_ARCHIVES_ARR=()
  local lJAVA_ARCHIVES_JAR_ARR=()
  local lJAVA_ARCHIVES_WAR_ARR=()
  local lJAVA_ARCHIVE=""
  local lJ_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lIMPLEMENT_TITLE="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lJAVA_ARCHIVES_JAR_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.jar" -type f)
  mapfile -t lJAVA_ARCHIVES_WAR_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name "*.war" -type f)
  lJAVA_ARCHIVES_ARR=( "${lJAVA_ARCHIVES_JAR_ARR[@]}" "${lJAVA_ARCHIVES_WAR_ARR[@]}" )

  if [[ "${#lJAVA_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lJAVA_ARCHIVES_ARR[@]}${NC} Java archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lJAVA_ARCHIVE in "${lJAVA_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lJAVA_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lJAVA_ARCHIVES_ARR[@]}${NC} Java archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lJAVA_ARCHIVE in "${lJAVA_ARCHIVES_ARR[@]}" ; do
      lJ_FILE=$(file "${lJAVA_ARCHIVE}")
      if [[ ! "${lJ_FILE}" == *"Java archive data"* && ! "${lJ_FILE}" == *"Zip archive"* ]]; then
        continue
      fi

      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lJAVA_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      lAPP_NAME=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Application-Name" || true)
      lAPP_NAME=${lAPP_NAME/*:\ /}
      lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

      lAPP_LIC=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "License" || true)
      lAPP_LIC=${lAPP_LIC/*:\ /}
      lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

      lIMPLEMENT_TITLE=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Implementation-Title" || true)
      lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE/*:/}
      lIMPLEMENT_TITLE=$(clean_package_details "${lIMPLEMENT_TITLE}")

      lAPP_VERS=$(unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF | grep "Implementation-Version" || true)
      lAPP_VERS=${lAPP_VERS/*:\ /}
      lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
      lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

      lMD5_CHECKSUM="$(md5sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
      lSHA256_CHECKSUM="$(sha256sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
      lSHA512_CHECKSUM="$(sha512sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"

      if [[ -z "${lAPP_NAME}" && -z "${lAPP_LIC}" && -z "${lIMPLEMENT_TITLE}" && -z "${lAPP_VERS}" ]]; then
        continue
      fi
      if [[ -z "${lAPP_NAME}" && -n "${lIMPLEMENT_TITLE}" ]]; then
        # in case APP_NAME is not set but we have an lIMPLEMENT_TITLE we use this
        lAPP_NAME="${lIMPLEMENT_TITLE}"
      fi

      lAPP_VENDOR="${lAPP_NAME}"
      lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

      if [[ -z "${lOS_IDENTIFIED}" ]]; then
        lOS_IDENTIFIED="generic"
      fi
      lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "java" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
      STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

      if command -v jo >/dev/null; then
        # add the python requirement path information to our properties array:
        # Todo: in the future we should check for the package, package hashes and which files
        # are in the package
        local lPROP_ARRAY_INIT_ARR=()
        lPROP_ARRAY_INIT_ARR+=( "source_path:${lJAVA_ARCHIVE}" )
        lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

        build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

        # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
        # final array with all hash values
        if ! build_sbom_json_hashes_arr "${lJAVA_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
          print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
          continue
        fi

        # create component entry - this allows adding entries very flexible:
        build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
      fi

      write_log "[*] Java archive details: ${ORANGE}${lJAVA_ARCHIVE}${NC} - ${ORANGE}${lAPP_NAME:-NA} / ${lIMPLEMENT_TITLE:-NA}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
      write_csv_log "${lPACKAGING_SYSTEM}" "${lJAVA_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
      lPOS_RES=1
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No JAVA packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No JAVA package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] Java package SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Java package SBOM results available"
  fi
}

debian_status_files_analysis() {
  local lPACKAGING_SYSTEM="debian_pkg_mgmt"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Debian package management identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lDEBIAN_MGMT_STATUS_ARR=()
  local lPACKAGE_FILE=""
  local lDEBIAN_PACKAGES_ARR=()
  local lPACKAGE_VERSION=""
  local lPACKAGE=""
  local lVERSION=""
  local lINSTALL_STATE=""
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
  local lAPP_DEPS=""
  local lAPP_DEPS_ARR=()

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

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

      if grep -q "Package: " "${lPACKAGE_FILE}"; then
        mapfile -t lDEBIAN_PACKAGES_ARR < <(grep "^Package: \|^Status: \|^Version: \|^Maintainer: \|^Architecture: \|^Description: \|^Depends: " "${lPACKAGE_FILE}" | sed -z 's/\nVersion: / - Version: /g' \
          | sed -z 's/\nStatus: / - Status: /g' | sed -z 's/\nMaintainer: / - Maintainer: /g' | sed -z 's/\nDescription: / - Description: /g' | sed -z 's/\nArchitecture: / - Architecture: /g' \
          | sed -z 's/\nDepends: / - Depends: /g')
        write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_log "[*] Found debian package details in ${ORANGE}${lPACKAGE_FILE}${NC}:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

        lMD5_CHECKSUM="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPACKAGE_FILE}" | awk '{print $1}')"

        for lPACKAGE_VERSION in "${lDEBIAN_PACKAGES_ARR[@]}" ; do
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
            continue
          fi

          if [[ -z "${lOS_IDENTIFIED}" ]]; then
            lOS_IDENTIFIED="debian-based"
          fi
          lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "deb" "${lPACKAGE:-NA}" "${lVERSION:-NA}" "${lAPP_ARCH:-NA}")
          lAPP_VENDOR="${lPACKAGE}"
          lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lPACKAGE}:${lVERSION}:*:*:*:*:*:*"
          STRIPPED_VERSION="::${lPACKAGE}:${lVERSION:-NA}"

          ### new SBOM json testgenerator
          if command -v jo >/dev/null; then
            # add source file path information to our properties array:
            local lPROP_ARRAY_INIT_ARR=()
            lPROP_ARRAY_INIT_ARR+=( "source_path:${lPACKAGE_FILE}" )
            lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )
            if [[ "${#lAPP_DEPS_ARR[@]}" -gt 0 ]]; then
              for lAPP_DEP in "${lAPP_DEPS_ARR[@]}"; do
                lPROP_ARRAY_INIT_ARR+=( "dependency:${lAPP_DEP#\ }" )
              done
            fi

            build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

            # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
            # final array with all hash values
            if ! build_sbom_json_hashes_arr "${lPACKAGE_FILE}" "${lPACKAGE:-NA}" "${lVERSION:-NA}"; then
              print_output "[*] Already found results for ${lPACKAGE} / ${lVERSION}" "no_log"
              continue
            fi

            # create component entry - this allows adding entries very flexible:
            build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lPACKAGE:-NA}" "${lVERSION:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
          fi

          write_log "[*] Debian package details: ${ORANGE}${lPACKAGE_FILE}${NC} - ${ORANGE}${lPACKAGE}${NC} - ${ORANGE}${lVERSION}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          write_csv_log "${lPACKAGING_SYSTEM}" "${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lPACKAGE}" "${lVERSION}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
          lPOS_RES=1
        done
      fi
    done

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

openwrt_control_files_analysis() {
  local lPACKAGING_SYSTEM="OpenWRT"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "OpenWRT package management identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lPACKAGE_FILE=""
  local lPACKAGE_VERSION=""
  local lAPP_NAME=""
  local lAPP_VERS=""
  local lVERSION=""
  local lAPP_LIC="NA"
  local lAPP_ARCH=""
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lAPP_DEPS_ARR=()
  local lAPP_DEP=""
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lOPENWRT_MGMT_CONTROL_ARR=()
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  mapfile -t lOPENWRT_MGMT_CONTROL_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -path "*opkg/info/*.control" -type f)

  if [[ "${#lOPENWRT_MGMT_CONTROL_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lOPENWRT_MGMT_CONTROL_ARR[@]}${NC} OpenWRT package management files." "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lPACKAGE_FILE in "${lOPENWRT_MGMT_CONTROL_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lPACKAGE_FILE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lOPENWRT_MGMT_CONTROL_ARR[@]}${NC} OpenWRT package management files." "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lPACKAGE_FILE in "${lOPENWRT_MGMT_CONTROL_ARR[@]}" ; do
      # if we have found multiple status files but all are the same -> we do not need to test duplicates
      lPKG_MD5="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lPACKAGE_FILE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      if grep -q "Package: " "${lPACKAGE_FILE}"; then
        lMD5_CHECKSUM="$(md5sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        lSHA256_CHECKSUM="$(sha256sum "${lPACKAGE_FILE}" | awk '{print $1}')"
        lSHA512_CHECKSUM="$(sha512sum "${lPACKAGE_FILE}" | awk '{print $1}')"

        lAPP_NAME=$(grep "^Package: " "${lPACKAGE_FILE}" | awk '{print $2}' | tr -dc '[:print:]' || true)
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        lAPP_VERS=$(grep "^Version: " "${lPACKAGE_FILE}" | awk '{print $2}' | tr -dc '[:print:]' || true)
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
        lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")

        lAPP_MAINT=$(grep "^Maintainer: " "${lPACKAGE_FILE}" | cut -d ':' -f2- | tr -dc '[:print:]' || true)
        lAPP_MAINT=${lAPP_MAINT#\ }
        lAPP_MAINT=$(clean_package_details "${lAPP_MAINT}")
        lAPP_MAINT=$(clean_package_versions "${lAPP_MAINT}")

        lAPP_DESC=$(grep "^Description: " "${lPACKAGE_FILE}" | cut -d ':' -f2- | tr -dc '[:print:]' || true)
        lAPP_DESC=${lAPP_DESC#\ }
        lAPP_DESC=$(clean_package_details "${lAPP_DESC}")
        lAPP_DESC=$(clean_package_versions "${lAPP_DESC}")

        mapfile -t lAPP_DEPS_ARR < <(grep "^Depends: " "${lPACKAGE_FILE}" | cut -d ':' -f2- | tr -dc '[:print:]' | tr ',' '\n' | sort -u || true)

        lAPP_VENDOR="${lAPP_NAME}"
        lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

        if [[ -z "${lOS_IDENTIFIED}" ]]; then
          lOS_IDENTIFIED="openwrt"
        fi
        lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "opkg" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
        STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS}"

        if command -v jo >/dev/null; then
          # add the python requirement path information to our properties array:
          # Todo: in the future we should check for the package, package hashes and which files
          # are in the package
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${lPACKAGE_FILE}" )
          lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${STRIPPED_VERSION}" )

          if [[ "${#lAPP_DEPS_ARR[@]}" -gt 0 ]]; then
            for lAPP_DEP in "${lAPP_DEPS_ARR[@]}"; do
              lPROP_ARRAY_INIT_ARR+=( "dependency:${lAPP_DEP#\ }" )
            done
          fi

          # if we have the list file also we can add all the paths provided by the package
          if [[ -f "${lPACKAGE_FILE/\.control/\.list}" ]]; then
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
            done < "${lPACKAGE_FILE/control/list}"
          fi

          build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

          # build_json_hashes_arr sets lHASHES_ARR globally and we unset it afterwards
          # final array with all hash values
          if ! build_sbom_json_hashes_arr "${lPACKAGE_FILE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
            print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
            continue
          fi

          # create component entry - this allows adding entries very flexible:
          build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
        fi

        write_log "[*] OpenWRT package details: ${ORANGE}${lPACKAGE_FILE}${NC} - ${ORANGE}${lAPP_NAME}${NC} - ${ORANGE}${lAPP_VERS}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      fi
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No OpenWRT packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No OpenWRT package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${lPOS_RES}" -eq 1 ]]; then
    print_output "[+] OpenWRT packages SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No OpenWRT packages SBOM results available"
  fi
}

rpm_package_mgmt_analysis() {
  local lPACKAGING_SYSTEM="RPM_pkg_mgmt"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "RPM package management identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if ! command -v rpm > /dev/null; then
    write_log "[-] RPM command not found ... not executing RPM test module" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    return
  fi

  local lRPM_PACKAGE_DBS_ARR=()
  local lPACKAGE_FILE=""
  local lRPM_PACKAGES_ARR=()
  local lRPM_DIR=""
  local lPACKAGE_AND_VERSION=""
  local lAPP_NAME=""
  local lAPP_VERS=""
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lPOS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lAPP_DEPS_ARR=()
  local lAPP_DEP=""
  local lAPP_FILE=""
  local lAPP_FILE_ID=""
  local lAPP_FILES_ARR=()

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""

  # this handles the Berkley database
  mapfile -t lRPM_PACKAGE_DBS_BRK_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -path "*rpm/Packages" -type f)
  # this handles the sqlite database
  mapfile -t lRPM_PACKAGE_DBS_SQLITE_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -path "*rpm/rpmdb.sqlite" -type f)
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
        write_log "[*] Testing RPM directory ${lRPM_DIR} with PACKAGE_AND_VERSION: ${lPACKAGE_AND_VERSION}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        lAPP_VERS=$(rpm -qi --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" | grep "^Version" || true)
        lAPP_VERS="${lAPP_VERS/*:\ }"
        lAPP_VERS=$(clean_package_details "${lAPP_VERS}")

        lAPP_NAME=$(rpm -qi --dbpath "${lRPM_DIR}" "${lPACKAGE_AND_VERSION}" | grep "^Name" || true)
        lAPP_NAME="${lAPP_NAME/*:\ }"
        lAPP_NAME=$(clean_package_details "${lAPP_NAME}")

        if [[ -z "${lAPP_NAME}" ]]; then
          continue
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
        STRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

        if command -v jo >/dev/null; then
          # add the python requirement path information to our properties array:
          # Todo: in the future we should check for the package, package hashes and which files
          # are in the package
          local lPROP_ARRAY_INIT_ARR=()
          lPROP_ARRAY_INIT_ARR+=( "source_path:${lPACKAGE_FILE}" )

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
          if ! build_sbom_json_hashes_arr "${lPACKAGE_FILE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}"; then
            print_output "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS}" "no_log"
            continue
          fi

          # create component entry - this allows adding entries very flexible:
          build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_MAINT:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"
        fi

        write_log "[*] RPM package details: ${ORANGE}${lAPP_NAME}${NC} - ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
        write_csv_log "${lPACKAGING_SYSTEM}" "${lRPM_DIR} / ${lPACKAGE_FILE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${STRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
        lPOS_RES=1
      done
    done

    if [[ "${lPOS_RES}" -eq 0 ]]; then
      write_log "[-] No RPM packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
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

clean_package_details() {
  local lCLEAN_ME_UP="${1}"

  lCLEAN_ME_UP=$(safe_echo "${lCLEAN_ME_UP}" | tr -dc '[:print:]')
  lCLEAN_ME_UP=${lCLEAN_ME_UP/\"}
  # Turn on extended globbing
  shopt -s extglob
  lCLEAN_ME_UP=${lCLEAN_ME_UP//+([\[\'\"\/\<\>\(\)\]])}
  lCLEAN_ME_UP=${lCLEAN_ME_UP##+( )}
  lCLEAN_ME_UP=${lCLEAN_ME_UP%%+( )}
  # Turn off extended globbing
  shopt -u extglob
  lCLEAN_ME_UP=${lCLEAN_ME_UP,,}
  lCLEAN_ME_UP=${lCLEAN_ME_UP//,/\.}
  lCLEAN_ME_UP=${lCLEAN_ME_UP//\ /_}
  echo "${lCLEAN_ME_UP}"
}

clean_package_versions() {
  local lVERSION="${1:-}"
  local STRIPPED_VERSION=""

  # usually we get a version like 1.2.3-4 or 1.2.3-0kali1bla or 1.2.3-unknown
  # this is a quick approach to clean this version identifier
  # there is a lot of room for future improvement
  STRIPPED_VERSION=$(safe_echo "${lVERSION}" | sed -r 's/-[0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-unknown$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+kali[0-9]+.*$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+ubuntu[0-9]+.*$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+build[0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+\.[0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+\.[a-d][0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/:[0-9]:/:/g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/^[0-9]://g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | tr -dc '[:print:]')
  STRIPPED_VERSION=${STRIPPED_VERSION//,/\.}
  echo "${STRIPPED_VERSION}"
}
