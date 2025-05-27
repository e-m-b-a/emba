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

S08_main_package_sbom() {
  module_log_init "${FUNCNAME[0]}"
  module_title "EMBA central package SBOM environment"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0
  local lWAIT_PIDS_S08_ARR=()
  local lOS_IDENTIFIED=""
  local lS08_SUBMODULE_PATH="${MOD_DIR}/S08_main_package_sbom_modules"
  export S08_DUPLICATES_LOG="${LOG_PATH_MODULE}/SBOM_duplicates.log"
  local lS08_SUBMODULES_FILES_ARR=()
  local lS08_SUBMODULE=""

  mapfile -t lS08_SUBMODULES_FILES_ARR < <(find "${lS08_SUBMODULE_PATH}" -type f -name "S08_*.sh")
  for lS08_SUBMODULE in "${lS08_SUBMODULES_FILES_ARR[@]}"; do
    print_output "[*] SBOM - loading sub module ${lS08_SUBMODULE}" "no_log"
    # shellcheck source=/dev/null
    source "${lS08_SUBMODULE}"
  done

  # shellcheck disable=SC2153
  check_for_s08_csv_log "${S08_CSV_LOG}"

  lOS_IDENTIFIED=$(distri_check)

  local lS08_MODULE=""

  if [[ ${THREADED} -eq 1 ]]; then
    for lS08_MODULE in "${S08_MODULES_ARR[@]}"; do
      print_output "[*] SBOM - starting ${lS08_MODULE}" "no_log"
      "${lS08_MODULE}" "${lOS_IDENTIFIED}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_S08_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_S08_ARR[@]}"
  else
    for lS08_MODULE in "${S08_MODULES_ARR[@]}"; do
      "${lS08_MODULE}" "${lOS_IDENTIFIED}"
    done
  fi

  build_dependency_tree

  # shellcheck disable=SC2153
  [[ -s "${S08_CSV_LOG}" ]] && lNEG_LOG=1
  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

build_dependency_tree() {
  if [[ ! -d "${SBOM_LOG_PATH}" ]]; then
    return
  fi

  sub_module_title "SBOM dependency tree builder"

  local lSBOM_COMPONENT_FILES_ARR=()
  local lSBOM_COMP=""

  local lWAIT_PIDS_S08_DEP_ARR=()

  mapfile -t lSBOM_COMPONENT_FILES_ARR < <(find "${SBOM_LOG_PATH}" -maxdepth 1 -type f -name "*.json")

  for lSBOM_COMP in "${lSBOM_COMPONENT_FILES_ARR[@]}"; do
    [[ ! -f "${lSBOM_COMP}" ]] && continue
    # to speed up the dep tree we are working threaded for every componentfile and write into dedicated json files
    # "${SBOM_LOG_PATH}/SBOM_deps/SBOM_dependency_${lSBOM_COMP_REF}".json which we can put together in f15
    create_comp_dep_tree_threader "${lSBOM_COMP}" &
    lWAIT_PIDS_S08_DEP_ARR+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S08_DEP_ARR
  done
  wait_for_pid "${lWAIT_PIDS_S08_DEP_ARR[@]}"

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
  local lSBOM_INVALID_COM_REF=""

  # extract needed metadata (VERS not really needed but nice to show)
  lSBOM_COMP_NAME=$(jq -r .name "${lSBOM_COMP}" || true)
  lSBOM_COMP_REF=$(jq -r '."bom-ref"' "${lSBOM_COMP}" || true)
  lSBOM_COMP_VERS=$(jq -r .version "${lSBOM_COMP}" || true)
  # Source is only used to ensure we check only matching sources (eg. check debian packages against debian sources)
  lSBOM_COMP_SOURCE=$(jq -r .group "${lSBOM_COMP}" || true)

  if [[ -z "${lSBOM_COMP_NAME}" || -z "${lSBOM_COMP_REF}" ]]; then
    return
  fi

  write_log "[*] Source file: ${lSBOM_COMP}" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"
  write_log "[*] Component: ${lSBOM_COMP_NAME} / ${lSBOM_COMP_VERS} / ${lSBOM_COMP_SOURCE} / ${lSBOM_COMP_REF}" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"

  # lets search for dependencies in every SBOM component file we have and store it in lSBOM_COMP_DEPS_ARR
  mapfile -t lSBOM_COMP_DEPS_FILES_ARR < <(jq -rc '.properties[] | select(.name | endswith(":dependency")).value' "${lSBOM_COMP}" || true)
  if [[ "${#lSBOM_COMP_DEPS_FILES_ARR[@]}" -eq 0 ]]; then
    return
  fi

  if [[ ! -d "${SBOM_LOG_PATH%\/}/SBOM_deps" ]]; then
    mkdir "${SBOM_LOG_PATH%\/}/SBOM_deps" 2>/dev/null || true
  fi

  # now we check every dependency for the current component
  for lSBOM_COMP_DEP in "${lSBOM_COMP_DEPS_FILES_ARR[@]}"; do
    # lets extract the name of the dependency
    lSBOM_COMP_DEP="${lSBOM_COMP_DEP//\'}"
    lSBOM_COMP_DEP="${lSBOM_COMP_DEP/\ *}"
    lSBOM_COMP_DEP="${lSBOM_COMP_DEP/\(*}"

    # check all sbom component files from this group (e.g. debian_pkg_mgmt) for the dependency as name:
    mapfile -t lSBOM_DEP_SOURCE_FILES_ARR < <(grep -l "name\":\"${lSBOM_COMP_DEP}\"" "${SBOM_LOG_PATH}"/"${lSBOM_COMP_SOURCE}"_* || true)

    # if we have the dependency in our components we can log it via the UUID
    # if we do not have the dependency installed and available via a UUID we log an indicator that this component is not available
    if [[ "${#lSBOM_DEP_SOURCE_FILES_ARR[@]}" -gt 0 ]]; then
      for lSBOM_COMP_SOURCE_FILE in "${lSBOM_DEP_SOURCE_FILES_ARR[@]}"; do
        # get the  bom-ref from the dependency
        lSBOM_COMP_SOURCE_REF=$(jq -r '."bom-ref"' "${lSBOM_COMP_SOURCE_FILE}" || true)
        write_log "[*] Component dependency found: ${lSBOM_COMP_NAME} / ${lSBOM_COMP_REF} -> ${lSBOM_COMP_DEP} / ${lSBOM_COMP_SOURCE_REF:-NA}" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"
        if ! [[ "${lSBOM_COMP_DEPS_ARR[*]}" == *"${lSBOM_COMP_SOURCE_REF}"* ]]; then
          lSBOM_COMP_DEPS_ARR+=("-s" "${lSBOM_COMP_SOURCE_REF}")
        fi
      done
    else
      write_log "[*] Component dependency without reference found: ${lSBOM_COMP_NAME} / ${lSBOM_COMP_REF} -> ${lSBOM_COMP_DEP} / No valid reference available" "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt"
      # this is only used to have a unique identifier
      lSBOM_INVALID_COM_REF="$(uuidgen)"
      lSBOM_COMP_DEPS_ARR+=("-s" "${lSBOM_INVALID_COM_REF}-NO_VALID_REF-${lSBOM_COMP_DEP}")
    fi
  done
  write_log "" "${SBOM_LOG_PATH}/SBOM_dependencies.txt"

  cat "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt" >> "${SBOM_LOG_PATH}/SBOM_dependencies.txt"
  rm "${TMP_DIR}/SBOM_dependencies_${lSBOM_COMP_REF}.txt" || true

  jo -p ref="${lSBOM_COMP_REF}" dependsOn="$(jo -a -- "${lSBOM_COMP_DEPS_ARR[@]}")" >> "${SBOM_LOG_PATH}/SBOM_deps/SBOM_dependency_${lSBOM_COMP_REF}".json
}

clean_package_details() {
  local lCLEAN_ME_UP="${1}"

  lCLEAN_ME_UP=$(safe_echo "${lCLEAN_ME_UP}")
  lCLEAN_ME_UP="${lCLEAN_ME_UP//[![:print:]]/}"
  lCLEAN_ME_UP="${lCLEAN_ME_UP/\"}"
  # Turn on extended globbing
  shopt -s extglob
  lCLEAN_ME_UP=${lCLEAN_ME_UP//+([\[\'\"\;\#\%\/\<\>\(\)\]])}
  lCLEAN_ME_UP=${lCLEAN_ME_UP##+( )}
  lCLEAN_ME_UP=${lCLEAN_ME_UP%%+( )}
  lCLEAN_ME_UP=${lCLEAN_ME_UP//\ /_}
  lCLEAN_ME_UP=${lCLEAN_ME_UP//+(_)/_}
  # Turn off extended globbing
  shopt -u extglob
  lCLEAN_ME_UP=${lCLEAN_ME_UP,,}
  lCLEAN_ME_UP=${lCLEAN_ME_UP//,/\.}
  echo "${lCLEAN_ME_UP}"
}

clean_package_versions() {
  local lVERSION="${1:-}"
  local lSTRIPPED_VERSION=""

  # usually we get a version like 1.2.3-4 or 1.2.3-0kali1bla or 1.2.3-unknown
  # this is a quick approach to clean this version identifier
  # there is a lot of room for future improvement
  lSTRIPPED_VERSION=$(safe_echo "${lVERSION}" | sed -r 's/-[0-9]+$//g')
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-unknown$//g')
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-[0-9]+kali[0-9]+.*$//g')
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-[0-9]+ubuntu[0-9]+.*$//g')
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-[0-9]+build[0-9]+$//g')
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-[0-9]+\.[0-9]+$//g')
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/-[0-9]+\.[a-d][0-9]+$//g')
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/:[0-9]:/:/g')
  lSTRIPPED_VERSION=$(safe_echo "${lSTRIPPED_VERSION}" | sed -r 's/^[0-9]://g')
  lSTRIPPED_VERSION=${lSTRIPPED_VERSION//,/\.}
  echo "${lSTRIPPED_VERSION//[![:print:]]/}"
}
