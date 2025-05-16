#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Searches for files with a specified string pattern inside.
export THREAD_PRIO=0

S106_deep_key_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Deep analysis of files for interesting key material"
  pre_module_reporter "${FUNCNAME[0]}"

  local lPATTERN=""
  local lPATTERNS=""
  lPATTERNS="$(config_list "${CONFIG_DIR}""/deep_key_search.cfg" "")"

  export PATTERN_LIST_ARR=()
  readarray -t PATTERN_LIST_ARR < <(printf '%s' "${lPATTERNS}")

  for lPATTERN in "${PATTERN_LIST_ARR[@]}";do
    print_output "[*] Pattern: ${lPATTERN}"
  done

  export SORTED_OCC_LIST=()

  deep_key_search
  deep_key_reporter

  module_end_log "${FUNCNAME[0]}" "${#SORTED_OCC_LIST[@]}"
}

deep_key_search() {
  local lGREP_PATTERN_COMMAND_ARR=()
  local lPATTERN=""
  local lMATCH_FILES_ARR=()
  local lMATCH_FILE=""
  local lFILE_NAME=""
  local lF_COUNT=0

  for lPATTERN in "${PATTERN_LIST_ARR[@]}" ; do
    lGREP_PATTERN_COMMAND_ARR=( "${lGREP_PATTERN_COMMAND_ARR[@]}" "-e" ".{0,15}""${lPATTERN}"".{0,15}" )
  done
  print_ln
  readarray -t lMATCH_FILES_ARR < <(grep -E -l -r "${lGREP_PATTERN_COMMAND_ARR[@]}" -D skip "${LOG_DIR}"/firmware 2>/dev/null || true)
  if [[ ${#lMATCH_FILES_ARR[@]} -gt 0 ]] ; then
    for lMATCH_FILE in "${lMATCH_FILES_ARR[@]}" ; do
      if ! [[ -f "${lMATCH_FILE}" ]]; then
        continue
      fi

      lFILE_NAME=$(basename "${lMATCH_FILE}")
      # we just write the FILE_PATH in the beginning to the file (e.g., the log file is not available -> we create it)
      if ! [[ -f "${LOG_PATH_MODULE}"/deep_key_search_"${lFILE_NAME}".txt ]]; then
        write_log "[*] FILE_PATH: $(print_path "${lMATCH_FILE}")" "${LOG_PATH_MODULE}/deep_key_search_${lFILE_NAME}.txt"
        write_log "" "${LOG_PATH_MODULE}/deep_key_search_${lFILE_NAME}.txt"
      fi
      grep -A 2 --no-group-separator -E -n -a -h "${lGREP_PATTERN_COMMAND_ARR[@]}" -D skip "${lMATCH_FILE}" 2>/dev/null | tr -d '\0' >> "${LOG_PATH_MODULE}"/deep_key_search_"${lFILE_NAME}".txt || true
      print_output "[+] $(print_path "${lMATCH_FILE}")"
      write_link "${LOG_PATH_MODULE}""/deep_key_search_""${lFILE_NAME}"".txt"
      local lD_S_FINDINGS=""
      for lPATTERN in "${PATTERN_LIST_ARR[@]}" ; do
        lF_COUNT=$(grep -c "${lPATTERN}" "${LOG_PATH_MODULE}"/deep_key_search_"${lFILE_NAME}"".txt" || true)
        if [[ ${lF_COUNT} -gt 0 ]] ; then
          lD_S_FINDINGS="${lD_S_FINDINGS}""    ""${lF_COUNT}""\t:\t""${lPATTERN}""\n"
        fi
      done
      print_output "${lD_S_FINDINGS}"
      write_log "" "${LOG_PATH_MODULE}/deep_key_search_${lFILE_NAME}.txt"
      write_log "[*] Deep search results:" "${LOG_PATH_MODULE}/deep_key_search_${lFILE_NAME}.txt"
      write_log "${lD_S_FINDINGS}" "${LOG_PATH_MODULE}/deep_key_search_${lFILE_NAME}.txt"
    done
  fi
}

deep_key_reporter() {
  local lOCC_ARR=()
  local lOCC_ENTRY=""
  local lP_COUNT=0

  for lPATTERN in "${PATTERN_LIST_ARR[@]}" ; do
    lP_COUNT=$(grep -c "${lPATTERN}" "${LOG_PATH_MODULE}"/deep_key_search_* 2>/dev/null | cut -d: -f2 | awk '{ SUM += $1} END { print SUM }' || true )
    if [[ "${lP_COUNT}" -gt 0 ]]; then
      lOCC_ARR=( "${lOCC_ARR[@]}" "${lP_COUNT}"": ""${lPATTERN}" )
    fi
  done

  if [[ "${#PATTERN_LIST_ARR[@]}" -gt 0 ]] ; then
    if [[ "${#lOCC_ARR[@]}" -gt 0 ]] ; then
      print_ln
      print_output "[*] Occurences of pattern:"
      mapfile -t SORTED_OCC_LIST < <(printf '%s\n' "${lOCC_ARR[@]}" | sort -r --version-sort)
      if [[ "${#SORTED_OCC_LIST[@]}" -gt 0 ]]; then
        for lOCC_ENTRY in "${SORTED_OCC_LIST[@]}"; do
          print_output "$( indent "$(orange "${lOCC_ENTRY}" )")""\n"
        done
      fi
    fi
  fi
}
