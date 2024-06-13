#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2024 Siemens Energy AG
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

  local PATTERNS=""
  PATTERNS="$(config_list "${CONFIG_DIR}""/deep_key_search.cfg" "")"

  readarray -t PATTERN_LIST < <(printf '%s' "${PATTERNS}")

  for PATTERN in "${PATTERN_LIST[@]}";do
    print_output "[*] Pattern: ${PATTERN}"
  done

  export SORTED_OCC_LIST=()

  deep_key_search
  deep_key_reporter

  module_end_log "${FUNCNAME[0]}" "${#SORTED_OCC_LIST[@]}"
}

deep_key_search() {
  local GREP_PATTERN_COMMAND=()
  local PATTERN=""
  local MATCH_FILES=()
  local MATCH_FILE=""
  local FILE_NAME=""
  local F_COUNT=0

  for PATTERN in "${PATTERN_LIST[@]}" ; do
    GREP_PATTERN_COMMAND=( "${GREP_PATTERN_COMMAND[@]}" "-e" ".{0,15}""${PATTERN}"".{0,15}" )
  done
  print_ln
  readarray -t MATCH_FILES < <(grep -E -l -r "${GREP_PATTERN_COMMAND[@]}" -D skip "${LOG_DIR}"/firmware 2>/dev/null || true)
  if [[ ${#MATCH_FILES[@]} -gt 0 ]] ; then
    for MATCH_FILE in "${MATCH_FILES[@]}" ; do
      if ! [[ -f "${MATCH_FILE}" ]]; then
        continue
      fi

      FILE_NAME=$(basename "${MATCH_FILE}")
      # we just write the FILE_PATH in the beginning to the file (e.g., the log file is not available -> we create it)
      if ! [[ -f "${LOG_PATH_MODULE}"/deep_key_search_"${FILE_NAME}".txt ]]; then
        write_log "[*] FILE_PATH: $(print_path "${MATCH_FILE}")" "${LOG_PATH_MODULE}/deep_key_search_${FILE_NAME}.txt"
        write_log "" "${LOG_PATH_MODULE}/deep_key_search_${FILE_NAME}.txt"
      fi
      grep -A 2 --no-group-separator -E -n -a -h "${GREP_PATTERN_COMMAND[@]}" -D skip "${MATCH_FILE}" 2>/dev/null | tr -d '\0' >> "${LOG_PATH_MODULE}"/deep_key_search_"${FILE_NAME}".txt || true
      print_output "[+] $(print_path "${MATCH_FILE}")"
      write_link "${LOG_PATH_MODULE}""/deep_key_search_""${FILE_NAME}"".txt"
      local D_S_FINDINGS=""
      for PATTERN in "${PATTERN_LIST[@]}" ; do
        F_COUNT=$(grep -c "${PATTERN}" "${LOG_PATH_MODULE}"/deep_key_search_"${FILE_NAME}"".txt" || true)
        if [[ ${F_COUNT} -gt 0 ]] ; then
          D_S_FINDINGS="${D_S_FINDINGS}""    ""${F_COUNT}""\t:\t""${PATTERN}""\n"
        fi
      done
      print_output "${D_S_FINDINGS}"
      write_log "" "${LOG_PATH_MODULE}/deep_key_search_${FILE_NAME}.txt"
      write_log "[*] Deep search results:" "${LOG_PATH_MODULE}/deep_key_search_${FILE_NAME}.txt"
      write_log "${D_S_FINDINGS}" "${LOG_PATH_MODULE}/deep_key_search_${FILE_NAME}.txt"
    done
  fi
}

deep_key_reporter() {
  local OCC_LIST=()
  local OCC=""
  local P_COUNT=0

  for PATTERN in "${PATTERN_LIST[@]}" ; do
    P_COUNT=$(grep -c "${PATTERN}" "${LOG_PATH_MODULE}"/deep_key_search_* 2>/dev/null | cut -d: -f2 | awk '{ SUM += $1} END { print SUM }' || true )
    if [[ "${P_COUNT}" -gt 0 ]]; then
      OCC_LIST=( "${OCC_LIST[@]}" "${P_COUNT}"": ""${PATTERN}" )
    fi
  done

  if [[ "${#PATTERN_LIST[@]}" -gt 0 ]] ; then
    if [[ "${#OCC_LIST[@]}" -gt 0 ]] ; then
      print_ln
      print_output "[*] Occurences of pattern:"
      SORTED_OCC_LIST=("$(printf '%s\n' "${OCC_LIST[@]}" | sort -r --version-sort)")
      if [[ "${#SORTED_OCC_LIST[@]}" -gt 0 ]]; then
        for OCC in "${SORTED_OCC_LIST[@]}"; do
          print_output "$( indent "$(orange "${OCC}" )")""\n"
        done
      fi
    fi
  fi
}
