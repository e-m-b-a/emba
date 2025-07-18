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

# Description:  This module extracts version information from the results of S115

S116_qemu_version_detection() {
  module_log_init "${FUNCNAME[0]}"
  local lNEG_LOG=0
  local lVERSION_LINE=""
  local lWAIT_PIDS_S116_ARR=()
  # emulation result confidence level:
  export CONFIDENCE_LEVEL=3

  if [[ "${QEMULATION}" -eq 0 ]]; then
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
    return
  fi

  if [[ "${RTOS}" -eq 0 ]]; then
    module_title "Identified software components - via usermode emulation."
    pre_module_reporter "${FUNCNAME[0]}"

    # This module waits for S115_usermode_emulator
    # check emba.log for S115_usermode_emulator
    module_wait "S115_usermode_emulator"

    # if module s09 is in our running modules array we wait until this module created the unhandled_files entries
    # otherwise we can't delete the irrelevant entries
    while ! [[ -f "${TMP_DIR}/S09_strings_generated.tmp" ]]; do
      if ! [[ " ${MODULES_EXPORTED[*]} " == *S09* ]]; then
        break
      fi
      if grep -q "S09_*finished" "${LOG_DIR}/emba.log"; then
        break
      fi
      print_output "[*] Waiting for S09 module - strings and unhandled file generation ..." "no_log"
      sleep 1
    done

    local lLOG_PATH_S115="${LOG_DIR}"/s115_usermode_emulator.txt
    if [[ -f "${lLOG_PATH_S115}" && -d "${LOG_DIR}/s115_usermode_emulator" ]]; then
      if [[ $(find "${LOG_DIR}/s115_usermode_emulator" -name "qemu_tmp*" | wc -l) -eq 0 ]]; then
        print_output "[-] No emulation logs available ... return"
        module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
        return
      fi

      local lVERSION_IDENTIFIER_CFG_PATH="${CONFIG_DIR}"/bin_version_identifiers
      local lVERSION_IDENTIFIER_CFG_ARR=()
      local lVERSION_JSON_CFG=""
      mapfile -t lVERSION_IDENTIFIER_CFG_ARR < <(find "${lVERSION_IDENTIFIER_CFG_PATH}" -name "*.json")

      for lVERSION_JSON_CFG in "${lVERSION_IDENTIFIER_CFG_ARR[@]}"; do
        if [[ -f "${CSV_DIR}"/s116_qemu_version_detection.csv ]]; then
          # this should prevent double checking - if a version identifier was already successful we do not need to
          # test the other identifiers. In threaded mode this usually does not decrease testing speed
          local lBINARY=""
          lBINARY="$(echo "${lVERSION_LINE}" | cut -d\; -f1)"
          if [[ "$(tail -n +2 "${CSV_DIR}"/s116_qemu_version_detection.csv | cut -d\; -f2 | grep -c "^${lBINARY}$")" -gt 0 ]]; then
            print_output "[*] Already identified component for identifier ${ORANGE}${lBINARY}${NC} ... skipping further tests" "no_log"
            continue
          fi
        fi

        version_detection_thread "${lVERSION_JSON_CFG}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S116_ARR+=( "${lTMP_PID}" )
      done
      print_ln "no_log"

      wait_for_pid "${lWAIT_PIDS_S116_ARR[@]}"
    fi
    lNEG_LOG=$(grep -c "Version information found" "${LOG_FILE}" || echo 0)
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

version_detection_thread() {
  local lVERSION_JSON_CFG="${1:-}"

  mapfile -t lPARSING_MODE_ARR < <(jq -r .parsing_mode[] "${lVERSION_JSON_CFG}")
  # print_output "[*] Testing json config ${ORANGE}${lVERSION_JSON_CFG}${NC}" "no_log"
  local lRULE_IDENTIFIER=""
  lRULE_IDENTIFIER=$(jq -r .identifier "${lVERSION_JSON_CFG}" || print_error "[-] Error in parsing ${lVERSION_JSON_CFG}")
  mapfile -t lLICENSES_ARR < <(jq -r .licenses[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  # shellcheck disable=SC2034
  mapfile -t lPRODUCT_NAME_ARR < <(jq -r .product_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  # shellcheck disable=SC2034
  mapfile -t lVENDOR_NAME_ARR < <(jq -r .vendor_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  # shellcheck disable=SC2034
  mapfile -t lCSV_REGEX_ARR < <(jq -r .version_extraction[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  if [[ "${lPARSING_MODE_ARR[*]}" == *"strict"* ]]; then
    mapfile -t lSTRICT_VERSION_IDENTIFIER_ARR < <(jq -r .strict_grep_commands[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  fi
  mapfile -t lVERSION_IDENTIFIER_ARR < <(jq -r .grep_commands[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  mapfile -t lAFFECTED_PATHS_ARR < <(jq -r .affected_paths[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)

  local lBINARY_PATH_=""
  local lBINARY_PATHS_ARR=()
  local lLOG_PATH_MODULE_S115="${LOG_DIR}"/s115_usermode_emulator/
  local lVERSION_IDENTIFIER=""
  export PACKAGING_SYSTEM="user_mode_bin_analysis"
  export TYPE="emulation"

  # if we have the key strict this version identifier only works for the defined binary and is not generic!
  if [[ ${lPARSING_MODE_ARR[*]} == *"strict"* ]]; then
    TYPE="emulation/strict"
    local lSTRICT_LOGS_ARR=()
    for lAPP_NAME in "${lAFFECTED_PATHS_ARR[@]}"; do
      local lSTRICT_LOGS_ARR_TMP=()
      lAPP_NAME="$(basename "${lAPP_NAME}")"
      mapfile -t lSTRICT_LOGS_ARR_TMP < <(find "${lLOG_PATH_MODULE_S115}" -name "qemu_tmp_*${lAPP_NAME}*" | sort -u || true)
      lSTRICT_LOGS_ARR+=("${lSTRICT_LOGS_ARR_TMP[@]}")
    done
    for lVERSION_IDENTIFIER in "${lSTRICT_VERSION_IDENTIFIER_ARR[@]}"; do
      for lEMULATION_LOG_ENTRY in "${lSTRICT_LOGS_ARR[@]}"; do
        lVERSION_IDENTIFIED=$(grep -a -o -E "${lVERSION_IDENTIFIER}" "${lEMULATION_LOG_ENTRY}" | sort -u || true)
        lVERSION_IDENTIFIED="${lVERSION_IDENTIFIED//[![:print:]]/}"
        if [[ -n ${lVERSION_IDENTIFIED} ]]; then
          mapfile -t lBINARY_PATHS_ARR < <(strip_color_codes "$(grep -a -h "Emulating binary:" "${lEMULATION_LOG_ENTRY}" | cut -d: -f2 | sed -e 's/^\ //' | sort -u 2>/dev/null || true)")
          for lBINARY_PATH_ in "${lBINARY_PATHS_ARR[@]}"; do
            local lBINARY_ENTRY=""
            lBINARY_ENTRY=$(grep "${lBINARY_PATH_}.*ELF" "${P99_CSV_LOG}" | sort -u | head -1 || true)
            if [[ -z "${lBINARY_ENTRY}" ]]; then
              lBINARY_ENTRY=$(grep -F "${lBINARY_PATH_}" "${P99_CSV_LOG}" | sort -u | head -1 || true)
            fi
            if [[ -n "${lBINARY_ENTRY}" ]]; then
              print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${NC}${GREEN} in binary ${ORANGE}${lBINARY_PATH_}${GREEN} (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}${TYPE}${GREEN})." "" "${lEMULATION_LOG_ENTRY}"
              if version_parsing_logging "${S09_CSV_LOG}" "S116_qemu_version_detection" "${lVERSION_IDENTIFIED}" "${lBINARY_ENTRY}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR"; then
                # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} -> continue to next binary"
                continue
              fi
              continue 2
            else
              print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${NC}${GREEN} without a valid binary path -> Check this entry (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}${TYPE}${GREEN})." "" "${lEMULATION_LOG_ENTRY}"
            fi

          done
        fi
      done
    done
  fi

  if [[ ${lPARSING_MODE_ARR[*]} == *"normal"* ]]; then
    TYPE="emulation"
    for lVERSION_IDENTIFIER in "${lVERSION_IDENTIFIER_ARR[@]}"; do
      # get the relevant emulation logs:
      readarray -t lLOGS_DETECTED_ARR < <(grep -a -l -E "${lVERSION_IDENTIFIER}" "${lLOG_PATH_MODULE_S115}"/qemu_tmp*.txt 2>/dev/null || true)
      for lEMULATION_LOG_MATCH in "${lLOGS_DETECTED_ARR[@]}"; do
        lVERSION_IDENTIFIED=$(grep -a -o -E "${lVERSION_IDENTIFIER}" "${lEMULATION_LOG_MATCH}" | sort -u || true)
        lVERSION_IDENTIFIED="${lVERSION_IDENTIFIED//[![:print:]]/}"
        if [[ -n ${lVERSION_IDENTIFIED} ]]; then
          mapfile -t lBINARY_PATHS_ARR < <(strip_color_codes "$(grep -h -a "Emulating binary:" "${lEMULATION_LOG_MATCH}" 2>/dev/null | cut -d: -f2 | sed -e 's/^\ //' | sort -u 2>/dev/null || true)")
          for lBINARY_PATH_ in "${lBINARY_PATHS_ARR[@]}"; do
            local lBINARY_ENTRY=""
            lBINARY_ENTRY=$(grep "${lBINARY_PATH_}.*ELF" "${P99_CSV_LOG}" | sort -u | head -1 || true)
            if [[ -z "${lBINARY_ENTRY}" ]]; then
              lBINARY_ENTRY=$(grep -F "${lBINARY_PATH_}" "${P99_CSV_LOG}" | sort -u | head -1 || true)
            fi
            if [[ -n "${lBINARY_ENTRY}" ]]; then
              print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${NC}${GREEN} in binary ${ORANGE}${lBINARY_PATH_}${GREEN} (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}${TYPE}${GREEN})." "" "${lEMULATION_LOG_MATCH}"
              if version_parsing_logging "${S09_CSV_LOG}" "S116_qemu_version_detection" "${lVERSION_IDENTIFIED}" "${lBINARY_ENTRY}" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR"; then
                # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} -> continue to next binary"
                continue
              fi
              continue 2
            else
              print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${NC}${GREEN} without a valid binary path -> Check this entry (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}${TYPE}${GREEN})." "" "${lEMULATION_LOG_MATCH}"
            fi
          done
        fi
      done
    done
  fi
}

