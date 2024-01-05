#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Iterates through a list with regex identifiers of version details
#               (e.g. busybox:binary:"BusyBox\ v[0-9]\.[0-9][0-9]\.[0-9]\ .*\ multi-call\ binary" ) of all executables and
#               checks if these fit on a binary in the firmware.
#               The version configuration file is stored in config/bin_version_strings.cfg

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=1

S09_firmware_base_version_check() {

  # this module check for version details statically.
  # this module is designed for *x based systems

  module_log_init "${FUNCNAME[0]}"
  module_title "Static binary firmware versions detection"
  pre_module_reporter "${FUNCNAME[0]}"

  EXTRACTOR_LOG="${LOG_DIR}"/p55_unblob_extractor/unblob_firmware.log

  print_output "[*] Static version detection running ..." "no_log" | tr -d "\n"
  write_csv_log "binary/file" "version_rule" "version_detected" "csv_rule" "license" "static/emulation"
  TYPE="static"

  while read -r VERSION_LINE; do
    if safe_echo "${VERSION_LINE}" | grep -v -q "^[^#*/;]"; then
      continue
    fi
    if safe_echo "${VERSION_LINE}" | grep -q ";no_static;"; then
      continue
    fi
    if safe_echo "${VERSION_LINE}" | grep -q ";live;"; then
      continue
    fi

    print_dot

    STRICT="$(safe_echo "${VERSION_LINE}" | cut -d\; -f2)"
    LIC="$(safe_echo "${VERSION_LINE}" | cut -d\; -f3)"
    BIN_NAME="$(safe_echo "${VERSION_LINE}" | cut -d\; -f1)"
    CSV_REGEX="$(echo "${VERSION_LINE}" | cut -d\; -f5)"

    if [[ -f "${CSV_DIR}"/s09_firmware_base_version_check.csv ]]; then
      # this should prevent double checking - if a version identifier was already successful we do not need to
      # test the other identifiers. In threaded mode this usually does not decrease testing speed.
      if [[ "$(tail -n +2 "${CSV_DIR}"/s09_firmware_base_version_check.csv | cut -d\; -f2 | grep -c "^${BIN_NAME}$")" -gt 0 ]]; then
        print_output "[*] Already identified component for identifier ${BIN_NAME} - ${CSV_REGEX} ... skipping further tests" "no_log"
        continue
      fi
    fi

    VERSION_IDENTIFIER="$(safe_echo "${VERSION_LINE}" | cut -d\; -f4)"
    VERSION_IDENTIFIER="${VERSION_IDENTIFIER/\"}"
    VERSION_IDENTIFIER="${VERSION_IDENTIFIER%\"}"

    if [[ "${STRICT}" == *"strict"* ]]; then

      # strict mode
      #   use the defined regex only on a binary called BIN_NAME (field 1)
      #   Warning: strict mode is deprecated and will be removed in the future.

      [[ "${RTOS}" -eq 1 ]] && continue

      mapfile -t STRICT_BINS < <(find "${OUTPUT_DIR}" -xdev -executable -type f -name "${BIN_NAME}" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3)
      for BIN in "${STRICT_BINS[@]}"; do
        # as the STRICT_BINS array could also include executable scripts we have to check for ELF files now:
        if file "${BIN}" | grep -q ELF ; then
          VERSION_FINDER=$(strings "${BIN}" | grep -E "${VERSION_IDENTIFIER}" | sort -u || true)
          if [[ -n ${VERSION_FINDER} ]]; then
            print_ln "no_log"
            print_output "[+] Version information found ${RED}${BIN_NAME} ${VERSION_FINDER}${NC}${GREEN} in binary ${ORANGE}$(print_path "${BIN}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static - strict - deprecated${GREEN})."
            get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}"
            write_csv_log "${BIN}" "${BIN_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
            continue
          fi
        fi
      done
      print_dot

    elif [[ "${STRICT}" == "zgrep" ]]; then

      # zgrep mode:
      #   search for files with identifier in field 1
      #   use regex (VERSION_IDENTIFIER) via zgrep on these files
      #   use csv-regex to get the csv-search string for csv lookup

      mapfile -t SPECIAL_FINDS < <(find "${FIRMWARE_PATH}" -xdev -type f -name "${BIN_NAME}" -exec zgrep -H "${VERSION_IDENTIFIER}" {} \; || true)
      for SFILE in "${SPECIAL_FINDS[@]}"; do
        BIN_PATH=$(safe_echo "${SFILE}" | cut -d ":" -f1)
        BIN_NAME="$(basename "$(safe_echo "${SFILE}" | cut -d ":" -f1)")"
        # CSV_REGEX=$(echo "${VERSION_LINE}" | cut -d\; -f5 | sed s/^\"// | sed s/\"$//)
        CSV_REGEX="$(echo "${VERSION_LINE}" | cut -d\; -f5)"
        CSV_REGEX="${CSV_REGEX/\"}"
        CSV_REGEX="${CSV_REGEX%\"}"
        VERSION_FINDER=$(safe_echo "${SFILE}" | cut -d ":" -f2-3 | tr -dc '[:print:]')
        get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}"
        print_output "[+] Version information found ${RED}""${VERSION_FINDER}""${NC}${GREEN} in binary ${ORANGE}$(print_path "${BIN_PATH}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static - zgrep${GREEN})."
        write_csv_log "${BIN_PATH}" "${BIN_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
      done
      print_dot

    else

      # This is default mode!

      if [[ -f "${EXTRACTOR_LOG}" ]]; then
        # check unblob files sometimes we can find kernel version information or something else in it
        VERSION_FINDER=$(grep -o -a -E "${VERSION_IDENTIFIER}" "${EXTRACTOR_LOG}" 2>/dev/null | head -1 2>/dev/null || true)
        if [[ -n ${VERSION_FINDER} ]]; then
          print_ln "no_log"
          print_output "[+] Version information found ${RED}""${VERSION_FINDER}""${NC}${GREEN} in unblob logs (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
          get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}"
          write_csv_log "unblob logs" "${BIN_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
          print_dot
        fi
      fi

      print_dot

      if [[ ${FIRMWARE} -eq 0 || -f ${FIRMWARE_PATH} ]]; then
        VERSION_FINDER=$(find "${FIRMWARE_PATH}" -xdev -type f -print0 2>/dev/null | xargs -0 strings | grep -o -a -E "${VERSION_IDENTIFIER}" | head -1 2>/dev/null || true)

        if [[ -n ${VERSION_FINDER} ]]; then
          print_ln "no_log"
          print_output "[+] Version information found ${RED}""${VERSION_FINDER}""${NC}${GREEN} in original firmware file (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
          get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}"
          write_csv_log "firmware" "${BIN_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
        fi
        print_dot
      fi

      if [[ ${RTOS} -eq 1 ]]; then
        # in RTOS mode we also test the original firmware file
        VERSION_FINDER=$(find "${FIRMWARE_PATH_BAK}" -xdev -type f -print0 2>/dev/null | xargs -0 strings | grep -o -a -E "${VERSION_IDENTIFIER}" | head -1 2>/dev/null || true)
        if [[ -n ${VERSION_FINDER} ]]; then
          print_ln "no_log"
          print_output "[+] Version information found ${RED}""${VERSION_FINDER}""${NC}${GREEN} in original firmware file (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
          get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}"
          write_csv_log "firmware" "${BIN_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
        fi
      fi

      if [[ "${THREADED}" -eq 1 ]]; then
        # this will burn the CPU but in most cases the time of testing is cut into half
        bin_string_checker &
        local TMP_PID="$!"
        store_kill_pids "${TMP_PID}"
        WAIT_PIDS_S09+=( "${TMP_PID}" )
      else
        bin_string_checker
      fi

      print_dot

    fi

    if [[ "${THREADED}" -eq 1 ]]; then
      if [[ "${#WAIT_PIDS_S09[@]}" -gt "${MAX_MOD_THREADS}" ]]; then
        recover_wait_pids "${WAIT_PIDS_S09[@]}"
        if [[ "${#WAIT_PIDS_S09[@]}" -gt "${MAX_MOD_THREADS}" ]]; then
          max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S09[@]}"
        fi
      fi
    fi

  done  < "${CONFIG_DIR}"/bin_version_strings.cfg

  print_dot

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S09[@]}"

  VERSIONS_DETECTED=$(grep -c "Version information found" "${LOG_FILE}" || true)

  module_end_log "${FUNCNAME[0]}" "${VERSIONS_DETECTED}"
}

bin_string_checker() {
  VERSION_IDENTIFIER="${VERSION_IDENTIFIER%\'}"
  VERSION_IDENTIFIER="${VERSION_IDENTIFIER/\'}"
  IFS='&&' read -r -a VERSION_IDENTIFIERS_ARR <<< "${VERSION_IDENTIFIER}"

  for BIN in "${FILE_ARR[@]}"; do
    for (( j=0; j<${#VERSION_IDENTIFIERS_ARR[@]}; j++ )); do
      local VERSION_IDENTIFIER="${VERSION_IDENTIFIERS_ARR["${j}"]}"
      local VERSION_FINDER=""
      [[ -z "${VERSION_IDENTIFIER}" ]] && continue
      # this is a workaround to handle the new multi_grep
      if [[ "${VERSION_IDENTIFIER: 0:1}" == '"' ]]; then
        VERSION_IDENTIFIER="${VERSION_IDENTIFIER/\"}"
        VERSION_IDENTIFIER="${VERSION_IDENTIFIER%\"}"
      fi
      if [[ ${RTOS} -eq 0 ]]; then
        BIN_FILE=$(file "${BIN}" || true)
        # as the FILE_ARR array also includes non binary stuff we have to check for relevant files now:
        if ! [[ "${BIN_FILE}" == *uImage* || "${BIN_FILE}" == *Kernel\ Image* || "${BIN_FILE}" == *ELF* ]] ; then
          continue 2
        fi
        if [[ "${BIN_FILE}" == *ELF* ]] ; then
          # print_output "[*] Testing $BIN with version identifier ${VERSION_IDENTIFIER}" "no_log"
          VERSION_FINDER=$(strings "${BIN}" | grep -o -a -E "${VERSION_IDENTIFIER}" | head -1 2> /dev/null || true)
          if [[ -n ${VERSION_FINDER} ]]; then
            if [[ "${#VERSION_IDENTIFIERS_ARR[@]}" -gt 1 ]] && [[ "$((j+1))" -lt "${#VERSION_IDENTIFIERS_ARR[@]}" ]]; then
              # we found the first identifier and now we need to check the other identifiers also
              print_output "[+] Found sub identifier ${ORANGE}${VERSION_IDENTIFIER}${GREEN} in binary ${ORANGE}${BIN}${GREEN}" "no_log"
              continue
            fi
            print_ln "no_log"
            print_output "[+] Version information found ${RED}${VERSION_FINDER}${NC}${GREEN} in binary ${ORANGE}$(print_path "${BIN}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
            get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}"
            write_csv_log "${BIN}" "${BIN_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
            # we test the next binary
            continue 2
          fi
        elif [[ "${BIN_FILE}" == *uImage* || "${BIN_FILE}" == *Kernel\ Image* ]] ; then
          VERSION_FINDER=$(strings "${BIN}" | grep -o -a -E "${VERSION_IDENTIFIER}" | head -1 2> /dev/null || true)
          if [[ -n ${VERSION_FINDER} ]]; then
            print_ln "no_log"
            print_output "[+] Version information found ${RED}${VERSION_FINDER}${NC}${GREEN} in kernel image ${ORANGE}$(print_path "${BIN}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
            get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}"
            write_csv_log "${BIN}" "${BIN_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
            continue 2
          fi
        fi
      else
        # this is RTOS mode
        # echo "Testing $BIN - $VERSION_IDENTIFIER"
        VERSION_FINDER="$(strings "${BIN}" | grep -o -a -E "${VERSION_IDENTIFIER}" | head -1 2> /dev/null || true)"
        if [[ -n ${VERSION_FINDER} ]]; then
          print_ln "no_log"
          print_output "[+] Version information found ${RED}${VERSION_FINDER}${NC}${GREEN} in binary ${ORANGE}$(print_path "${BIN}")${GREEN} (license: ${ORANGE}${LIC}${GREEN}) (${ORANGE}static${GREEN})."
          get_csv_rule "${VERSION_FINDER}" "${CSV_REGEX}"
          write_csv_log "${BIN}" "${BIN_NAME}" "${VERSION_FINDER}" "${CSV_RULE}" "${LIC}" "${TYPE}"
          continue 2
        fi
      fi
      continue 2
    done
  done
}

recover_wait_pids() {
  local TEMP_PIDS=()
  local PID=""
  # check for really running PIDs and re-create the array
  for PID in "${WAIT_PIDS_S09[@]}"; do
    # print_output "[*] max pid protection: ${#WAIT_PIDS[@]}"
    if [[ -e /proc/"${PID}" ]]; then
      TEMP_PIDS+=( "${PID}" )
    fi
  done
  # print_output "[!] S09 - really running pids: ${#TEMP_PIDS[@]}"

  # recreate the array with the current running PIDS
  WAIT_PIDS_S09=()
  WAIT_PIDS_S09=("${TEMP_PIDS[@]}")
}

