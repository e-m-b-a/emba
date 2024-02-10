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
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Chao Yang - firmianay

# Description:  Runs a Docker container with cwe-checker on Ghidra to check binary for
#               common bug classes such as vicious functions or integer overflows.
#               As the runtime is quite long, it needs to be activated separately via -c switch.
#               Currently this module only work in a non docker environment!

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

S17_cwe_checker()
{
  if [[ ${BINARY_EXTENDED} -eq 1 ]] ; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Check binaries for vulnerabilities with cwe-checker"
    pre_module_reporter "${FUNCNAME[0]}"
    local lCWE_CNT_=0
    local lTESTED_BINS=0

    [[ "${IN_DOCKER}" -eq 1 ]] && cwe_container_prepare
    module_wait "S13_weak_func_check"

    cwe_check

    if [[ -f "${TMP_DIR}"/CWE_CNT.tmp ]]; then
      lCWE_CNT_=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/CWE_CNT.tmp || true)
      lTESTED_BINS=$(grep -c "cwe-checker found.*different security issues in" "${LOG_FILE}" || true)
    fi

    final_cwe_log "${lCWE_CNT_}" "${lTESTED_BINS}"

    write_log ""
    write_log "[*] Statistics:${lCWE_CNT_}:${lTESTED_BINS}"
    module_end_log "${FUNCNAME[0]}" "${lCWE_CNT_}"
  else
    print_output "[!] Check with cwe-checker is disabled!"
    print_output "[!] Enable it with the -c switch."
  fi
}

cwe_container_prepare() {
  # as we are in a read only docker environment we need to trick a bit:
  # /root is mounted as a writable tempfs. With this we need to set it up
  # on every run from scratch:
  if [[ -d "${EXT_DIR}"/cwe_checker/.config ]]; then
    print_output "[*] Restoring config directory in read-only container" "no_log"
    if ! [[ -d "${HOME}"/.config/ ]]; then
      mkdir -p "${HOME}"/.config
    fi
    cp -pr "${EXT_DIR}"/cwe_checker/.config/cwe_checker "${HOME}"/.config/
    cp -pr "${EXT_DIR}"/cwe_checker/.local/share "${HOME}"/.local/
  fi

  # Todo: move this to dependency check
  if [[ -d "${HOME}"/.cargo/bin ]]; then
    export PATH=${PATH}:"${HOME}"/.cargo/bin/:"${EXT_DIR}"/jdk/bin/
  else
    print_output "[!] CWE checker installation broken ... please check it manually!"
    return
  fi
}

cwe_check() {
  local BINARY=""
  local BIN_TO_CHECK=""
  local BIN_TO_CHECK_ARR=()
  local WAIT_PIDS_S17=()
  local NAME=""
  local BINS_CHECKED_ARR=()

  if [[ -f "${CSV_DIR}"/s13_weak_func_check.csv ]]; then
    local BINARIES=()
    # usually binaries with strcpy or system calls are more interesting for further analysis
    # to keep analysis time low we only check these bins
    mapfile -t BINARIES < <(grep "strcpy\|system" "${CSV_DIR}"/s13_weak_func_check.csv | sort -k 3 -t ';' -n -r | awk '{print $1}')
  fi

  for BINARY in "${BINARIES[@]}" ; do
    # as we usually have not the full path from the s13 log, we need to search for the binary again:
    mapfile -t BIN_TO_CHECK_ARR < <(find "${LOG_DIR}/firmware" -name "$(basename "${BINARY}")" | sort -u || true)
    for BIN_TO_CHECK in "${BIN_TO_CHECK_ARR[@]}"; do
      if [[ -f "${BASE_LINUX_FILES}" && "${FULL_TEST}" -eq 0 ]]; then
        # if we have the base linux config file we only test non known Linux binaries
        # with this we do not waste too much time on open source Linux stuff
        NAME=$(basename "${BIN_TO_CHECK}")
        if grep -E -q "^${NAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
          continue
        fi
      fi

      if ( file "${BIN_TO_CHECK}" | grep -q ELF ) ; then
        # do not try to analyze kernel modules:
        [[ "${BIN_TO_CHECK}" == *".ko" ]] && continue
        # ensure we have not tested this binary entry
        local BIN_MD5=""
        BIN_MD5="$(md5sum "${BIN_TO_CHECK}" | awk '{print $1}')"
        if [[ "${BINS_CHECKED_ARR[*]}" == *"${BIN_MD5}"* ]]; then
          # print_output "[*] ${ORANGE}${BIN_TO_CHECK}${NC} already tested with ghidra/semgrep" "no_log"
          continue
        fi
        BINS_CHECKED_ARR+=( "${BIN_MD5}" )

        if [[ "${THREADED}" -eq 1 ]]; then
          # while s09 is running we throttle this module:
          local MAX_MOD_THREADS=$(("$(grep -c ^processor /proc/cpuinfo || true)" / 3))
          if [[ $(grep -i -c S09_ "${LOG_DIR}"/"${MAIN_LOG_FILE}" || true) -eq 1 ]]; then
            local MAX_MOD_THREADS=1
          fi
          cwe_checker_threaded "${BIN_TO_CHECK}" &
          local TMP_PID="$!"
          store_kill_pids "${TMP_PID}"
          WAIT_PIDS_S17+=( "${TMP_PID}" )

          max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S17[@]}"
        else
          cwe_checker_threaded "${BIN_TO_CHECK}"
        fi
        # we stop checking after the first 20 binaries
        # usually these are non-linux binaries and ordered by the usage of system/strcpy legacy usages
        if [[ "${#BINS_CHECKED_ARR[@]}" -gt 20 ]] && [[ "${FULL_TEST}" -ne 1 ]]; then
          print_output "[*] 20 binaries already analysed - ending Ghidra binary analysis now." "no_log"
          print_output "[*] For complete analysis enable FULL_TEST." "no_log"
          break 2
        fi
      fi
    done
  done

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S17[@]}"
}

cwe_checker_threaded () {
  local BINARY_="${1:-}"
  local CWE_OUT=()
  local CWE_LINE=""
  local CWE=""
  local CWE_DESC=""
  local CWE_CNT=0
  local MEM_LIMIT=$(( "${TOTAL_MEMORY}"/2 ))

  local NAME=""
  NAME=$(basename "${BINARY_}")

  local OLD_LOG_FILE="${LOG_FILE}"
  local LOG_FILE="${LOG_PATH_MODULE}""/cwe_check_""${NAME}"".txt"
  BINARY_=$(readlink -f "${BINARY_}")

  ulimit -Sv "${MEM_LIMIT}"
  timeout --preserve-status --signal SIGINT 3000 cwe_checker "${BINARY_}" --json --out "${LOG_PATH_MODULE}"/cwe_"${NAME}".log 2>/dev/null || true
  ulimit -Sv unlimited
  print_output "[*] Tested ${ORANGE}""$(print_path "${BINARY_}")""${NC}" "no_log"

  if [[ -s "${LOG_PATH_MODULE}"/cwe_"${NAME}".log ]]; then
    jq -r '.[] | "\(.name) - \(.description)"' "${LOG_PATH_MODULE}"/cwe_"${NAME}".log | sort -u || true
    mapfile -t CWE_OUT < <( jq -r '.[] | "\(.name) \(.description)"' "${LOG_PATH_MODULE}"/cwe_"${NAME}".log | cut -d\) -f1 | tr -d '('  | sort -u|| true)
    # this is the logging after every tested file
    if [[ ${#CWE_OUT[@]} -ne 0 ]] ; then
      print_output "[+] cwe-checker found ""${ORANGE}""${#CWE_OUT[@]}""${GREEN}"" different security issues in ""${ORANGE}""${NAME}""${GREEN}"":" "" "${LOG_PATH_MODULE}"/cwe_"${NAME}".log
      for CWE_LINE in "${CWE_OUT[@]}"; do
        CWE="$(echo "${CWE_LINE}" | awk '{print $1}')"
        CWE_DESC="$(echo "${CWE_LINE}" | cut -d\  -f2-)"
        CWE_CNT="$(grep -c "${CWE}" "${LOG_PATH_MODULE}"/cwe_"${NAME}".log 2>/dev/null || true)"
        echo "${CWE_CNT}" >> "${TMP_DIR}"/CWE_CNT.tmp
        print_output "$(indent "$(orange "${CWE}""${GREEN}"" - ""${CWE_DESC}"" - ""${ORANGE}""${CWE_CNT}"" times.")")"
      done
    else
      print_output "[-] Nothing found in ""${ORANGE}""${NAME}""${NC}" "no_log"
      rm "${LOG_PATH_MODULE}"/cwe_"${NAME}".log
    fi
  fi

  print_ln

  if [[ -f "${LOG_FILE}" ]]; then
    cat "${LOG_FILE}" >> "${OLD_LOG_FILE}"
    rm "${LOG_FILE}" 2> /dev/null
  fi
  LOG_FILE="${OLD_LOG_FILE}"
}

final_cwe_log() {
  local TOTAL_CWE_CNT="${1:-}"
  local lTESTED_BINS="${2:-}"
  local CWE_OUT=()
  local CWE_LINE=""
  local CWE=""
  local CWE_DESC=""
  local CWE_CNT=""
  local CWE_LOGS=()

  if [[ -d "${LOG_PATH_MODULE}" ]]; then
    mapfile -t CWE_LOGS < <(find "${LOG_PATH_MODULE}" -type f -name "cwe_*.log")
    if [[ "${#CWE_LOGS[@]}" -gt 0 ]]; then
      mapfile -t CWE_OUT < <( jq -r '.[] | "\(.name) \(.description)"' "${LOG_PATH_MODULE}"/cwe_*.log | cut -d\) -f1 | tr -d '('  | sort -u|| true)
      if [[ ${#CWE_OUT[@]} -gt 0 ]] ; then
        sub_module_title "Results - CWE-checker binary analysis"
        print_output "[+] cwe-checker found a total of ""${ORANGE}""${TOTAL_CWE_CNT}""${GREEN}"" of the following security issues in ${ORANGE}${lTESTED_BINS}${GREEN} tested binaries:"
        for CWE_LINE in "${CWE_OUT[@]}"; do
          CWE="$(echo "${CWE_LINE}" | awk '{print $1}')"
          CWE_DESC="$(echo "${CWE_LINE}" | cut -d\  -f2-)"
          # do not change this to grep -c!
          # shellcheck disable=SC2126
          CWE_CNT="$(grep "${CWE}" "${LOG_PATH_MODULE}"/cwe_*.log 2>/dev/null | wc -l || true)"
          print_output "$(indent "$(orange "${CWE}""${GREEN}"" - ""${CWE_DESC}"" - ""${ORANGE}""${CWE_CNT}"" times.")")"
        done
        print_bar
      fi
    fi
  fi
}

