#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2023 Siemens Energy AG
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
export THREAD_PRIO=1

S120_cwe_checker()
{
  if [[ ${CWE_CHECKER} -eq 1 ]] ; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Check binaries with cwe-checker"
    pre_module_reporter "${FUNCNAME[0]}"
    local CWE_CNT_=0

    [[ "${IN_DOCKER}" -eq 1 ]] && cwe_container_prepare

    cwe_check

    if [[ -f "${TMP_DIR}"/CWE_CNT.tmp ]]; then
      CWE_CNT_=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/CWE_CNT.tmp || true)
    fi

    final_cwe_log "${CWE_CNT_}"

    write_log ""
    write_log "[*] Statistics:${CWE_CNT_}"
    module_end_log "${FUNCNAME[0]}" "${CWE_CNT_}"
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

  for BINARY in "${BINARIES[@]}" ; do
    if ( file "${BINARY}" | grep -q ELF ) ; then
      # do not try to analyze kernel modules:
      [[ "${BINARY}" == *".ko" ]] && continue
      if [[ "${THREADED}" -eq 1 ]]; then
        local MAX_MOD_THREADS=$(("$(grep -c ^processor /proc/cpuinfo || true)" / 3))
        if [[ $(grep -i -c S09_ "${LOG_DIR}"/"${MAIN_LOG_FILE}" || true) -eq 1 ]]; then
          local MAX_MOD_THREADS=1
        fi

        cwe_checker_threaded "${BINARY}" &
        local TMP_PID="$!"
        store_kill_pids "${TMP_PID}"
        WAIT_PIDS_S120+=( "${TMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S120[@]}"
        continue
      else
        cwe_checker_threaded "${BINARY}"
      fi
    fi
  done

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S120[@]}"
}

cwe_checker_threaded () {
  local BINARY_="${1:-}"
  local TEST_OUTPUT=()
  local CWE_OUT=()
  local CWE_LINE=""
  local CWE=""
  local CWE_DESC=""
  local CWE_CNT=0
  local MEM_LIMIT=$(( "${TOTAL_MEMORY}"/2 ))

  local NAME=""
  NAME=$(basename "${BINARY_}")

  if [[ -f "${BASE_LINUX_FILES}" ]]; then
    # if we have the base linux config file we only test non known Linux binaries
    # with this we do not waste too much time on open source Linux stuff
    if grep -E -q "^${NAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
      return
    fi
  fi

  local OLD_LOG_FILE="${LOG_FILE}"
  local LOG_FILE="${LOG_PATH_MODULE}""/cwe_check_""${NAME}"".txt"
  BINARY_=$(readlink -f "${BINARY_}")

  ulimit -Sv "${MEM_LIMIT}"
  cwe_checker "${BINARY}" --json --out "${LOG_PATH_MODULE}"/cwe_"${NAME}".log 2>/dev/null|| true
  ulimit -Sv unlimited
  print_output "[*] Tested ${ORANGE}""$(print_path "${BINARY_}")""${NC}"

  if [[ -s "${LOG_PATH_MODULE}"/cwe_"${NAME}".log ]]; then
    jq -r '.[] | "\(.name) - \(.description)"' "${LOG_PATH_MODULE}"/cwe_"${NAME}".log | sort -u || true
    mapfile -t CWE_OUT < <( jq -r '.[] | "\(.name) \(.description)"' "${LOG_PATH_MODULE}"/cwe_"${NAME}".log | cut -d\) -f1 | tr -d '('  | sort -u|| true)
    # this is the logging after every tested file
    if [[ ${#CWE_OUT[@]} -ne 0 ]] ; then
      print_ln
      print_output "[+] cwe-checker found ""${ORANGE}""${#CWE_OUT[@]}""${GREEN}"" different security issues in ""${ORANGE}""${NAME}""${GREEN}"":" "" "${LOG_PATH_MODULE}"/cwe_"${NAME}".log
      for CWE_LINE in "${CWE_OUT[@]}"; do
        CWE="$(echo "${CWE_LINE}" | awk '{print $1}')"
        CWE_DESC="$(echo "${CWE_LINE}" | cut -d\  -f2-)"
        CWE_CNT="$(grep -c "${CWE}" "${LOG_PATH_MODULE}"/cwe_"${NAME}".log 2>/dev/null || true)"
        echo "${CWE_CNT}" >> "${TMP_DIR}"/CWE_CNT.tmp
        print_output "$(indent "$(orange "${CWE}""${GREEN}"" - ""${CWE_DESC}"" - ""${ORANGE}""${CWE_CNT}"" times.")")"
      done
      print_ln
    else
      print_ln
      print_output "[-] Nothing found in ""${ORANGE}""${NAME}""${NC}""\\n"
      rm "${LOG_PATH_MODULE}"/cwe_"${NAME}".log
    fi
  fi
  [[ ${#TEST_OUTPUT[@]} -ne 0 ]] && print_ln

  if [[ -f "${LOG_FILE}" ]]; then
    cat "${LOG_FILE}" >> "${OLD_LOG_FILE}"
    rm "${LOG_FILE}" 2> /dev/null
  fi
  LOG_FILE="${OLD_LOG_FILE}"
}

final_cwe_log() {
  local TOTAL_CWE_CNT="${1:-}"
  local CWE_OUT=()
  local CWE_LINE=""
  local CWE=""
  local CWE_DESC=""
  local CWE_CNT=""

  if [[ -d "${LOG_PATH_MODULE}" ]]; then
    local CWE_LOGS=("${LOG_PATH_MODULE}"/cwe_*.log)
    if [[ "${#CWE_LOGS[@]}" -gt 0 ]]; then
      mapfile -t CWE_OUT < <( jq -r '.[] | "\(.name) \(.description)"' "${LOG_PATH_MODULE}"/cwe_*.log | cut -d\) -f1 | tr -d '('  | sort -u|| true)
      print_ln
      if [[ ${#CWE_OUT[@]} -gt 0 ]] ; then
        print_bar
        print_output "[+] cwe-checker found a total of ""${ORANGE}""${TOTAL_CWE_CNT}""${GREEN}"" of the following security issues:"
        for CWE_LINE in "${CWE_OUT[@]}"; do
          CWE="$(echo "${CWE_LINE}" | awk '{print $1}')"
          CWE_DESC="$(echo "${CWE_LINE}" | cut -d\  -f2-)"
          # do not change this to grep -c!
          # shellcheck disable=SC2126
          CWE_CNT="$(grep "${CWE}" "${LOG_PATH_MODULE}"/cwe_*.log 2>/dev/null | wc -l || true)"
          print_output "$(indent "$(orange "${CWE}""${GREEN}"" - ""${CWE_DESC}"" - ""${ORANGE}""${CWE_CNT}"" times.")")"
        done
        print_bar
        print_ln
      fi
    fi
  fi
}

