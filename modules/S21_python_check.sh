#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Checks for bugs, stylistic errors, etc. in python scripts, then it lists the found error types.
#               For bandit configuration the ./config/bandit.yaml file can be adjusted

S21_python_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Check python scripts for security issues"
  pre_module_reporter "${FUNCNAME[0]}"

  local lS21_PY_VULNS=0
  local lS21_PY_SCRIPTS=0
  local lPY_SCRIPT=""
  local lNAME=""
  local lPYTHON_SCRIPTS_ARR=()
  local lS21_VULN_TYPES_ARR=()
  local lVTYPE=""
  local lWAIT_PIDS_S21_ARR=()

  if [[ ${PYTHON_CHECK} -eq 1 ]]; then
    # clearing tmp log file first
    rm -f "${TMP_DIR}"/S21_VULNS.tmp

    write_csv_log "Script path" "Python issues detected" "common linux file"
    # mapfile -t lPYTHON_SCRIPTS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iname "*.py" -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 )
    mapfile -t lPYTHON_SCRIPTS_ARR < <(grep "Python script.*executable" "${P99_CSV_LOG}" | sort -u || true)

    for lPY_SCRIPT in "${lPYTHON_SCRIPTS_ARR[@]}"; do
      if [[ -f "${BASE_LINUX_FILES}" && "${FULL_TEST}" -eq 0 ]]; then
        # if we have the base linux config file we only test non known Linux binaries
        # with this we do not waste too much time on open source Linux stuff
        lNAME=$(basename "$(cut -d ';' -f2 <<< "${lPY_SCRIPT}")" 2>/dev/null)  # field 2
        if grep -E -q "^${lNAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
          continue
        fi
      fi
      ((lS21_PY_SCRIPTS += 1))
      if [[ "${THREADED}" -eq 1 ]]; then
        s21_script_bandit "$(cut -d ';' -f2 <<< "${lPY_SCRIPT}")" &  # field 2
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S21_ARR+=("${lTMP_PID}")
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S21_ARR
        continue
      else
        s21_script_bandit "$(cut -d ';' -f2 <<< "${lPY_SCRIPT}")"  # field 2
      fi
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S21_ARR[@]}"

    if [[ -f "${TMP_DIR}"/S21_VULNS.tmp ]]; then
      lS21_PY_VULNS=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S21_VULNS.tmp)
    fi

    if [[ "${lS21_PY_VULNS}" -gt 0 ]]; then
      print_ln
      print_output "[+] Found ""${ORANGE}""${lS21_PY_VULNS}"" possible issues""${GREEN}"" in ""${ORANGE}""${lS21_PY_SCRIPTS}""${GREEN}"" python files:""${NC}""\\n"
    fi

    write_log ""
    write_log "[*] Statistics:${lS21_PY_VULNS}:${lS21_PY_SCRIPTS}"

    # we just print one issue per issue type:
    mapfile -t lS21_VULN_TYPES_ARR < <(grep "[A-Z][0-9][0-9][0-9]" "${LOG_PATH_MODULE}"/bandit_* 2>/dev/null | grep Issue | cut -d: -f3- | tr -d '[' | tr ']' ':' | sort -u || true)
    for lVTYPE in "${lS21_VULN_TYPES_ARR[@]}"; do
      print_output "$(indent "${NC}""[""${GREEN}""+""${NC}""]""${GREEN}"" ""${lVTYPE}""${GREEN}")"
    done
  else
    print_output "[-] Python check is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "${lS21_PY_VULNS}"
}

s21_script_bandit() {
  local lPY_SCRIPT_="${1:-}"
  local lSCRIPT_NAME=""
  local lPY_LOG=""
  local lVULNS=""
  local lGPT_PRIO_=2
  local lAI_ANCHOR=""
  local lS21_SOURCE_DIR="${LOG_PATH_MODULE}/py_sources"

  lSCRIPT_NAME=$(basename "${lPY_SCRIPT_}" 2>/dev/null | sed -e 's/:/_/g')
  lPY_LOG="${LOG_PATH_MODULE}""/bandit_""${lSCRIPT_NAME}"".txt"
  bandit -c "${CONFIG_DIR}/bandit.yaml" "${lPY_SCRIPT_}" >"${lPY_LOG}" 2>/dev/null || true

  lVULNS=$(grep -c ">> Issue: " "${lPY_LOG}" 2>/dev/null || true)
  if [[ "${lVULNS}" -ne 0 ]]; then
    [[ ! -d "${lS21_SOURCE_DIR}" ]] && mkdir -p "${lS21_SOURCE_DIR}"

    # safe the sources and link it in the lSHELL_LOG
    write_log "" "${lPY_LOG}"
    write_log "[*] Source file ${ORANGE}${lSCRIPT_NAME}${NC}" "${lPY_LOG}"
    copy_and_link_file "${lPY_SCRIPT_}" "${lS21_SOURCE_DIR}/${lSCRIPT_NAME}.log" "${lPY_LOG}"

    # check if this is common linux file:
    local lCOMMON_FILES_FOUND=""
    local lCFF=""
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      lCOMMON_FILES_FOUND="(""${RED}""common linux file: no""${GREEN}"")"
      lCFF="no"
      if grep -q "^${lSCRIPT_NAME}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        lCOMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${GREEN}"")"
        lCFF="yes"
      fi
    else
      lCOMMON_FILES_FOUND=""
      lCFF="NA"
    fi
    if [[ "${lVULNS}" -gt 20 ]]; then
      print_output "[+] Found ${RED}${lVULNS} issues${GREEN} in script ${lCOMMON_FILES_FOUND}:${NC} $(print_path "${lPY_SCRIPT_}")" "" "${lPY_LOG}"
      lGPT_PRIO_=3
    else
      print_output "[+] Found ${ORANGE}${lVULNS} issues${GREEN} in script ${lCOMMON_FILES_FOUND}:${NC} $(print_path "${lPY_SCRIPT_}")" "" "${lPY_LOG}"
    fi

    write_csv_log "$(print_path "${lPY_SCRIPT_}")" "${lVULNS}" "${lCFF}" "NA"
    if [[ "${AI_OPTION}" -gt 0 ]]; then
      lAI_ANCHOR="$(openssl rand -hex 8)"
      # if we have some default python packages we rate them lower
      if [[ "${lPY_SCRIPT_}" == *"dist-packages"* || "${lPY_SCRIPT_}" == *"site-packages"* ]]; then
        lGPT_PRIO_=$((lGPT_PRIO_ - 1))
      elif ! grep -E -q "^$(basename "${lPY_SCRIPT_}")$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        # if no entry in our BASE_LINUX_FILES config we do not have a default
        # linux file and we rate it higher for faster AI test
        lGPT_PRIO_=$((lGPT_PRIO_ + 1))
      fi
      # "${GPT_INPUT_FILE_}" "${lAI_ANCHOR}" "${lGPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
      write_csv_AI_tmp "${lS21_SOURCE_DIR}/${lSCRIPT_NAME}.log" "${lAI_ANCHOR}" "${lGPT_PRIO_}" "${GPT_QUESTION}" "${lPY_LOG}" "" ""
      # add ChatGPT link to output file
      printf '%s\n\n' "" >>"${lPY_LOG}"
      write_anchor_AI "${lAI_ANCHOR}" "${lPY_LOG}"
      printf '%s\n\n' "" >>"${lS21_SOURCE_DIR}/${lSCRIPT_NAME}.log"
      write_anchor_AI "${lAI_ANCHOR}" "${lS21_SOURCE_DIR}/${lSCRIPT_NAME}.log"
    fi
    echo "${lVULNS}" >>"${TMP_DIR}"/S21_VULNS.tmp
  fi
}
