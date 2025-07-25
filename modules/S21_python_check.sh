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

# Description:  Checks for bugs, stylistic errors, etc. in python scripts, then it lists the found error types.

S21_python_check()
{
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

  if [[ ${PYTHON_CHECK} -eq 1 ]] ; then
    # clearing tmp log file first
    rm -f "${TMP_DIR}"/S21_VULNS.tmp

    write_csv_log "Script path" "Python issues detected" "common linux file"
    # mapfile -t lPYTHON_SCRIPTS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iname "*.py" -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 )
    mapfile -t lPYTHON_SCRIPTS_ARR < <(grep "Python script.*executable" "${P99_CSV_LOG}" | sort -u || true)

    for lPY_SCRIPT in "${lPYTHON_SCRIPTS_ARR[@]}" ; do
      if [[ -f "${BASE_LINUX_FILES}" && "${FULL_TEST}" -eq 0 ]]; then
        # if we have the base linux config file we only test non known Linux binaries
        # with this we do not waste too much time on open source Linux stuff
        lNAME=$(basename "$(echo "${lPY_SCRIPT}" | cut -d';' -f2)" 2> /dev/null)
        if grep -E -q "^${lNAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
          continue
        fi
      fi
      ((lS21_PY_SCRIPTS+=1))
      if [[ "${THREADED}" -eq 1 ]]; then
        s21_script_bandit "$(echo "${lPY_SCRIPT}" | cut -d';' -f2)" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S21_ARR+=( "${lTMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S21_ARR
        continue
      else
        s21_script_bandit "$(echo "${lPY_SCRIPT}" | cut -d';' -f2)"
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
    for lVTYPE in "${lS21_VULN_TYPES_ARR[@]}" ; do
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
  local lGPT_ANCHOR_=""

  lSCRIPT_NAME=$(basename "${lPY_SCRIPT_}" 2> /dev/null | sed -e 's/:/_/g')
  lPY_LOG="${LOG_PATH_MODULE}""/bandit_""${lSCRIPT_NAME}"".txt"
  bandit "${lPY_SCRIPT_}" > "${lPY_LOG}" 2> /dev/null || true

  lVULNS=$(grep -c ">> Issue: " "${lPY_LOG}" 2> /dev/null || true)
  if [[ "${lVULNS}" -ne 0 ]] ; then
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
    if [[ "${lVULNS}" -gt 20 ]] ; then
      print_output "[+] Found ""${RED}""${lVULNS}"" issues""${GREEN}"" in script ""${lCOMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${lPY_SCRIPT_}")" ""  "${lPY_LOG}"
      lGPT_PRIO_=3
    else
      print_output "[+] Found ""${ORANGE}""${lVULNS}"" issues""${GREEN}"" in script ""${lCOMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${lPY_SCRIPT_}")" "" "${lPY_LOG}"
    fi

    write_csv_log "$(print_path "${lPY_SCRIPT_}")" "${lVULNS}" "${lCFF}" "NA"
    if [[ "${GPT_OPTION}" -gt 0 ]]; then
      lGPT_ANCHOR_="$(openssl rand -hex 8)"
      if [[ -f "${BASE_LINUX_FILES}" ]]; then
        # if we have the base linux config file we are checking it:
        if ! grep -E -q "^$(basename "${lPY_SCRIPT_}")$" "${BASE_LINUX_FILES}" 2>/dev/null; then
          lGPT_PRIO_=$((lGPT_PRIO_+1))
        fi
      fi
      # "${GPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "${lGPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
      write_csv_gpt_tmp "$(cut_path "${lPY_SCRIPT_}")" "${lGPT_ANCHOR_}" "${lGPT_PRIO_}" "${GPT_QUESTION}" "${lPY_LOG}" "" ""
      # add ChatGPT link to output file
      printf '%s\n\n' "" >> "${lPY_LOG}"
      write_anchor_gpt "${lGPT_ANCHOR_}" "${lPY_LOG}"
    fi
    echo "${lVULNS}" >> "${TMP_DIR}"/S21_VULNS.tmp
  fi
}

