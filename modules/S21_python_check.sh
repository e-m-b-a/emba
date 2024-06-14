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

# Description:  Checks for bugs, stylistic errors, etc. in python scripts, then it lists the found error types.

S21_python_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check python scripts for security issues"
  pre_module_reporter "${FUNCNAME[0]}"

  local S21_PY_VULNS=0
  local S21_PY_SCRIPTS=0
  local PY_SCRIPT=""
  local lNAME=""
  local PYTHON_SCRIPTS=()
  local S21_VULN_TYPES=()
  local VTYPE=""
  local WAIT_PIDS_S21=()

  if [[ ${PYTHON_CHECK} -eq 1 ]] ; then
    write_csv_log "Script path" "Python issues detected" "common linux file"
    mapfile -t PYTHON_SCRIPTS < <(find "${FIRMWARE_PATH}" -xdev -type f -iname "*.py" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
    for PY_SCRIPT in "${PYTHON_SCRIPTS[@]}" ; do
      if ( file "${PY_SCRIPT}" | grep -q "Python script.*executable" ) ; then
        if [[ -f "${BASE_LINUX_FILES}" && "${FULL_TEST}" -eq 0 ]]; then
          # if we have the base linux config file we only test non known Linux binaries
          # with this we do not waste too much time on open source Linux stuff
          lNAME=$(basename "${PY_SCRIPT}" 2> /dev/null)
          if grep -E -q "^${lNAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
            continue
          fi
        fi
        ((S21_PY_SCRIPTS+=1))
        if [[ "${THREADED}" -eq 1 ]]; then
          s21_script_bandit "${PY_SCRIPT}" &
          local TMP_PID="$!"
          store_kill_pids "${TMP_PID}"
          WAIT_PIDS_S21+=( "${TMP_PID}" )
          max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S21[@]}"
          continue
        else
          s21_script_bandit "${PY_SCRIPT}"
        fi
      fi
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S21[@]}"

    if [[ -f "${TMP_DIR}"/S21_VULNS.tmp ]]; then
      S21_PY_VULNS=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S21_VULNS.tmp)
    fi

    if [[ "${S21_PY_VULNS}" -gt 0 ]]; then
      print_ln
      print_output "[+] Found ""${ORANGE}""${S21_PY_VULNS}"" possible issues""${GREEN}"" in ""${ORANGE}""${S21_PY_SCRIPTS}""${GREEN}"" python files:""${NC}""\\n"
    fi

    write_log ""
    write_log "[*] Statistics:${S21_PY_VULNS}:${S21_PY_SCRIPTS}"

    # we just print one issue per issue type:
    mapfile -t S21_VULN_TYPES < <(grep "[A-Z][0-9][0-9][0-9]" "${LOG_PATH_MODULE}"/bandit_* 2>/dev/null | grep Issue | cut -d: -f3- | tr -d '[' | tr ']' ':' | sort -u || true)
    for VTYPE in "${S21_VULN_TYPES[@]}" ; do
      print_output "$(indent "${NC}""[""${GREEN}""+""${NC}""]""${GREEN}"" ""${VTYPE}""${GREEN}")"
    done
  else
    print_output "[-] Python check is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "${S21_PY_VULNS}"
}

s21_script_bandit() {
  local PY_SCRIPT_="${1:-}"
  local NAME=""
  local PY_LOG=""
  local VULNS=""
  local GPT_PRIO_=2
  local GPT_ANCHOR_=""

  NAME=$(basename "${PY_SCRIPT_}" 2> /dev/null | sed -e 's/:/_/g')
  PY_LOG="${LOG_PATH_MODULE}""/bandit_""${NAME}"".txt"
  bandit -r "${PY_SCRIPT_}" > "${PY_LOG}" 2> /dev/null || true

  VULNS=$(grep -c ">> Issue: " "${PY_LOG}" 2> /dev/null || true)
  if [[ "${VULNS}" -ne 0 ]] ; then
    # check if this is common linux file:
    local COMMON_FILES_FOUND=""
    local CFF=""
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      COMMON_FILES_FOUND="(""${RED}""common linux file: no""${GREEN}"")"
      CFF="no"
      if grep -q "^${NAME}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        COMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${GREEN}"")"
        CFF="yes"
      fi
    else
      COMMON_FILES_FOUND=""
      CFF="NA"
    fi
    if [[ "${VULNS}" -gt 20 ]] ; then
      print_output "[+] Found ""${RED}""${VULNS}"" issues""${GREEN}"" in script ""${COMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${PY_SCRIPT_}")" ""  "${PY_LOG}"
      GPT_PRIO_=3
    else
      print_output "[+] Found ""${ORANGE}""${VULNS}"" issues""${GREEN}"" in script ""${COMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${PY_SCRIPT_}")" "" "${PY_LOG}"
    fi

    write_csv_log "$(print_path "${PY_SCRIPT_}")" "${VULNS}" "${CFF}" "NA"
    if [[ "${GPT_OPTION}" -gt 0 ]]; then
      GPT_ANCHOR_="$(openssl rand -hex 8)"
      if [[ -f "${BASE_LINUX_FILES}" ]]; then
        # if we have the base linux config file we are checking it:
        if ! grep -E -q "^$(basename "${PY_SCRIPT_}")$" "${BASE_LINUX_FILES}" 2>/dev/null; then
          GPT_PRIO_=$((GPT_PRIO_+1))
        fi
      fi
      # "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
      write_csv_gpt_tmp "$(cut_path "${PY_SCRIPT_}")" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION}" "${PY_LOG}" "" ""
      # add ChatGPT link to output file
      printf '%s\n\n' "" >> "${PY_LOG}"
      write_anchor_gpt "${GPT_ANCHOR_}" "${PY_LOG}"
    fi
    echo "${VULNS}" >> "${TMP_DIR}"/S21_VULNS.tmp
  fi
}
