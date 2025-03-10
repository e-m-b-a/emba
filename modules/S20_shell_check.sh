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

# Description:  Checks for bugs, stylistic errors, etc. in shell scripts, then it lists the found error types.

S20_shell_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check scripts with shellcheck and semgrep"
  pre_module_reporter "${FUNCNAME[0]}"

  export S20_SHELL_VULNS=0
  export S20_SCRIPTS=0
  local lSH_SCRIPTS_ARR=()
  local lSH_SCRIPT=""
  local lS20_VULN_TYPES_ARR=()
  local lVTYPE=""
  local lSEMGREP=1
  local lNEG_LOG=0
  local lS20_SEMGREP_ISSUES=0
  local lWAIT_PIDS_S20_ARR=()

  # mapfile -t lSH_SCRIPTS_ARR < <( find "${FIRMWARE_PATH}" -xdev -type f -print0|xargs -r -0 -P 16 -I % sh -c 'file "%" | grep "shell script, ASCII text executable" 2>/dev/null | cut -d: -f1' | sort -u || true )
  mapfile -t lSH_SCRIPTS_ARR < <(grep "shell script, ASCII text executable" "${P99_CSV_LOG}" | sort -u || true)
  write_csv_log "Script path" "Shell issues detected" "common linux file" "shellcheck/semgrep"

  if [[ ${SHELLCHECK} -eq 1 ]] ; then
    sub_module_title "Check scripts with shellcheck"
    for lSH_SCRIPT in "${lSH_SCRIPTS_ARR[@]}" ; do
      ((S20_SCRIPTS+=1))
      if [[ "${THREADED}" -eq 1 ]]; then
        s20_script_check "${lSH_SCRIPT/;*}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S20_ARR+=( "${lTMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S20_ARR
        continue
      else
        s20_script_check "${lSH_SCRIPT/;*}"
      fi
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S20_ARR[@]}"

    if [[ -f "${TMP_DIR}"/S20_VULNS.tmp ]]; then
      S20_SHELL_VULNS=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S20_VULNS.tmp)
      rm "${TMP_DIR}"/S20_VULNS.tmp
    fi
    [[ "${S20_SHELL_VULNS}" -gt 0 ]] && lNEG_LOG=1

    print_ln
    if [[ "${S20_SHELL_VULNS}" -gt 0 ]]; then
      sub_module_title "Summary of shell issues (shellcheck)"
      print_output "[+] Found ""${ORANGE}""${S20_SHELL_VULNS}"" issues""${GREEN}"" in ""${ORANGE}""${S20_SCRIPTS}""${GREEN}"" shell scripts (shellcheck mode)""${NC}""\\n"
    fi
    write_log ""
    write_log "[*] Statistics:${S20_SHELL_VULNS}:${S20_SCRIPTS}"

    mapfile -t lS20_VULN_TYPES_ARR < <(grep "\^--\ SC[0-9]" "${LOG_PATH_MODULE}"/shellchecker_* 2>/dev/null | cut -d: -f2- | sed -e 's/\ \+\^--\ //g' | sed -e 's/\^--\ //g' | sort -u -t: -k1,1 | sed -e 's/ \\n//' || true)
    for lVTYPE in "${lS20_VULN_TYPES_ARR[@]}" ; do
      print_output "$(indent "${NC}""[""${GREEN}""+""${NC}""]""${GREEN}"" ""${lVTYPE}""${NC}")"
    done

  else
    print_output "[-] Shellchecker is disabled ... no tests performed"
  fi

  if [[ ${lSEMGREP} -eq 1 ]] ; then
    sub_module_title "Check shell scripts with semgrep"
    local lS20_SEMGREP_SCRIPTS=0
    local lS20_SEMGREP_VULNS=0
    local lSHELL_LOG="${LOG_PATH_MODULE}"/semgrep.log

    semgrep --disable-version-check --config "${EXT_DIR}"/semgrep-rules/bash "${LOG_DIR}"/firmware/ > "${lSHELL_LOG}" 2>&1 || true

    if [[ -s "${lSHELL_LOG}" ]]; then
      lS20_SEMGREP_ISSUES=$(grep "\ findings\." "${lSHELL_LOG}" | cut -d: -f2 | awk '{print $1}' || true)
      lS20_SEMGREP_VULNS=$(grep -c "semgrep-rules.bash.lang.security" "${lSHELL_LOG}" || true)
      lS20_SEMGREP_SCRIPTS=$(grep "\ findings\." "${lSHELL_LOG}" | awk '{print $5}' || true)
      if [[ "${lS20_SEMGREP_VULNS}" -gt 0 ]]; then
        print_output "[+] Found ""${ORANGE}""${lS20_SEMGREP_ISSUES}"" issues""${GREEN}"" (""${ORANGE}""${lS20_SEMGREP_VULNS}"" vulnerabilites${GREEN}) in ""${ORANGE}""${lS20_SEMGREP_SCRIPTS}""${GREEN}"" shell scripts (semgrep mode)""${NC}" "" "${lSHELL_LOG}"
      elif [[ "${lS20_SEMGREP_ISSUES}" -gt 0 ]]; then
        print_output "[+] Found ""${ORANGE}""${lS20_SEMGREP_ISSUES}"" issues""${GREEN}"" in ""${ORANGE}""${lS20_SEMGREP_SCRIPTS}""${GREEN}"" shell scripts""${NC}" "" "${lSHELL_LOG}"
      fi
      # highlight security findings in semgrep log:
      sed -i -r "s/.*external\.semgrep-rules\.bash\.lang\.security.*/\x1b[32m&\x1b[0m/" "${lSHELL_LOG}"
    else
      print_output "[-] No shell issues found with semgrep"
    fi

    [[ "${lS20_SEMGREP_ISSUES}" -gt 0 ]] && lNEG_LOG=1

    write_log ""
    write_log "[*] Statistics1:${lS20_SEMGREP_ISSUES}:${lS20_SEMGREP_SCRIPTS}"
  else
    print_output "[-] Semgrepper is disabled ... no tests performed"
  fi

  s20_eval_script_check "${lSH_SCRIPTS_ARR[@]}"

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

s20_eval_script_check() {
  local lSH_SCRIPTS_ARR=("${@}")
  local lSH_SCRIPT=""
  local lGPT_PRIO_=3
  local lGPT_ANCHOR_=""
  local lEVAL_RESULTS=0
  local lSH_SCRIPT_NAME=""

  sub_module_title "Summary of shell eval usages"

  for lSH_SCRIPT in "${lSH_SCRIPTS_ARR[@]}" ; do
    # print_output "[*] Testing ${ORANGE}${lSH_SCRIPT}${NC} for eval usage" "no_log"
    if grep "eval " "${lSH_SCRIPT/;*}" | grep -q -v "^#.*"; then
      lEVAL_RESULTS=1
      lSH_SCRIPT_NAME="$(basename "${lSH_SCRIPT/;*}")"
      local lSHELL_LOG="${LOG_PATH_MODULE}"/sh_eval_sources/"${lSH_SCRIPT_NAME}".log
      ! [[ -d "${LOG_PATH_MODULE}"/sh_eval_sources/ ]] && mkdir "${LOG_PATH_MODULE}"/sh_eval_sources/
      [[ -f "${lSH_SCRIPT/;*}" ]] && cp "${lSH_SCRIPT/;*}" "${lSHELL_LOG}"
      sed -i -r "s/.*eval\ .*/\x1b[32m&\x1b[0m/" "${lSHELL_LOG}"
      print_output "[+] Found ${ORANGE}eval${GREEN} usage in ${ORANGE}${lSH_SCRIPT_NAME}${NC}" "" "${lSHELL_LOG}"

      if [[ "${GPT_OPTION}" -gt 0 ]]; then
        lGPT_ANCHOR_="$(openssl rand -hex 8)"
        if [[ -f "${BASE_LINUX_FILES}" ]]; then
          # if we have the base linux config file we are checking it:
          if ! grep -E -q "^${lSH_SCRIPT_NAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
            lGPT_PRIO_=$((lGPT_PRIO_+1))
          fi
        fi
        # "${GPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "GPT-Prio-$lGPT_PRIO_" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
        write_csv_gpt_tmp "$(cut_path "${lSH_SCRIPT/;*}")" "${lGPT_ANCHOR_}" "${lGPT_PRIO_}" "${GPT_QUESTION}" "${lSHELL_LOG}" "" ""
        # add ChatGPT link
        printf '%s\n\n' "" >> "${lSHELL_LOG}"
        write_anchor_gpt "${lGPT_ANCHOR_}" "${lSHELL_LOG}"
      fi
    fi
  done
  if [[ "${lEVAL_RESULTS}" -eq 0 ]]; then
    print_output "[-] No eval usage found in shell scripts"
  fi
}

s20_script_check() {
  local lSH_SCRIPT_="${1:-}"
  local lSH_NAME=""
  local lSHELL_LOG=""
  local lVULNS=""

  lSH_NAME=$(basename "${lSH_SCRIPT_}" 2> /dev/null | sed -e 's/:/_/g')
  lSHELL_LOG="${LOG_PATH_MODULE}""/shellchecker_""${lSH_NAME}"".txt"
  shellcheck -C "${lSH_SCRIPT_}" > "${lSHELL_LOG}" 2> /dev/null || true
  lVULNS=$(grep -c "\\^-- SC" "${lSHELL_LOG}" 2> /dev/null || true)

  s20_reporter "${lVULNS}" "${lSH_SCRIPT_}" "${lSHELL_LOG}"
}

s20_reporter() {
  local lVULNS="${1:-}"
  local lSH_SCRIPT_="${2:-}"
  local lSHELL_LOG="${3:-}"
  local lGPT_PRIO_=2
  local lGPT_ANCHOR_=""
  local lSH_NAME=""
  lSH_NAME=$(basename "${lSH_SCRIPT_}" 2> /dev/null | sed -e 's/:/_/g')

  if [[ "${lVULNS}" -ne 0 ]] ; then
    # check if this is common linux file:
    local lCOMMON_FILES_FOUND=""
    local lCFF=""
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      lCOMMON_FILES_FOUND="(""${RED}""common linux file: no""${GREEN}"")"
      lCFF="no"
      if grep -q "^${lSH_NAME}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        lCOMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${GREEN}"")"
        lCFF="yes"
      fi
    else
      lCOMMON_FILES_FOUND=""
    fi

    if [[ "${lVULNS}" -gt 20 ]] ; then
      print_output "[+] Found ""${RED}""${lVULNS}"" issues""${GREEN}"" in script ""${lCOMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${lSH_SCRIPT_}")" "" "${lSHELL_LOG}"
      lGPT_PRIO_=$((lGPT_PRIO_+1))
    else
      print_output "[+] Found ""${ORANGE}""${lVULNS}"" issues""${GREEN}"" in script ""${lCOMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${lSH_SCRIPT_}")" "" "${lSHELL_LOG}"
    fi
    write_csv_log "$(print_path "${lSH_SCRIPT_}")" "${lVULNS}" "${lCFF}" "NA"

    if [[ "${GPT_OPTION}" -gt 0 ]]; then
      lGPT_ANCHOR_="$(openssl rand -hex 8)"
      # "${GPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "GPT-Prio-$lGPT_PRIO_" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
      write_csv_gpt_tmp "$(cut_path "${lSH_SCRIPT_}")" "${lGPT_ANCHOR_}" "${lGPT_PRIO_}" "${GPT_QUESTION}" "${lSHELL_LOG}" "" ""
      # add ChatGPT link
      printf '%s\n\n' "" >> "${lSHELL_LOG}"
      write_anchor_gpt "${lGPT_ANCHOR_}" "${lSHELL_LOG}"
    fi

    echo "${lVULNS}" >> "${TMP_DIR}"/S20_VULNS.tmp
  fi
}
