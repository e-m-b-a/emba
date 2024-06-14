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

# Description:  Checks for bugs, stylistic errors, etc. in shell scripts, then it lists the found error types.

S20_shell_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check scripts with shellcheck and semgrep"
  pre_module_reporter "${FUNCNAME[0]}"

  export S20_SHELL_VULNS=0
  export S20_SCRIPTS=0
  local SH_SCRIPTS=()
  local SH_SCRIPT=""
  local S20_VULN_TYPES=()
  local VTYPE=""
  local SEMGREP=1
  local NEG_LOG=0
  local S20_SEMGREP_ISSUES=0
  local WAIT_PIDS_S20=()

  mapfile -t SH_SCRIPTS < <( find "${FIRMWARE_PATH}" -xdev -type f -type f -exec file {} \; | grep "shell script, ASCII text executable" 2>/dev/null | cut -d: -f1 | sort -u || true )
  write_csv_log "Script path" "Shell issues detected" "common linux file" "shellcheck/semgrep"

  if [[ ${SHELLCHECK} -eq 1 ]] ; then
    sub_module_title "Check scripts with shellcheck"
    for SH_SCRIPT in "${SH_SCRIPTS[@]}" ; do
      if ( file "${SH_SCRIPT}" | grep -q "shell script" ) ; then
        ((S20_SCRIPTS+=1))
        if [[ "${THREADED}" -eq 1 ]]; then
          s20_script_check "${SH_SCRIPT}" &
          local TMP_PID="$!"
          store_kill_pids "${TMP_PID}"
          WAIT_PIDS_S20+=( "${TMP_PID}" )
          max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S20[@]}"
          continue
        else
          s20_script_check "${SH_SCRIPT}"
        fi
      fi
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S20[@]}"

    if [[ -f "${TMP_DIR}"/S20_VULNS.tmp ]]; then
      S20_SHELL_VULNS=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S20_VULNS.tmp)
      rm "${TMP_DIR}"/S20_VULNS.tmp
    fi
    [[ "${S20_SHELL_VULNS}" -gt 0 ]] && NEG_LOG=1

    print_ln
    if [[ "${S20_SHELL_VULNS}" -gt 0 ]]; then
      sub_module_title "Summary of shell issues (shellcheck)"
      print_output "[+] Found ""${ORANGE}""${S20_SHELL_VULNS}"" issues""${GREEN}"" in ""${ORANGE}""${S20_SCRIPTS}""${GREEN}"" shell scripts""${NC}""\\n"
    fi
    write_log ""
    write_log "[*] Statistics:${S20_SHELL_VULNS}:${S20_SCRIPTS}"

    mapfile -t S20_VULN_TYPES < <(grep "\^--\ SC[0-9]" "${LOG_PATH_MODULE}"/shellchecker_* 2>/dev/null | cut -d: -f2- | sed -e 's/\ \+\^--\ //g' | sed -e 's/\^--\ //g' | sort -u -t: -k1,1 | sed -e 's/ \\n//' || true)
    for VTYPE in "${S20_VULN_TYPES[@]}" ; do
      print_output "$(indent "${NC}""[""${GREEN}""+""${NC}""]""${GREEN}"" ""${VTYPE}""${NC}")"
    done

  else
    print_output "[-] Shellchecker is disabled ... no tests performed"
  fi

  if [[ ${SEMGREP} -eq 1 ]] ; then
    sub_module_title "Check shell scripts with semgrep"
    local S20_SEMGREP_SCRIPTS=0
    local S20_SEMGREP_VULNS=0
    local SHELL_LOG="${LOG_PATH_MODULE}"/semgrep.log

    semgrep --disable-version-check --config "${EXT_DIR}"/semgrep-rules/bash "${LOG_DIR}"/firmware/ > "${SHELL_LOG}" 2>&1 || true

    if [[ -s "${SHELL_LOG}" ]]; then
      S20_SEMGREP_ISSUES=$(grep "\ findings\." "${SHELL_LOG}" | cut -d: -f2 | awk '{print $1}' || true)
      S20_SEMGREP_VULNS=$(grep -c "semgrep-rules.bash.lang.security" "${SHELL_LOG}" || true)
      S20_SEMGREP_SCRIPTS=$(grep "\ findings\." "${SHELL_LOG}" | awk '{print $5}' || true)
      if [[ "${S20_SEMGREP_VULNS}" -gt 0 ]]; then
        print_output "[+] Found ""${ORANGE}""${S20_SEMGREP_ISSUES}"" issues""${GREEN}"" (""${ORANGE}""${S20_SEMGREP_VULNS}"" vulnerabilites${GREEN}) in ""${ORANGE}""${S20_SEMGREP_SCRIPTS}""${GREEN}"" shell scripts""${NC}" "" "${SHELL_LOG}"
      elif [[ "${S20_SEMGREP_ISSUES}" -gt 0 ]]; then
        print_output "[+] Found ""${ORANGE}""${S20_SEMGREP_ISSUES}"" issues""${GREEN}"" in ""${ORANGE}""${S20_SEMGREP_SCRIPTS}""${GREEN}"" shell scripts""${NC}" "" "${SHELL_LOG}"
      fi
      # highlight security findings in semgrep log:
      sed -i -r "s/.*external\.semgrep-rules\.bash\.lang\.security.*/\x1b[32m&\x1b[0m/" "${SHELL_LOG}"
    else
      print_output "[-] No shell issues found with semgrep"
    fi

    [[ "${S20_SEMGREP_ISSUES}" -gt 0 ]] && NEG_LOG=1

    write_log ""
    write_log "[*] Statistics1:${S20_SEMGREP_ISSUES}:${S20_SEMGREP_SCRIPTS}"
  else
    print_output "[-] Semgrepper is disabled ... no tests performed"
  fi

  s20_eval_script_check "${SH_SCRIPTS[@]}"

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

s20_eval_script_check() {
  local SH_SCRIPTS_=("${@}")
  local SH_SCRIPT=""
  local GPT_PRIO_=3
  local GPT_ANCHOR_=""
  local EVAL_RESULTS=0
  local SH_SCRIPT_NAME=""

  sub_module_title "Summary of shell eval usages"

  for SH_SCRIPT in "${SH_SCRIPTS_[@]}" ; do
    # print_output "[*] Testing ${ORANGE}${SH_SCRIPT}${NC} for eval usage" "no_log"
    if grep "eval " "${SH_SCRIPT}" | grep -q -v "^#.*"; then
      EVAL_RESULTS=1
      SH_SCRIPT_NAME="$(basename "${SH_SCRIPT}")"
      local SHELL_LOG="${LOG_PATH_MODULE}"/sh_eval_sources/"${SH_SCRIPT_NAME}".log
      ! [[ -d "${LOG_PATH_MODULE}"/sh_eval_sources/ ]] && mkdir "${LOG_PATH_MODULE}"/sh_eval_sources/
      [[ -f "${SH_SCRIPT}" ]] && cp "${SH_SCRIPT}" "${SHELL_LOG}"
      sed -i -r "s/.*eval\ .*/\x1b[32m&\x1b[0m/" "${SHELL_LOG}"
      print_output "[+] Found ${ORANGE}eval${GREEN} usage in ${ORANGE}${SH_SCRIPT_NAME}${NC}" "" "${SHELL_LOG}"

      if [[ "${GPT_OPTION}" -gt 0 ]]; then
        GPT_ANCHOR_="$(openssl rand -hex 8)"
        if [[ -f "${BASE_LINUX_FILES}" ]]; then
          # if we have the base linux config file we are checking it:
          if ! grep -E -q "^${SH_SCRIPT_NAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
            GPT_PRIO_=$((GPT_PRIO_+1))
          fi
        fi
        # "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "GPT-Prio-$GPT_PRIO_" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
        write_csv_gpt_tmp "$(cut_path "${SH_SCRIPT}")" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION}" "${SHELL_LOG}" "" ""
        # add ChatGPT link
        printf '%s\n\n' "" >> "${SHELL_LOG}"
        write_anchor_gpt "${GPT_ANCHOR_}" "${SHELL_LOG}"
      fi
    fi
  done
  if [[ "${EVAL_RESULTS}" -eq 0 ]]; then
    print_output "[-] No eval usage found in shell scripts"
  fi
}

s20_script_check() {
  local SH_SCRIPT_="${1:-}"
  local CFF=""
  local NAME=""
  local SHELL_LOG=""
  local VULNS=""

  NAME=$(basename "${SH_SCRIPT_}" 2> /dev/null | sed -e 's/:/_/g')
  SHELL_LOG="${LOG_PATH_MODULE}""/shellchecker_""${NAME}"".txt"
  shellcheck -C "${SH_SCRIPT_}" > "${SHELL_LOG}" 2> /dev/null || true
  VULNS=$(grep -c "\\^-- SC" "${SHELL_LOG}" 2> /dev/null || true)

  s20_reporter "${VULNS}" "${SH_SCRIPT_}" "${SHELL_LOG}"
}

s20_reporter() {
  local VULNS="${1:0}"
  local SH_SCRIPT_="${2:0}"
  local SHELL_LOG="${3:0}"
  local GPT_PRIO_=2
  local GPT_ANCHOR_=""

  if [[ "${VULNS}" -ne 0 ]] ; then
    # check if this is common linux file:
    local COMMON_FILES_FOUND=""
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      COMMON_FILES_FOUND="(""${RED}""common linux file: no""${GREEN}"")"
      CFF="no"
      if grep -q "^${NAME}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        COMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${GREEN}"")"
        CFF="yes"
      fi
    else
      COMMON_FILES_FOUND=""
    fi

    if [[ "${VULNS}" -gt 20 ]] ; then
      print_output "[+] Found ""${RED}""${VULNS}"" issues""${GREEN}"" in script ""${COMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${SH_SCRIPT}")" "" "${SHELL_LOG}"
      GPT_PRIO_=$((GPT_PRIO_+1))
    else
      print_output "[+] Found ""${ORANGE}""${VULNS}"" issues""${GREEN}"" in script ""${COMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${SH_SCRIPT}")" "" "${SHELL_LOG}"
    fi
    write_csv_log "$(print_path "${SH_SCRIPT}")" "${VULNS}" "${CFF}" "NA"

    if [[ "${GPT_OPTION}" -gt 0 ]]; then
      GPT_ANCHOR_="$(openssl rand -hex 8)"
      # "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "GPT-Prio-$GPT_PRIO_" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
      write_csv_gpt_tmp "$(cut_path "${SH_SCRIPT}")" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION}" "${SHELL_LOG}" "" ""
      # add ChatGPT link
      printf '%s\n\n' "" >> "${SHELL_LOG}"
      write_anchor_gpt "${GPT_ANCHOR_}" "${SHELL_LOG}"
    fi

    echo "${VULNS}" >> "${TMP_DIR}"/S20_VULNS.tmp
  fi
}
