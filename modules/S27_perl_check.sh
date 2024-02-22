#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Checks for bugs, stylistic errors, etc. in perl scripts with zarn - https://github.com/htrgouvea/zarn

S27_perl_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check perl scripts for security issues"
  pre_module_reporter "${FUNCNAME[0]}"

  local lS27_PL_VULNS=0

  if ! [[ -f "${EXT_DIR}"/zarn/zarn.pl ]]; then
    print_output "[-] Zarn installation not available - please check your installation/docker image"
    module_end_log "${FUNCNAME[0]}" "${lS27_PL_VULNS}"
    return
  fi

  local lS27_PL_SCRIPTS=0
  local lPL_SCRIPT=""
  local lPERL_SCRIPTS_ARR=()
  local lWAIT_PIDS_S27=()

  write_csv_log "Script path" "Perl issues detected" "common linux file" "vuln title" "vuln line nr" "vuln note"
  mapfile -t lPERL_SCRIPTS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f \( -name "*.pl" -o -name "*.pm" -o -name "*.cgi" \) -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  for lPL_SCRIPT in "${lPERL_SCRIPTS_ARR[@]}" ; do
    if ( file "${lPL_SCRIPT}" | grep -q "Perl script.*executable" ) ; then
      ((lS27_PL_SCRIPTS+=1))
      if [[ "${THREADED}" -eq 1 ]]; then
        s27_zarn_perl_checks "${lPL_SCRIPT}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        WAIT_PIDS_S27+=( "${lTMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_S27[@]}"
        continue
      else
        s27_zarn_perl_checks "${lPL_SCRIPT}"
      fi
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S27[@]}"
  [[ -d "${TMP_DIR}"/s27 ]] && rm -r "${TMP_DIR}"/s27

  write_log ""
  write_log "[*] Statistics:${lS27_PL_VULNS}:${lS27_PL_SCRIPTS}"
  module_end_log "${FUNCNAME[0]}" "${lS27_PL_VULNS}"
}

s27_zarn_perl_checks() {
  local lPL_SCRIPT="${1:-}"
  local lNAME=""
  local lPL_LOG=""
  local lVULNS=""
  local lGPT_PRIO=2
  local lGPT_ANCHOR=""
  local lZARN_SARIF_RESULTS_ARR=()
  local lSARIF_RESULT=""
  local lZARN_VULN_TITLE=""
  local lZARN_VULN_MESSAGE=""
  local lZARN_VULN_LINE=""

  lNAME=$(basename "${lPL_SCRIPT}" 2> /dev/null | sed -e 's/:/_/g')
  lPL_LOG="${LOG_PATH_MODULE}""/zarn_""${lNAME}"".txt"
  if [[ "${lPL_SCRIPT: -4}" == ".cgi" ]]; then
    if ! [[ -d "${TMP_DIR}"/s27 ]]; then
      mkdir "${TMP_DIR}"/s27
    fi
    # as zarn does not like cgi's, we need to temp rename these files now
    cp "${lPL_SCRIPT}" "${TMP_DIR}"/s27/"${lNAME/.cgi/.pl}"
    perl "${EXT_DIR}"/zarn/zarn.pl -r "${EXT_DIR}"/zarn/rules/default.yml --source "${TMP_DIR}"/s27/"${lNAME/.cgi/.pl}" --sarif "${LOG_PATH_MODULE}""/zarn_""${lNAME}"".sarif" > "${lPL_LOG}" 2> /dev/null || true
    rm "${TMP_DIR}"/s27/"${lNAME/.cgi/.pl}"
  else
    perl "${EXT_DIR}"/zarn/zarn.pl -r "${EXT_DIR}"/zarn/rules/default.yml --source "${lPL_SCRIPT}" --sarif "${LOG_PATH_MODULE}""/zarn_""${lNAME}"".sarif" > "${lPL_LOG}" 2> /dev/null || true
  fi

  lVULNS=$(grep -c "\[vuln\]" "${lPL_LOG}" 2> /dev/null || true)
  if [[ "${lVULNS}" -gt 0 ]] ; then
    # check if this is common linux file:
    local lCOMMON_FILES_FOUND=""
    local lCFF=""
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      lCOMMON_FILES_FOUND="(""${RED}""common linux file: no""${GREEN}"")"
      lCFF="no"
      if grep -q "^${lNAME}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        lCOMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${GREEN}"")"
        lCFF="yes"
      fi
    else
      lCOMMON_FILES_FOUND=""
      lCFF="NA"
    fi
    if [[ "${lVULNS}" -gt 20 ]] ; then
      print_output "[+] Found ""${RED}""${lVULNS}"" issues""${GREEN}"" in script ""${lCOMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${lPL_SCRIPT}")" ""  "${lPL_LOG}"
      lGPT_PRIO=3
    else
      print_output "[+] Found ""${ORANGE}""${lVULNS}"" issues""${GREEN}"" in script ""${lCOMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${lPL_SCRIPT}")" "" "${lPL_LOG}"
    fi

    mapfile -t lZARN_SARIF_RESULTS_ARR < <(jq -rc '.runs[].results[]' "${LOG_PATH_MODULE}""/zarn_""${lNAME}"".sarif")
    for lSARIF_RESULT in "${lZARN_SARIF_RESULTS_ARR[@]}"; do
      lZARN_VULN_TITLE=$(echo "${lSARIF_RESULT}" | jq -rc '.properties.title' || true)
      lZARN_VULN_MESSAGE=$(echo "${lSARIF_RESULT}" | jq -rc '.message.text' || true)
      lZARN_VULN_LINE=$(echo "${lSARIF_RESULT}" | jq -rc 'locations[].physicalLocation.region.startLine' || true)

      write_csv_log "$(print_path "${lPL_SCRIPT}")" "${lVULNS}" "${lCFF}" "${lZARN_VULN_TITLE}" "${lZARN_VULN_LINE}" "${lZARN_VULN_MESSAGE}"
      print_output "$(indent "$(green "${lNAME} - ${lZARN_VULN_TITLE} - line ${lZARN_VULN_LINE}")")"
    done

    # writing gpt details:
    if [[ "${GPT_OPTION}" -gt 0 ]]; then
      lGPT_ANCHOR="$(openssl rand -hex 8)"
      if [[ -f "${BASE_LINUX_FILES}" ]]; then
        # if we have the base linux config file we are checking it:
        if ! grep -E -q "^$(basename "${lPL_SCRIPT}")$" "${BASE_LINUX_FILES}" 2>/dev/null; then
          lGPT_PRIO=$((lGPT_PRIO+1))
        fi
      fi
      # "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
      write_csv_gpt_tmp "$(cut_path "${lPL_SCRIPT}")" "${lGPT_ANCHOR}" "${lGPT_PRIO}" "${GPT_QUESTION}" "${lPL_LOG}" "" ""
      # add ChatGPT link to output file
      printf '%s\n\n' "" >> "${lPL_LOG}"
      write_anchor_gpt "${lGPT_ANCHOR}" "${lPL_LOG}"
    fi
    echo "${lVULNS}" >> "${TMP_DIR}"/S27_VULNS.tmp
  fi
}
