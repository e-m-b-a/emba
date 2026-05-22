#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2021-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Benedikt Kuehne
# Contributor(s): Michael Messner

# Description:  Resolves all dependancies and links between Q- and S-Modules

F05_qs_resolver() {
  module_log_init "${FUNCNAME[0]}"
  module_title "AI Resolver"

  if [[ "${AI_OPTION}" -gt 0 ]]; then
    if grep -q "Q02_openai_question starting" "${MAIN_LOG}"; then
      print_output "[*] Waiting for the GPT analysis module to stop ... " "no_log"
      while ! grep -q "Q02_openai_question finished\|Quest container finished" "${MAIN_LOG}"; do
        print_output "[*] Waiting for Q02 module"
        sleep 5
      done
      print_output "[*] GPT testing module finished ... " "no_log"
    fi

    if grep -q "Q03_localai_connector starting" "${MAIN_LOG}"; then
      print_output "[*] Waiting for the LocalAI analysis module to stop ... " "no_log"
      while ! grep -q "Q03_localai_connector finished\|Quest container finished" "${MAIN_LOG}"; do
        print_output "[*] Waiting for Q03 module"
        sleep 5
      done
      print_output "[*] LocalAI testing module finished ... " "no_log"
    fi

    # local _GPT_INPUT_FILE_=""
    local lAI_ANCHOR=""
    local l_GPT_PRIO_=3
    local lGPT_QUESTION_=""
    local lGPT_RESPONSE_=""
    local lAI_RESPONSE_FILE=""
    local lGPT_TOKENS_=0
    local lGPT_OUTPUT_FILE_=""
    local lGPT_OUTPUT_FILE_HTML_ARR_=()
    local lGPT_REVERSE_LINK_=""
    local lWAIT_PIDS_F05_ARR=()

    if [[ -f "${CSV_DIR}/ai_question.csv" ]]; then
      while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
        lGPT_INPUT_FILE_="${COL1_}"
        lAI_ANCHOR="${COL2_}"
        l_GPT_PRIO_="${COL3_}"
        lGPT_QUESTION_="${COL4_}"
        lGPT_OUTPUT_FILE_="${COL5_}"
        lGPT_TOKENS_="${COL6_//cost\=/}"
        # file with AI response:
        lAI_RESPONSE_FILE="${COL7_}"

        print_output "[*] AI resolver - testing ${ORANGE}${CSV_DIR}/ai_question.csv${NC}"

        gpt_resolver_csv "${lGPT_INPUT_FILE_}" "${lAI_ANCHOR}" "${l_GPT_PRIO_}" "${lGPT_QUESTION_}" "${lGPT_OUTPUT_FILE_}" "${lGPT_TOKENS_}" "${lAI_RESPONSE_FILE}" &
        lWAIT_PIDS_F05_ARR+=("$!")
        store_kill_pids "${lWAIT_PIDS_F05_ARR[-1]}"
      done <"${CSV_DIR}/ai_question.csv"

      wait_for_pid "${lWAIT_PIDS_F05_ARR[@]}"
    fi

    if [[ -f "${CSV_DIR}/ai_question.csv.tmp" ]]; then
      while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
        local lGPT_INPUT_FILE_="${COL1_}"
        local lAI_ANCHOR="${COL2_}"
        local l_GPT_PRIO_="${COL3_}"
        local lGPT_QUESTION_="${COL4_}"
        local lGPT_OUTPUT_FILE_="${COL5_}"
        local lGPT_TOKENS_="${COL6_//cost\=/}"
        local lGPT_RESPONSE_="${COL7_//\"/}"

        print_output "[*] Trying to resolve ${ORANGE}Anchor ${lAI_ANCHOR}${NC} in ${ORANGE}Output_file ${lGPT_OUTPUT_FILE_}${NC}."

        gpt_resolver_csv_tmp "${lGPT_INPUT_FILE_}" "${lAI_ANCHOR}" "${l_GPT_PRIO_}" "${lGPT_QUESTION_}" "${lGPT_OUTPUT_FILE_}" "${lGPT_TOKENS_}" "${lGPT_RESPONSE_}" &
        local lTMP_PID="$!"
        lWAIT_PIDS_F05_ARR+=("${lTMP_PID}")
        store_kill_pids "${lTMP_PID}"
        # max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_F05_ARR[@]}"
      done <"${CSV_DIR}/ai_question.csv.tmp"

      wait_for_pid "${lWAIT_PIDS_F05_ARR[@]}"
    fi
  fi

  #if [[ -d "${HTML_PATH}" ]]; then
    # lets do a final cleanup to get rid of all the ASK_AI entries:
  #  find "${HTML_PATH}" -type f -name "*.html" -exec sed -i '/ASK_AI/d' {} \;
  #fi

  # lets do a final cleanup to get rid of all the ASK_AI entries:
  #find "${LOG_DIR}" -maxdepth 1 -type f -name "*.txt" -exec sed -i '/ASK_AI/d' {} \;

  # do not create a web reporter page
  module_end_log "${FUNCNAME[0]}" 0
}

gpt_resolver_csv() {
  local lGPT_INPUT_FILE_="${1:-}"
  local lAI_ANCHOR="${2:-}"
  local l_GPT_PRIO_="${3:-}"
  local lGPT_QUESTION_="${4:-}"
  local lGPT_OUTPUT_FILE_="${5:-}"
  local lGPT_TOKENS_="${6:-}"
  local lAI_RESPONSE_FILE="${7:-}"
  local lHTML_FILE_=""
  local lHTML_FILE_X=""

  print_output "[*] Trying to resolve ${ORANGE}Anchor ${lAI_ANCHOR}${NC}."
  if [[ ! -f "${lAI_RESPONSE_FILE}" ]]; then
    print_output "[-] WARNING: No AI response file available - ${lAI_RESPONSE_FILE}"
    return
  fi

  if [[ ${lGPT_TOKENS_} -ne 0 ]]; then
    # replace anchor in html-report with link to response

    local lMD5_OF_AI_RESPONSE_FILE=""
    lMD5_OF_AI_RESPONSE_FILE=$(md5sum "${lAI_RESPONSE_FILE}" | awk '{print $1}')
    lAI_RESPONSE_FILE=$(find "${HTML_PATH}" -iname "${lMD5_OF_AI_RESPONSE_FILE}.html" 2>/dev/null | sort -u | head -1)
    lAI_RESPONSE_FILE_NAME=$(basename "${lAI_RESPONSE_FILE}")
    print_output "[*] Testing ${lAI_RESPONSE_FILE} with md5sum of ${lMD5_OF_AI_RESPONSE_FILE}" "no_log"

    readarray -t lGPT_OUTPUT_FILE_HTML_ARR_ < <(grep -r -l "\[ASK_AI\]\ ${lAI_ANCHOR}" "${HTML_PATH}" 2>/dev/null || true)

    for lHTML_FILE_ in "${lGPT_OUTPUT_FILE_HTML_ARR_[@]}"; do
      print_output "[*] Testing ${lHTML_FILE_} for anchor ${lAI_ANCHOR}" "no_log"
      # should point back to q02-submodule with name "${lGPT_INPUT_FILE_}"
      lGPT_REVERSE_LINK_="$(tr "[:upper:]" "[:lower:]" <<<"${lGPT_INPUT_FILE_}" | sed -e "s@[^a-zA-Z0-9]@@g")"
      # shellcheck disable=SC2001
      lHTML_FILE_X=$(echo "${lHTML_FILE_}" | sed 's#'"${HTML_PATH}"'##')
      print_output "[*] Linking AI results ${ORANGE}${lGPT_REVERSE_LINK_}${NC} into ${ORANGE}${lHTML_FILE_X}${NC}" "no_log"
      local lDEPTH="\.\.\/"

      if [[ "${AI_OPTION}" -eq 3 ]]; then
        if [[ -f "${lAI_RESPONSE_FILE}" ]]; then
          print_output "[*] Replacing Anchor ${lAI_ANCHOR} with link to ${lAI_RESPONSE_FILE_NAME} - ${lAI_RESPONSE_FILE} in ${lHTML_FILE_}"
          sed -i "s/\[ASK_AI\]\ ${lAI_ANCHOR}/\ \ \ \ \<a class\=\"reference\" href\=\"${lDEPTH}q03\_localai\_connector\/${lAI_RESPONSE_FILE_NAME}\" title\=\"${lAI_RESPONSE_FILE_NAME}\"\ \>\<span\ class=\"green\"\>[+] LocalAI results are available\<\/span\>\<\/a\>\n/1" "${lHTML_FILE_}"
        else
          # link to localAI module results - q03_localai_connector.html
          sed -i "s/\[ASK_AI\]\ ${lAI_ANCHOR}/\ \ \ \ \<a class\=\"reference\" href\=\"${lDEPTH}q03\_localai\_connector\.html\#aianalysisfor${lGPT_REVERSE_LINK_}\" title\=\"${lGPT_REVERSE_LINK_}\"\ \>\<span\ class=\"green\"\>[+] LocalAI results are available\<\/span\>\<\/a\>\n/1" "${lHTML_FILE_}"
        fi
      else
        print_output "[-] Deprecated and unsupporte OpenAI mode - bypass"
      fi
    done
  fi
}

gpt_resolver_csv_tmp() {
  local lGPT_INPUT_FILE_="${1:-}"
  local lAI_ANCHOR="${2:-}"
  local l_GPT_PRIO_="${3:-}"
  local lGPT_QUESTION_="${4:-}"
  local lGPT_OUTPUT_FILE_="${5:-}"
  local lGPT_TOKENS_="${6:-}"
  local lGPT_RESPONSE_="${7:-}"
  local lHTML_FILE_=""
  local lHTML_FILE_X=""

  print_output "[*] Trying to resolve ${ORANGE}Anchor ${lAI_ANCHOR}${NC}."

  print_output "[*] AI module didn't check ${lGPT_INPUT_FILE_}, linking to the GPT module page instead"

  readarray -t lGPT_OUTPUT_FILE_HTML_ARR_ < <(grep -r -l "\[ASK_AI\]\ ${lAI_ANCHOR}" "${HTML_PATH}" 2>/dev/null || true)

  for lHTML_FILE_ in "${lGPT_OUTPUT_FILE_HTML_ARR_[@]}"; do
    # should point back to q02-submodule with name "${lGPT_INPUT_FILE_}"
    lGPT_REVERSE_LINK_="$(tr "[:upper:]" "[:lower:]" <<<"${lGPT_INPUT_FILE_}" | sed -e "s@[^a-zA-Z0-9]@@g")"

    # we need to find the depth which we need to link to the file
    # shellcheck disable=SC2001
    lHTML_FILE_X=$(echo "${lHTML_FILE_}" | sed 's#'"${HTML_PATH}"'##')
    print_output "[*] Linking AI results ${ORANGE}${lGPT_REVERSE_LINK_}${NC} into ${ORANGE}${lHTML_FILE_X}${NC}" "no_log"
    local lDEPTH="\.\.\/"

    if [[ "${AI_OPTION}" -eq 3 ]]; then
      sed -i "s/\[ASK_AI\]\ ${lAI_ANCHOR}/\ \ \ \ \<a class\=\"reference\" href\=\"${lDEPTH}q03\_localai\_connector\.html\" title\=\"${lGPT_REVERSE_LINK_}\"\ \>\<span\ class=\"orange\"\>[*] LocalAI module did not finish\<\/span\>\<\/a\>\n/1" "${lHTML_FILE_}"
    else
      print_output "[-] Deprecated and unsupporte OpenAI mode - bypass"
    fi
  done
}
