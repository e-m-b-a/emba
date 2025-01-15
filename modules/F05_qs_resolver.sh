#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2021-2025 Siemens Energy AG
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
  module_title "GPT Resolver"

  if [[ "${GPT_OPTION}" -gt 0 ]]; then
    # wait for completion or 1m
    if grep -q "Q02_openai_question starting" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
      print_output "[*] Waiting for the GPT testing module to stop ... " "no_log"
      grep -q "Q02_openai_question finished" "${LOG_DIR}"/"${MAIN_LOG_FILE}" || sleep 1m
      print_output "[*] GPT testing module stopped ... " "no_log"
    fi

    # local _GPT_INPUT_FILE_=""
    local lGPT_ANCHOR_=""
    local l_GPT_PRIO_=3
    local lGPT_QUESTION_=""
    local lGPT_RESPONSE_=""
    local lGPT_TOKENS_=0
    local lGPT_OUTPUT_FILE_=""
    local lGPT_OUTPUT_FILE_HTML_ARR_=()
    local lGPT_REVERSE_LINK_=""
    local lWAIT_PIDS_F05_ARR=()

    if [[ -f "${CSV_DIR}/q02_openai_question.csv" ]]; then
      while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
        lGPT_INPUT_FILE_="${COL1_}"
        lGPT_ANCHOR_="${COL2_}"
        l_GPT_PRIO_="${COL3_}"
        lGPT_QUESTION_="${COL4_}"
        lGPT_OUTPUT_FILE_="${COL5_}"
        lGPT_TOKENS_="${COL6_//cost\=/}"
        lGPT_RESPONSE_="${COL7_//\"/}"

        print_output "[*] GPT resolver - testing ${ORANGE}${CSV_DIR}/q02_openai_question.csv${NC}"

        if [[ "${THREADED}" -eq 1 ]]; then
          gpt_resolver_csv "${lGPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "${l_GPT_PRIO_}" "${lGPT_QUESTION_}" "${lGPT_OUTPUT_FILE_}" "${lGPT_TOKENS_}" "${lGPT_RESPONSE_}" &
          local lTMP_PID="$!"
          store_kill_pids "${lTMP_PID}"
          lWAIT_PIDS_F05_ARR+=( "${lTMP_PID}" )
          # max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_F05_ARR[@]}"
        else
          gpt_resolver_csv "${lGPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "${l_GPT_PRIO_}" "${lGPT_QUESTION_}" "${lGPT_OUTPUT_FILE_}" "${lGPT_TOKENS_}" "${lGPT_RESPONSE_}"
        fi

      done < "${CSV_DIR}/q02_openai_question.csv"

      [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_F05_ARR[@]}"

    fi

    if [[ -f "${CSV_DIR}/q02_openai_question.csv.tmp" ]]; then
      while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
        local lGPT_INPUT_FILE_="${COL1_}"
        local lGPT_ANCHOR_="${COL2_}"
        local l_GPT_PRIO_="${COL3_}"
        local lGPT_QUESTION_="${COL4_}"
        local lGPT_OUTPUT_FILE_="${COL5_}"
        local lGPT_TOKENS_="${COL6_//cost\=/}"
        local lGPT_RESPONSE_="${COL7_//\"/}"

        print_output "[*] Trying to resolve ${ORANGE}Anchor ${lGPT_ANCHOR_}${NC} in ${ORANGE}Output_file ${lGPT_OUTPUT_FILE_}${NC}."

        if [[ "${THREADED}" -eq 1 ]]; then
          gpt_resolver_csv_tmp "${lGPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "${l_GPT_PRIO_}" "${lGPT_QUESTION_}" "${lGPT_OUTPUT_FILE_}" "${lGPT_TOKENS_}" "${lGPT_RESPONSE_}" &
          local lTMP_PID="$!"
          store_kill_pids "${lTMP_PID}"
          lWAIT_PIDS_F05_ARR+=( "${lTMP_PID}" )
          # max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_F05_ARR[@]}"
        else
          gpt_resolver_csv_tmp "${lGPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "${l_GPT_PRIO_}" "${lGPT_QUESTION_}" "${lGPT_OUTPUT_FILE_}" "${lGPT_TOKENS_}" "${lGPT_RESPONSE_}"
        fi
      done < "${CSV_DIR}/q02_openai_question.csv.tmp"

      [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_F05_ARR[@]}"

    fi
  fi

  if [[ -d "${HTML_PATH}" ]]; then
    # lets do a final cleanup to get rid of all the ASK_GPT entries:
    find "${HTML_PATH}" -type f -name "*.html" -exec sed -i '/ASK_GPT/d' {} \;
  fi

  # lets do a final cleanup to get rid of all the ASK_GPT entries:
  find "${LOG_DIR}" -maxdepth 1 -type f -name "*.txt" -exec sed -i '/ASK_GPT/d' {} \;

  # do not create a web reporter page
  module_end_log "${FUNCNAME[0]}" 0
}

gpt_resolver_csv() {
  local lGPT_INPUT_FILE_="${1:-}"
  local lGPT_ANCHOR_="${2:-}"
  local l_GPT_PRIO_="${3:-}"
  local lGPT_QUESTION_="${4:-}"
  local lGPT_OUTPUT_FILE_="${5:-}"
  local lGPT_TOKENS_="${6:-}"
  local lGPT_RESPONSE_="${7:-}"
  local lGPT_OUTPUT_FILE_NAME=""
  local lGPT_OUTPUT_FILE_NAME_bak=""
  local lHTML_FILE_=""
  local lHTML_FILE_X=""

  print_output "[*] Trying to resolve ${ORANGE}Anchor ${lGPT_ANCHOR_}${NC} in ${ORANGE}Output_file ${lGPT_OUTPUT_FILE_}${NC}."

  if [[ ${lGPT_TOKENS_} -ne 0 ]]; then
    if ! [ -f "${lGPT_OUTPUT_FILE_}" ]; then
      print_output "[-] Something went wrong with the Output file ${lGPT_OUTPUT_FILE_}"
      if [[ -z ${lGPT_OUTPUT_FILE_} ]]; then
        print_output "    there is no file name for anchor: ${lGPT_ANCHOR_}"
      fi
    else
      sed -i "s/${lGPT_ANCHOR_}/Q\: ${lGPT_QUESTION_}\nA\: /1" "${lGPT_OUTPUT_FILE_}"
      # grep "${lGPT_ANCHOR_}" "${CSV_DIR}/q02_openai_question.csv" | cut -d";" -f7 >> "${lGPT_OUTPUT_FILE_}"
      printf '%q\n' "${lGPT_RESPONSE_//\\/}" >> "${lGPT_OUTPUT_FILE_}"
      # replace anchor in html-report with link to response

      if [[ "${lGPT_OUTPUT_FILE_}" == *".log" ]]; then
        lGPT_OUTPUT_FILE_NAME="$(basename "${lGPT_OUTPUT_FILE_//\.log/}.html")"
      elif [[ "${lGPT_OUTPUT_FILE_}" == *".txt" ]]; then
        lGPT_OUTPUT_FILE_NAME="$(basename "${lGPT_OUTPUT_FILE_//\.txt/}.html")"
      elif [[ "${lGPT_OUTPUT_FILE_}" == *".c" ]]; then
        lGPT_OUTPUT_FILE_NAME="$(basename "${lGPT_OUTPUT_FILE_//\.c/}.html")"
      fi

      readarray -t lGPT_OUTPUT_FILE_HTML_ARR_ < <(find "${HTML_PATH}" -iname "${lGPT_OUTPUT_FILE_NAME}" 2>/dev/null)
      # the following search is because of inconsistency in file names.
      # Todo: check this and fix it to only use the rules above
      lGPT_OUTPUT_FILE_NAME_bak="$(basename "${lGPT_OUTPUT_FILE_//\./}.html")"
      readarray -t GPT_OUTPUT_FILE_HTML_ARR_bak < <(find "${HTML_PATH}" -iname "${lGPT_OUTPUT_FILE_NAME_bak}" 2>/dev/null)
      lGPT_OUTPUT_FILE_HTML_ARR_+=( "${GPT_OUTPUT_FILE_HTML_ARR_bak[@]}" )

      for lHTML_FILE_ in "${lGPT_OUTPUT_FILE_HTML_ARR_[@]}"; do
        # should point back to q02-submodule with name "${lGPT_INPUT_FILE_}"
        lGPT_REVERSE_LINK_="$(tr "[:upper:]" "[:lower:]" <<< "${lGPT_INPUT_FILE_}" | sed -e "s@[^a-zA-Z0-9]@@g")"
        # we need to find the depth which we need to link to the file
        # shellcheck disable=SC2001
        lHTML_FILE_X=$(echo "${lHTML_FILE_}" | sed 's#'"${HTML_PATH}"'##')
        print_output "[*] Linking GPT results ${ORANGE}${lGPT_REVERSE_LINK_}${NC} into ${ORANGE}${lHTML_FILE_X}${NC}" "no_log"
        depth_cnt="${lHTML_FILE_X//[^\/]}"
        depth_cnt="$(( "${#depth_cnt}"-1 ))"
        local lDEPTH="\.\.\/"
        local lmyDEPTH=""
        lmyDEPTH=$(printf "%${depth_cnt}s")
        lDEPTH="${lmyDEPTH// /${lDEPTH}}"

        sed -i "s/\[ASK_GPT\]\ ${lGPT_ANCHOR_}/\ \ \ \ \<a class\=\"reference\" href\=\"${lDEPTH}q02\_openai\_question\.html\#aianalysisfor${lGPT_REVERSE_LINK_}\" title\=\"${lGPT_REVERSE_LINK_}\"\ \>\<span\ class=\"green\"\>[+] OpenAI results are available\<\/span\>\<\/a\>\n/1" "${lHTML_FILE_}"
      done
    fi
  fi
}

gpt_resolver_csv_tmp() {
  local lGPT_INPUT_FILE_="${1:-}"
  local lGPT_ANCHOR_="${2:-}"
  local l_GPT_PRIO_="${3:-}"
  local lGPT_QUESTION_="${4:-}"
  local lGPT_OUTPUT_FILE_="${5:-}"
  local lGPT_TOKENS_="${6:-}"
  local lGPT_RESPONSE_="${7:-}"
  local lGPT_OUTPUT_FILE_NAME=""
  local lHTML_FILE_=""
  local lHTML_FILE_X=""

  print_output "[*] Trying to resolve ${ORANGE}Anchor ${lGPT_ANCHOR_}${NC} in ${ORANGE}output_file ${lGPT_OUTPUT_FILE_}${NC}."

  if ! [ -f "${lGPT_OUTPUT_FILE_}" ]; then
    print_output "[-] Something went wrong with the Output file ${lGPT_OUTPUT_FILE_}"
    if [[ -z ${lGPT_OUTPUT_FILE_} ]]; then
      print_output "    there is no file name for anchor: ${lGPT_ANCHOR_}"
    fi
  else
    print_output "[*] Q02 didn't check ${lGPT_INPUT_FILE_}, linking to the GPT module page instead"

    # sed -i "s/${lGPT_ANCHOR_}/Check did not finish!/1" "${lGPT_OUTPUT_FILE_}"

    if [[ "${lGPT_OUTPUT_FILE_}" == *".log" ]]; then
      lGPT_OUTPUT_FILE_NAME="$(basename "${lGPT_OUTPUT_FILE_//\.log/}.html")"
    elif [[ "${lGPT_OUTPUT_FILE_}" == *".txt" ]]; then
      lGPT_OUTPUT_FILE_NAME="$(basename "${lGPT_OUTPUT_FILE_//\.txt/}.html")"
    elif [[ "${lGPT_OUTPUT_FILE_}" == *".c" ]]; then
      lGPT_OUTPUT_FILE_NAME="$(basename "${lGPT_OUTPUT_FILE_//\.c/}.html")"
    fi

    readarray -t lGPT_OUTPUT_FILE_HTML_ARR_ < <(find "${HTML_PATH}" -iname "${lGPT_OUTPUT_FILE_NAME}" 2>/dev/null)

    for lHTML_FILE_ in "${lGPT_OUTPUT_FILE_HTML_ARR_[@]}"; do
      # should point back to q02-submodule with name "${lGPT_INPUT_FILE_}"
      lGPT_REVERSE_LINK_="$(tr "[:upper:]" "[:lower:]" <<< "${lGPT_INPUT_FILE_}" | sed -e "s@[^a-zA-Z0-9]@@g")"

      # we need to find the depth which we need to link to the file
      # shellcheck disable=SC2001
      lHTML_FILE_X=$(echo "${lHTML_FILE_}" | sed 's#'"${HTML_PATH}"'##')
      print_output "[*] Linking GPT results ${ORANGE}${lGPT_REVERSE_LINK_}${NC} into ${ORANGE}${lHTML_FILE_X}${NC}" "no_log"
      depth_cnt="${lHTML_FILE_X//[^\/]}"
      depth_cnt="$(( "${#depth_cnt}"-1 ))"
      local lDEPTH="\.\.\/"
      local lmyDEPTH=""
      lmyDEPTH=$(printf "%${depth_cnt}s")
      lDEPTH="${lmyDEPTH// /${lDEPTH}}"

      sed -i "s/\[ASK_GPT\]\ ${lGPT_ANCHOR_}/\ \ \ \ \<a class\=\"reference\" href\=\"${lDEPTH}q02\_openai\_question\.html\" title\=\"${lGPT_REVERSE_LINK_}\"\ \>\<span\ class=\"orange\"\>[*] OpenAI module did not finish\<\/span\>\<\/a\>\n/1" "${lHTML_FILE_}"
    done
  fi
}
