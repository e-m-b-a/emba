#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2021-2024 Siemens Energy AG
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
    local GPT_ANCHOR_=""
    local _GPT_PRIO_=3
    local GPT_QUESTION_=""
    # local GPT_RESPONSE_=""
    local GPT_TOKENS_=0
    local GPT_OUTPUT_FILE_=""
    local GPT_OUTPUT_FILE_HTML_ARR_=()
    local GPT_REVERSE_LINK_=""
    local WAIT_PIDS_F05=()

    if [[ -f "${CSV_DIR}/q02_openai_question.csv" ]]; then
      while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
        GPT_INPUT_FILE_="${COL1_}"
        GPT_ANCHOR_="${COL2_}"
        _GPT_PRIO_="${COL3_}"
        GPT_QUESTION_="${COL4_}"
        GPT_OUTPUT_FILE_="${COL5_}"
        GPT_TOKENS_="${COL6_//cost\=/}"
        GPT_RESPONSE_="${COL7_//\"/}"

        print_output "[*] GPT resolver - testing ${ORANGE}${CSV_DIR}/q02_openai_question.csv${NC}"

        if [[ "${THREADED}" -eq 1 ]]; then
          gpt_resolver_csv "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${_GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "${GPT_TOKENS_}" "${GPT_RESPONSE_}" &
          local TMP_PID="$!"
          store_kill_pids "${TMP_PID}"
          WAIT_PIDS_F05+=( "${TMP_PID}" )
          # max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_F05[@]}"
        else
          gpt_resolver_csv "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${_GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "${GPT_TOKENS_}" "${GPT_RESPONSE_}"
        fi

      done < "${CSV_DIR}/q02_openai_question.csv"

      [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_F05[@]}"

    fi

    if [[ -f "${CSV_DIR}/q02_openai_question.csv.tmp" ]]; then
      while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
        local GPT_INPUT_FILE_="${COL1_}"
        local GPT_ANCHOR_="${COL2_}"
        local _GPT_PRIO_="${COL3_}"
        local GPT_QUESTION_="${COL4_}"
        local GPT_OUTPUT_FILE_="${COL5_}"
        local GPT_TOKENS_="${COL6_//cost\=/}"
        local GPT_RESPONSE_="${COL7_//\"/}"

        print_output "[*] Trying to resolve ${ORANGE}Anchor ${GPT_ANCHOR_}${NC} in ${ORANGE}Output_file ${GPT_OUTPUT_FILE_}${NC}."

        if [[ "${THREADED}" -eq 1 ]]; then
          gpt_resolver_csv_tmp "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${_GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "${GPT_TOKENS_}" "${GPT_RESPONSE_}" &
          local TMP_PID="$!"
          store_kill_pids "${TMP_PID}"
          WAIT_PIDS_F05+=( "${TMP_PID}" )
          # max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_F05[@]}"
        else
          gpt_resolver_csv_tmp "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${_GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "${GPT_TOKENS_}" "${GPT_RESPONSE_}"
        fi
      done < "${CSV_DIR}/q02_openai_question.csv.tmp"

      [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_F05[@]}"

    fi
  fi

  if [[ -d "${HTML_PATH}" ]]; then
    # lets do a final cleanup to get rid of all the ASK_GPT entries:
    find "${HTML_PATH}" -type f -name "*.html" -exec sed -i '/ASK_GPT/d' {} \;
  fi

  # lets do a final cleanup to get rid of all the ASK_GPT entries:
  find "${LOG_DIR}" -max-depth 1 -type f -name "*.txt" -exec sed -i '/ASK_GPT/d' {} \;

  # do not create a web reporter page
  module_end_log "${FUNCNAME[0]}" 0
}

gpt_resolver_csv() {
  local GPT_INPUT_FILE_="${1:-}"
  local GPT_ANCHOR_="${2:-}"
  local _GPT_PRIO_="${3:-}"
  local GPT_QUESTION_="${4:-}"
  local GPT_OUTPUT_FILE_="${5:-}"
  local GPT_TOKENS_="${6:-}"
  local GPT_RESPONSE_="${7:-}"
  local GPT_OUTPUT_FILE_NAME=""
  local GPT_OUTPUT_FILE_NAME_bak=""
  local HTML_FILE_=""
  local HTML_FILE_X=""

  print_output "[*] Trying to resolve ${ORANGE}Anchor ${GPT_ANCHOR_}${NC} in ${ORANGE}Output_file ${GPT_OUTPUT_FILE_}${NC}."

  if [[ ${GPT_TOKENS_} -ne 0 ]]; then
    if ! [ -f "${GPT_OUTPUT_FILE_}" ]; then
      print_output "[-] Something went wrong with the Output file ${GPT_OUTPUT_FILE_}"
      if [[ -z ${GPT_OUTPUT_FILE_} ]]; then
        print_output "    there is no file name for anchor: ${GPT_ANCHOR_}"
      fi
    else
      sed -i "s/${GPT_ANCHOR_}/Q\: ${GPT_QUESTION_}\nA\: /1" "${GPT_OUTPUT_FILE_}"
      # grep "${GPT_ANCHOR_}" "${CSV_DIR}/q02_openai_question.csv" | cut -d";" -f7 >> "${GPT_OUTPUT_FILE_}"
      printf '%q\n' "${GPT_RESPONSE_//\\/}" >> "${GPT_OUTPUT_FILE_}"
      # replace anchor in html-report with link to response

      if [[ "${GPT_OUTPUT_FILE_}" == *".log" ]]; then
        GPT_OUTPUT_FILE_NAME="$(basename "${GPT_OUTPUT_FILE_//\.log/}.html")"
      elif [[ "${GPT_OUTPUT_FILE_}" == *".txt" ]]; then
        GPT_OUTPUT_FILE_NAME="$(basename "${GPT_OUTPUT_FILE_//\.txt/}.html")"
      elif [[ "${GPT_OUTPUT_FILE_}" == *".c" ]]; then
        GPT_OUTPUT_FILE_NAME="$(basename "${GPT_OUTPUT_FILE_//\.c/}.html")"
      fi

      readarray -t GPT_OUTPUT_FILE_HTML_ARR_ < <(find "${HTML_PATH}" -iname "${GPT_OUTPUT_FILE_NAME}" 2>/dev/null)
      # the following search is because of inconsistency in file names.
      # Todo: check this and fix it to only use the rules above
      GPT_OUTPUT_FILE_NAME_bak="$(basename "${GPT_OUTPUT_FILE_//\./}.html")"
      readarray -t GPT_OUTPUT_FILE_HTML_ARR_bak < <(find "${HTML_PATH}" -iname "${GPT_OUTPUT_FILE_NAME_bak}" 2>/dev/null)
      GPT_OUTPUT_FILE_HTML_ARR_+=( "${GPT_OUTPUT_FILE_HTML_ARR_bak[@]}" )

      for HTML_FILE_ in "${GPT_OUTPUT_FILE_HTML_ARR_[@]}"; do
        # should point back to q02-submodule with name "${GPT_INPUT_FILE_}"
        GPT_REVERSE_LINK_="$(tr "[:upper:]" "[:lower:]" <<< "${GPT_INPUT_FILE_}" | sed -e "s@[^a-zA-Z0-9]@@g")"
        # we need to find the depth which we need to link to the file
        # shellcheck disable=SC2001
        HTML_FILE_X=$(echo "${HTML_FILE_}" | sed 's#'"${HTML_PATH}"'##')
        print_output "[*] Linking GPT results ${ORANGE}${GPT_REVERSE_LINK_}${NC} into ${ORANGE}${HTML_FILE_X}${NC}" "no_log"
        depth_cnt="${HTML_FILE_X//[^\/]}"
        depth_cnt="$(( "${#depth_cnt}"-1 ))"
        local DEPTH="\.\.\/"
        local myDEPTH=""
        myDEPTH=$(printf "%${depth_cnt}s")
        DEPTH="${myDEPTH// /${DEPTH}}"

        sed -i "s/\[ASK_GPT\]\ ${GPT_ANCHOR_}/\ \ \ \ \<a class\=\"reference\" href\=\"${DEPTH}q02\_openai\_question\.html\#aianalysisfor${GPT_REVERSE_LINK_}\" title\=\"${GPT_REVERSE_LINK_}\"\ \>\<span\ class=\"green\"\>[+] OpenAI results are available\<\/span\>\<\/a\>\n/1" "${HTML_FILE_}"
      done
    fi
  fi
}

gpt_resolver_csv_tmp() {
  local GPT_INPUT_FILE_="${1:-}"
  local GPT_ANCHOR_="${2:-}"
  local _GPT_PRIO_="${3:-}"
  local GPT_QUESTION_="${4:-}"
  local GPT_OUTPUT_FILE_="${5:-}"
  local GPT_TOKENS_="${6:-}"
  local GPT_RESPONSE_="${7:-}"
  local GPT_OUTPUT_FILE_NAME=""
  local HTML_FILE_=""
  local HTML_FILE_X=""

  print_output "[*] Trying to resolve ${ORANGE}Anchor ${GPT_ANCHOR_}${NC} in ${ORANGE}output_file ${GPT_OUTPUT_FILE_}${NC}."

  if ! [ -f "${GPT_OUTPUT_FILE_}" ]; then
    print_output "[-] Something went wrong with the Output file ${GPT_OUTPUT_FILE_}"
    if [[ -z ${GPT_OUTPUT_FILE_} ]]; then
      print_output "    there is no file name for anchor: ${GPT_ANCHOR_}"
    fi
  else
    print_output "[*] Q02 didn't check ${GPT_INPUT_FILE_}, linking to the GPT module page instead"

    # sed -i "s/${GPT_ANCHOR_}/Check did not finish!/1" "${GPT_OUTPUT_FILE_}"

    if [[ "${GPT_OUTPUT_FILE_}" == *".log" ]]; then
      GPT_OUTPUT_FILE_NAME="$(basename "${GPT_OUTPUT_FILE_//\.log/}.html")"
    elif [[ "${GPT_OUTPUT_FILE_}" == *".txt" ]]; then
      GPT_OUTPUT_FILE_NAME="$(basename "${GPT_OUTPUT_FILE_//\.txt/}.html")"
    elif [[ "${GPT_OUTPUT_FILE_}" == *".c" ]]; then
      GPT_OUTPUT_FILE_NAME="$(basename "${GPT_OUTPUT_FILE_//\.c/}.html")"
    fi

    readarray -t GPT_OUTPUT_FILE_HTML_ARR_ < <(find "${HTML_PATH}" -iname "${GPT_OUTPUT_FILE_NAME}" 2>/dev/null)

    for HTML_FILE_ in "${GPT_OUTPUT_FILE_HTML_ARR_[@]}"; do
      # should point back to q02-submodule with name "${GPT_INPUT_FILE_}"
      GPT_REVERSE_LINK_="$(tr "[:upper:]" "[:lower:]" <<< "${GPT_INPUT_FILE_}" | sed -e "s@[^a-zA-Z0-9]@@g")"

      # we need to find the depth which we need to link to the file
      # shellcheck disable=SC2001
      HTML_FILE_X=$(echo "${HTML_FILE_}" | sed 's#'"${HTML_PATH}"'##')
      print_output "[*] Linking GPT results ${ORANGE}${GPT_REVERSE_LINK_}${NC} into ${ORANGE}${HTML_FILE_X}${NC}" "no_log"
      depth_cnt="${HTML_FILE_X//[^\/]}"
      depth_cnt="$(( "${#depth_cnt}"-1 ))"
      local DEPTH="\.\.\/"
      local myDEPTH=""
      myDEPTH=$(printf "%${depth_cnt}s")
      DEPTH="${myDEPTH// /${DEPTH}}"

      sed -i "s/\[ASK_GPT\]\ ${GPT_ANCHOR_}/\ \ \ \ \<a class\=\"reference\" href\=\"${DEPTH}q02\_openai\_question\.html\" title\=\"${GPT_REVERSE_LINK_}\"\ \>\<span\ class=\"orange\"\>[*] OpenAI module did not finish\<\/span\>\<\/a\>\n/1" "${HTML_FILE_}"
    done
  fi
}
