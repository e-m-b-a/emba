#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Benedikt Kuehne

# Description: Openai questioning module for container #2
# Note:        Important requirement for Q-modules is the self termination when a certain phase ends

Q02_openai_question() { 
  if [[ "${GPT_OPTION}" -gt 0 ]]; then
    module_log_init "${FUNCNAME[0]}"
    # Prints title to CLI and into log
    module_title "AI analysis via OpenAI"
    export CHATGPT_RESULT_CNT=1

    # we wait until there arer entries in the question csv
    while ! [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; do
      sleep 10
    done

    if [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; then
      while ! [[ -f  "${CSV_DIR}/q02_openai_question.csv.tmp" ]]; do
        sleep 3
      done
    fi
    while ! grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; do
      if [[ "${CHATGPT_RESULT_CNT}" -gt 0 ]]; then
        ask_chatgpt
      fi
      sleep 20
    done
    unset OPENAI_API_KEY
    module_end_log "${FUNCNAME[0]}" "${CHATGPT_RESULT_CNT}"
  fi
}

# looks through the modules and finds chatgpt questions inside the csv
ask_chatgpt() {
  local GPT_FILE_DIR_="${LOG_PATH_MODULE}""/gpt_files/"
  local GPT_PRIO_=3
  # default vars
  local GPT_QUESTION_="" 
  local CHATGPT_CODE_=""
  local GPT_RESPONSE_=""
  local GPT_RESPONSE_CLEANED_=""
  local GPT_TOKENS_=0
  local HTTP_CODE_=200
  local ORIGIN_MODULE_=""
  print_output "[*] Checking scripts with ChatGPT that have priority ${MINIMUM_GPT_PRIO} or lower" "no_log"
  mkdir "${GPT_FILE_DIR_}"
  while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
    SCRIPT_PATH_TMP_="${COL1_}"
    GPT_ANCHOR_="${COL2_}"
    GPT_PRIO_="${COL3_//GPT-Prio-/}"
    GPT_QUESTION_="${COL4_}"
    GPT_OUTPUT_FILE_="${COL5_}"
    GPT_TOKENS_="${COL6_//cost\=/}"
    GPT_RESPONSE_="${COL7_}"
    GPT_INPUT_FILE_="$(basename "${SCRIPT_PATH_TMP_}")"
    
    print_output "[*]trying to check inside ${LOG_DIR}/firmware" "no_log"
    SCRIPT_PATH_TMP_="$(find "${LOG_DIR}/firmware" -wholename "*${SCRIPT_PATH_TMP_}")"
    cp "${GPT_INPUT_FILE_}" "${GPT_FILE_DIR_}/${GPT_INPUT_FILE_}.log"
    print_output "[*]trying to check ${SCRIPT_PATH_TMP_} with Question ${GPT_QUESTION_} " "no_log"
    print_output "[*]Prio is ${GPT_PRIO_}"  "no_log"

    if [[ -z ${GPT_ANSWER_}  ]] && [[ ${GPT_PRIO_} -le ${MINIMUM_GPT_PRIO} ]]; then
      if [ -f "${SCRIPT_PATH_TMP_}" ]; then
        # add navbar-item for file
        sub_module_title "${GPT_INPUT_FILE_}"
        print_output "[*] Asking ChatGPT about $(print_path "${SCRIPT_PATH_TMP_}")" "" "${GPT_FILE_DIR_}/${GPT_INPUT_FILE_}.log"
        head -n -2 "${CONFIG_DIR}/gpt_template.json" > "${TMP_DIR}/chat.json"
        CHATGPT_CODE_=$(sed 's/\\//g;s/"/\\\"/g' "${SCRIPT_PATH_TMP_}" | tr -d '[:space:]')
        printf '"%s %s"\n}]}' "${GPT_QUESTION_}" "${CHATGPT_CODE_}" >> "${TMP_DIR}/chat.json"
        print_output "[*] The Combined Cost of the OpenAI request / the length is: ${#GPT_QUESTION_} + ${#CHATGPT_CODE_}" "no_log"
        HTTP_CODE_=$(curl https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" \
          -H "Authorization: Bearer ${OPENAI_API_KEY}" \
          -d @"${TMP_DIR}/chat.json" -o "${TMP_DIR}/response.json" --write-out "%{http_code}")
        if [[ "${HTTP_CODE_}" -ne 200 ]] ; then
          print_output "[-] Something went wrong with the ChatGPT requests"
          if [ -f "${TMP_DIR}/response.json" ]; then
            print_output "[-] ERROR response:$(cat "${TMP_DIR}/response.json")"
          fi
          if jq '.error.type' "${TMP_DIR}"/response.json | grep -q "insufficient_quota" ; then
            CHATGPT_RESULT_CNT=-1
            break 2
          fi
        fi
        GPT_RESPONSE_=$(jq '.choices[] | .message.content' "${TMP_DIR}"/response.json)
        GPT_RESPONSE_CLEANED_="${GPT_RESPONSE_//\;/}" #remove ; from response
        GPT_TOKENS_=$(jq '.usage.total_tokens' "${TMP_DIR}"/response.json)
        if [[ ${GPT_TOKENS_} -ne 0 ]]; then
          # write new into done csv
          write_csv_gpt "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "GPT-Prio-${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=${GPT_TOKENS_}" "'${GPT_RESPONSE_CLEANED_//\'/}'"
          # print openai response
          print_output "CHATGPT:${GPT_RESPONSE_//\"/}"
          # add proper module link
          print_output "[+] Further results available for $GPT_INPUT_FILE_"
          ORIGIN_MODULE_="$(basename "$(dirname "${GPT_OUTPUT_FILE_}")" | cut -d_ -f1)"
          write_link "${ORIGIN_MODULE_}"
          ((CHATGPT_RESULT_CNT++))
        fi
      else
        print_output "[-] Couldn't find $(print_path "${SCRIPT_PATH_TMP_}")"
      fi
    fi
    if [[ "${GPT_OPTION}" -ne 2 ]]; then
      sleep 20s
    fi
  done < "${CSV_DIR}/q02_openai_question.csv.tmp"
  while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
    GPT_ANCHOR_="${COL2_}"
    sed -i "/${GPT_ANCHOR_}/d" "${CSV_DIR}/q02_openai_question.csv.tmp"
    # TODO remove [CHATGPT] line in output file
  done < "${CSV_DIR}/q02_openai_question.csv"
}