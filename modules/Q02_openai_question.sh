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
  if [[ "${GPT_OPTION}" -gt 0 ]] && [[ -n "${OPENAI_API_KEY}" ]]; then
    module_log_init "${FUNCNAME[0]}"
    # Prints title to CLI and into log
    module_title "AI analysis via OpenAI"
    export CHATGPT_RESULT_CNT=0

    # we wait until there arer entries in the question csv
    while ! [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; do
      sleep 10
    done

    if [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; then
      while ! [[ -f  "${CSV_DIR}/q02_openai_question.csv.tmp" ]]; do
        sleep 3
      done
    fi

    export GTP_CHECKED_ARR=()
    while ! grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; do
      if [[ "${CHATGPT_RESULT_CNT}" -ge 0 ]]; then
        ask_chatgpt
      fi
      sleep 2
    done

    unset OPENAI_API_KEY
    module_end_log "${FUNCNAME[0]}" "${CHATGPT_RESULT_CNT}"
  fi
}

# looks through the modules and finds chatgpt questions inside the csv
ask_chatgpt() {
  local GPT_FILE_DIR_="${LOG_PATH_MODULE}""/gpt_files"
  local GPT_PRIO_=3
  # default vars
  local GPT_QUESTION_="" 
  local CHATGPT_CODE_=""
  local GPT_RESPONSE_=""
  local GPT_RESPONSE_CLEANED_=""
  local GPT_TOKENS_=0
  local HTTP_CODE_=200
  local ORIGIN_MODULE_=""
  local GPT_SERVER_ERROR_CNT_=0

  print_output "[*] Checking scripts with ChatGPT that have priority ${ORANGE}${MINIMUM_GPT_PRIO}${NC} or lower" "no_log"
  if ! [[ -d "${GPT_FILE_DIR_}" ]]; then
    mkdir "${GPT_FILE_DIR_}"
  fi

  # generating Array for GPT requests - sorting according the prio in field 3
  # this array gets regenerated on every round
  readarray -t Q02_OPENAI_QUESTIONS < <(sort -u -k 3 -t ';' -r "${CSV_DIR}/q02_openai_question.csv.tmp")

  for (( ELE_INDEX=0; ELE_INDEX<"${#Q02_OPENAI_QUESTIONS[@]}"; ELE_INDEX++ )); do
    ELEM="${Q02_OPENAI_QUESTIONS["${ELE_INDEX}"]}"
    SCRIPT_PATH_TMP_="$(echo "${ELEM}" | cut -d\; -f1)"

    # as we always start with the highest rated entry, we need to check if this entry was already tested:
    if [[ " ${GTP_CHECKED_ARR[*]} " =~ ${SCRIPT_PATH_TMP_} ]]; then
      # print_output "[*] GPT - Already tested ${SCRIPT_PATH_TMP_}" "no_log"
      # lets test the next entry
      continue
    fi

    GPT_ANCHOR_="$(echo "${ELEM}" | cut -d\; -f2)"
    GPT_PRIO_="$(echo "${ELEM}" | cut -d\; -f3)"
    # GPT_PRIO_="${GPT_PRIO_//GPT-Prio-/}"
    GPT_QUESTION_="$(echo "${ELEM}" | cut -d\; -f4)"
    GPT_OUTPUT_FILE_="$(echo "${ELEM}" | cut -d\; -f5)"
    GPT_TOKENS_="$(echo "${ELEM}" | cut -d\; -f6)"
    GPT_TOKENS_="${GPT_TOKENS_//cost\=/}"
    GPT_RESPONSE_="$(echo "${ELEM}" | cut -d\; -f7)"
    GPT_INPUT_FILE_="$(basename "${SCRIPT_PATH_TMP_}")"
    
    # in case we have nothing we are going to move on
    [[ -z "${SCRIPT_PATH_TMP_}" ]] && continue
    print_output "[*] Identification of ${ORANGE}${SCRIPT_PATH_TMP_} / ${GPT_INPUT_FILE_}${NC} inside ${ORANGE}${LOG_DIR}/firmware${NC}" "no_log"
    SCRIPT_PATH_TMP_="$(find "${LOG_DIR}/firmware" -wholename "*${SCRIPT_PATH_TMP_}")"

    # in case we have nothing we are going to move on
    ! [[ -f "${SCRIPT_PATH_TMP_}" ]] && continue
    [[ -f "${SCRIPT_PATH_TMP_}" ]] && cp "${SCRIPT_PATH_TMP_}" "${GPT_FILE_DIR_}/${GPT_INPUT_FILE_}.log"

    print_output "[*] AI-Assisted analysis of script ${ORANGE}${SCRIPT_PATH_TMP_}${NC} with question ${ORANGE}${GPT_QUESTION_}${NC}" "no_log"
    print_output "[*] Current priority for testing is ${GPT_PRIO_}" "no_log"

    if [[ -z ${GPT_RESPONSE_} ]] && [[ ${GPT_PRIO_} -ge ${MINIMUM_GPT_PRIO} ]] && [[ "${SCRIPT_PATH_TMP_}" != '' ]]; then
      if [[ -f "${SCRIPT_PATH_TMP_}" ]]; then
        # add navbar-item for file
        sub_module_title "${GPT_INPUT_FILE_}"

        print_output "[*] AI-Assisted analysis for ${ORANGE}$(print_path "${SCRIPT_PATH_TMP_}")${NC}" "" "${GPT_FILE_DIR_}/${GPT_INPUT_FILE_}.log"
        head -n -2 "${CONFIG_DIR}/gpt_template.json" > "${TMP_DIR}/chat.json"
        CHATGPT_CODE_=$(sed 's/\\//g;s/"/\\\"/g' "${SCRIPT_PATH_TMP_}" | tr -d '[:space:]')
        printf '"%s %s"\n}]}' "${GPT_QUESTION_}" "${CHATGPT_CODE_}" >> "${TMP_DIR}/chat.json"
        print_output "[*] The Combined Cost of the OpenAI request / the length is: ${ORANGE}${#GPT_QUESTION_} + ${#CHATGPT_CODE_}${NC}" "no_log"
        if [[ "${#CHATGPT_CODE_}" -gt 4561 ]]; then
          print_output "[-] GPT request is too big ... skipping it now"
          GTP_CHECKED_ARR+=("${SCRIPT_PATH_TMP_}")
          continue
        fi

        HTTP_CODE_=$(curl https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" \
          -H "Authorization: Bearer ${OPENAI_API_KEY}" \
          -d @"${TMP_DIR}/chat.json" -o "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json" --write-out "%{http_code}" || true)

        if [[ "${HTTP_CODE_}" -ne 200 ]] ; then
          print_output "[-] Something went wrong with the ChatGPT requests"
          if [[ -f "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json" ]]; then
            print_output "[-] ERROR response: $(cat "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json")"

            if jq '.error.type' "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json" | grep -q "insufficient_quota" ; then
              print_output "[-] Stopping OpenAI requests since the API key has reached its quota limit"
              CHATGPT_RESULT_CNT=-1
              sleep 20
              break
            elif jq '.error.type' "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json" | grep -q "server_error" ; then
              ((GPT_SERVER_ERROR_CNT_+=1))
              if [[ "${GPT_SERVER_ERROR_CNT_}" -ge 5 ]]; then
                # more than 5 failes we stop trying until the newxt round
                print_output "[-] Stopping OpenAI requests since the Server seems to be overloaded"
                CHATGPT_RESULT_CNT=-1
                sleep 20
                break
              fi
            elif jq '.error.code' "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json" | grep -q "rate_limit_exceeded" ; then
              # rate limit handling - if we got a response like:
              # Please try again in 7m12s.
              # then we will wate ~10mins and try it afterwards again
              # in this time we need to check if the Testing phase is running or not
              if jq '.error.message' "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json" | grep -q "Please try again in " ; then
                local CNT=0
                while [[ "${CNT}" -lt 1000 ]]; do
                  CNT=$((CNT+1))
                  (( "${CNT}" % 100 == 0 )) && print_output "[*] Rate limit handling ... sleep mode - ${CNT}" "no_log"
                  if grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
                    break 2
                  fi
                  sleep 1
                done
                # TODO: now we should redo the last test
              else
                print_output "[-] Stopping OpenAI requests since the API key has reached its rate_limit"
                CHATGPT_RESULT_CNT=-1
                break
              fi
            fi

            cat "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json" >> "${GPT_FILE_DIR_}/openai_server_errors.log"
            readarray -t Q02_OPENAI_QUESTIONS < <(sort -u -k 3 -t ';' -r "${CSV_DIR}/q02_openai_question.csv.tmp")
            # reset the array index to start again with the highest rated entry
            ELE_INDEX=0
            sleep 30s
            continue
          fi
        fi

        if ! [[ -f "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json" ]]; then
          # catches: (56) Recv failure: Connection reset by peer
          print_output "[-] Something went wrong with the ChatGPT request for ${GPT_INPUT_FILE_}"
          break
        fi

        GPT_RESPONSE_=("$(jq '.choices[] | .message.content' "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json")")
        GPT_RESPONSE_CLEANED_="${GPT_RESPONSE_[*]//\;/}" #remove ; from response
        GPT_TOKENS_=$(jq '.usage.total_tokens' "${TMP_DIR}/${GPT_INPUT_FILE_}_response.json")

        if [[ ${GPT_TOKENS_} -ne 0 ]]; then
          GTP_CHECKED_ARR+=("${SCRIPT_PATH_TMP_}")
          # write new into done csv
          write_csv_gpt "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=${GPT_TOKENS_}" "'${GPT_RESPONSE_CLEANED_//\'/}'"
          # print openai response
          print_ln
          print_output "[*] ${ORANGE}AI-assisted analysis results via OpenAI ChatGPT:${NC}\\n"
          echo -e "${GPT_RESPONSE_[*]}" | tee -a "${LOG_FILE}"
          # add proper module link
          print_ln

          if [[ "${GPT_OUTPUT_FILE_}" == '/logs/'* ]]; then
            ORIGIN_MODULE_="$(echo "${GPT_OUTPUT_FILE_}" | cut -d / -f3 | cut -d_ -f1)"
          else
            ORIGIN_MODULE_="$(basename "$(dirname "${GPT_OUTPUT_FILE_}")" | cut -d_ -f1)"
          fi

          print_output "[*] Trying to link to module: ${ORIGIN_MODULE_}" "no_log"
          print_output "[+] Further results available for ${ORANGE}${GPT_INPUT_FILE_//./}${GREEN} script" "" "${ORIGIN_MODULE_}"
          print_ln
          ((CHATGPT_RESULT_CNT+=1))
        fi
      else
        print_output "[-] Couldn't find ${ORANGE}$(print_path "${SCRIPT_PATH_TMP_}")${NC}"
      fi
    fi

    if grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
      break
    fi

    if [[ "${GPT_OPTION}" -ne 2 ]]; then
      sleep 20s
    fi

    # reload q02 results:
    print_output "[*] Regenerate analysis array ..." "no_log"
    readarray -t Q02_OPENAI_QUESTIONS < <(sort -u -k 3 -t ';' -r "${CSV_DIR}/q02_openai_question.csv.tmp")
    # reset the array index to start again with the highest rated entry
    ELE_INDEX=0
  done

  if [[ -f "${CSV_DIR}/q02_openai_question.csv" ]]; then
    local GPT_ENTRY_LINE=""
    while read -r GPT_ENTRY_LINE; do
      GPT_ANCHOR_="$(echo "${GPT_ENTRY_LINE}" | cut -d ';' -f2)"
      sed -i "/${GPT_ANCHOR_}/d" "${CSV_DIR}/q02_openai_question.csv.tmp"
    done < "${CSV_DIR}/q02_openai_question.csv"
  fi
}
