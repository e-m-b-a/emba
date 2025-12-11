#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Benedikt Kuehne

# Description: Openai questioning module for container #2
# Note:        Important requirement for Q-modules is the self termination when a certain phase ends

Q02_openai_question() {
  module_log_init "${FUNCNAME[0]}"
  export CHATGPT_RESULT_CNT=0
  if [[ "${GPT_OPTION}" -gt 0 ]] && [[ -n "${OPENAI_API_KEY}" ]]; then
    # Prints title to CLI and into log
    module_title "AI analysis via OpenAI"
    pre_module_reporter "${FUNCNAME[0]}"

    # we wait until there arer entries in the question csv
    while ! [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; do
      if ! [[ -d "${LOG_DIR}" ]]; then
        # this usually happens if we automate analysis and remove the logging directory while this module was not finished at all
        return
      fi
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
  fi
  module_end_log "${FUNCNAME[0]}" "${CHATGPT_RESULT_CNT}"
}

# looks through the modules and finds chatgpt questions inside the csv
ask_chatgpt() {
  local lGPT_FILE_DIR="${LOG_PATH_MODULE}/gpt_files"
  local lGPT_PRIO=3
  # default vars
  local lGPT_QUESTION=""
  local lCHATGPT_CODE=""
  local lGPT_RESPONSE=""
  local lGPT_RESPONSE_CLEANED=""
  local lGPT_TOKENS=0
  local lHTTP_CODE=200
  local lORIGIN_MODULE=""
  local lGPT_SERVER_ERROR_CNT=0
  local lELE_INDEX=0
  local lGPT_ANCHOR=""
  local lGPT_INPUT_FILE=""
  local lGPT_INPUT_FILE_mod=""
  local lGPT_OUTPUT_FILE=""
  local lSCRIPT_PATH_TMP=""

  print_output "[*] Checking scripts with ChatGPT that have priority ${ORANGE}${MINIMUM_GPT_PRIO}${NC} or lower" "no_log"
  if ! [[ -d "${lGPT_FILE_DIR}" ]]; then
    mkdir "${lGPT_FILE_DIR}"
  fi

  # generating Array for GPT requests - sorting according the prio in field 3
  # this array gets regenerated on every round
  readarray -t Q02_OPENAI_QUESTIONS < <(sort -k 3 -t ';' -r "${CSV_DIR}/q02_openai_question.csv.tmp")

  for (( lELE_INDEX=0; lELE_INDEX<"${#Q02_OPENAI_QUESTIONS[@]}"; lELE_INDEX++ )); do
    local lELEM="${Q02_OPENAI_QUESTIONS["${lELE_INDEX}"]}"
    lSCRIPT_PATH_TMP="$(echo "${lELEM}" | cut -d\; -f1)"

    # as we always start with the highest rated entry, we need to check if this entry was already tested:
    if [[ " ${GTP_CHECKED_ARR[*]} " =~ ${lSCRIPT_PATH_TMP} ]]; then
      # print_output "[*] GPT - Already tested ${lSCRIPT_PATH_TMP}" "no_log"
      # lets test the next entry
      continue
    fi

    lGPT_ANCHOR="$(echo "${lELEM}" | cut -d\; -f2)"
    lGPT_PRIO="$(echo "${lELEM}" | cut -d\; -f3)"
    # lGPT_PRIO="${lGPT_PRIO//GPT-Prio-/}"
    lGPT_QUESTION="$(echo "${lELEM}" | cut -d\; -f4)"
    lGPT_OUTPUT_FILE="$(echo "${lELEM}" | cut -d\; -f5)"
    lGPT_TOKENS="$(echo "${lELEM}" | cut -d\; -f6)"
    lGPT_TOKENS="${lGPT_TOKENS//cost\=/}"
    lGPT_RESPONSE="$(echo "${lELEM}" | cut -d\; -f7)"
    lGPT_INPUT_FILE="$(basename "${lSCRIPT_PATH_TMP}")"
    lGPT_INPUT_FILE_mod="${lGPT_INPUT_FILE//\./}"

    # in case we have nothing we are going to move on
    [[ -z "${lSCRIPT_PATH_TMP}" ]] && continue

    if [[ "${lSCRIPT_PATH_TMP}" == *"s16_ghidra_decompile_checks"* ]]; then
      # our ghidra check stores the decompiled code in the log directory. We need to copy it to the gpt log directory for further processing
      print_output "[*] Ghidra decompiled code found ${lSCRIPT_PATH_TMP}" "no_log"
      [[ -f "${lSCRIPT_PATH_TMP}" ]] && cp "${lSCRIPT_PATH_TMP}" "${lGPT_FILE_DIR}/${lGPT_INPUT_FILE_mod}.log"
    else
      # this is currently the usual case for scripts
      print_output "[*] Identification of ${ORANGE}${lSCRIPT_PATH_TMP} / ${lGPT_INPUT_FILE}${NC} inside ${ORANGE}${LOG_DIR}/firmware${NC}" "no_log"
      if [[ "${lSCRIPT_PATH_TMP}" == ".""${LOG_DIR}"* ]]; then
        print_output "[*] Warning: System path is not stripped with the root directory - we try to fix it now" "no_log"
        # remove the '.'
        lSCRIPT_PATH_TMP="${lSCRIPT_PATH_TMP:1}"
        # remove the LOG_DIR
        # shellcheck disable=SC2001
        lSCRIPT_PATH_TMP="$(echo "${lSCRIPT_PATH_TMP}" | sed 's#'"${LOG_DIR}"'##')"
        print_output "[*] Stripped path ${lSCRIPT_PATH_TMP}" "no_log"
      fi
      # dirty fix - Todo: use array in future
      lSCRIPT_PATH_TMP="$(find "${LOG_DIR}/firmware" -wholename "*${lSCRIPT_PATH_TMP}" | head -1)"

      # in case we have nothing we are going to move on
      ! [[ -f "${lSCRIPT_PATH_TMP}" ]] && continue
      [[ -f "${lSCRIPT_PATH_TMP}" ]] && cp "${lSCRIPT_PATH_TMP}" "${lGPT_FILE_DIR}/${lGPT_INPUT_FILE_mod}.log"
    fi

    print_output "[*] AI-Assisted analysis of script ${ORANGE}${lSCRIPT_PATH_TMP}${NC} with question ${ORANGE}${lGPT_QUESTION}${NC}" "no_log"
    print_output "[*] Current priority for testing is ${lGPT_PRIO}" "no_log"

    if [[ -z ${lGPT_RESPONSE} ]] && [[ ${lGPT_PRIO} -ge ${MINIMUM_GPT_PRIO} ]] && [[ "${lSCRIPT_PATH_TMP}" != '' ]]; then
      if [[ -f "${lSCRIPT_PATH_TMP}" ]]; then
        # add navbar-item for file
        sub_module_title "AI analysis for ${lGPT_INPUT_FILE}"

        # print_output "[*] AI-Assisted analysis for ${ORANGE}${lGPT_INPUT_FILE}${NC}" "" "${lGPT_FILE_DIR}/${lGPT_INPUT_FILE_mod}.log"
        print_output "[*] AI-Assisted analysis for ${lGPT_INPUT_FILE_mod}" "" "${lGPT_FILE_DIR}/${lGPT_INPUT_FILE_mod}.log"
        print_output "$(indent "$(orange "$(print_path "${lSCRIPT_PATH_TMP}")")")"
        head -n -2 "${CONFIG_DIR}/gpt_template.json" > "${TMP_DIR}/chat.json" || print_error "[-] Tmp file create error for ${lSCRIPT_PATH_TMP}"
        if [[ ! -f "${TMP_DIR}/chat.json" ]]; then
          print_output "[-] Temp file ${TMP_DIR}/chat.json for further analysis of ${lSCRIPT_PATH_TMP} was not created ... some Error occured"
          return
        fi

        lCHATGPT_CODE=$(sed 's/\\//g;s/"/\\\"/g' "${lSCRIPT_PATH_TMP}" | tr -d '[:space:]' | sed 's/\[ASK_GPT\].*//')
        if [[ "${#lCHATGPT_CODE}" -gt 4561 ]]; then
          print_output "[*] GPT request is too big ... stripping it now" "no_log"
          lCHATGPT_CODE=$(sed 's/\\//g;s/"/\\\"/g' "${lSCRIPT_PATH_TMP}" | tr -d '[:space:]' | cut -c-4560 | sed 's/\[ASK_GPT\].*//')
        fi
        strip_color_codes "$(printf '"%s %s"\n}]}' "${lGPT_QUESTION}" "${lCHATGPT_CODE}")" >> "${TMP_DIR}/chat.json"

        print_output "[*] Testing the following code with ChatGPT:" "no_log"
        cat "${lSCRIPT_PATH_TMP}"
        print_ln "no_log"
        print_output "[*] Adjusted the code under test to send it to ChatGPT:" "no_log"
        cat "${TMP_DIR}/chat.json"
        print_ln "no_log"

        print_output "[*] The combined cost of the OpenAI request / the length is: ${ORANGE}${#lGPT_QUESTION} + ${#lCHATGPT_CODE}${NC}" "no_log"

        lHTTP_CODE=$(curl https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" \
          -H "Authorization: Bearer ${OPENAI_API_KEY}" \
          -d @"${TMP_DIR}/chat.json" -o "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" --write-out "%{http_code}" || true)

        if [[ "${lHTTP_CODE}" -ne 200 ]] ; then
          print_output "[-] Something went wrong with the ChatGPT requests"
          if [[ -f "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" ]]; then
            print_output "[-] ERROR response: $(cat "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json")"

            if jq '.error.type' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" | grep -q "insufficient_quota" ; then
              print_output "[-] Stopping OpenAI requests since the API key has reached its quota limit"
              CHATGPT_RESULT_CNT=-1
              sleep 20
              break
            elif jq '.error.type' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" | grep -q "server_error" ; then
              ((lGPT_SERVER_ERROR_CNT+=1))
              if [[ "${lGPT_SERVER_ERROR_CNT}" -ge 5 ]]; then
                # more than 5 failes we stop trying until the newxt round
                print_output "[-] Stopping OpenAI requests since the Server seems to be overloaded"
                CHATGPT_RESULT_CNT=-1
                sleep 20
                break
              fi
            elif jq '.error.code' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" | grep -q "rate_limit_exceeded" ; then
              # rate limit handling - if we got a response like:
              # Please try again in 7m12s.
              # then we will wate ~10mins and try it afterwards again
              # in this time we need to check if the Testing phase is running or not
              if jq '.error.message' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" | grep -q "Please try again in " ; then
                local lCNT=0
                while [[ "${lCNT}" -lt 1000 ]]; do
                  lCNT=$((lCNT+1))
                  local lTEMP_VAR="$(( "${lCNT}" % 100 ))"
                  (( "${lTEMP_VAR}" == 0 )) && print_output "[*] Rate limit handling ... sleep mode - ${lCNT}" "no_log"
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

            cat "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" >> "${lGPT_FILE_DIR}/openai_server_errors.log"
            readarray -t Q02_OPENAI_QUESTIONS < <(sort -k 3 -t ';' -r "${CSV_DIR}/q02_openai_question.csv.tmp")
            # reset the array index to start again with the highest rated entry
            lELE_INDEX=0
            if grep -q "Testing phase ended" "${LOG_DIR}"/"${MAIN_LOG_FILE}"; then
              return
            fi
            sleep 30s
            continue
          fi
        fi

        if ! [[ -f "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json" ]]; then
          # catches: (56) Recv failure: Connection reset by peer
          print_output "[-] Something went wrong with the ChatGPT request for ${lGPT_INPUT_FILE}"
          break
        fi

        lGPT_RESPONSE=("$(jq '.choices[] | .message.content' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json")")
        lGPT_RESPONSE_CLEANED="${lGPT_RESPONSE[*]//\;/}" #remove ; from response
        lGPT_TOKENS=$(jq '.usage.total_tokens' "${TMP_DIR}/${lGPT_INPUT_FILE_mod}_response.json")

        if [[ ${lGPT_TOKENS} -ne 0 ]]; then
          GTP_CHECKED_ARR+=("${lSCRIPT_PATH_TMP}")
          # write new into done csv
          write_csv_gpt "${lGPT_INPUT_FILE}" "${lGPT_ANCHOR}" "${lGPT_PRIO}" "${lGPT_QUESTION}" "${lGPT_OUTPUT_FILE}" "cost=${lGPT_TOKENS}" "'${lGPT_RESPONSE_CLEANED//\'/}'"

          # we store the answers in dedicated files for further interlinking within the report
          if ! [[ -d "${LOG_PATH_MODULE}"/gpt_answers ]]; then
            mkdir "${LOG_PATH_MODULE}"/gpt_answers || true
          fi
          echo "${lGPT_RESPONSE_CLEANED}" > "${LOG_PATH_MODULE}"/gpt_answers/gpt_response_"${lGPT_INPUT_FILE_mod}".log

          # print openai response
          print_ln
          # print_output "[*] ${ORANGE}AI-assisted analysis results via OpenAI ChatGPT:${NC}\\n"
          echo -e "${lGPT_RESPONSE[*]}" | tee -a "${LOG_FILE}"

          # add proper module link
          if [[ "${lGPT_OUTPUT_FILE}" == *'/csv_logs/'* ]]; then
            # if we have a csv_logs path we need to adjust the cut
            lORIGIN_MODULE="$(echo "${lGPT_OUTPUT_FILE}" | cut -d / -f4 | cut -d_ -f1)"
          elif [[ "${lGPT_OUTPUT_FILE}" == '/logs/'* ]]; then
            lORIGIN_MODULE="$(echo "${lGPT_OUTPUT_FILE}" | cut -d / -f3 | cut -d_ -f1)"
          else
            lORIGIN_MODULE="$(basename "$(dirname "${lGPT_OUTPUT_FILE}")" | cut -d_ -f1)"
          fi

          print_ln
          print_output "[+] Further results for ${ORANGE}${lGPT_INPUT_FILE_mod}${GREEN} available in module ${ORANGE}${lORIGIN_MODULE}${NC}" "" "${lORIGIN_MODULE}"
          print_output "[+] Analysed source file ${ORANGE}${lGPT_INPUT_FILE_mod}${GREEN}" "" "${lGPT_FILE_DIR}/${lGPT_INPUT_FILE_mod}.log"
          # print_output "[+] Analysed source script popup ${ORANGE}${lGPT_INPUT_FILE_mod}${GREEN} script"
          # write_local_overlay_link "${lGPT_FILE_DIR}/${lGPT_INPUT_FILE_mod}.log"
          if [[ -f "${LOG_PATH_MODULE}"/gpt_answers/gpt_response_"${lGPT_INPUT_FILE_mod}".log ]]; then
            print_output "[+] GPT answer file for ${ORANGE}${lGPT_INPUT_FILE_mod}${NC}" "" "${LOG_PATH_MODULE}"/gpt_answers/gpt_response_"${lGPT_INPUT_FILE_mod}".log
          fi

          print_ln
          ((CHATGPT_RESULT_CNT+=1))
        fi
      else
        print_output "[-] Couldn't find ${ORANGE}$(print_path "${lSCRIPT_PATH_TMP}")${NC}"
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
    readarray -t Q02_OPENAI_QUESTIONS < <(sort -k 3 -t ';' -r "${CSV_DIR}/q02_openai_question.csv.tmp")
    # reset the array index to start again with the highest rated entry
    lELE_INDEX=0
  done

  if [[ -f "${CSV_DIR}/q02_openai_question.csv" ]]; then
    local lGPT_ENTRY_LINE=""
    while read -r lGPT_ENTRY_LINE; do
      lGPT_ANCHOR="$(echo "${lGPT_ENTRY_LINE}" | cut -d ';' -f2)"
      sed -i "/${lGPT_ANCHOR}/d" "${CSV_DIR}/q02_openai_question.csv.tmp"
    done < "${CSV_DIR}/q02_openai_question.csv"
  fi
}
