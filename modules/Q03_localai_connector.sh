#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Benedikt Kuehne, Michael Messner

# Description: LocalAI questioning module for container #2
# Note:        Important requirement for Q-modules is the self termination when a certain phase ends
#              This module has an additional minimum runtime mechanism. Ensure the F05 module is respecting
#              the minimum runtime and waits for the module to finish.

# set DEBUG to 1 to enable further debug messages
: "${DEBUG:=0}"
export DEBUG

Q03_localai_connector() {
  module_log_init "${FUNCNAME[0]}"
  export AI_RESULT_CNT=0

  if [[ "${AI_OPTION}" -eq 3 ]]; then
    module_title "AI analysis via LocalAI"
    pre_module_reporter "${FUNCNAME[0]}"

    export AI_RESULT_CNT=0
    export AI_ERROR_CNT=0
    local lMAX_AI_ERROR_CNT=10

    local lMODEL_LOCALAI=""
    lMODEL_LOCALAI=$(identify_ai_model)
    if [[ -z "${lMODEL_LOCALAI}" ]]; then
      print_output "[-] No model identified - is the AI responsive? Exit now."
      module_end_log "${FUNCNAME[0]}" 0
      return
    fi

    print_output "[*] Identified AI model: ${lMODEL_LOCALAI}"

    if [[ "${lMODEL_LOCALAI}" != *"${LOCAL_AI_MODEL}"* ]]; then
      print_output "[-] Configured model ${LOCAL_AI_MODEL} does not match the identified model ${lMODEL_LOCALAI} - exit now"
      module_end_log "${FUNCNAME[0]}" 0
      return
    fi

    # we wait until there arer entries in the question csv
    while ! [[ -f "${MAIN_LOG}" ]]; do
      if ! [[ -d "${LOG_DIR}" ]]; then
        # this usually happens if we automate analysis and remove the logging directory while this module was not finished at all
        return
      fi
      sleep 10
    done

    if [[ -f "${MAIN_LOG}" ]]; then
      while ! [[ -f "${CSV_DIR}/ai_question.csv.tmp" ]]; do
        sleep 3
      done
    fi

    export SECONDS=0
    AI_MIN_RUNTIME=$(convert_timeformat "${AI_MIN_RUNTIME}")

    export GTP_CHECKED_ARR=()
    local lMODULE_RUNTIME=${SECONDS}
    adjust_minimum_runtime "${lMODULE_RUNTIME}"
    # check for runtime
    while [[ "${lMODULE_RUNTIME}" -lt "${AI_MIN_RUNTIME}" ]]; do
      if [[ "${AI_ERROR_CNT}" -lt "${lMAX_AI_ERROR_CNT}" ]]; then
        ask_localai "${lMODEL_LOCALAI}"
      else
        # exit if too many errors happened
        break
      fi
      local lMODULE_RUNTIME=${SECONDS}
      adjust_minimum_runtime "${lMODULE_RUNTIME}"
    done
  fi
  module_end_log "${FUNCNAME[0]}" "${AI_RESULT_CNT}"
}

adjust_minimum_runtime() {
  local lMODULE_RUNTIME="${1:-}"

  # if the minimum runtime is not set we adjust it to something bigger then the module runtime
  # with this we can start and the later rules to end this module will jump in
  if [[ -z "${AI_MIN_RUNTIME}" ]]; then
    AI_MIN_RUNTIME=$((lMODULE_RUNTIME + 10))
    return
  fi
  # to enusure the AI module is running at least until the reporting phase started we tweak the minimum
  # runtime to a higher value as the module runtime as long as the reporting phase is not started
  if ! grep -q "Reporting phase started" "${MAIN_LOG}" && [[ "${lMODULE_RUNTIME}" -ge "${AI_MIN_RUNTIME}" ]]; then
    AI_MIN_RUNTIME=$((lMODULE_RUNTIME + 10))
  fi
}

# looks through the modules and finds localAI questions inside the csv
ask_localai() {
  local lMODEL_LOCALAI="${1:-}"

  local lAI_FILE_DIR="${LOG_PATH_MODULE}/ai_files"
  export AI_PROMPT_DIR="${LOG_PATH_MODULE}/ai_prompt"
  local lAI_PRIO=3
  # default vars
  local lHTTP_CODE=200
  local lORIGIN_MODULE=""
  local lELE_INDEX=0
  local lAI_ANCHOR=""
  local lAI_INPUT_FILE=""
  local lAI_INPUT_FILE_mod=""
  local lAI_SOURCE_FILE=""
  local lSCRIPT_PATH_TMP=""

  print_output "[*] Checking scripts with LocalAI that have a priority of ${ORANGE}${MINIMUM_GPT_PRIO}${NC} or higher" "no_log"
  if ! [[ -d "${lAI_FILE_DIR}" ]]; then
    mkdir "${lAI_FILE_DIR}"
  fi
  if ! [[ -d "${AI_PROMPT_DIR}" ]]; then
    mkdir "${AI_PROMPT_DIR}"
  fi

  # generating Array for AI requests - sorting according the prio in field 3
  # this array gets regenerated on every round
  regenerate_ai_todo_list

  for ((lELE_INDEX = 0; lELE_INDEX < "${#Q03_LOCALAI_QUESTIONS[@]}"; lELE_INDEX++)); do
    local lELEM="${Q03_LOCALAI_QUESTIONS["${lELE_INDEX}"]}"
    lSCRIPT_PATH_TMP="${lELEM%%;*}"

    # as we always start with the highest rated entry, we need to check if this entry was already tested:
    if [[ " ${GTP_CHECKED_ARR[*]} " =~ ${lSCRIPT_PATH_TMP} ]]; then
      print_output "[*] AI - Already tested ${lSCRIPT_PATH_TMP}" "no_log"
      # lets test the next entry
      continue
    fi

    lAI_PRIO="$(echo "${lELEM}" | cut -d\; -f3)"
    lAI_SOURCE_FILE="$(echo "${lELEM}" | cut -d\; -f5)"
    lAI_ANCHOR="${lELEM#*;}"; lAI_ANCHOR="${lAI_ANCHOR%%;*}"
    lAI_INPUT_FILE="$(basename "${lSCRIPT_PATH_TMP}")"
    lAI_INPUT_FILE_mod="${lAI_INPUT_FILE//\./}"

    # in case we have nothing we are going to move on
    [[ -z "${lSCRIPT_PATH_TMP}" ]] && continue

    if [[ "${lSCRIPT_PATH_TMP}" == *"s16_ghidra_decompile_checks"* ]]; then
      print_output "[*] Ghidra decompiled code found ${lSCRIPT_PATH_TMP}" "no_log"
      print_output "[*] AI-Assisted analysis of binary function ${ORANGE}${lSCRIPT_PATH_TMP}${NC}" "no_log"
    elif [[ "${lSCRIPT_PATH_TMP}" == *"s28_java_check"* ]]; then
      print_output "[*] Decompiled Java code found ${lSCRIPT_PATH_TMP}" "no_log"
      print_output "[*] AI-Assisted analysis of Java binary ${ORANGE}${lSCRIPT_PATH_TMP}${NC}" "no_log"
    elif [[ "${lSCRIPT_PATH_TMP}" == *"s20_shell_check"* ]]; then
      print_output "[*] Shell code found ${lSCRIPT_PATH_TMP}" "no_log"
      print_output "[*] AI-Assisted analysis of shell script ${ORANGE}${lSCRIPT_PATH_TMP}${NC}" "no_log"
    elif [[ "${lSCRIPT_PATH_TMP}" == *"s21_python_check"* ]]; then
      print_output "[*] Python code found ${lSCRIPT_PATH_TMP}" "no_log"
      print_output "[*] AI-Assisted analysis of python script ${ORANGE}${lSCRIPT_PATH_TMP}${NC}" "no_log"
    elif [[ "${lSCRIPT_PATH_TMP}" == *"s22_php_check"* ]]; then
      print_output "[*] PHP code found ${lSCRIPT_PATH_TMP}" "no_log"
      print_output "[*] AI-Assisted analysis of PHP script ${ORANGE}${lSCRIPT_PATH_TMP}${NC}" "no_log"
    elif [[ "${lSCRIPT_PATH_TMP}" == *"s23_lua_check"* ]]; then
      print_output "[*] Lua code found ${lSCRIPT_PATH_TMP}" "no_log"
      print_output "[*] AI-Assisted analysis of lua script ${ORANGE}${lSCRIPT_PATH_TMP}${NC}" "no_log"
    elif [[ "${lSCRIPT_PATH_TMP}" == *"s27_perl_check"* ]]; then
      print_output "[*] Perl code found ${lSCRIPT_PATH_TMP}" "no_log"
      print_output "[*] AI-Assisted analysis of perl script ${ORANGE}${lSCRIPT_PATH_TMP}${NC}" "no_log"
    else
      # this should not happen. If we land here we have changed something in the module area
      # or we have a new module that is not handled correctly
      print_output "[*] Identification of ${ORANGE}${lSCRIPT_PATH_TMP} / ${lAI_INPUT_FILE}${NC} inside ${ORANGE}${LOG_DIR}/firmware${NC}" "no_log"
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
      print_output "[*] AI-Assisted analysis of script ${ORANGE}${lSCRIPT_PATH_TMP}${NC}" "no_log"
    fi

    print_output "[*] Current priority for testing is ${lAI_PRIO}" "no_log"

    if [[ ${lAI_PRIO} -ge ${MINIMUM_GPT_PRIO} ]] && [[ "${lSCRIPT_PATH_TMP}" != '' ]]; then
      if [[ -f "${lSCRIPT_PATH_TMP}" ]]; then
        sub_module_title "AI analysis for ${lAI_INPUT_FILE//\.log/}"

        local lBINARY_NAME="NA"
        local lFUNCTION_NAME="NA"

        # Starting with special attention modules
        if [[ "${lSCRIPT_PATH_TMP}" == *"s16_ghidra_decompile_checks"* ]]; then
          lBINARY_NAME="$(echo "${lSCRIPT_PATH_TMP}" | rev | cut -d '/' -f2 | rev | sed 's/haruspex_//')"
          lFUNCTION_NAME=$(extract_s16_fct_name "${lSCRIPT_PATH_TMP}")
          print_output "[*] AI-Assisted analysis for function ${ORANGE}${lFUNCTION_NAME}${NC} of decompiled binary ${ORANGE}${lBINARY_NAME}${NC}" "" "${lSCRIPT_PATH_TMP}"
          print_output "$(indent "$(orange "$(print_path "${lSCRIPT_PATH_TMP}")")")"
          generate_prompt_binary "${lSCRIPT_PATH_TMP}"
        elif [[ "${lSCRIPT_PATH_TMP}" == *"s28_java_check"* ]]; then
          # we start with a path like /logs/s28_java_check/java_decompile/i.class_16708/i.java
          # -> the last are we use as function name
          lFUNCTION_NAME="${lSCRIPT_PATH_TMP//*\//}"
          # -> the middle area is the binary name
          lBINARY_NAME="${lSCRIPT_PATH_TMP%\/*}"
          lBINARY_NAME="${lBINARY_NAME//*\//}"
          lBINARY_NAME="${lBINARY_NAME//_*/}"
          print_output "[*] AI-Assisted analysis for decompiled Java binary function ${ORANGE}${lFUNCTION_NAME}${NC} of ${ORANGE}${lBINARY_NAME}${NC}" "" "${lSCRIPT_PATH_TMP}"
          # as we are using lSCRIPT_PATH_TMP in the prompt generator we get a prompt file like prompt_localai_NeoterisStatic.java_Java.txt which is the current lFUNCTION_NAME
          # later on we can't find the prompt file as we look for the lBINARY_NAME. This means we rewrite the lBINARY_NAME with the lFUNCTION_NAME
          lBINARY_NAME="${lFUNCTION_NAME//\.log/}"

          # we need to redefine the lFUNCTION_NAME now as the type of analysed binary
          # Todo: rename and cleanup variable names
          lFUNCTION_NAME="Java"
          print_output "$(indent "$(orange "$(print_path "${lSCRIPT_PATH_TMP}")")")"
          generate_prompt_script "${lSCRIPT_PATH_TMP}" "${lFUNCTION_NAME}"
        else
          # for all the default modules
          lBINARY_NAME=$(basename "${lSCRIPT_PATH_TMP}")
          lBINARY_NAME="${lBINARY_NAME//*\//}"
          lBINARY_NAME="${lBINARY_NAME//\.log/}"

          if [[ "${lAI_SOURCE_FILE}" == *"s22_php_check"* ]]; then
            lFUNCTION_NAME="PHP"
          elif [[ "${lAI_SOURCE_FILE}" == *"s20_shell_check"* ]]; then
            lFUNCTION_NAME="shell"
          elif [[ "${lAI_SOURCE_FILE}" == *"s21_python_check"* ]]; then
            lFUNCTION_NAME="python"
          elif [[ "${lAI_SOURCE_FILE}" == *"s23_lua_check"* ]]; then
            lFUNCTION_NAME="lua"
          elif [[ "${lAI_SOURCE_FILE}" == *"s27_perl_check"* ]]; then
            lFUNCTION_NAME="perl"
          else
            # fallback
            lBINARY_NAME=$(basename "${lSCRIPT_PATH_TMP}")
            lFUNCTION_NAME="unknown"
          fi

          print_output "[*] AI-Assisted analysis for ${ORANGE}${lFUNCTION_NAME}${NC} script ${ORANGE}${lBINARY_NAME}${NC}" "" "${lSCRIPT_PATH_TMP}"
          print_output "$(indent "$(orange "$(print_path "${lSCRIPT_PATH_TMP}")")")"
          generate_prompt_script "${lSCRIPT_PATH_TMP}" "${lFUNCTION_NAME}"
        fi

        if [[ ! -f "${AI_PROMPT_DIR}/prompt_localai_${lBINARY_NAME}_${lFUNCTION_NAME}.txt" ]]; then
          print_output "[-] No prompt generated for ${AI_PROMPT_DIR}/prompt_localai_${lBINARY_NAME}_${lFUNCTION_NAME}.txt ... next one"
          continue
        fi

        lPROMPT=$(cat "${AI_PROMPT_DIR}/prompt_localai_${lBINARY_NAME}_${lFUNCTION_NAME}.txt")
        local lAI_LOG_FILE="${lAI_FILE_DIR}/ai_response_${lBINARY_NAME}_${lFUNCTION_NAME}.md"

        local lWC_M_FILE=""
        local lWC_L_FILE=""
        local lTOKENS_PRE=""
        # lWC_M_FILE=$(echo "${lPROMPT}" | wc -m)
        lWC_M_FILE="${#lPROMPT}"
        lWC_L_FILE=$(echo "${lPROMPT}" | wc -l)
        # just a very rough estimation
        lTOKENS_PRE=$((lWC_M_FILE / 2))

        print_output "[*] Testing prompt" "" "${AI_PROMPT_DIR}/prompt_localai_${lBINARY_NAME}_${lFUNCTION_NAME}.txt"
        print_output "${ORANGE}${lPROMPT}${NC}" "no_log"
        print_output "[*] Testing code with ${ORANGE}${lWC_L_FILE}${NC} lines and ${ORANGE}${lWC_M_FILE}${NC} characters"
        print_output "[*] Testing will need at least ${ORANGE}${lTOKENS_PRE}${NC} tokens\n"

        local lJSON_PAYLOAD=""
        local lstart_time=""
        local lTOKENS_POST=""
        local lfinished_time=""
        local lruntime=""

        lJSON_PAYLOAD=$(jq -n \
          --arg model "${lMODEL_LOCALAI}" \
          --arg prompt "${lPROMPT}" \
          '{model: $model, messages: [{role: "user", content: $prompt}], temperature: 0.2}')

        lstart_time=$(date +%s)
        lHTTP_CODE=$(curl --connect-timeout 10 --max-time 600 -s http://"${LOCAL_AI_IP}":8080/v1/chat/completions \
          -H "Content-Type: application/json" \
          -d "${lJSON_PAYLOAD}" -o "${lAI_LOG_FILE}.json" --write-out "%{http_code}" || true)

        if [[ -f "${lAI_LOG_FILE}.json" ]]; then
          # reformat the output to also have the token usage avaialble
          jq -r '. | "\(.choices[].message.content)\n\nTokens used: \(.usage.total_tokens)"' "${lAI_LOG_FILE}.json" >"${lAI_LOG_FILE}" || print_error "[-] Q03 - AI parsing error for ${lAI_LOG_FILE}.json"
        fi

        if [[ ! -f "${lAI_LOG_FILE}" ]] || [[ ! -s "${lAI_LOG_FILE}" ]]; then
          print_output "[-] WARNING: No AI response for function ${lFUNCTION_NAME}"
          continue
        fi
        # our currenty AI output starts the headlines with level 3 headlines ###
        parse_markdown_to_emba_txt "${lAI_LOG_FILE}" "${lAI_LOG_FILE//\.md/\.txt}" 3

        # just for the user output on cli:
        cat "${lAI_LOG_FILE//\.md/\.txt}"

        lTOKENS_POST=$(grep "Tokens used:" "${lAI_LOG_FILE}" | cut -d ':' -f2)
        lTOKENS_POST=${lTOKENS_POST//\ /}
        lfinished_time=$(date +%s)
        lruntime=$((lfinished_time - lstart_time))

        if [[ "${lTOKENS_POST}" -gt 0 && "${lruntime}" -gt 0 ]]; then
          print_output "[*] AI took ${ORANGE}${lruntime}${NC} seconds and ${ORANGE}${lTOKENS_POST}${NC} tokens to complete this request."
          print_output "[*] Tokens/sec: ${ORANGE}~$((lTOKENS_POST / lruntime))${NC}" || true
        fi

        if [[ "${lHTTP_CODE}" -ne 200 ]]; then
          print_output "[-] Something went wrong with the LocalAI requests"
          # track the errors. If we get too many we are going to stop AI requests
          AI_ERROR_CNT=$((AI_ERROR_CNT + 1))

          if [[ -f "${lAI_LOG_FILE}" ]]; then
            print_output "[-] ERROR response: $(cat "${lAI_LOG_FILE}")"
          fi

          # if the testing is over we can just return now
          local lMODULE_RUNTIME=${SECONDS}
          adjust_minimum_runtime "${lMODULE_RUNTIME}"
          if [[ "${lMODULE_RUNTIME}" -gt "${AI_MIN_RUNTIME}" ]]; then
            return
          fi

          continue
        fi

        if ! [[ -f "${lAI_LOG_FILE}" ]]; then
          # catches: (56) Recv failure: Connection reset by peer
          print_output "[-] Something went wrong with the LocalAI request for ${lAI_INPUT_FILE}"
          AI_ERROR_CNT=$((AI_ERROR_CNT + 1))

          continue
        fi

        if [[ ${lTOKENS_POST} -ne 0 ]]; then
          GTP_CHECKED_ARR+=("${lSCRIPT_PATH_TMP}")
          # write results into done csv
          # lAI_INPUT_FILE - lAI_ANCHOR - Priority - used Prompt file - source file to test - cost - ai final log file with results
          write_csv_AI "${lAI_INPUT_FILE}" "${lAI_ANCHOR}" "${lAI_PRIO}" "${AI_PROMPT_DIR}/prompt_localai_${lBINARY_NAME}_${lFUNCTION_NAME}.txt" "${lAI_SOURCE_FILE}" "cost=${lTOKENS_POST}" "${lAI_LOG_FILE//\.md/\.txt}"

          # add proper module link
          if [[ "${lAI_SOURCE_FILE}" == *'/csv_logs/'* ]]; then
            # if we have a csv_logs path we need to adjust the cut
            lORIGIN_MODULE="$(echo "${lAI_SOURCE_FILE}" | cut -d / -f4 | cut -d_ -f1)"
          elif [[ "${lAI_SOURCE_FILE}" == '/logs/'* ]]; then
            lORIGIN_MODULE="$(echo "${lAI_SOURCE_FILE}" | grep -E "[splfq][0-9]{2,3}_.*" -o | cut -d '_' -f1)"
          else
            lORIGIN_MODULE="$(basename "$(dirname "${lAI_SOURCE_FILE}")" | cut -d_ -f1)"
          fi

          print_ln
          print_output "[+] Further analysis results for ${ORANGE}${lAI_INPUT_FILE_mod}${GREEN} available in module ${ORANGE}${lORIGIN_MODULE}${NC}" "" "${lAI_SOURCE_FILE}"
          if [[ -f "${lAI_LOG_FILE}" ]]; then
            print_output "[+] AI analysis results for ${ORANGE}${lAI_INPUT_FILE_mod}${GREEN} available${NC}" "" "${lAI_LOG_FILE//\.md/\.txt}"
            local lSECURITY_RATING=""
            lSECURITY_RATING=$(grep -h "Security rating: " "${lAI_LOG_FILE}" | tr '.' '\n' | grep -o -E "[0-9]+/10" || true)
            if [[ -n "${lSECURITY_RATING}" ]]; then
              print_output "[+] AI security rating for ${ORANGE}${lAI_INPUT_FILE_mod}${GREEN}: ${ORANGE}${lSECURITY_RATING}${NC}" "" "${lAI_LOG_FILE//\.md/\.txt}"
            fi
          fi

          print_ln
          ((AI_RESULT_CNT += 1))
        fi
      else
        print_output "[-] Couldn't find ${ORANGE}$(print_path "${lSCRIPT_PATH_TMP}")${NC}"
      fi
    fi

    # exit conditions
    local lMODULE_RUNTIME=${SECONDS}
    adjust_minimum_runtime "${lMODULE_RUNTIME}"
    print_output "[*] Current AI module runtime: ${lMODULE_RUNTIME} / min module runtime ${AI_MIN_RUNTIME}" "no_log"

    # if our module runtime is longer as our configured min runtime:
    if [[ "${lMODULE_RUNTIME}" -gt "${AI_MIN_RUNTIME}" ]]; then
      break
    fi

    regenerate_ai_todo_list
    # reset the array index to start again with the highest rated entry
    lELE_INDEX=-1
  done
}

regenerate_ai_todo_list() {
  print_output "[*] Regenerate analysis array ..." "no_log"

  if [[ -f "${CSV_DIR}/ai_question.csv" ]]; then
    local lGPT_ENTRY_LINE=""
    while read -r lGPT_ENTRY_LINE; do
      lAI_ANCHOR="${lGPT_ENTRY_LINE#*;}"; lAI_ANCHOR="${lAI_ANCHOR%%;*}"
      sed -i "/${lAI_ANCHOR}/d" "${CSV_DIR}/ai_question.csv.tmp"
    done <"${CSV_DIR}/ai_question.csv"
  fi

  # reload and resort current state of questions:
  readarray -t Q03_LOCALAI_QUESTIONS < <(sort -k 3 -t ';' -r "${CSV_DIR}/ai_question.csv.tmp")
}

identify_ai_model() {
  local lMODEL_LOCALAI=""
  local lCNT=1
  while [[ -z "${lMODEL_LOCALAI}" ]]; do
    lMODEL_LOCALAI=$(curl --connect-timeout 10 --max-time 30 http://"${LOCAL_AI_IP}":8080/v1/models 2>/dev/null | jq -r .data[].id || true)
    [[ -n "${lMODEL_LOCALAI}" ]] && break
    sleep 5
    lCNT=$((lCNT + 1))
    [[ "${lCNT}" -gt 10 ]] && break
  done
  echo "${lMODEL_LOCALAI}"
}

extract_s16_fct_name() {
  local lSCRIPT_PATH_TMP="${1:-}"
  # extract the function name from the beginning of the first part of the file
  # e.g.: bool fct_name(asdf)
  local lBINARY_NAME=""
  lBINARY_NAME="$(echo "${lSCRIPT_PATH_TMP}" | rev | cut -d '/' -f2 | rev | sed 's/haruspex_//')"
  lFUNCTION_NAME="$(strip_color_codes "$(head "${lSCRIPT_PATH_TMP}")")"
  lFUNCTION_NAME="$(echo "${lFUNCTION_NAME}" | grep "^bool\|^uint\|^ulong\|^long\|^int\|^undefined\|^void\|^char\|^ssize\|^size" | grep "(.*" || true)"
  if [[ -z "${lFUNCTION_NAME}" ]]; then
    # e.g.: fct_name(asdf)
    lFUNCTION_NAME="$(strip_color_codes "$(head "${lSCRIPT_PATH_TMP}")")"
    lFUNCTION_NAME="$(echo "${lFUNCTION_NAME}" | grep "^[a-zA-Z0-9_-]*(.*" || true)"
  fi
  if [[ -z "${lFUNCTION_NAME}" ]]; then
    lFUNCTION_NAME="unknown_${lBINARY_NAME:-NA}"
  fi
  lFUNCTION_NAME="${lFUNCTION_NAME//\(*/}"
  lFUNCTION_NAME="${lFUNCTION_NAME//* /}"
  echo "${lFUNCTION_NAME}"
}

generate_prompt_script() {
  local lSCRIPT_PATH_TMP="${1:-}"
  local lSCRIPT_TYPE="${2:-unknown}"

  local lCODE_CONTENT_tmp=""
  local lCODE_CONTENT=""
  local lPROMPT=""
  local lBINARY_NAME=""
  lBINARY_NAME=$(basename "${lSCRIPT_PATH_TMP}")
  lBINARY_NAME="${lBINARY_NAME//*\//}"
  lBINARY_NAME="${lBINARY_NAME//\.log/}"

  print_output "[*] Build prompt for ${lSCRIPT_PATH_TMP} - lSCRIPT_NAME: ${lBINARY_NAME} - script type: ${lSCRIPT_TYPE}" "no_log"

  # Read the file content and remove the ASK_AI marker
  lCODE_CONTENT_tmp=$(grep -v "ASK_AI" "${lSCRIPT_PATH_TMP}" || true)
  # remove REF entries for HTML links
  lCODE_CONTENT_tmp=$(sed '/^\[REF\] .*/d' <<<"${lCODE_CONTENT_tmp}" || print_error "[-] Code parsing issue for ${lSCRIPT_PATH_TMP} - 1")
  # remove semgrep identifiers
  lCODE_CONTENT_tmp=$(sed 's/\/\/possible issue identified -.*//' <<<"${lCODE_CONTENT_tmp}" || print_error "[-] Code parsing issue for ${lSCRIPT_PATH_TMP} - 2")
  # remove color codes
  lCODE_CONTENT_tmp=$(strip_color_codes "${lCODE_CONTENT_tmp}")

  # remove shell comment lines:
  lCODE_CONTENT_tmp=$(sed '/^[[:blank:]]*#/d' <<<"${lCODE_CONTENT_tmp}" || print_error "[-] Code parsing issue for ${lSCRIPT_PATH_TMP} - 4")
  # remove shell comments:
  # shellcheck disable=SC2001
  lCODE_CONTENT_tmp=$(sed 's/[[:blank:]]*#.*//' <<<"${lCODE_CONTENT_tmp}" || print_error "[-] Code parsing issue for ${lSCRIPT_PATH_TMP} - 5")
  # remove empty lines (includes also empty lines with spaces):
  lCODE_CONTENT=$(sed -r '/^\s*$/d' <<<"${lCODE_CONTENT_tmp}" || print_error "[-] Code parsing issue for ${lSCRIPT_PATH_TMP} - 3")

  lPROMPT="You are an expert software architect. Analyze the provided source code."
  lPROMPT+=" The following source code is from a Linux based firmware ${lSCRIPT_TYPE} script called ${lBINARY_NAME}."
  lPROMPT+=" Give a short summary of the functionality of the provided code"
  lPROMPT+=" Improve the readability of the original source code inline with comments on the functionality. Perform an indepth security and vulnerability analysis of the provided source code. Use all available information for your security and vulnerability analysis. Include security notes inline in the original source code for security relevant areas and for identified vulnerabilities inline to the improved source code. Finally, give a security rating between 1 and 10 points, while 1 point is very insecure and 10 is a good security rating."
  lPROMPT+=" Structure your report the following way:"
  lPROMPT+=" 1.) Summary of ${lSCRIPT_TYPE} script ${lBINARY_NAME}"
  lPROMPT+=" 2.) Optimized source code of ${lSCRIPT_TYPE} script ${lBINARY_NAME} with comments"
  lPROMPT+=" 3.) Security overview with identified vulnerabilities"
  lPROMPT+=" 4.) Final security rating in the form \"Security rating: <your rating>/10.\""

  if [[ "${#lCODE_CONTENT}" -gt "${AI_MAX_CHARS_TO_ANALYSE}" ]]; then
    print_output "[*] Limit code of ${lBINARY_NAME}/${lSCRIPT_TYPE} for analysis to ${AI_MAX_CHARS_TO_ANALYSE} characters" "no_log"
  fi
  lPROMPT="${lPROMPT}\nHere is the code:\n\n${lCODE_CONTENT:0:${AI_MAX_CHARS_TO_ANALYSE}}\n"

  echo -n "${lPROMPT}" >"${AI_PROMPT_DIR}/prompt_localai_${lBINARY_NAME}_${lSCRIPT_TYPE}.txt"
}

generate_prompt_binary() {
  local lSCRIPT_PATH_TMP="${1:-}"

  local lARCH=""
  local lEND=""
  local lKERNELV=""
  local lRELRO=""
  local lCANARIES=""
  local lNX=""
  local lSYMBOLS=""
  local lCODE_CONTENT_tmp=""
  local lCODE_CONTENT=""
  local lPROMPT=""
  local lBINARY_NAME=""
  local lFUNCTION_NAME=""

  lBINARY_NAME="$(echo "${lSCRIPT_PATH_TMP}" | rev | cut -d '/' -f2 | rev | sed 's/haruspex_//')"
  lFUNCTION_NAME=$(extract_s16_fct_name "${lSCRIPT_PATH_TMP}")

  print_output "[*] Build prompt for ${lSCRIPT_PATH_TMP} - lBINARY_NAME: ${lBINARY_NAME} - lFUNCTION_NAME: ${lFUNCTION_NAME}" "no_log"

  # extract further binary details from the current EMBA report
  if [[ -f "${P99_LOG}" ]]; then
    lARCH="$(grep Statistics "${P99_LOG}" | cut -d ':' -f2)"
    lEND="$(grep Statistics "${P99_LOG}" | cut -d ':' -f3)"
  fi
  if [[ -f "${S24_CSV_LOG}" ]]; then
    lKERNELV=$(tail -n +2 "${S24_CSV_LOG}" | cut -d ';' -f2 | sort -u | head -1)
  fi
  if [[ -f "${S12_CSV_LOG}" ]]; then
    lRELRO=$(grep "/${lBINARY_NAME}$" "${S12_CSV_LOG}" | cut -d ';' -f1 | sort -u | head -1)
    lCANARIES=$(grep "/${lBINARY_NAME}$" "${S12_CSV_LOG}" | cut -d ';' -f2 | sort -u | head -1)
    lNX=$(grep "/${lBINARY_NAME}$" "${S12_CSV_LOG}" | cut -d ';' -f3 | sort -u | head -1)
    lSYMBOLS=$(grep "/${lBINARY_NAME}$" "${S12_CSV_LOG}" | cut -d ';' -f7 | sort -u | head -1)
  fi

  # Read the file content and remove the ASK_AI marker
  lCODE_CONTENT_tmp=$(grep -v "ASK_AI" "${lSCRIPT_PATH_TMP}" || true)
  # remove REF entries for HTML links
  lCODE_CONTENT_tmp=$(sed '/^\[REF\] .*/d' <<<"${lCODE_CONTENT_tmp}" || print_error "[-] Code parsing issue for ${lSCRIPT_PATH_TMP} - 1")
  # remove semgrep identifiers
  lCODE_CONTENT_tmp=$(sed 's/\/\/possible issue identified -.*//' <<<"${lCODE_CONTENT_tmp}" || print_error "[-] Code parsing issue for ${lSCRIPT_PATH_TMP} - 2")
  # remove color codes
  lCODE_CONTENT_tmp=$(strip_color_codes "${lCODE_CONTENT_tmp}")

  # remove shell comment lines:
  lCODE_CONTENT_tmp=$(sed '/^[[:blank:]]*#/d' <<<"${lCODE_CONTENT_tmp}" || print_error "[-] Code parsing issue for ${lSCRIPT_PATH_TMP} - 4")
  # remove shell comments:
  # shellcheck disable=SC2001
  lCODE_CONTENT_tmp=$(sed 's/[[:blank:]]*#.*//' <<<"${lCODE_CONTENT_tmp}" || print_error "[-] Code parsing issue for ${lSCRIPT_PATH_TMP} - 5")
  # remove empty lines (includes also empty lines with spaces):
  lCODE_CONTENT=$(sed -r '/^\s*$/d' <<<"${lCODE_CONTENT_tmp}" || print_error "[-] Code parsing issue for ${lSCRIPT_PATH_TMP} - 3")

  lPROMPT="You are an expert software architect. Analyze the provided source code."
  lPROMPT+=" The following source code is from a Linux based firmware binary called ${lBINARY_NAME}."
  lPROMPT+=" It was automatically generated with the reverse engineering framework Ghidra."
  if [[ -n "${lARCH}" ]]; then
    lPROMPT+=" The architecture of the firmware is ${lARCH}."
    if [[ -n "${lEND}" ]]; then
      lPROMPT+=" The endianess of the firmware is ${lEND}."
    fi
  fi
  if [[ -n "${lKERNELV}" ]]; then
    lPROMPT+=" The original device was running a Linux kernel in version ${lKERNELV}."
  fi
  if [[ -n "${lRELRO}" ]]; then
    lPROMPT+=" The original binary has the following RELRO security setting: ${lRELRO}."
  fi
  if [[ -n "${lCANARIES}" ]]; then
    lPROMPT+=" The original binary has the following Stack Canaries security setting: ${lCANARIES}."
  fi
  if [[ -n "${lNX}" ]]; then
    lPROMPT+=" The original binary has the following NX security setting: ${lNX}."
  fi
  if [[ -n "${lSYMBOLS}" ]]; then
    if [[ "${lSYMBOLS}" == "No Symbols" ]]; then
      lPROMPT+=" The original binary has no symbols included."
    else
      lPROMPT+=" The original binary has symbols included."
    fi
  fi

  lPROMPT+=" Give a short summary of the functionality of the provided code with the functionname ${lFUNCTION_NAME}."
  lPROMPT+=" Improve the readability of the original source code inline with comments on the functionality and useful variable names. Perform an indepth security and vulnerability analysis of the provided source code. Use all available information for your security and vulnerability analysis. Include security notes inline in the original source code for security relevant areas and for identified vulnerabilities inline to the improved source code. The variable names of the provided source code should be always renamed for better readability to support manual verification and further manual analysis. Finally, give a security rating between 1 and 10 points, while 1 point is very insecure and 10 is a good security rating."
  lPROMPT+=" Structure your report the following way:"
  lPROMPT+=" 1.) Summary of function ${lFUNCTION_NAME}"
  lPROMPT+=" 2.) Optimized source code of function ${lFUNCTION_NAME} with renamed variables and comments"
  lPROMPT+=" 3.) Security overview with identified vulnerabilities"
  lPROMPT+=" 4.) Final security rating in the form \"Security rating: <your rating>/10.\""

  if [[ "${#lCODE_CONTENT}" -gt "${AI_MAX_CHARS_TO_ANALYSE}" ]]; then
    print_output "[*] Limit code of ${lBINARY_NAME}/${lFUNCTION_NAME} for analysis to ${AI_MAX_CHARS_TO_ANALYSE} characters"
  fi
  # limit the code to analyse to 5000 characters
  lPROMPT="${lPROMPT}\nHere is the code:\n\n${lCODE_CONTENT:0:${AI_MAX_CHARS_TO_ANALYSE}}\n"

  # print_output "[*] Wrting prompt for ${lSCRIPT_PATH_TMP} - ${lPROMPT} to ${AI_PROMPT_DIR}/prompt_localai_${lBINARY_NAME}_${lFUNCTION_NAME}.txt"

  echo -n "${lPROMPT}" >"${AI_PROMPT_DIR}/prompt_localai_${lBINARY_NAME}_${lFUNCTION_NAME}.txt"
}
