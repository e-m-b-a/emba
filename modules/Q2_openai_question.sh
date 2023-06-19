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
# Note:   Important requirement for Q-modules is the self termination when a certain phase ends

Q2_openai_question(){
  if [[ ${GPT_OPTION} -gt 0 ]]; then
    module_log_init "${FUNCNAME[0]}"
    # Prints title to CLI and into log
    module_title "openai_question"
    export "$(grep -v '^#' "$CONFIG_DIR/gpt_config.env" | xargs || true )" # readin of all vars in that env file
    export CHATGPT_RESULT_CNT=1

    if [ -z "$OPENAI_API_KEY" ]; then
      print_output "[!] There is no API key in the config file"
      print_output "[!] Can't ask ChatGPT with this setup"
      print_output "There is no API key in the config file, aborting"
      CHATGPT_RESULT_CNT=-1
    else
      # test connection
      print_output "[*] Testing API-Key"
      print_output "the running container is: $CONTAINER_NUMBER"
      print_output "Testing API key : $OPENAI_API_KEY "
      if ! curl https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" \
              -H "Authorization: Bearer $OPENAI_API_KEY" \
              -d @"$CONFIG_DIR/gpt_template.json" &>"$LOG_DIR/chatgpt.log" ; then
        print_output "[!] ChatGPT error while testing the API-Key"
        print_output "requests aren't working, aborting"
        CHATGPT_RESULT_CNT=-1
      fi
      print_output "[*] ChatGPT test successful"
    fi
    # we wait until there arer entries in the question csv
    while ! [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; do
      sleep 10
    done
    if [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; then
      while ! [[ -f  "$CSV_DIR/Q2_openai_question.csv.tmp" ]]; do
        sleep 3
      done
    fi
    while ! grep -q "Testing phase ended" "$LOG_DIR"/"$MAIN_LOG_FILE"; do
      ask_chatgpt
      sleep 20
    done
    unset OPENAI_API_KEY
    module_end_log "${FUNCNAME[0]}"
  fi  
}

# looks through the modules and finds chatgpt questions inside the csv
ask_chatgpt(){
  local MINIMUM_GPT_PRIO=2
  print_output "[*] checking scripts with ChatGPT that have priority $MINIMUM_GPT_PRIO or lower" "no_log"
  if [ $CHATGPT_RESULT_CNT -gt 0 ]; then
    local GPT_PRIO_=3
    # default vars
    local GPT_QUESTION_="Please identify all vulnerabilities in this code: "
    local CHATGPT_CODE_=""
    local GPT_RESPONSE_=""
    local GPT_TOKENS_=0
    local HTTP_CODE_=200
    while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
      SCRIPT_PATH_TMP_="${COL1_}"
      GPT_ANCHOR_="${COL2_}"
      GPT_PRIO_="${COL3_//GPT-Prio-/}"
      GPT_QUESTION_="${COL4_}"
      GPT_RESPONSE_="${COL5_}"
      GPT_TOKENS_="${COL6_//cost\=/}"
      GPT_OUTPUT_FILE_="${COL7_}"
      GPT_INPUT_FILE_="$(basename "$SCRIPT_PATH_TMP_")"
      
      print_output "trying to check inside $LOG_DIR/firmware"
      SCRIPT_PATH_TMP_="$(find "$LOG_DIR/firmware" -wholename "*$SCRIPT_PATH_TMP_")"
      print_output "trying to check $SCRIPT_PATH_TMP_ with Question $GPT_QUESTION_ "
      print_output "Prio is $GPT_PRIO_"

      if [[ -z $GPT_ANSWER_  ]] && [[ $GPT_PRIO_ -le $MINIMUM_GPT_PRIO ]]; then
        if [ -f "$SCRIPT_PATH_TMP_" ]; then
          print_output "Asking ChatGPT about $(print_path "$SCRIPT_PATH_TMP_")"
          head -n -2 "$CONFIG_DIR/gpt_template.json" > "$TMP_DIR/chat.json"
          CHATGPT_CODE_=$(sed 's/\\//g;s/"/\\\"/g' "$SCRIPT_PATH_TMP_" | tr -d '[:space:]')
          printf '"%s %s"\n}]}' "$GPT_QUESTION_" "$CHATGPT_CODE_" >> "$TMP_DIR/chat.json"
          print_output "The Combined Cost of the OpenAI request / the length is: ${#GPT_QUESTION_} + ${#CHATGPT_CODE_}"
          HTTP_CODE_=$(curl https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" \
            -H "Authorization: Bearer $OPENAI_API_KEY" \
            -d @"$TMP_DIR/chat.json" -o "$TMP_DIR/response.json" --write-out "%{http_code}")
          if [[ "$HTTP_CODE_" -ne 200 ]] ; then
            print_output "[!] Something went wrong with the ChatGPT requests"
            if [ -f "$TMP_DIR/response.json" ]; then
              print_output "ERROR response:$(cat "$TMP_DIR/response.json")"
            fi
          fi
          GPT_RESPONSE_=$(jq '.choices[] | .message.content' "$TMP_DIR"/response.json)
          # GPT_RESPONSE_CLEANED_="${GPT_RESPONSE_//$'\n'/}" #remove newlines from response
          GPT_TOKENS_=$(jq '.usage.total_tokens' "$TMP_DIR"/response.json)
          if [[ $GPT_TOKENS_ -ne 0 ]]; then
            # write new into done csv
            write_csv_gpt "${GPT_INPUT_FILE_}" "$GPT_ANCHOR_" "GPT-Prio-$GPT_PRIO_" "$GPT_QUESTION_" "$GPT_RESPONSE_" "cost=$GPT_TOKENS_" "$GPT_OUTPUT_FILE_"
            print_output "Q:${GPT_QUESTION_} $(print_path "${SCRIPT_PATH_TMP_}") CHATGPT:${GPT_RESPONSE_}"
            ((CHATGPT_RESULT_CNT++))
          fi
        fi
        print_output "Couldn't find $(print_path "$SCRIPT_PATH_TMP_")"
      fi
      if [[ $GPT_OPTION -ne 2 ]]; then
        sleep 20s
      fi
    done < "$CSV_DIR/Q2_openai_question.csv.tmp"
    while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
      GPT_ANCHOR_="${COL2_}"
      sed -i "/$GPT_ANCHOR_/d" "$CSV_DIR/Q2_openai_question.csv.tmp"
    done < "$CSV_DIR/Q2_openai_question.csv"
  fi
}