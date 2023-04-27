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

# Description:  Checks files with CHATGPT 
export THREAD_PRIO=0

S111_gpt_check()
{
  export CHATGPT_DIR_="$TMP_DIR"
  export "$(grep -v '^#' $CONFIG_DIR/gpt_config.env | xargs || true )" # readin of all vars in that env file
  module_log_init "${FUNCNAME[0]}"
  module_title "Ask Chatgpt"
  print_output "Running chatgpt check module for identification of vulnerabilities within the firmwares script files ..." "no_log"

  pre_module_reporter "${FUNCNAME[0]}"
  export CHATGPT_RESULT_CNT=0
  if [ -z "$OPENAI_API_KEY" ]; then
    print_output "[!] There is no API key in the config file"
    print_output "[!] Can't ask ChatGPT with this setup"
  else
    ask_chatgpt ./test-scripts  #TODO set this correctly, maybe from grepit?
  fi
  

  module_end_log "${FUNCNAME[0]}" "$CHATGPT_RESULT_CNT"
  unset OPENAI_API_KEY
}


ask_chatgpt(){
  local TEST_DIR_="${1:-}"
  local INPUT_FILES_=()
  local GPT_QUESTION_="Please identify all vulnerabilities in this code: "
  local CHATGPT_CODE_=""
  local GPT_RESPONSE_=""

  local HTTP_CODE_=200

  sub_module_title "ask_chatgpt"

  print_output "[*] checking scripts in $TEST_DIR_"

  mapfile -t INPUT_FILES_ < <(find "${TEST_DIR_}" -name "*.js" -or -name "*.lua" -type f 2>/dev/null)  # TODO what file types?

  for FILE in "${INPUT_FILES_[@]}" ; do
    head -n -2 "$CONFIG_DIR"/gpt_template.json > $CHATGPT_DIR_/chat.json
    CHATGPT_CODE_=$(sed 's/"/\\\"/g' "$FILE" | tr -d '[:space:]')
    printf '"%s %s"\n}]}' "$GPT_QUESTION_" "$CHATGPT_CODE_" >> $CHATGPT_DIR_/chat.json
    HTTP_CODE_=$(curl https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" \
      -H "Authorization: Bearer $OPENAI_API_KEY" \
      -d @$CHATGPT_DIR_/chat.json -o "$CHATGPT_DIR_"/response.json --write-out "%{http_code}")
    if [[ "$HTTP_CODE_" -ne 200 ]] ; then
      print_output "[!] Something went wrong with the requests"
      print_output "ERROR response:$(cat "$CHATGPT_DIR_"/response.json)"
      CHATGPT_RESULT_CNT=0
      break
    fi

    GPT_RESPONSE_=$(jq '.choices[] | .message.content' "$CHATGPT_DIR_"/response.json)
    printf '%s:%s;' "$FILE" "$GPT_RESPONSE_" >> "$CSV_DIR"/s111_gpt_check.csv
    print_output "Q:$GPT_QUESTION_ ($FILE) CHATGPT:$GPT_RESPONSE_"
    ((CHATGPT_RESULT_CNT++))
  done
}
