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
export OPENAI_API_KEY="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"  # TODO get from config and make global readin?

S111_gpt_check()
{
  # TODO
}


ask_chatgpt(){
  local TEST_DIR_="${1:-}"
  local CHATGPT_DIR="./s111_chatgpt_checks"
  local INPUT_FILES=()
  local GPT_QUESTION="Please identify all vulnerabilities in this code: "
  local CHATGPT_CODE=""
  local GPT_RESPONSE=""

  sub_module_title "ask_chatgpt"

  print_output "[*] checking scripts in $TEST_DIR_"
  if ! [ -d "$CHATGPT_DIR" ]; then
    mkdir "$CHATGPT_DIR"
    cp "$CONFIG_DIR"/gpt_template.json "$CHATGPT_DIR"
    touch "$CHATGPT_DIR"/gpt_results.csv
    touch "$CHATGPT_DIR"/chat.json
  fi

  mapfile -t INPUT_FILES < <(find "${TEST_DIR}" -name "*.js" -or -name "*.lua" -type f 2>/dev/null)  # TODO what file types?

  for FILE in "${INPUT_FILES[@]}" ; do
    head -n -2 $CHATGPT_DIR/gpt_template.json > $CHATGPT_DIR/chat.json
    CHATGPT_CODE=$(sed 's/"/\\\"/g' "$FILE" | tr -d '[:space:]')
    printf '"%s %s"\n}]}' "$GPT_QUESTION" "$CHATGPT_CODE" >> $CHATGPT_DIR/chat.json
    curl https://api.openai.com/v1/chat/completions -H "Content-Type: application/json" \
      -H "Authorization: Bearer $OPENAI_API_KEY" \
      -d @$CHATGPT_DIR/chat.json | tee "$CHATGPT_DIR"/response.json

    GPT_RESPONSE=$(jq '.choices[] | .message.content' "$CHATGPT_DIR"/response.json)
    printf '%s:%s;' "$FILE" "$GPT_RESPONSE" >> "$CHATGPT_DIR"/gpt_results.csv
  done
}
