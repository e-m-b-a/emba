#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2021-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Benedikt Kuehne

# Description:  Resolves all dependancies and links between Q- and S-Modules

F05_qs_resolver(){
  module_log_init "${FUNCNAME[0]}"
  module_title "QS-Resolver"
  if [[ -f "${CSV_DIR}/q02_openai_question.csv" ]]; then
    while IFS=";" read -r COL1_ COL2_ COL3_ COL4_ COL5_ COL6_ COL7_; do
      SCRIPT_PATH_TMP_="${COL1_}"
      GPT_ANCHOR_="${COL2_}"
      _GPT_PRIO_="${COL3_//GPT-Prio-/}"
      GPT_QUESTION_="${COL4_}"
      GPT_RESPONSE_="${COL5_}"
      GPT_TOKENS_="${COL6_//cost\=/}"
      GPT_OUTPUT_FILE_="${COL7_}"
      _GPT_INPUT_FILE_="$(basename "$SCRIPT_PATH_TMP_")"

      if [[ $GPT_TOKENS_ -ne 0 ]]; then
        GPT_OUTPUT_FILE_=$(find ~+ -iname "$(basename "$GPT_OUTPUT_FILE_")" )
        if ! [ -f "$GPT_OUTPUT_FILE_" ]; then
          print_output "[-] Something went wrong with the Output file $GPT_OUTPUT_FILE_"
        else
          sed -i "s/$GPT_ANCHOR_/$GPT_QUESTION_\n$GPT_RESPONSE_\n/1" "$GPT_OUTPUT_FILE_"
        fi
      fi
    done < "$CSV_DIR/q02_openai_question.csv"
  fi
  module_end_log "${FUNCNAME[0]}" 1
}
