#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Checks for bugs, stylistic errors, etc. in lua scripts

S23_lua_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check lua scripts for security issues"
  pre_module_reporter "${FUNCNAME[0]}"

  local S23_LUA_VULNS=0
  local LUA_SCRIPT=""
  local S23_LUA_SCRIPTS=()
  export S23_ISSUE_FOUND=0
  local WAIT_PIDS_S23=()

  write_csv_log "Script path" "LUA issues detected" "LUA vulnerabilities detected" "common linux file"
  mapfile -t S23_LUA_SCRIPTS < <(find "${FIRMWARE_PATH}" -xdev -type f -iname "*.lua" -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum % 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 )

  sub_module_title "LUA linter checks module"

  for LUA_SCRIPT in "${S23_LUA_SCRIPTS[@]}" ; do
    if [[ "${THREADED}" -eq 1 ]]; then
      # linting check:
      s23_luacheck "${LUA_SCRIPT}" &
      local TMP_PID="$!"
      store_kill_pids "${TMP_PID}"
      WAIT_PIDS_S23+=( "${TMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S23[@]}"
      continue
    else
      s23_luacheck "${LUA_SCRIPT}"
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S23[@]}"

  # simple lua checks to identify files which should be analysed in more detail
  print_ln
  s23_luaseccheck

  if [[ "${S23_LUA_VULNS}" -gt 0 ]]; then
    print_ln
    print_output "[+] Found ""${ORANGE}""${S23_LUA_VULNS}"" security issues""${GREEN}"" in ""${ORANGE}""${#LUA_CGI_FILES[@]}""${GREEN}"" lua files""${NC}""\\n"
  fi

  write_log ""
  write_log "[*] Statistics:${S23_LUA_VULNS}:${#LUA_CGI_FILES[@]}"
  module_end_log "${FUNCNAME[0]}" "${S23_ISSUE_FOUND}"
}

# this is a very basic checker for LUA issues
s23_luaseccheck() {
  local NAME=""
  local LUA_LOG=""
  local GPT_ANCHOR_=""
  local GPT_PRIO_=3
  local ENTRY=""
  local QUERY_ENTRIES=()
  local QUERY_FILE=""
  export LUA_CGI_FILES=()

  sub_module_title "LUA Security checks module"

  mapfile -t LUA_CGI_FILES < <(find "${FIRMWARE_PATH}" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'grep -H cgilua\. % 2>/dev/null | cut -d ':' -f1' | sort -u)

  for QUERY_FILE in "${LUA_CGI_FILES[@]}"; do
    local ISSUES_FILE=0

    mapfile -t QUERY_ENTRIES < <(grep -E "=.*cgilua\.QUERY" "${QUERY_FILE}" | tr ' ' '\n' | sed 's/.*cgilua.QUERY.//' \
       | sed 's/.*cgilua.QUERY.//' | grep -o -E "^[[:alnum:]]+" | grep -v "^local$" | sort -u || true)

    for ENTRY in "${QUERY_ENTRIES[@]}"; do
      ENTRY="$(echo "${ENTRY}" | tr -dc '[:print:]')"
      [[ -z "${ENTRY}" ]] && continue
      ! [[ "${ENTRY}" =~ ^[a-zA-Z0-9_-]+$ ]] && continue

      if grep "${ENTRY}" "${QUERY_FILE}" | grep -E -q "io\.(p)?open"; then
        # possible file access
        S23_LUA_VULNS=$((S23_LUA_VULNS+1))
        ISSUES_FILE=$((ISSUES_FILE+1))
        print_output "[+] Found lua QUERY (GET/POST) entry: ${ORANGE}${ENTRY}${GREEN} in file ${ORANGE}${QUERY_FILE}${GREEN} with file access capabilities."
        S23_ISSUE_FOUND=1
        GPT_PRIO_=$((GPT_PRIO_+1))
      fi
      if grep "${ENTRY}" "${QUERY_FILE}" | grep -q "os.execute"; then
        # command exec - critical
        S23_LUA_VULNS=$((S23_LUA_VULNS+1))
        ISSUES_FILE=$((ISSUES_FILE+1))
        print_output "[+] Found lua QUERY (GET/POST) entry: ${ORANGE}${ENTRY}${GREEN} in file ${ORANGE}${QUERY_FILE}${GREEN} with command execution capabilities."
        S23_ISSUE_FOUND=1
        GPT_PRIO_=$((GPT_PRIO_+1))
      fi
    done
    if [[ "${ISSUES_FILE}" -eq 0 ]] && grep -q "os.execute" "${QUERY_FILE}"; then
      # command exec - not our parameter but we check it
      print_output "[*] Found lua file ${ORANGE}${QUERY_FILE}${NC} with possible command execution for review."
      S23_ISSUE_FOUND=1
    fi
    if [[ "${ISSUES_FILE}" -eq 0 ]] && grep -E -q "io\.(p)?open" "${QUERY_FILE}"; then
      # command exec - not our parameter but we check it
      print_output "[*] Found lua file ${ORANGE}${QUERY_FILE}${NC} with possible file access for review."
      S23_ISSUE_FOUND=1
    fi

    if [[ "${ISSUES_FILE}" -gt 0 ]]; then
      write_csv_log "$(print_path "${QUERY_FILE}")" "0" "${ISSUES_FILE}" "NA"
      if [[ "${GPT_OPTION}" -gt 0 ]]; then
        GPT_ANCHOR_="$(openssl rand -hex 8)"
        # "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
        write_csv_gpt_tmp "$(cut_path "${QUERY_FILE}")" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION}" "${S23_CSV_LOG}" "" ""
        # add ChatGPT link
        print_ln
        print_ln
        write_anchor_gpt "${GPT_ANCHOR_}"
      fi
    fi
  done
}

s23_luacheck() {
  local LUA_SCRIPT_="${1:-}"
  local NAME=""
  local LUA_LOG=""

  NAME=$(basename "${LUA_SCRIPT_}" 2> /dev/null | sed -e 's/:/_/g')
  LUA_LOG="${LOG_PATH_MODULE}""/luacheck_""${NAME}"".txt"
  luacheck "${LUA_SCRIPT_}" > "${LUA_LOG}" 2> /dev/null || true

  ISSUES=$(strip_color_codes "$(grep Total "${LUA_LOG}" | awk '{print $2}' 2> /dev/null || true)")
  if [[ "${ISSUES}" -gt 0 ]] ; then
    S23_ISSUE_FOUND=1
    # check if this is common linux file:
    local COMMON_FILES_FOUND=""
    local CFF=""
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      COMMON_FILES_FOUND="(""${RED}""common linux file: no""${GREEN}"")"
      CFF="no"
      if grep -q "^${NAME}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        COMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${GREEN}"")"
        CFF="yes"
      fi
    else
      COMMON_FILES_FOUND=""
      CFF="NA"
    fi
    print_output "[+] Found ""${ORANGE}""${ISSUES}"" coding issues""${GREEN}"" in lua script ""${COMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${LUA_SCRIPT_}")" "" "${LUA_LOG}"
    write_csv_log "$(print_path "${LUA_SCRIPT_}")" "${ISSUES}" "0" "${CFF}"
  fi
}
