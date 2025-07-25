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
# Author(s): Michael Messner

# Description:  Checks for bugs, stylistic errors, etc. in lua scripts

S23_lua_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check lua scripts for security issues"
  pre_module_reporter "${FUNCNAME[0]}"

  local lS23_LUA_VULNS=0
  local lLUA_SCRIPT=""
  local lS23_LUA_SCRIPTS_ARR=()
  export S23_ISSUE_FOUND=0
  local lWAIT_PIDS_S23_ARR=()

  write_csv_log "Script path" "LUA issues detected" "LUA vulnerabilities detected" "common linux file"
  # mapfile -t lS23_LUA_SCRIPTS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f -iname "*.lua" -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null || true' | sort -u -k1,1 | cut -d\  -f3 || true)
  mapfile -t lS23_LUA_SCRIPTS_ARR < <(grep ".lua;" "${P99_CSV_LOG}" | sort -u || true)

  sub_module_title "LUA linter checks module"

  for lLUA_SCRIPT in "${lS23_LUA_SCRIPTS_ARR[@]}" ; do
    if [[ "${THREADED}" -eq 1 ]]; then
      # linting check:
      s23_luacheck "$(echo "${lLUA_SCRIPT}" | cut -d';' -f2)" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S23_ARR+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S23_ARR
      continue
    else
      s23_luacheck "$(echo "${lLUA_SCRIPT}" | cut -d';' -f2)"
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S23_ARR[@]}"

  # simple lua checks to identify files which should be analysed in more detail
  print_ln
  s23_luaseccheck

  if [[ "${lS23_LUA_VULNS}" -gt 0 ]]; then
    print_ln
    print_output "[+] Found ""${ORANGE}""${lS23_LUA_VULNS}"" security issues""${GREEN}"" in ""${ORANGE}""${#LUA_CGI_FILES_ARR[@]}""${GREEN}"" lua files""${NC}""\\n"
  fi

  write_log ""
  write_log "[*] Statistics:${lS23_LUA_VULNS}:${#LUA_CGI_FILES_ARR[@]}"
  module_end_log "${FUNCNAME[0]}" "${S23_ISSUE_FOUND}"
}

# this is a very basic checker for LUA issues
s23_luaseccheck() {
  local lGPT_ANCHOR_=""
  local lGPT_PRIO_=3
  local lENTRY=""
  local lQUERY_ENTRIES_ARR=()
  local lQUERY_FILE=""
  export LUA_CGI_FILES_ARR=()

  sub_module_title "LUA Security checks module"

  mapfile -t LUA_CGI_FILES_ARR < <(find "${FIRMWARE_PATH}" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'grep -H cgilua\. "%" 2>/dev/null || true | cut -d : -f1' | sort -u || true)

  for lQUERY_FILE in "${LUA_CGI_FILES_ARR[@]}"; do
    local lISSUES_FILE=0

    mapfile -t lQUERY_ENTRIES_ARR < <(grep -E "=.*cgilua\.QUERY" "${lQUERY_FILE}" | tr ' ' '\n' | sed 's/.*cgilua.QUERY.//' \
       | sed 's/.*cgilua.QUERY.//' | grep -o -E "^[[:alnum:]]+" | grep -v "^local$" | sort -u || true)

    for lENTRY in "${lQUERY_ENTRIES_ARR[@]}"; do
      lENTRY="${lENTRY//[![:print:]]/}"
      [[ -z "${lENTRY}" ]] && continue
      ! [[ "${lENTRY}" =~ ^[a-zA-Z0-9_-]+$ ]] && continue

      if grep "${lENTRY}" "${lQUERY_FILE}" | grep -E -q "io\.(p)?open"; then
        # possible file access
        lS23_LUA_VULNS=$((lS23_LUA_VULNS+1))
        lISSUES_FILE=$((lISSUES_FILE+1))
        print_output "[+] Found lua QUERY (GET/POST) entry: ${ORANGE}${lENTRY}${GREEN} in file ${ORANGE}${lQUERY_FILE}${GREEN} with file access capabilities."
        S23_ISSUE_FOUND=1
        lGPT_PRIO_=$((lGPT_PRIO_+1))
      fi
      if grep "${lENTRY}" "${lQUERY_FILE}" | grep -q "os.execute"; then
        # command exec - critical
        lS23_LUA_VULNS=$((lS23_LUA_VULNS+1))
        lISSUES_FILE=$((lISSUES_FILE+1))
        print_output "[+] Found lua QUERY (GET/POST) entry: ${ORANGE}${lENTRY}${GREEN} in file ${ORANGE}${lQUERY_FILE}${GREEN} with command execution capabilities."
        S23_ISSUE_FOUND=1
        lGPT_PRIO_=$((lGPT_PRIO_+1))
      fi
    done
    if [[ "${lISSUES_FILE}" -eq 0 ]] && grep -q "os.execute" "${lQUERY_FILE}"; then
      # command exec - not our parameter but we check it
      print_output "[*] Found lua file ${ORANGE}${lQUERY_FILE}${NC} with possible command execution for review."
      S23_ISSUE_FOUND=1
    fi
    if [[ "${lISSUES_FILE}" -eq 0 ]] && grep -E -q "io\.(p)?open" "${lQUERY_FILE}"; then
      # command exec - not our parameter but we check it
      print_output "[*] Found lua file ${ORANGE}${lQUERY_FILE}${NC} with possible file access for review."
      S23_ISSUE_FOUND=1
    fi

    if [[ "${lISSUES_FILE}" -gt 0 ]]; then
      write_csv_log "$(print_path "${lQUERY_FILE}")" "0" "${lISSUES_FILE}" "NA"
      if [[ "${GPT_OPTION}" -gt 0 ]]; then
        lGPT_ANCHOR_="$(openssl rand -hex 8)"
        # "${GPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "${lGPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
        write_csv_gpt_tmp "$(cut_path "${lQUERY_FILE}")" "${lGPT_ANCHOR_}" "${lGPT_PRIO_}" "${GPT_QUESTION}" "${S23_CSV_LOG}" "" ""
        # add ChatGPT link
        print_ln
        print_ln
        write_anchor_gpt "${lGPT_ANCHOR_}"
      fi
    fi
  done
}

s23_luacheck() {
  local lLUA_SCRIPT_="${1:-}"
  local lSCRIPT_NAME=""
  local lLUA_LOG=""
  local lLUA_ISSUES=""

  lSCRIPT_NAME=$(basename "${lLUA_SCRIPT_}" 2> /dev/null | sed -e 's/:/_/g')
  lLUA_LOG="${LOG_PATH_MODULE}""/luacheck_""${lSCRIPT_NAME}"".txt"
  luacheck "${lLUA_SCRIPT_}" > "${lLUA_LOG}" 2> /dev/null || true

  lLUA_ISSUES=$(strip_color_codes "$(grep Total "${lLUA_LOG}" | awk '{print $2}' 2> /dev/null || true)")
  if [[ "${lLUA_ISSUES}" -gt 0 ]] ; then
    S23_ISSUE_FOUND=1
    # check if this is common linux file:
    local lCOMMON_FILES_FOUND=""
    local lCFF=""
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      lCOMMON_FILES_FOUND="(""${RED}""common linux file: no""${GREEN}"")"
      lCFF="no"
      if grep -q "^${lSCRIPT_NAME}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        lCOMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${GREEN}"")"
        lCFF="yes"
      fi
    else
      lCOMMON_FILES_FOUND=""
      lCFF="NA"
    fi
    print_output "[+] Found ""${ORANGE}""${lLUA_ISSUES}"" coding issues""${GREEN}"" in lua script ""${lCOMMON_FILES_FOUND}"":""${NC}"" ""$(print_path "${lLUA_SCRIPT_}")" "" "${lLUA_LOG}"
    write_csv_log "$(print_path "${lLUA_SCRIPT_}")" "${lLUA_ISSUES}" "0" "${lCFF}"
  fi
}

