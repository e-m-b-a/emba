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
  local lS23_LUA_ISSUES=0
  local lLUA_SCRIPT=""
  local lWAIT_PIDS_S23_ARR=()

  write_csv_log "Script path" "LUA issues detected" "LUA vulnerabilities detected" "common linux file"

  export LUA_CGI_FILES_ARR=()
  local lLUA_CGI_FILES_ARR_2=()
  local lLUA_CGI_FILES_ARR_3=()

  # find scripts with cgilua as contend:
  mapfile -t LUA_CGI_FILES_ARR < <(find "${FIRMWARE_PATH}" -type f -print0|xargs -r -0 -P 16 -I % sh -c 'grep -H cgilua\. "%" 2>/dev/null || true | cut -d : -f1' | sort -u || true)
  # extract lua scripts that are known as lua scripts in out P99_CSV_LOG
  mapfile -t lLUA_CGI_FILES_ARR_2 < <(grep "Lua script" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)
  # find files with lua in the name and some lua content
  mapfile -t lLUA_CGI_FILES_ARR_3 < <(grep "\.lua;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  LUA_CGI_FILES_ARR=( "${LUA_CGI_FILES_ARR[@]}" "${lLUA_CGI_FILES_ARR_2[@]}" "${lLUA_CGI_FILES_ARR_3[@]}" )

  mapfile -t LUA_CGI_FILES_ARR < <(printf "%s\n" "${LUA_CGI_FILES_ARR[@]}" | sort -u)

  sub_module_title "LUA linter checks module"

  for lLUA_SCRIPT in "${LUA_CGI_FILES_ARR[@]}" ; do
    [[ ! -f "${lLUA_SCRIPT}" ]] && continue
    # linting check:
    # s23_luacheck "$(echo "${lLUA_SCRIPT}" | cut -d';' -f2)" &
    s23_luacheck "${lLUA_SCRIPT}" &
    local lTMP_PID="$!"
    lWAIT_PIDS_S23_ARR+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S23_ARR
  done

  wait_for_pid "${lWAIT_PIDS_S23_ARR[@]}"

  # simple lua checks to identify files which should be analysed in more detail
  # we should thread this in the future
  print_ln
  s23_luaseccheck

  lS23_LUA_ISSUES=$(wc -l 2>/dev/null < "${S23_CSV_LOG}")
  # remove the csv header:
  [[ "${lS23_LUA_ISSUES}" -gt 0 ]] && ((lS23_LUA_ISSUES--))
  # extract the not 0 results of the vulnerabilities
  lS23_LUA_VULNS=$(cut -d ';' -f 3 "${S23_CSV_LOG}" 2>/dev/null | tail +2 | grep -v -c "^0$" || true)

  if [[ "${lS23_LUA_VULNS}" -gt 0 ]]; then
    print_ln
    print_output "[+] Found ${ORANGE}${lS23_LUA_VULNS} possible security issues${GREEN} in ${ORANGE}${#LUA_CGI_FILES_ARR[@]}${GREEN} lua files.${NC}"
  fi
  if [[ "${lS23_LUA_ISSUES}" -gt 0 ]]; then
    print_ln
    print_output "[+] Found ${ORANGE}${lS23_LUA_ISSUES} coding issues${GREEN} in ${ORANGE}${#LUA_CGI_FILES_ARR[@]}${GREEN} lua files.${NC}"
  fi

  write_log ""
  write_log "[*] Statistics:${lS23_LUA_ISSUES}:${lS23_LUA_VULNS}:${#LUA_CGI_FILES_ARR[@]}"
  module_end_log "${FUNCNAME[0]}" "${lS23_LUA_ISSUES}"
}

# this is a very basic checker for LUA issues
s23_luaseccheck() {
  local lGPT_ANCHOR_=""
  local lGPT_PRIO_=3
  local lENTRY=""
  local lQUERY_ENTRIES_ARR=()
  local lQUERY_FILE=""

  sub_module_title "LUA Security checks module"

  # walk through all lua files for analysis
  for lQUERY_FILE in "${LUA_CGI_FILES_ARR[@]}"; do
    [[ ! -f "${lQUERY_FILE}" ]] && continue
    local lISSUES_FILE=0

    mapfile -t lQUERY_ENTRIES_ARR < <(grep -E "=.*cgilua\.QUERY" "${lQUERY_FILE}" | tr ' ' '\n' | sed 's/.*cgilua.QUERY.//' \
       | sed 's/.*cgilua.QUERY.//' | grep -o -E "^[[:alnum:]]+" | grep -v "^local$" | sort -u || true)

    for lENTRY in "${lQUERY_ENTRIES_ARR[@]}"; do
      lENTRY="${lENTRY//[![:print:]]/}"
      [[ -z "${lENTRY}" ]] && continue
      ! [[ "${lENTRY}" =~ ^[a-zA-Z0-9_-]+$ ]] && continue

      if grep "${lENTRY}" "${lQUERY_FILE}" 2>/dev/null | grep -E -q "io\.(p)?open"; then
        # possible file access
        lS23_LUA_VULNS=$((lS23_LUA_VULNS+1))
        lISSUES_FILE=$((lISSUES_FILE+1))
        print_output "[+] Found lua QUERY (GET/POST) entry: ${ORANGE}${lENTRY}${GREEN} in file ${ORANGE}${lQUERY_FILE}${GREEN} with file access capabilities."
        copy_and_link_file "${lQUERY_FILE}" "${LOG_PATH_MODULE}/$(basename "${lQUERY_FILE}").log"
        sed -i -r "s/.*io\.(p)?open.*/\x1b[32m&\x1b[0m/" "${LOG_PATH_MODULE}/$(basename "${lQUERY_FILE}").log"
        lGPT_PRIO_=$((lGPT_PRIO_+1))
      fi
      if grep "${lENTRY}" "${lQUERY_FILE}" 2>/dev/null | grep -q "os.execute"; then
        # command exec - critical
        lS23_LUA_VULNS=$((lS23_LUA_VULNS+1))
        lISSUES_FILE=$((lISSUES_FILE+1))
        print_output "[+] Found lua QUERY (GET/POST) entry: ${ORANGE}${lENTRY}${GREEN} in file ${ORANGE}${lQUERY_FILE}${GREEN} with command execution capabilities."
        copy_and_link_file "${lQUERY_FILE}" "${LOG_PATH_MODULE}/$(basename "${lQUERY_FILE}").log"
        sed -i -r "s/.*os\.execute.*/\x1b[32m&\x1b[0m/" "${LOG_PATH_MODULE}/$(basename "${lQUERY_FILE}").log"
        lGPT_PRIO_=$((lGPT_PRIO_+1))
      fi
    done

    # The following grep command checks for variants of the following patterns
    #   os.execute("some_command" .. variable)
    #   os.execute(string.format("sleep %d", tonumber(sec)))
    #   os.execute(asdf_cmd)
    if [[ "${lISSUES_FILE}" -eq 0 ]] && grep -E -q "os\.execute\(.*\.\..*\)|os\.execute\(.*\%.*\)|os\.execute\([[:alnum:]_]+\)" "${lQUERY_FILE}"; then
      local lLOG_QUERYFILE=""
      lLOG_QUERYFILE="${LOG_PATH_MODULE}/$(basename "${lQUERY_FILE}").log"
      print_output "[+] Found lua file ${ORANGE}${lQUERY_FILE}${GREEN} with possible command execution for review."
      copy_and_link_file "${lQUERY_FILE}" "${lLOG_QUERYFILE}"
      if [[ -f "${lLOG_QUERYFILE}" ]]; then
        # os\.execute\(.*\.\..*\)
        sed -i -r "s/.*os\.execute\(.*\.\..*\)/\x1b[32m&\x1b[0m/" "${lLOG_QUERYFILE}"
        # os\.execute\(.*\%.*\)
        sed -i -r "s/.*os\.execute\(.*\%.*\)/\x1b[32m&\x1b[0m/" "${lLOG_QUERYFILE}"
        # os\.execute\([[:alnum:]_]+\)
        sed -i -r "s/.*os\.execute\([[:alnum:]_]+\)/\x1b[32m&\x1b[0m/" "${lLOG_QUERYFILE}"
      fi
      lISSUES_FILE=$((lISSUES_FILE+1))
    fi
    if [[ "${lISSUES_FILE}" -eq 0 ]] && grep -E -q "io\.(p)?open" "${lQUERY_FILE}"; then
      # command exec - not our parameter but we check it
      print_output "[+] Found lua file ${ORANGE}${lQUERY_FILE}${GREEN} with possible file access for review."
      copy_and_link_file "${lQUERY_FILE}" "${LOG_PATH_MODULE}/$(basename "${lQUERY_FILE}").log"
      sed -i -r "s/.*io\.(p)?open.*/\x1b[32m&\x1b[0m/" "${LOG_PATH_MODULE}/$(basename "${lQUERY_FILE}").log"
      lISSUES_FILE=$((lISSUES_FILE+1))
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

