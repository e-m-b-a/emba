#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck

# Description:  Checks for vulnerabilities in php scripts.
#               Checks for configuration issues in php.ini files

S22_php_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "PHP vulnerability checks"
  pre_module_reporter "${FUNCNAME[0]}"

  local PHP_SCRIPTS=()
  export S22_PHP_VULNS=0
  export S22_PHP_SCRIPTS=0
  export S22_PHP_INI_ISSUES=0
  export S22_PHP_INI_CONFIGS=0
  export S22_PHPINFO_ISSUES=0
  export S22_SEMGREP_ISSUES=0

  if [[ ${PHP_CHECK} -eq 1 ]] ; then
    mapfile -t PHP_SCRIPTS < <( find "${FIRMWARE_PATH}" -xdev -type f -iname "*.php" -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum % 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 )
    s22_vuln_check_caller "${PHP_SCRIPTS[@]}"

    s22_vuln_check_semgrep "${PHP_SCRIPTS[@]}"

    s22_check_php_ini

    s22_phpinfo_check "${PHP_SCRIPTS[@]}"

    write_log ""
    write_log "[*] Statistics:${S22_PHP_VULNS}:${S22_PHP_SCRIPTS}:${S22_PHP_INI_ISSUES}:${S22_PHP_INI_CONFIGS}"

  else
    print_output "[-] PHP check is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "$(( "${S22_PHP_VULNS}" + "${S22_PHP_INI_ISSUES}" + "${S22_PHPINFO_ISSUES}" + "${S22_SEMGREP_ISSUES}" ))"
}

s22_phpinfo_check() {
  sub_module_title "PHPinfo file detection"
  local PHP_SCRIPTS=("$@")
  local PHPINFO=""

  for PHPINFO in "${PHP_SCRIPTS[@]}" ; do
    if grep -E "extension_loaded\('ionCube Loader" "${PHPINFO}"; then
      print_output "[-] Warning: ionCube protected PHP file detected ${ORANGE}${PHPINFO}${NC}"
      continue
    fi
    if grep -q "phpinfo()" "${PHPINFO}"; then
      print_output "[+] Found php file with debugging information: ${ORANGE}${PHPINFO}${NC}"
      grep -A 2 -B 2 "phpinfo()" "${PHPINFO}" | tee -a "${LOG_FILE}"
      ((S22_PHPINFO_ISSUES+=1))
    fi
  done
  if [[ "${S22_PHPINFO_ISSUES}" -eq 0 ]]; then
    print_output "[-] No phpinfo files found"
  fi
  print_ln
}

s22_vuln_check_semgrep() {
  sub_module_title "PHP script vulnerabilities - semgrep"
  local PHP_SEMGREP_LOG="${LOG_PATH_MODULE}"/semgrep_php_results_xml.log
  local S22_SEMGREP_VULNS=0
  local SEMG_SOURCES_ARR=()
  local S22_SEMGREP_SCRIPTS=""
  local SEMG_SOURCE_NOTE=""

  # multiple output options would be nice. Currently we have the xml output to parse it easily for getting the line number of the issue
  # but this output is not very beautiful to show in the report.
  semgrep --disable-version-check --junit-xml --config "${EXT_DIR}"/semgrep-rules/php "${LOG_DIR}"/firmware/ > "${PHP_SEMGREP_LOG}" 2>&1 || true

  if [[ -f "${PHP_SEMGREP_LOG}" ]]; then
    S22_SEMGREP_ISSUES=$(grep -c "testcase name" "${PHP_SEMGREP_LOG}" || true)
    S22_SEMGREP_VULNS=$(grep -c "semgrep-rules.php.lang.security" "${PHP_SEMGREP_LOG}" || true)
    S22_SEMGREP_SCRIPTS=$(grep "Scanning\ .* rules\." "${PHP_SEMGREP_LOG}" | awk '{print $2}' || true)

    if [[ "${S22_SEMGREP_VULNS}" -gt 0 ]]; then
      print_output "[+] Found ""${ORANGE}""${S22_SEMGREP_ISSUES}"" issues""${GREEN}"" (""${ORANGE}""${S22_SEMGREP_VULNS}"" vulnerabilites${GREEN}) in ""${ORANGE}""${S22_SEMGREP_SCRIPTS}""${GREEN}"" php files""${NC}" "" "${PHP_SEMGREP_LOG}"
    elif [[ "${S22_SEMGREP_ISSUES}" -gt 0 ]]; then
      print_output "[+] Found ""${ORANGE}""${S22_SEMGREP_ISSUES}"" issues""${GREEN}"" in ""${ORANGE}""${S22_SEMGREP_SCRIPTS}""${GREEN}"" php files""${NC}" "" "${PHP_SEMGREP_LOG}"
    else
      print_output "[-] No PHP issues found with semgrep"
    fi
    # highlight security findings in semgrep log:
    sed -i -r "s/.*external\.semgrep-rules\.php\.lang\.security.*/\x1b[32m&\x1b[0m/" "${PHP_SEMGREP_LOG}"

    mapfile -t SEMG_SOURCES_ARR < <(grep -E -o "name=.* file=.*\" line=\"[0-9]+" "${PHP_SEMGREP_LOG}" | sort -u || true)

    for SEMG_SOURCE_NOTE in "${SEMG_SOURCES_ARR[@]}"; do
      local SEMG_ISSUE_NAME=""
      local SEMG_SOURCE_FILE=""
      local SEMG_SOURCE_FILE_NAME=""
      local SEMG_LINE_NR=""
      local GPT_PRIO_=4
      local GPT_ANCHOR_=""

      ! [[ -d "${LOG_PATH_MODULE}"/semgrep_sources/ ]] && mkdir "${LOG_PATH_MODULE}"/semgrep_sources/

      SEMG_ISSUE_NAME=$(echo "${SEMG_SOURCE_NOTE}" | tr ' ' '\n' | grep "^name=")
      SEMG_ISSUE_NAME="$(echo "${SEMG_ISSUE_NAME}" | sed 's/name=\"//' | tr -d '"')"

      SEMG_SOURCE_FILE=$(echo "${SEMG_SOURCE_NOTE}" | tr ' ' '\n' | grep "^file=")
      SEMG_SOURCE_FILE="$(echo "${SEMG_SOURCE_FILE}" | sed 's/file=\"//' | tr -d '"')"
      SEMG_SOURCE_FILE_NAME=$(basename "${SEMG_SOURCE_FILE}")

      [[ -f "${SEMG_SOURCE_FILE}" && ! -f "${LOG_PATH_MODULE}"/semgrep_sources/"${SEMG_SOURCE_FILE_NAME}".log ]] && cp "${SEMG_SOURCE_FILE}" "${LOG_PATH_MODULE}"/semgrep_sources/"${SEMG_SOURCE_FILE_NAME}".log

      SEMG_LINE_NR=$(echo "${SEMG_SOURCE_NOTE}" | tr ' ' '\n' | grep "^line=")
      SEMG_LINE_NR="$(echo "${SEMG_LINE_NR}" | sed 's/line=\"//' | tr -d '"')"

      sed -i -r "${SEMG_LINE_NR}s/.*/\x1b[32m&\x1b[0m/" "${LOG_PATH_MODULE}"/semgrep_sources/"${SEMG_SOURCE_FILE_NAME}".log
      print_output "[+] Found possible PHP vulnerability ${ORANGE}${SEMG_ISSUE_NAME}${GREEN} in ${ORANGE}${SEMG_SOURCE_FILE_NAME}${GREEN}" "" "${LOG_PATH_MODULE}/semgrep_sources/${SEMG_SOURCE_FILE_NAME}.log"

      if [[ "${GPT_OPTION}" -gt 0 ]]; then
        GPT_ANCHOR_="$(openssl rand -hex 8)"
        if [[ -f "${BASE_LINUX_FILES}" ]]; then
          # if we have the base linux config file we are checking it:
          if ! grep -E -q "^${SEMG_SOURCE_FILE_NAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
            GPT_PRIO_=$((GPT_PRIO_+1))
          fi
        fi
        # "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
        write_csv_gpt_tmp "$(cut_path "${SEMG_SOURCE_FILE}")" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION} And I think there might be something in line ${SEMG_LINE_NR}" "${LOG_PATH_MODULE}/semgrep_sources/${SEMG_SOURCE_FILE_NAME}.log" "" ""
        # add ChatGPT link
        printf '%s\n\n' "" >> "${LOG_PATH_MODULE}/semgrep_sources/${SEMG_SOURCE_FILE_NAME}.log"
        write_anchor_gpt "${GPT_ANCHOR_}" "${LOG_PATH_MODULE}/semgrep_sources/${SEMG_SOURCE_FILE_NAME}.log"
      fi
    done
  fi
  write_log ""
  write_log "[*] Statistics1:${S22_SEMGREP_ISSUES}:${S22_SEMGREP_SCRIPTS}"
}

s22_vuln_check_caller() {
  sub_module_title "PHP script vulnerabilities (progpilot)"
  write_csv_log "Script path" "PHP issues detected" "common linux file"
  local PHP_SCRIPTS=("$@")
  local VULNS=0
  local PHP_SCRIPT=""
  local WAIT_PIDS_S22=()

  for PHP_SCRIPT in "${PHP_SCRIPTS[@]}" ; do
    if ( file "${PHP_SCRIPT}" | grep -q "PHP script" ) ; then
      ((S22_PHP_SCRIPTS+=1))
      if [[ "${THREADED}" -eq 1 ]]; then
        s22_vuln_check "${PHP_SCRIPT}" &
        local TMP_PID="$!"
        store_kill_pids "${TMP_PID}"
        WAIT_PIDS_S22+=( "${TMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S22[@]}"
        continue
      else
        s22_vuln_check "${PHP_SCRIPT}"
      fi
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S22[@]}"

  if [[ -f "${TMP_DIR}"/S22_VULNS.tmp ]]; then
    S22_PHP_VULNS=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S22_VULNS.tmp)
  fi

  if [[ "${S22_PHP_VULNS}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${S22_PHP_VULNS}"" vulnerabilities""${GREEN}"" in ""${ORANGE}""${S22_PHP_SCRIPTS}""${GREEN}"" php files.""${NC}""\\n"
  else
    print_output "[-] No PHP issues found with progpilot"
  fi
}

s22_vuln_check() {
  local PHP_SCRIPT_="${1:-}"

  if ! [[ -f "${PHP_SCRIPT_}" ]]; then
    print_output "[-] No PHP script for analysis provided"
    return
  fi

  local NAME=""
  local VULNS=0
  local TOTAL_MEMORY=0

  TOTAL_MEMORY="$(grep MemTotal /proc/meminfo | awk '{print $2}' || true)"
  local MEM_LIMIT=$(( "${TOTAL_MEMORY}"/2 ))

  NAME=$(basename "${PHP_SCRIPT_}" 2> /dev/null | sed -e 's/:/_/g')
  local PHP_LOG="${LOG_PATH_MODULE}""/php_vuln_""${NAME}""-${RANDOM}.txt"

  ulimit -Sv "${MEM_LIMIT}"
  "${EXT_DIR}"/progpilot "${PHP_SCRIPT_}" >> "${PHP_LOG}" 2>&1 || true
  ulimit -Sv unlimited

  VULNS=$(grep -c "vuln_name" "${PHP_LOG}" 2> /dev/null || true)
  local GPT_PRIO_=4
  local GPT_ANCHOR_=""
  if [[ "${VULNS}" -gt 0 ]] ; then
    # check if this is common linux file:
    local COMMON_FILES_FOUND=""
    local CFF=""
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      COMMON_FILES_FOUND=" (""${RED}""common linux file: no""${GREEN}"")"
      CFF="no"
      if grep -q "^${NAME}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        COMMON_FILES_FOUND=" (""${CYAN}""common linux file: yes""${GREEN}"")"
        CFF="yes"
        GPT_PRIO_=1
      fi
    else
      COMMON_FILES_FOUND=""
      CFF="NA"
    fi
    print_output "[+] Found ""${ORANGE}""${VULNS}"" vulnerabilities""${GREEN}"" in php file"": ""${ORANGE}""$(print_path "${PHP_SCRIPT_}")""${GREEN}""${COMMON_FILES_FOUND}""${NC}" "" "${PHP_LOG}"
    write_csv_log "$(print_path "${PHP_SCRIPT_}")" "${VULNS}" "${CFF}" "NA"
    if [[ "${GPT_OPTION}" -gt 0 ]]; then
      GPT_ANCHOR_="$(openssl rand -hex 8)"
      # "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "GPT-Prio-$GPT_PRIO_" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
      write_csv_gpt_tmp "$(cut_path "${PHP_SCRIPT_}")" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION}" "${TMP_DIR}/S22_VULNS.tmp" "" ""
      # add ChatGPT link
      printf '%s\n\n' "" >> "${TMP_DIR}"/S22_VULNS.tmp
      write_anchor_gpt "${GPT_ANCHOR_}" "${TMP_DIR}"/S22_VULNS.tmp
    fi
    echo "${VULNS}" >> "${TMP_DIR}"/S22_VULNS.tmp
  else
    # print_output "[*] Warning: No VULNS detected in $PHP_LOG" "no_log"
    rm "${PHP_LOG}" 2>/dev/null || true
  fi
}

s22_check_php_ini() {
  sub_module_title "PHP configuration checks (php.ini)"
  local PHP_INI_FAILURE=0
  local PHP_INI_LIMIT_EXCEEDED=0
  local PHP_INI_WARNINGS=0
  local PHP_INI_FILE=()
  local PHP_FILE=""
  local INISCAN_RESULT=()
  local LINE=""
  local PHP_INISCAN_PATH="${EXT_DIR}""/iniscan/vendor/bin/iniscan"

  mapfile -t PHP_INI_FILE < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname 'php.ini' -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum % 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 )
  if [[ "${#PHP_INI_FILE[@]}" -eq 0 ]]; then
    print_output "[-] No PHP.ini issues found"
    return
  fi

  disable_strict_mode "${STRICT_MODE}"
  for PHP_FILE in "${PHP_INI_FILE[@]}" ;  do
    # print_output "[*] iniscan check of ""$(print_path "${PHP_FILE}")"
    mapfile -t INISCAN_RESULT < <( "${PHP_INISCAN_PATH}" scan --path="${PHP_FILE}" || true)
    for LINE in "${INISCAN_RESULT[@]}" ; do
      local LIMIT_CHECK=""
      # nosemgrep
      local IFS='|'
      IFS='|' read -ra LINE_ARR <<< "${LINE}"
      # TODO: STRICT mode not working here:
      add_recommendations "${LINE_ARR[3]}" "${LINE_ARR[4]}"
      LIMIT_CHECK="$?"
      if [[ "${LIMIT_CHECK}" -eq 1 ]]; then
        print_output "$(magenta "${LINE}")"
        PHP_INI_LIMIT_EXCEEDED=$(( PHP_INI_LIMIT_EXCEEDED+1 ))
      elif ( echo "${LINE}" | grep -q "FAIL" ) && ( echo "${LINE}" | grep -q "ERROR" ) ; then
        print_output "$(red "${LINE}")"
      elif ( echo "${LINE}" | grep -q "FAIL" ) && ( echo "${LINE}" | grep -q "WARNING" )  ; then
        print_output "$(orange "${LINE}")"
      elif ( echo "${LINE}" | grep -q "FAIL" ) && ( echo "${LINE}" | grep -q "INFO" ) ; then
        print_output "$(blue "${LINE}")"
      elif ( echo "${LINE}" | grep -q "PASS" ) ; then
        continue
      else
        if ( echo "${LINE}" | grep -q "failure" ) && ( echo "${LINE}" | grep -q "warning" ) ; then
          IFS=' ' read -ra LINE_ARR <<< "${LINE}"
          PHP_INI_FAILURE=${LINE_ARR[0]}
          PHP_INI_WARNINGS=${LINE_ARR[3]}
          (( S22_PHP_INI_ISSUES="${S22_PHP_INI_ISSUES}"+"${PHP_INI_LIMIT_EXCEEDED}"+"${PHP_INI_FAILURE}"+"${PHP_INI_WARNINGS}" ))
          S22_PHP_INI_CONFIGS=$(( S22_PHP_INI_CONFIGS+1 ))
        elif ( echo "${LINE}" | grep -q "passing" ) ; then
          IFS=' ' read -ra LINE_ARR <<< "${LINE}"
          # semgrep does not like the following line of code:
          LINE_ARR[0]=$(( "${LINE_ARR[0]}" - "${PHP_INI_LIMIT_EXCEEDED}" ))
        fi
      fi
    done
    if [[ "${S22_PHP_INI_ISSUES}" -gt 0 ]]; then
      print_ln
      print_output "[+] Found ""${ORANGE}""${S22_PHP_INI_ISSUES}""${GREEN}"" PHP configuration issues in php config file :""${ORANGE}"" ""$(print_path "${PHP_FILE}")"
      print_ln
    else
      print_output "[-] No PHP.ini issues found"
    fi
  done
  enable_strict_mode "${STRICT_MODE}"
}

add_recommendations() {
   local VALUE="${1:-}"
   local KEY="${2:-}"

   if [[ ${VALUE} == *"M"* ]]; then
      LIMIT="${VALUE//M/}"
   fi

   if [[ ${KEY} == *"memory_limit"* ]] && [[ $(( LIMIT)) -gt 50 ]]; then
     return 1
   elif [[ ${KEY} == *"post_max_size"* ]] && [[ $(( LIMIT)) -gt 20 ]]; then
     return 1
   elif [[ ${KEY} == *"max_execution_time"* ]] && [[ $(( LIMIT )) -gt 60 ]]; then
     return 1
   else
     return 0
   fi
}

