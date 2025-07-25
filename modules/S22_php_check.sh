#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
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

  local lPHP_SCRIPTS_ARR=()
  export S22_PHP_VULNS=0
  export S22_PHP_SCRIPTS=0
  export S22_PHP_INI_ISSUES=0
  export S22_PHP_INI_CONFIGS=0
  export S22_PHPINFO_ISSUES=0
  export S22_SEMGREP_ISSUES=0

  if [[ ${PHP_CHECK} -eq 1 ]] ; then
    mapfile -t lPHP_SCRIPTS_ARR < <(grep "PHP script" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
    write_csv_log "Script path" "PHP issue" "source (e.g. semgrep)" "common linux file"
    s22_vuln_check_caller "${lPHP_SCRIPTS_ARR[@]}"

    s22_vuln_check_semgrep "${lPHP_SCRIPTS_ARR[@]}"

    s22_check_php_ini

    s22_phpinfo_check "${lPHP_SCRIPTS_ARR[@]}"

    write_log ""
    write_log "[*] Statistics:${S22_PHP_VULNS}:${S22_PHP_SCRIPTS}:${S22_PHP_INI_ISSUES}:${S22_PHP_INI_CONFIGS}"

  else
    print_output "[-] PHP check is disabled ... no tests performed"
  fi
  module_end_log "${FUNCNAME[0]}" "$(( "${S22_PHP_VULNS}" + "${S22_PHP_INI_ISSUES}" + "${S22_PHPINFO_ISSUES}" + "${S22_SEMGREP_ISSUES}" ))"
}

s22_phpinfo_check() {
  sub_module_title "PHPinfo file detection"
  local lPHP_SCRIPTS_ARR=("$@")
  local lPHPINFO=""

  for lPHPINFO in "${lPHP_SCRIPTS_ARR[@]}" ; do
    if grep -E "extension_loaded\('ionCube Loader" "${lPHPINFO}"; then
      print_output "[-] Warning: ionCube protected PHP file detected ${ORANGE}${lPHPINFO}${NC}"
      continue
    fi
    if grep -E "return sg_load\('" "${lPHPINFO}"; then
      print_output "[-] Warning: SourceGuardian protected PHP file detected ${ORANGE}${lPHPINFO}${NC}"
      continue
    fi
    if grep -q "phpinfo()" "${lPHPINFO}"; then
      print_output "[+] Found php file with debugging information: ${ORANGE}${lPHPINFO}${NC}"
      grep -A 2 -B 2 "phpinfo()" "${lPHPINFO}" | tee -a "${LOG_FILE}"
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
  local lPHP_SEMGREP_LOG="${LOG_PATH_MODULE}"/semgrep_php_results_xml.log
  local lS22_SEMGREP_VULNS=0
  local lSEMG_SOURCES_ARR=()
  local lS22_SEMGREP_SCRIPTS=""
  local lSEMG_SOURCE_NOTE=""

  # multiple output options would be nice. Currently we have the xml output to parse it easily for getting the line number of the issue
  # but this output is not very beautiful to show in the report.
  semgrep --disable-version-check --metrics=off --junit-xml --config "${EXT_DIR}"/semgrep-rules/php "${LOG_DIR}"/firmware/ > "${lPHP_SEMGREP_LOG}" || true
  tidy -xml -iq "${lPHP_SEMGREP_LOG}" > "${lPHP_SEMGREP_LOG/\.log/\.pretty\.log}" || true

  if [[ -f "${lPHP_SEMGREP_LOG}" ]]; then
    S22_SEMGREP_ISSUES=$(grep -c "testcase name" "${lPHP_SEMGREP_LOG/\.log/\.pretty\.log}" || true)
    lS22_SEMGREP_VULNS=$(grep -c "semgrep-rules.php.lang.security" "${lPHP_SEMGREP_LOG/\.log/\.pretty\.log}" || true)
    lS22_SEMGREP_SCRIPTS=$(grep "Scanning\ .* rules\." "${lPHP_SEMGREP_LOG}" | awk '{print $2}' || true)

    if [[ "${lS22_SEMGREP_VULNS}" -gt 0 ]]; then
      print_output "[+] Found ""${ORANGE}""${S22_SEMGREP_ISSUES}"" issues""${GREEN}"" (""${ORANGE}""${lS22_SEMGREP_VULNS}"" vulnerabilites${GREEN}) in ""${ORANGE}""${lS22_SEMGREP_SCRIPTS}""${GREEN}"" php files""${NC}" "" "${lPHP_SEMGREP_LOG/\.log/\.pretty\.log}"
    elif [[ "${S22_SEMGREP_ISSUES}" -gt 0 ]]; then
      print_output "[+] Found ""${ORANGE}""${S22_SEMGREP_ISSUES}"" issues""${GREEN}"" in ""${ORANGE}""${lS22_SEMGREP_SCRIPTS}""${GREEN}"" php files""${NC}" "" "${lPHP_SEMGREP_LOG/\.log/\.pretty\.log}"
    else
      print_output "[-] No PHP issues found with semgrep"
    fi
    # highlight security findings in semgrep log:
    sed -i -r "s/.*external\.semgrep-rules\.php\.lang\.security.*/\x1b[32m&\x1b[0m/" "${lPHP_SEMGREP_LOG/\.log/\.pretty\.log}"

    mapfile -t lSEMG_SOURCES_ARR < <(grep -E -o -e "testcase name=\".*\"" -e "file=.*\"" -e "line=\"[0-9]+" "${lPHP_SEMGREP_LOG/\.log/\.pretty\.log}" | sed -z 's/"\n/\ /g' | sort -u || true)

    for lSEMG_SOURCE_NOTE in "${lSEMG_SOURCES_ARR[@]}"; do
      local lSEMG_ISSUE_NAME=""
      local lSEMG_SOURCE_FILE=""
      local lSEMG_SOURCE_FILE_NAME=""
      local lSEMG_LINE_NR=""
      local lGPT_PRIO_=4
      local lGPT_ANCHOR_=""

      ! [[ -d "${LOG_PATH_MODULE}"/semgrep_sources/ ]] && mkdir "${LOG_PATH_MODULE}"/semgrep_sources/

      lSEMG_ISSUE_NAME=$(echo "${lSEMG_SOURCE_NOTE}" | tr ' ' '\n' | grep "^name=")
      lSEMG_ISSUE_NAME="${lSEMG_ISSUE_NAME/name=\"/}"

      lSEMG_SOURCE_FILE=$(echo "${lSEMG_SOURCE_NOTE}" | tr ' ' '\n' | grep "^file=")
      lSEMG_SOURCE_FILE="${lSEMG_SOURCE_FILE/file=\"/}"
      lSEMG_SOURCE_FILE_NAME=$(basename "${lSEMG_SOURCE_FILE}")

      [[ -f "${lSEMG_SOURCE_FILE}" && ! -f "${LOG_PATH_MODULE}"/semgrep_sources/"${lSEMG_SOURCE_FILE_NAME}".log ]] && cp "${lSEMG_SOURCE_FILE}" "${LOG_PATH_MODULE}"/semgrep_sources/"${lSEMG_SOURCE_FILE_NAME}".log

      lSEMG_LINE_NR=$(echo "${lSEMG_SOURCE_NOTE}" | tr ' ' '\n' | grep "^line=")
      lSEMG_LINE_NR="${lSEMG_LINE_NR/line=\"/}"

      sed -i -r "${lSEMG_LINE_NR}s/.*/\x1b[32m&\x1b[0m/" "${LOG_PATH_MODULE}"/semgrep_sources/"${lSEMG_SOURCE_FILE_NAME}".log || true
      print_output "[+] Found possible PHP vulnerability ${ORANGE}${lSEMG_ISSUE_NAME}${GREEN} in ${ORANGE}${lSEMG_SOURCE_FILE_NAME}${GREEN}" "" "${LOG_PATH_MODULE}/semgrep_sources/${lSEMG_SOURCE_FILE_NAME}.log"
      write_csv_log "${lSEMG_SOURCE_FILE}" "${lSEMG_ISSUE_NAME}" "semgrep" "unknown"

      if [[ "${GPT_OPTION}" -gt 0 ]]; then
        lGPT_ANCHOR_="$(openssl rand -hex 8)"
        if [[ -f "${BASE_LINUX_FILES}" ]]; then
          # if we have the base linux config file we are checking it:
          if ! grep -E -q "^${lSEMG_SOURCE_FILE_NAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
            lGPT_PRIO_=$((lGPT_PRIO_+1))
          fi
        fi
        # "${GPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "${lGPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
        write_csv_gpt_tmp "$(cut_path "${lSEMG_SOURCE_FILE}")" "${lGPT_ANCHOR_}" "${lGPT_PRIO_}" "${GPT_QUESTION} And I think there might be something in line ${lSEMG_LINE_NR}" "${LOG_PATH_MODULE}/semgrep_sources/${lSEMG_SOURCE_FILE_NAME}.log" "" ""
        # add ChatGPT link
        printf '%s\n\n' "" >> "${LOG_PATH_MODULE}/semgrep_sources/${lSEMG_SOURCE_FILE_NAME}.log"
        write_anchor_gpt "${lGPT_ANCHOR_}" "${LOG_PATH_MODULE}/semgrep_sources/${lSEMG_SOURCE_FILE_NAME}.log"
      fi
    done
  fi
  write_log ""
  write_log "[*] Statistics1:${S22_SEMGREP_ISSUES}:${lS22_SEMGREP_SCRIPTS}"
}

s22_vuln_check_caller() {
  sub_module_title "PHP script vulnerabilities (progpilot)"
  local lPHP_SCRIPTS_ARR=("$@")
  local lVULNS=0
  local lPHP_SCRIPT=""
  local lWAIT_PIDS_S22_ARR=()

  for lPHP_SCRIPT in "${lPHP_SCRIPTS_ARR[@]}" ; do
    ((S22_PHP_SCRIPTS+=1))
    if [[ "${THREADED}" -eq 1 ]]; then
      s22_vuln_check "${lPHP_SCRIPT}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S22_ARR+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S22_ARR
      continue
    else
      s22_vuln_check "${lPHP_SCRIPT}"
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S22_ARR[@]}"

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
  local lPHP_SCRIPT_="${1:-}"

  if ! [[ -f "${lPHP_SCRIPT_}" ]]; then
    print_output "[-] No PHP script for analysis provided"
    return
  fi

  local lPHP_SCRIPT_NAME=""
  local lVULNS=0
  local lTOTAL_MEMORY=0

  lTOTAL_MEMORY="$(grep MemTotal /proc/meminfo | awk '{print $2}' || true)"
  local lMEM_LIMIT=$(( "${lTOTAL_MEMORY}"/2 ))

  lPHP_SCRIPT_NAME=$(basename "${lPHP_SCRIPT_}" 2> /dev/null | sed -e 's/:/_/g')
  local lPHP_LOG="${LOG_PATH_MODULE}""/php_vuln_""${lPHP_SCRIPT_NAME}""-${RANDOM}.txt"

  ulimit -Sv "${lMEM_LIMIT}"
  "${EXT_DIR}"/progpilot "${lPHP_SCRIPT_}" >> "${lPHP_LOG}" 2>&1 || true
  ulimit -Sv unlimited

  lVULNS=$(grep -c "vuln_name" "${lPHP_LOG}" 2> /dev/null || true)
  local lGPT_PRIO_=4
  local lGPT_ANCHOR_=""
  if [[ "${lVULNS}" -gt 0 ]] ; then
    # check if this is common linux file:
    local lCOMMON_FILES_FOUND=""
    local lCFF=""
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      lCOMMON_FILES_FOUND=" (""${RED}""common linux file: no""${GREEN}"")"
      lCFF="no"
      if grep -q "^${lPHP_SCRIPT_NAME}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        lCOMMON_FILES_FOUND=" (""${CYAN}""common linux file: yes""${GREEN}"")"
        lCFF="yes"
        lGPT_PRIO_=1
      fi
    else
      lCOMMON_FILES_FOUND=""
      lCFF="NA"
    fi
    print_output "[+] Found ""${ORANGE}""${lVULNS}"" vulnerabilities""${GREEN}"" in php file"": ""${ORANGE}""$(print_path "${lPHP_SCRIPT_}")""${GREEN}""${lCOMMON_FILES_FOUND}""${NC}" "" "${lPHP_LOG}"
    write_csv_log "${lPHP_SCRIPT_}" "TODO" "progpilot" "${lCFF}"

    if [[ "${GPT_OPTION}" -gt 0 ]]; then
      lGPT_ANCHOR_="$(openssl rand -hex 8)"
      # "${GPT_INPUT_FILE_}" "${lGPT_ANCHOR_}" "GPT-Prio-$lGPT_PRIO_" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
      write_csv_gpt_tmp "$(cut_path "${lPHP_SCRIPT_}")" "${lGPT_ANCHOR_}" "${lGPT_PRIO_}" "${GPT_QUESTION}" "${TMP_DIR}/S22_VULNS.tmp" "" ""
      # add ChatGPT link
      printf '%s\n\n' "" >> "${TMP_DIR}"/S22_VULNS.tmp
      write_anchor_gpt "${lGPT_ANCHOR_}" "${TMP_DIR}"/S22_VULNS.tmp
    fi
    echo "${lVULNS}" >> "${TMP_DIR}"/S22_VULNS.tmp
  else
    # print_output "[*] Warning: No VULNS detected in $lPHP_LOG" "no_log"
    rm "${lPHP_LOG}" 2>/dev/null || true
  fi
}

s22_check_php_ini() {
  sub_module_title "PHP configuration checks (php.ini)"
  local lPHP_INI_FAILURE=0
  local lPHP_INI_LIMIT_EXCEEDED=0
  local lPHP_INI_WARNINGS=0
  local lPHP_INI_FILES_ARR=()
  local lPHP_FILE=""
  local lINISCAN_RESULT_ARR=()
  local lINI_RESULT_LINE=""
  local lPHP_INISCAN_PATH="${EXT_DIR}""/iniscan/vendor/bin/iniscan"

  # mapfile -t lPHP_INI_FILES_ARR < <( find "${FIRMWARE_PATH}" -xdev "${EXCL_FIND[@]}" -iname 'php.ini' -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 )
  mapfile -t lPHP_INI_FILES_ARR < <(grep "php.ini;" "${P99_CSV_LOG}" | sort -u || true)
  if [[ "${#lPHP_INI_FILES_ARR[@]}" -eq 0 ]]; then
    print_output "[-] No PHP.ini issues found"
    return
  fi

  disable_strict_mode "${STRICT_MODE}"
  for lPHP_FILE in "${lPHP_INI_FILES_ARR[@]}" ;  do
    # print_output "[*] iniscan check of ""$(print_path "${lPHP_FILE}")"
    mapfile -t lINISCAN_RESULT_ARR < <( "${lPHP_INISCAN_PATH}" scan --path="${lPHP_FILE/;*}" || true)
    for lINI_RESULT_LINE in "${lINISCAN_RESULT_ARR[@]}" ; do
      local lLIMIT_CHECK=""
      # nosemgrep
      local IFS='|'
      IFS='|' read -ra LINE_ARR <<< "${lINI_RESULT_LINE}"
      # TODO: STRICT mode not working here:
      add_recommendations "${LINE_ARR[3]}" "${LINE_ARR[4]}"
      lLIMIT_CHECK="$?"
      if [[ "${lLIMIT_CHECK}" -eq 1 ]]; then
        print_output "$(magenta "${lINI_RESULT_LINE}")"
        lPHP_INI_LIMIT_EXCEEDED=$(( lPHP_INI_LIMIT_EXCEEDED+1 ))
      elif ( echo "${lINI_RESULT_LINE}" | grep -q "FAIL" ) && ( echo "${lINI_RESULT_LINE}" | grep -q "ERROR" ) ; then
        print_output "$(red "${lINI_RESULT_LINE}")"
      elif ( echo "${lINI_RESULT_LINE}" | grep -q "FAIL" ) && ( echo "${lINI_RESULT_LINE}" | grep -q "WARNING" )  ; then
        print_output "$(orange "${lINI_RESULT_LINE}")"
      elif ( echo "${lINI_RESULT_LINE}" | grep -q "FAIL" ) && ( echo "${lINI_RESULT_LINE}" | grep -q "INFO" ) ; then
        print_output "$(blue "${lINI_RESULT_LINE}")"
      elif ( echo "${lINI_RESULT_LINE}" | grep -q "PASS" ) ; then
        continue
      else
        if ( echo "${lINI_RESULT_LINE}" | grep -q "failure" ) && ( echo "${lINI_RESULT_LINE}" | grep -q "warning" ) ; then
          IFS=' ' read -ra LINE_ARR <<< "${lINI_RESULT_LINE}"
          lPHP_INI_FAILURE=${LINE_ARR[0]}
          lPHP_INI_WARNINGS=${LINE_ARR[3]}
          (( S22_PHP_INI_ISSUES="${S22_PHP_INI_ISSUES}"+"${lPHP_INI_LIMIT_EXCEEDED}"+"${lPHP_INI_FAILURE}"+"${lPHP_INI_WARNINGS}" ))
          S22_PHP_INI_CONFIGS=$(( S22_PHP_INI_CONFIGS+1 ))
        elif ( echo "${lINI_RESULT_LINE}" | grep -q "passing" ) ; then
          IFS=' ' read -ra LINE_ARR <<< "${lINI_RESULT_LINE}"
          # semgrep does not like the following line of code:
          LINE_ARR[0]=$(( "${LINE_ARR[0]}" - "${lPHP_INI_LIMIT_EXCEEDED}" ))
        fi
      fi
    done
    if [[ "${S22_PHP_INI_ISSUES}" -gt 0 ]]; then
      print_ln
      print_output "[+] Found ""${ORANGE}""${S22_PHP_INI_ISSUES}""${GREEN}"" PHP configuration issues in php config file :""${ORANGE}"" ""$(print_path "${lPHP_FILE/;*}")"
      print_ln
    else
      print_output "[-] No PHP.ini issues found"
    fi
  done
  enable_strict_mode "${STRICT_MODE}"
}

add_recommendations() {
   local lVALUE="${1:-}"
   local lKEY="${2:-}"

   local lLIMIT=""

   if [[ ${lVALUE} == *"M"* ]]; then
      lLIMIT="${lVALUE//M/}"
   fi

   if [[ ${lKEY} == *"memory_limit"* ]] && [[ $(( lLIMIT)) -gt 50 ]]; then
     return 1
   elif [[ ${lKEY} == *"post_max_size"* ]] && [[ $(( lLIMIT)) -gt 20 ]]; then
     return 1
   elif [[ ${lKEY} == *"max_execution_time"* ]] && [[ $(( lLIMIT )) -gt 60 ]]; then
     return 1
   else
     return 0
   fi
}

