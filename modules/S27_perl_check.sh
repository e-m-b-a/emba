#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Checks for bugs and possible vulnerabilities in perl scripts with zarn - https://github.com/htrgouvea/zarn
#               See also https://heitorgouvea.me/2023/03/19/static-security-analysis-tool-perl

S27_perl_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check perl scripts for security issues"
  pre_module_reporter "${FUNCNAME[0]}"

  local lS27_PL_VULNS=0

  if ! [[ -f "${EXT_DIR}"/zarn/zarn.pl ]]; then
    print_output "[-] Zarn installation not available - please check your installation/docker image"
    module_end_log "${FUNCNAME[0]}" "${lS27_PL_VULNS}"
    return
  fi

  local lS27_PL_SCRIPTS=0
  local lPL_SCRIPT=""
  local lPERL_SCRIPTS_ARR=()
  local lNAME=""
  local lWAIT_PIDS_S27=()

  export PERL5LIB="${EXT_DIR}"/zarn/lib

  write_csv_log "Script path" "Perl issues detected" "common linux file" "vuln title" "vuln line nr" "vuln note"
  # mapfile -t lPERL_SCRIPTS_ARR < <(find "${FIRMWARE_PATH}" -xdev -type f \( -name "*.pl" -o -name "*.pm" -o -name "*.cgi" \) -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 )
  mapfile -t lPERL_SCRIPTS_ARR < <(grep "Perl script.*executable" "${P99_CSV_LOG}" | sort -u || true)
  for lPL_SCRIPT in "${lPERL_SCRIPTS_ARR[@]}" ; do
    if [[ -f "${BASE_LINUX_FILES}" && "${FULL_TEST}" -eq 0 ]]; then
      # if we have the base linux config file we only test non known Linux binaries
      # with this we do not waste too much time on open source Linux stuff
      lNAME=$(basename "$(echo "${lPL_SCRIPT}" | cut -d';' -f2)" 2> /dev/null)
      if grep -E -q "^${lNAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        continue
      fi
    fi
    ((lS27_PL_SCRIPTS+=1))
    if [[ "${THREADED}" -eq 1 ]]; then
      s27_zarn_perl_checks "$(echo "${lPL_SCRIPT}" | cut -d';' -f2)" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S27+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S27
      continue
    else
      s27_zarn_perl_checks "$(echo "${lPL_SCRIPT}" | cut -d';' -f2)"
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S27[@]}"
  [[ -d "${TMP_DIR}"/s27 ]] && ( rm -r "${TMP_DIR}"/s27 || true )

  if [[ -f "${TMP_DIR}"/S27_VULNS.tmp ]]; then
    lS27_PL_VULNS=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S27_VULNS.tmp)
  fi

  write_log ""
  write_log "[*] Statistics:${lS27_PL_VULNS}:${lS27_PL_SCRIPTS}"
  module_end_log "${FUNCNAME[0]}" "${lS27_PL_VULNS}"
}

s27_zarn_perl_checks() {
  local lPL_SCRIPT="${1:-}"
  local lNAME=""
  local lPL_LOG=""  # text log with original output from zarn analysis
  local lVULNS=""
  local lGPT_PRIO=2
  local lGPT_ANCHOR=""
  local lZARN_SARIF_RESULTS_ARR=()
  local lSARIF_RESULT=""
  local lZARN_VULN_TITLE=""
  local lZARN_VULN_MESSAGE=""
  local lZARN_VULN_LINE=""
  local lCODE_LINE=""
  local lPL_LOG_LINKED=""  # 2nd stage log which is linked from the main log

  lNAME=$(basename "${lPL_SCRIPT}" 2> /dev/null | sed -e 's/:/_/g')
  print_output "[*] Testing perl script ${ORANGE}${lPL_SCRIPT}${NC}" "no_log"
  lPL_LOG="${LOG_PATH_MODULE}""/zarn_""${lNAME}"".txt"
  if [[ "${lPL_SCRIPT: -4}" == ".cgi" ]]; then
    if ! [[ -d "${TMP_DIR}"/s27 ]]; then
      mkdir "${TMP_DIR}"/s27
    fi
    # as zarn does not like cgi's, we need to temp rename these files now
    cp "${lPL_SCRIPT}" "${TMP_DIR}"/s27/"${lNAME/.cgi/.pl}"
    if [[ -f "${TMP_DIR}"/s27/"${lNAME/.cgi/.pl}" ]]; then
      perl "${EXT_DIR}"/zarn/zarn.pl -r "${EXT_DIR}"/zarn/rules/default.yml --source "${TMP_DIR}"/s27/"${lNAME/.cgi/.pl}" --sarif "${LOG_PATH_MODULE}""/zarn_""${lNAME}"".sarif" | tee -a "${lPL_LOG}" || print_error "[-] Analysis of ${lNAME} failed"
      rm "${TMP_DIR}"/s27/"${lNAME/.cgi/.pl}" || true
    fi
  else
    perl "${EXT_DIR}"/zarn/zarn.pl -r "${EXT_DIR}"/zarn/rules/default.yml --source "${lPL_SCRIPT}" --sarif "${LOG_PATH_MODULE}""/zarn_""${lNAME}"".sarif" | tee -a "${lPL_LOG}" || print_error "[-] Analysis of ${lNAME} failed"
  fi

  ## reporting starts here
  lVULNS=$(grep -c "\[vuln\]" "${lPL_LOG}" 2> /dev/null || true)
  if [[ "${lVULNS}" -gt 0 ]] ; then
    # check if this is common linux file:
    local lCOMMON_FILES_FOUND=""
    local lCFF=""
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      lCOMMON_FILES_FOUND="(""${RED}""common linux file: no""${GREEN}"")"
      lCFF="no"
      if grep -q "^${lNAME}\$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        lCOMMON_FILES_FOUND="(""${CYAN}""common linux file: yes""${GREEN}"")"
        lCFF="yes"
      fi
    else
      lCOMMON_FILES_FOUND=""
      lCFF="NA"
    fi
    lPL_LOG_LINKED="${LOG_PATH_MODULE}""/zarn_""${lNAME}""_details.txt"
    print_output "[+] Found ""${RED}""${lVULNS}"" possible issue(s)""${GREEN}"" in perl script ""${lCOMMON_FILES_FOUND}"":""${ORANGE}"" ""$(print_path "${lPL_SCRIPT}")" "" "${lPL_LOG_LINKED}"
    if [[ "${lVULNS}" -gt 20 ]] ; then
      lGPT_PRIO=$((lGPT_PRIO+1))
    fi

    mapfile -t lZARN_SARIF_RESULTS_ARR < <(jq -rc '.runs[].results[]' "${LOG_PATH_MODULE}""/zarn_""${lNAME}"".sarif")

    if ! [[ -d "${LOG_PATH_MODULE}"/pl_source_files/ ]]; then
      mkdir "${LOG_PATH_MODULE}"/pl_source_files/ || true
    fi

    write_log "[+] Found ""${ORANGE}""${lVULNS}"" possible issue(s)""${GREEN}"" in perl script ""${lCOMMON_FILES_FOUND}"":""${ORANGE}"" ""$(print_path "${lPL_SCRIPT}")" "${lPL_LOG_LINKED}"
    write_link "${LOG_PATH_MODULE}"/pl_source_files/"${lNAME}".txt "${lPL_LOG_LINKED}"
    write_log "$(indent "$(orange "$(file "${lPL_SCRIPT}")")")" "${lPL_LOG_LINKED}"
    write_log "\n" "${lPL_LOG_LINKED}"

    for lSARIF_RESULT in "${lZARN_SARIF_RESULTS_ARR[@]}"; do
      lZARN_VULN_TITLE=$(echo "${lSARIF_RESULT}" | jq -rc '.properties.title' || true)
      lZARN_VULN_MESSAGE=$(echo "${lSARIF_RESULT}" | jq -rc '.message.text' || true)
      lZARN_VULN_LINE=$(echo "${lSARIF_RESULT}" | jq -rc '.locations[].physicalLocation.region.startLine' || true)

      write_csv_log "$(print_path "${lPL_SCRIPT}")" "${lVULNS}" "${lCFF}" "${lZARN_VULN_TITLE}" "${lZARN_VULN_LINE}" "${lZARN_VULN_MESSAGE}"
      write_log "$(indent "$(indent "Vulnerability title: ${ORANGE}${lZARN_VULN_TITLE}${NC}")")" "${lPL_LOG_LINKED}"
      write_log "$(indent "$(indent "Vulnerability description: ${ORANGE}${lZARN_VULN_MESSAGE}${NC}")")" "${lPL_LOG_LINKED}"
      write_log "" "${lPL_LOG_LINKED}"

      # we need the original perl script to link to it and to highlight the affected lines of code
      if ! [[ -f "${LOG_PATH_MODULE}"/pl_source_files/"${lNAME}".txt ]]; then
        cp "${lPL_SCRIPT}" "${LOG_PATH_MODULE}"/pl_source_files/"${lNAME}".txt || print_error "[-] Copy of ${lPL_SCRIPT} to log directory failed"
      fi

      lCODE_LINE="$(strip_color_codes "$(sed -n "${lZARN_VULN_LINE}"p "${LOG_PATH_MODULE}/pl_source_files/${lNAME}.txt" 2>/dev/null)")"
      sed -i -r "${lZARN_VULN_LINE}s/.*/\x1b[32m&\x1b[0m/" "${LOG_PATH_MODULE}/pl_source_files/${lNAME}.txt" || true
      write_log "$(indent "$(indent "${GREEN}${lZARN_VULN_LINE}${NC} - ${ORANGE}${lCODE_LINE}${NC}")")" "${lPL_LOG_LINKED}"
      write_log "\\n-----------------------------------------------------------------\\n" "${lPL_LOG_LINKED}"
    done

    # writing gpt details:
    if [[ "${GPT_OPTION}" -gt 0 ]]; then
      lGPT_ANCHOR="$(openssl rand -hex 8)"
      if [[ -f "${BASE_LINUX_FILES}" ]]; then
        # if we have the base linux config file we are checking it:
        if ! grep -E -q "^$(basename "${lPL_SCRIPT}")$" "${BASE_LINUX_FILES}" 2>/dev/null; then
          lGPT_PRIO=$((lGPT_PRIO+1))
        fi
      fi
      # "${GPT_INPUT_FILE_}" "${GPT_ANCHOR_}" "${GPT_PRIO_}" "${GPT_QUESTION_}" "${GPT_OUTPUT_FILE_}" "cost=$GPT_TOKENS_" "${GPT_RESPONSE_}"
      write_csv_gpt_tmp "$(cut_path "${lPL_SCRIPT}")" "${lGPT_ANCHOR}" "${lGPT_PRIO}" "${GPT_QUESTION}" "${lPL_LOG}" "" ""
      # add ChatGPT link to output file
      printf '%s\n\n' "" >> "${lPL_LOG}"
      write_anchor_gpt "${lGPT_ANCHOR}" "${lPL_LOG}"
    fi
    echo "${lVULNS}" >> "${TMP_DIR}"/S27_VULNS.tmp
  fi
}

