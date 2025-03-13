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

# Description:  This module is using Ghidra to generate decompiled code from the firmware binaries.
#               This module uses the ghidra script Haruspex.java (https://github.com/0xdea/ghidra-scripts)
#               The generated source code is further analysed with semgrep and the rules provided by 0xdea
#               (https://github.com/0xdea/semgrep-rules)

S16_ghidra_decompile_checks()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check decompiled binary source code for vulnerabilities"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ ${BINARY_EXTENDED} -ne 1 ]] ; then
    print_output "[-] ${FUNCNAME[0]} - BINARY_EXTENDED not set to 1. You can set it up via a scan-profile."
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  if ! [[ -d "${EXT_DIR}"/ghidra_scripts ]]; then
    print_output "[-] ${FUNCNAME[0]} - missing ghidra_scripts dependencies, no ${EXT_DIR}/ghidra_scripts"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local lBIN_TO_CHECK=""
  local lTMP_PID=""
  local lVULN_COUNTER=0
  local lWAIT_PIDS_S16_ARR=()
  local lNAME=""
  local lBINS_CHECKED_ARR=()

  if [[ "${FULL_TEST}" -ne 1 ]]; then
    # we need to wait in default mode for the results of S13 and S14
    module_wait "S13_weak_func_check"
    module_wait "S14_weak_func_radare_check"
  fi

  local lBINARIES_ARR=()
  if [[ -f "${S13_CSV_LOG}" ]] || [[ -f "${S14_CSV_LOG}" ]]; then
    # usually binaries with strcpy or system calls are more interesting for further analysis
    # to keep analysis time low we only check these bins
    mapfile -t lBINARIES_ARR < <(grep -h "strcpy\|system" "${S13_CSV_LOG}" "${S14_CSV_LOG}" 2>/dev/null | sort -k 3 -t ';' -n -r | awk '{print $1}' || true)
  else
    mapfile -t lBINARIES_ARR < <(grep -v "ASCII text\|Unicode text" "${P99_CSV_LOG}" | grep ";ELF" | cut -d ';' -f1 || true)
  fi

  for lBIN_TO_CHECK in "${lBINARIES_ARR[@]}"; do
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      # if we have the base linux config file we only test non known Linux binaries
      # with this we do not waste too much time on open source Linux stuff
      lNAME=$(basename "${lBIN_TO_CHECK}" 2> /dev/null)
      if grep -E -q "^${lNAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        continue
      fi
    fi

    # from s13 and s14 we get a path like ./path/to/file
    # let's remove the ^.
    lBIN_TO_CHECK="${lBIN_TO_CHECK#\.}"

    if ! [[ -f "${lBIN_TO_CHECK}" ]]; then
      lBIN_TO_CHECK=$(grep "$(escape_echo "${lBIN_TO_CHECK}")" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u | head -1 || true)
    fi
    if ! [[ -f "${lBIN_TO_CHECK}" ]]; then
      continue
    fi
    # ensure we have not tested this binary entry
    local lBIN_MD5=""
    lBIN_MD5="$(md5sum "${lBIN_TO_CHECK}" | awk '{print $1}')"
    if [[ "${lBINS_CHECKED_ARR[*]}" == *"${lBIN_MD5}"* ]]; then
      # print_output "[*] ${ORANGE}${lBIN_TO_CHECK}${NC} already tested with ghidra/semgrep" "no_log"
      continue
    fi
    # print_output "[*] Testing ${lBIN_TO_CHECK} with ghidra/semgrep"
    lBINS_CHECKED_ARR+=( "${lBIN_MD5}" )
    if [[ "${THREADED}" -eq 1 ]]; then
      ghidra_analyzer "${lBIN_TO_CHECK}" &
      lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_S16_ARR+=( "${lTMP_PID}" )
      max_pids_protection "$(("${MAX_MOD_THREADS}"/3))" lWAIT_PIDS_S16_ARR
    else
      ghidra_analyzer "${lBIN_TO_CHECK}"
    fi

    # we stop checking after the first MAX_EXT_CHECK_BINS binaries
    if [[ "${#lBINS_CHECKED_ARR[@]}" -gt "${MAX_EXT_CHECK_BINS}" ]] && [[ "${FULL_TEST}" -ne 1 ]]; then
      print_output "[*] ${MAX_EXT_CHECK_BINS} binaries already analysed - ending Ghidra binary analysis now." "no_log"
      print_output "[*] For complete analysis enable FULL_TEST." "no_log"
      break
    fi
  done < <(grep -v "ASCII text\|Unicode text" "${P99_CSV_LOG}" | grep "ELF" || true)

  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S16_ARR[@]}"

  # cleanup - remove the rest without issues now
  rm -r /tmp/haruspex_* 2>/dev/null || true

  if [[ "$(find "${LOG_PATH_MODULE}" -name "semgrep_*.csv" | wc -l)" -gt 0 ]]; then
    # can't use grep -c here as it counts on file base and we need the number of semgrep-rules
    # shellcheck disable=SC2126
    lVULN_COUNTER=$(wc -l "${LOG_PATH_MODULE}"/semgrep_*.csv | tail -n1 | awk '{print $1}' || true)
  fi
  if [[ "${lVULN_COUNTER}" -gt 0 ]]; then
    print_ln
    sub_module_title "Results - Ghidra decompiled code analysis via Semgrep"
    print_output "[+] Found ""${ORANGE}""${lVULN_COUNTER}""${GREEN}"" possible vulnerabilities (${ORANGE}via semgrep on Ghidra decompiled code${GREEN}) in ""${ORANGE}""${#lBINS_CHECKED_ARR[@]}""${GREEN}"" tested binaries:""${NC}"
    local lVULN_CAT_CNT=0
    local lVULN_CATS_ARR=()
    local lVULN_CATEGORY=""
    mapfile -t lVULN_CATS_ARR < <(grep -h -o "external.semgrep-rules-0xdea.c.raptor-[a-zA-Z0-9_\-]*" "${LOG_PATH_MODULE}"/semgrep_*.csv | sort -u)
    for lVULN_CATEGORY in "${lVULN_CATS_ARR[@]}"; do
      lVULN_CAT_CNT=$(grep -h -o "${lVULN_CATEGORY}" "${LOG_PATH_MODULE}"/semgrep_*.csv | wc -l)
      local lVULN_CATEGORY_STRIPPED=${lVULN_CATEGORY//external.semgrep-rules-0xdea.c.raptor-/}
      print_output "$(indent "${GREEN}${lVULN_CATEGORY_STRIPPED}${ORANGE} - ${lVULN_CAT_CNT} times.${NC}")"
    done
    print_bar
  fi

  write_log "[*] Statistics:${lVULN_COUNTER}:${#lBINS_CHECKED_ARR[@]}"
  module_end_log "${FUNCNAME[0]}" "${lVULN_COUNTER}"
}

ghidra_analyzer() {
  local lBINARY="${1:-}"
  local lNAME=""
  local lGPT_PRIO_=2
  local lS16_SEMGREP_ISSUES=0
  local lHARUSPEX_FILE_ARR=()
  local lWAIT_PIDS_S16_1=()
  # just in case Ghidra hangs on a binary
  local lGHIDRA_TIMEOUT=7200

  if ! [[ -f "${lBINARY}" ]]; then
    return
  fi

  lNAME=$(basename "${lBINARY}" 2> /dev/null)

  if [[ -d "/tmp/haruspex_${lNAME}" ]]; then
    print_output "[-] WARNING: Temporary directory already exists for binary ${ORANGE}${lNAME}${NC} - skipping analysis" "no_log"
    return
  fi

  print_output "[*] Extracting decompiled code from binary ${ORANGE}${lNAME} / ${lBINARY}${NC} with Ghidra" "no_log"
  local lIDENTIFIER="${RANDOM}"

  timeout --preserve-status --signal SIGINT "${lGHIDRA_TIMEOUT}" "${GHIDRA_PATH}"/support/analyzeHeadless "${LOG_PATH_MODULE}" "ghidra_${lNAME}_${lIDENTIFIER}" -import "${lBINARY}" -log "${LOG_PATH_MODULE}"/ghidra_"${lNAME}"_"${lIDENTIFIER}".txt -scriptPath "${EXT_DIR}"/ghidra_scripts -postScript Haruspex || print_error "[-] Error detected while Ghidra Headless run for ${lNAME}"

  # Ghidra cleanup:
  if [[ -d "${LOG_PATH_MODULE}"/"ghidra_${lNAME}_${lIDENTIFIER}.rep" ]]; then
    rm -r "${LOG_PATH_MODULE}"/"ghidra_${lNAME}_${lIDENTIFIER}.rep" || print_error "[-] Error detected while removing Ghidra log file ghidra_${lNAME}.rep"
  fi
  if [[ -f "${LOG_PATH_MODULE}"/"ghidra_${lNAME}_${lIDENTIFIER}.gpr" ]]; then
    rm -r "${LOG_PATH_MODULE}"/"ghidra_${lNAME}_${lIDENTIFIER}.gpr" || print_error "[-] Error detected while removing Ghidra log file ghidra_${lNAME}.rep"
  fi

  # if Ghidra was not able to produce code we can return now:
  if ! [[ -d /tmp/haruspex_"${lNAME}" ]]; then
    print_output "[-] No Ghidra decompiled code for further analysis of binary ${ORANGE}${lNAME}${NC} available ..." "no_log"
    return
  fi

  print_output "[*] Semgrep analysis on decompiled code from binary ${ORANGE}${lNAME}${NC}" "no_log"
  local lSEMGREPLOG="${LOG_PATH_MODULE}"/semgrep_"${lNAME}".json
  local lSEMGREPLOG_CSV="${lSEMGREPLOG/\.json/\.csv}"
  local lSEMGREPLOG_TXT="${lSEMGREPLOG/\.json/\.log}"
  if [[ -f "${lSEMGREPLOG}" ]]; then
    local lSEMGREPLOG="${LOG_PATH_MODULE}"/semgrep_"${lNAME}"_"${RANDOM}".json
  fi

  if [[ -f "${S12_LOG}" ]]; then
    # we start the log file with the binary protection mechanisms
    # FUNC_LOG is currently global for log_bin_hardening from modules/S13_weak_func_check.sh -> todo as parameter
    export FUNC_LOG="${lSEMGREPLOG_TXT}"
    write_log "\\n" "${lSEMGREPLOG_TXT}"
    log_bin_hardening "${lBINARY}" "${lSEMGREPLOG_TXT}"
    write_log "\\n-----------------------------------------------------------------\\n" "${lSEMGREPLOG_TXT}"
  fi

  # cleanup filenames
  local lFPATH_ARR=()
  mapfile -t lFPATH_ARR < <(find /tmp/haruspex_"${lNAME}" -type f)
  local lFNAME=""
  for FPATH in "${lFPATH_ARR[@]}"; do
    lFNAME=$(basename "${FPATH}")
    if ! [[ -f /tmp/haruspex_"${lNAME}"/"${lFNAME//[^A-Za-z0-9._-]/_}" ]]; then
      mv "${FPATH}" /tmp/haruspex_"${lNAME}"/"${lFNAME//[^A-Za-z0-9._-]/_}" || true
    fi
  done

  semgrep --disable-version-check --metrics=off --severity ERROR --severity WARNING --json --config "${EXT_DIR}"/semgrep-rules-0xdea /tmp/haruspex_"${lNAME}"/* >> "${lSEMGREPLOG}" || print_error "[-] Semgrep error detected on testing ${lNAME}"

  # check if there are more details in our log (not only the header with the binary protections)
  if [[ "$(wc -l "${lSEMGREPLOG}" | awk '{print $1}' 2>/dev/null)" -gt 0 ]]; then
    jq  -rc '.results[] | "\(.path),\(.check_id),\(.end.line),\(.extra.message)"' "${lSEMGREPLOG}" >> "${lSEMGREPLOG_CSV}" || true
    lS16_SEMGREP_ISSUES=$(wc -l "${lSEMGREPLOG_CSV}" | awk '{print $1}' || true)

    if [[ "${lS16_SEMGREP_ISSUES}" -gt 0 ]]; then
      print_output "[+] Found ""${ORANGE}""${lS16_SEMGREP_ISSUES}"" issues""${GREEN}"" in native binary ""${ORANGE}""${lNAME}""${NC}" "" "${lSEMGREPLOG_TXT}"
      # highlight security findings in the main semgrep log:
      # sed -i -r "s/.*external\.semgrep-rules-0xdea.*/\x1b[32m&\x1b[0m/" "${lSEMGREPLOG}"
      lGPT_PRIO_=$((lGPT_PRIO_+1))
      # Todo: highlight the identified code areas in the decompiled code
    else
      print_output "[-] No C/C++ issues found for binary ${ORANGE}${lNAME}${NC}" "no_log"
      rm "${lSEMGREPLOG}" || print_error "[-] Error detected while removing ${lSEMGREPLOG}"
      return
    fi
  else
    rm "${lSEMGREPLOG}" || print_error "[-] Error detected while removing ${lSEMGREPLOG}"
    return
  fi

  # write the logs
  if [[ -d /tmp/haruspex_"${lNAME}" ]] && [[ -f "${lSEMGREPLOG}" ]]; then
    mapfile -t lHARUSPEX_FILE_ARR < <(find /tmp/haruspex_"${lNAME}" -type f || true)
    # we only store decompiled code with issues:
    if ! [[ -d "${LOG_PATH_MODULE}"/haruspex_"${lNAME}" ]]; then
      mkdir "${LOG_PATH_MODULE}"/haruspex_"${lNAME}" || print_error "[-] Error detected while creating ${LOG_PATH_MODULE}/haruspex_${lNAME}"
    fi
    for lHARUSPEX_FILE in "${lHARUSPEX_FILE_ARR[@]}"; do
      if [[ ${THREADED} -eq 1 ]]; then
        # threading is currently not working because of mangled output
        # we need to rewrite the logging functionality in here to provide threading
        s16_semgrep_logger "${lHARUSPEX_FILE}" "${lNAME}" "${lSEMGREPLOG}" "${lGPT_PRIO_}" &
        local lTMP_PID="$!"
        lWAIT_PIDS_S16_1+=( "${lTMP_PID}" )
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S16_1
      else
        s16_semgrep_logger "${lHARUSPEX_FILE}" "${lNAME}" "${lSEMGREPLOG}" "${lGPT_PRIO_}"
      fi
    done

    if [[ ${THREADED} -eq 1 ]]; then
      wait_for_pid "${lWAIT_PIDS_S16_1[@]}"
      s16_finish_the_log "${lSEMGREPLOG}" "${lNAME}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_S16_ARR+=( "${lTMP_PID}" )
    else
      s16_finish_the_log "${lSEMGREPLOG}" "${lNAME}"
    fi
  fi
}

# function is just for speeding up the process
s16_finish_the_log() {
  local lSEMGREPLOG="${1:-}"
  local lNAME="${2:-}"
  local lSEMGREPLOG_TXT="${lSEMGREPLOG/\.json/\.log}"
  local lTMP_FILE=""

  for lTMP_FILE in "${lSEMGREPLOG/\.json/}"_"${lNAME}"*.tmp; do
    if [[ -f "${lTMP_FILE}" ]]; then
      cat "${lTMP_FILE}" >> "${lSEMGREPLOG_TXT}" || print_error "[-] Error in logfile processing - ${lTMP_FILE}"
      rm "${lTMP_FILE}" || true
    fi
  done
}

s16_semgrep_logger() {
  local lHARUSPEX_FILE="${1:-}"
  local lNAME="${2:-}"
  local lSEMGREPLOG="${3:-}"
  local lGPT_PRIO="${4:-}"

  local lSEMGREPLOG_CSV="${lSEMGREPLOG/\.json/\.csv}"
  local lSEMGREPLOG_TXT="${lSEMGREPLOG/\.json/\.log}"
  local lGPT_ANCHOR=""
  local lCODE_LINE=""
  local lLINE_NR=""
  local lHARUSPEX_FILE_NAME=""

  lHARUSPEX_FILE_NAME="$(basename "${lHARUSPEX_FILE}")"
  local lSEMGREPLOG_TMP="${lSEMGREPLOG/\.json/}"_"${lNAME}"_"${lHARUSPEX_FILE_NAME}".tmp

  if [[ ! -f "${lSEMGREPLOG_CSV}" ]]; then
    return
  fi

  # we only handle decompiled code files with semgrep issues, otherwise we move to the next function
  # print_output "[*] Testing ${lHARUSPEX_FILE_NAME} against semgrep log ${lSEMGREPLOG}"
  if ! grep -q "${lHARUSPEX_FILE_NAME}" "${lSEMGREPLOG_CSV}"; then
    return
  fi
  if [[ -f "${lHARUSPEX_FILE}" ]]; then
    mv "${lHARUSPEX_FILE}" "${LOG_PATH_MODULE}"/haruspex_"${lNAME}" || print_error "[-] Error storing Ghidra decompiled code for ${lNAME} in log directory"
  fi
  # print_output "[*] moved ${lHARUSPEX_FILE} to ${LOG_PATH_MODULE}/haruspex_${lNAME}" "no_log"
  if [[ -f "${lSEMGREPLOG}" ]]; then
    # now we rebuild our logfile
    while IFS="," read -r lPATH lCHECK_ID lLINE_NR lMESSAGE; do
      if [[ "${lPATH}" != *"${lHARUSPEX_FILE_NAME}"* ]]; then
        continue
      fi
      write_log "[+] Identified source function: ${ORANGE}${LOG_PATH_MODULE}/haruspex_${lNAME}/${lHARUSPEX_FILE_NAME}${NC}" "${lSEMGREPLOG_TMP}"
      write_link "${LOG_PATH_MODULE}/haruspex_${lNAME}/${lHARUSPEX_FILE_NAME}" "${lSEMGREPLOG_TMP}"
      write_log "$(indent "$(indent "Semgrep rule: ${ORANGE}${lCHECK_ID}${NC}")")" "${lSEMGREPLOG_TMP}"
      write_log "$(indent "$(indent "Issue description:\\n${lMESSAGE}")")" "${lSEMGREPLOG_TMP}"
      write_log "" "${lSEMGREPLOG_TMP}"
      if [[ -f "${LOG_PATH_MODULE}/haruspex_${lNAME}/${lHARUSPEX_FILE_NAME}" ]]; then
        # extract the identified code line from the source code to show it in the overview page
        lCODE_LINE="$(strip_color_codes "$(sed -n "${lLINE_NR}"p "${LOG_PATH_MODULE}/haruspex_${lNAME}/${lHARUSPEX_FILE_NAME}" 2>/dev/null)")"
        shopt -s extglob
        lCODE_LINE="${lCODE_LINE##+([[:space:]])}"
        lCODE_LINE="$(echo -e "${lCODE_LINE}" | tr -d '\0')"
        shopt -u extglob
        # with a normal echo we automatically remove the null bytes which caused issues
        # shellcheck disable=SC2116
        lLINE_NR="$(echo "${lLINE_NR}")"
        # color the identified line in the source file:
        sed -i -r "${lLINE_NR}s/.*/\x1b[32m&\x1b[0m/" "${LOG_PATH_MODULE}/haruspex_${lNAME}/${lHARUSPEX_FILE_NAME}" || true
        # this is the output
        write_log "$(indent "$(indent "${GREEN}${lLINE_NR}${NC} - ${ORANGE}${lCODE_LINE}${NC}")")" "${lSEMGREPLOG_TMP}"

        # lBINARY;source function;semgrep rule;code line nr; code line
        write_csv_log "${lNAME}" "${lHARUSPEX_FILE_NAME}" "${lCHECK_ID}" "${lLINE_NR}" "${lCODE_LINE/\;}" "${lMESSAGE/\;}"
      fi
      write_log "\\n-----------------------------------------------------------------\\n" "${lSEMGREPLOG_TMP}"
    done < "${lSEMGREPLOG_CSV}"
  fi

  # GPT integration
  lGPT_ANCHOR="$(openssl rand -hex 8)"
  if [[ -f "${BASE_LINUX_FILES}" ]]; then
    # if we have the base linux config file we are checking it:
    if ! grep -E -q "^${lNAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
      lGPT_PRIO=$((lGPT_PRIO+1))
    fi
  fi
  write_csv_gpt_tmp "${LOG_PATH_MODULE}/haruspex_${lNAME}/${lHARUSPEX_FILE_NAME}" "${lGPT_ANCHOR}" "${lGPT_PRIO}" "${GPT_QUESTION}" "${LOG_PATH_MODULE}/haruspex_${lNAME}/${lHARUSPEX_FILE_NAME}" "" ""
  write_anchor_gpt "${lGPT_ANCHOR}" "${LOG_PATH_MODULE}"/haruspex_"${lNAME}"/"${lHARUSPEX_FILE_NAME}"

  cat "${lSEMGREPLOG_TMP}" >> "${lSEMGREPLOG_TXT}"
}
