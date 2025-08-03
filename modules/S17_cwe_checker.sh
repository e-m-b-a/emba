#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Chao Yang - firmianay

# Description:  Runs a Docker container with cwe-checker on Ghidra to check binary for
#               common bug classes such as vicious functions or integer overflows.
#               As the runtime is quite long, it needs to be activated separately via -c switch.
#               Currently this module only work in a non docker environment!

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

S17_cwe_checker()
{
  if [[ ${BINARY_EXTENDED} -eq 1 ]] ; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Check binaries for vulnerabilities with cwe-checker"
    pre_module_reporter "${FUNCNAME[0]}"
    local lCWE_CNT_=0
    local lTESTED_BINS=0

    if [[ "${FULL_TEST}" -ne 1 ]]; then
      # we need to wait in default mode for the results of S13 and S14
      module_wait "S13_weak_func_check"
      module_wait "S14_weak_func_radare_check"
    fi

    cwe_check

    if [[ -f "${TMP_DIR}"/CWE_CNT.tmp ]]; then
      lCWE_CNT_=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/CWE_CNT.tmp || true)
      lTESTED_BINS=$(grep -c "cwe-checker found.*different security issues in" "${LOG_FILE}" || true)
    fi

    final_cwe_log "${lCWE_CNT_}" "${lTESTED_BINS}"

    write_log ""
    write_log "[*] Statistics:${lCWE_CNT_}:${lTESTED_BINS}"
    module_end_log "${FUNCNAME[0]}" "${lCWE_CNT_}"
  else
    print_output "[!] Check with cwe-checker is disabled!"
    print_output "[!] Enable it with the -c switch."
  fi
}

cwe_check() {
  local lBINARY=""
  local lBIN_TO_CHECK=""
  local lWAIT_PIDS_S17=()
  local lNAME=""
  local lBINS_CHECKED_ARR=()

  local lBINARIES_ARR=()
  if [[ "$(wc -l 2>/dev/null < "${S13_CSV_LOG}")" -gt 1 ]] || [[ "$(wc -l 2>/dev/null < "${S14_CSV_LOG}")" -gt 1 ]] || [[ "$(wc -l 2>/dev/null < "${S15_CSV_LOG}")" -gt 1 ]]; then
    # usually binaries with strcpy or system calls are more interesting for further analysis
    # to keep analysis time low we only check these bins
    mapfile -t lBINARIES_ARR < <(grep -h "strcpy\|system" "${S13_CSV_LOG}" "${S14_CSV_LOG}" "${S15_CSV_LOG}" 2>/dev/null | sort -k 3 -t ';' -n -r | awk '{print $1}' || true)
    # we usually get a path like /sbin/httpd which is not resolvable and needs to queried again in the P99_CSV_LOG later on
  else
    mapfile -t lBINARIES_ARR < <(grep -v "ASCII text\|Unicode text" "${P99_CSV_LOG}" | grep "ELF" | cut -d ';' -f2 || true)
  fi

  for lBIN_TO_CHECK in "${lBINARIES_ARR[@]}"; do
    if [[ -f "${BASE_LINUX_FILES}" ]]; then
      # if we have the base linux config file we only test non known Linux binaries
      # with this we do not waste too much time on open source Linux stuff
      lNAME=$(basename "${lBIN_TO_CHECK}")
      if grep -E -q "^${lNAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        continue
      fi
    fi

    # do not try to analyze kernel modules:
    [[ "${lBIN_TO_CHECK}" == *".ko" ]] && continue
    lBIN_TO_CHECK="${lBIN_TO_CHECK#\.}"
    if ! [[ -f "${lBIN_TO_CHECK}" ]]; then
      lBIN_TO_CHECK=$(grep "$(escape_echo "${lBIN_TO_CHECK}")" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u | head -1 || true)
    fi
    if ! [[ -f "${lBIN_TO_CHECK}" ]]; then
      continue
    fi
    local lBIN_MD5=""
    lBIN_MD5="$(md5sum "${lBIN_TO_CHECK}" | awk '{print $1}')"
    if [[ "${lBINS_CHECKED_ARR[*]}" == *"${lBIN_MD5}"* ]]; then
      # print_output "[*] ${ORANGE}${lBIN_TO_CHECK}${NC} already tested with ghidra/semgrep" "no_log"
      continue
    fi
    lBINS_CHECKED_ARR+=( "${lBIN_MD5}" )

    # while s09 is running we throttle this module:
    local lMAX_MOD_THREADS=$(("$(nproc || echo 1)" / 3))
    if [[ $(grep -i -c S09_ "${LOG_DIR}"/"${MAIN_LOG_FILE}" || true) -eq 1 ]]; then
      local lMAX_MOD_THREADS=1
    fi
    cwe_checker_threaded "${lBIN_TO_CHECK}" &
    local lTMP_PID="$!"
    lWAIT_PIDS_S17+=( "${lTMP_PID}" )
    max_pids_protection "${lMAX_MOD_THREADS}" lWAIT_PIDS_S17
    # we stop checking after the first MAX_EXT_CHECK_BINS binaries
    # usually these are non-linux binaries and ordered by the usage of system/strcpy legacy usages
    if [[ "${#lBINS_CHECKED_ARR[@]}" -ge "${MAX_EXT_CHECK_BINS}" ]] && [[ "${FULL_TEST}" -ne 1 ]]; then
      print_output "[*] ${MAX_EXT_CHECK_BINS} binaries already analysed - ending cwe_checker binary analysis now." "no_log"
      print_output "[*] For complete analysis enable FULL_TEST." "no_log"
      break
    fi
  done

  wait_for_pid "${lWAIT_PIDS_S17[@]}"
}

cwe_checker_threaded() {
  local lBINARY="${1:-}"
  local lCWE_OUT=()
  local lCWE_LINE=""
  local lCWE=""
  local lCWE_DESC=""
  local lCWE_CNT=""
  local lADDRESSES=""
  local lCWE_TOTAL_CNT=0
  local lMEM_LIMIT=$(( "${TOTAL_MEMORY}"/2 ))
  local lCWE_CHECKER_BARE_METAL_CFG=""
  local lCWE_CHECKER_OPTS_ARR=()

  local lNAME=""
  lNAME=$(basename "${lBINARY}")

  local lOLD_LOG_FILE="${LOG_FILE}"
  local LOG_FILE="${LOG_PATH_MODULE}""/cwe_check_""${lNAME}"".txt"
  lBINARY=$(readlink -f "${lBINARY}")

  if [[ $(grep -F "$(escape_echo "${lBINARY}")" "${P99_CSV_LOG}" | cut -d ';' -f8 | sort -u | head -1 || true) == *"Tricore"* ]]; then
    print_output "[*] Tricore processor detected - adjusting Ghidra parameters" "no_log"
    lCWE_CHECKER_BARE_METAL_CFG="${CONFIG_DIR}/cwe_checker_tricore.json"
    lCWE_CHECKER_OPTS_ARR+=("--bare-metal-config" "${lCWE_CHECKER_BARE_METAL_CFG}")
  fi

  ulimit -Sv "${lMEM_LIMIT}"
  timeout --preserve-status --signal SIGINT 60m cwe_checker "${lBINARY}" --json --out "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log "${lCWE_CHECKER_OPTS_ARR[@]}" || true
  ulimit -Sv unlimited
  print_output "[*] Tested ${ORANGE}""$(print_path "${lBINARY}")""${NC}" "no_log"

  if [[ -s "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log ]]; then
    jq -r '.[] | "\(.name) - \(.description)"' "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log | sort -u || true
    # get the total number of vulnerabilities in hte binary
    lCWE_TOTAL_CNT=$(jq -r '.[] | "\(.name) \(.description)"' "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log | wc -l || true)
    mapfile -t lCWE_OUT < <( jq -r '.[] | "\(.name) \(.description)"' "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log | cut -d\) -f1 | tr -d '(' | sort -u || true)
    # this is the logging after every tested file
    if [[ ${#lCWE_OUT[@]} -ne 0 ]] ; then
      print_ln

      # check for known linux files
      if [[ -f "${BASE_LINUX_FILES}" ]]; then
        # if we have the base linux config file we are checking it:
        if grep -E -q "^${lNAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
          # shellcheck disable=SC2153
          print_output "[+] cwe-checker found a total of ${ORANGE}${lCWE_TOTAL_CNT:-0}${GREEN} and ${ORANGE}${#lCWE_OUT[@]}${GREEN} different security issues in ${ORANGE}${lNAME}${GREEN} (${CYAN}common linux file: yes${GREEN}):${NC}" "" "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log
        else
          print_output "[+] cwe-checker found a total of ${ORANGE}${lCWE_TOTAL_CNT:-0}${GREEN} and ${ORANGE}${#lCWE_OUT[@]}${GREEN} different security issues in ${ORANGE}${lNAME}${GREEN} (${RED}common linux file: no${GREEN}):${NC}" "" "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log
        fi
      else
        print_output "[+] cwe-checker found a total of ${ORANGE}${lCWE_TOTAL_CNT:-0}${GREEN} and ${ORANGE}${#lCWE_OUT[@]}${GREEN} different security issues in ${ORANGE}${lNAME}${GREEN}:${NC}" "" "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log
      fi

      for lCWE_LINE in "${lCWE_OUT[@]}"; do
        lCWE="$(echo "${lCWE_LINE}" | awk '{print $1}')"
        lCWE_DESC="$(echo "${lCWE_LINE}" | cut -d\  -f2-)"
        lCWE_CNT="$(grep -c "${lCWE}" "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log 2>/dev/null || true)"
        # get a list of all affected addresses:
        lADDRESSES="$(jq -cr '.[]? | select(.name=="'"${lCWE}"'") | .addresses' "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log | tr -d '\n' | sed 's/\]\[/,/g')"
        echo "${lCWE_CNT}" >> "${TMP_DIR}"/CWE_CNT.tmp
        print_output "$(indent "$(orange "${lCWE}""${GREEN}"" - ""${lCWE_DESC}"" - ""${ORANGE}""${lCWE_CNT}"" times.")")"
        write_csv_log "${lNAME}" "${lBINARY}" "${lCWE_TOTAL_CNT}" "${lCWE}" "${lCWE_CNT}" "${lADDRESSES}" "${lCWE_DESC}"
      done
    else
      print_output "[-] Nothing found in ""${ORANGE}""${lNAME}""${NC}" "no_log"
      rm "${LOG_PATH_MODULE}"/cwe_"${lNAME}".log
    fi
  fi

  if [[ -f "${LOG_FILE}" ]]; then
    cat "${LOG_FILE}" >> "${lOLD_LOG_FILE}"
    rm "${LOG_FILE}" 2> /dev/null
  fi
  LOG_FILE="${lOLD_LOG_FILE}"
}

final_cwe_log() {
  local lTOTAL_CWE_CNT="${1:-}"
  local lTESTED_BINS="${2:-}"
  local lCWE_OUT_ARR=()
  local lCWE_LINE=""
  local lCWE_ID=""
  local lCWE_DESC=""
  local lCWE_CNT=""
  local lCWE_LOGS_ARR=()

  if [[ -d "${LOG_PATH_MODULE}" ]]; then
    mapfile -t lCWE_LOGS_ARR < <(find "${LOG_PATH_MODULE}" -type f -name "cwe_*.log")
    if [[ "${#lCWE_LOGS_ARR[@]}" -gt 0 ]]; then
      mapfile -t lCWE_OUT_ARR < <( jq -r '.[] | "\(.name) \(.description)"' "${LOG_PATH_MODULE}"/cwe_*.log | cut -d\) -f1 | tr -d '('  | sort -u|| true)
      if [[ ${#lCWE_OUT_ARR[@]} -gt 0 ]] ; then
        sub_module_title "Results - CWE-checker binary analysis"
        print_output "[+] cwe-checker found a total of ""${ORANGE}""${lTOTAL_CWE_CNT}""${GREEN}"" of the following security issues in ${ORANGE}${lTESTED_BINS}${GREEN} tested binaries:"
        for lCWE_LINE in "${lCWE_OUT_ARR[@]}"; do
          lCWE_ID="$(echo "${lCWE_LINE}" | awk '{print $1}')"
          lCWE_DESC="$(echo "${lCWE_LINE}" | cut -d\  -f2-)"
          # do not change this to grep -c!
          # shellcheck disable=SC2126
          lCWE_CNT="$(grep "${lCWE_ID}" "${LOG_PATH_MODULE}"/cwe_*.log 2>/dev/null | wc -l || true)"
          print_output "$(indent "$(orange "${lCWE_ID}""${GREEN}"" - ""${lCWE_DESC}"" - ""${ORANGE}""${lCWE_CNT}"" times.")")"
        done
        print_bar
      fi
    fi
  fi
}

