#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2025-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Decompiles Java files
#               In the future it should also perform security analysis on the extracted sources
#               This module was inspired by the crass java checkers here:
#               https://github.com/floyd-fuh/crass/blob/master/java-decompile.sh

S28_java_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Decompiles Java files and performs security tests"
  pre_module_reporter "${FUNCNAME[0]}"

  local lS28_JAVA_SCRIPTS=0
  local lJAVA_BINS_ARR=()
  local lJAVA_BINARY=""
  local lJNAME=""
  local lJAVA_VULNS=0
  local lWAIT_PIDS_S28=()

  export JAVA_DECOMPILER="${EXT_DIR}/vineflower-1.11.2.jar"

  write_csv_log "Script path" "Java issues detected" "common linux file" "vuln title" "vuln line nr" "vuln note"
  mapfile -t lJAVA_BINS_ARR < <(grep "Java\ archive\|\.jar;\|\.war;\|\.java;\|\.class;" "${P99_CSV_LOG}" | sort -u || true)

  if [[ "${#lJAVA_BINS_ARR[@]}" -eq 0 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  for lJAVA_BINARY in "${lJAVA_BINS_ARR[@]}" ; do
    if [[ -f "${BASE_LINUX_FILES}" && "${FULL_TEST}" -eq 0 ]]; then
      # if we have the base linux config file we only test non known Linux binaries
      # with this we do not waste too much time on open source Linux stuff
      lJNAME=$(basename "$(echo "${lJAVA_BINARY}" | cut -d';' -f2)" 2> /dev/null)
      if grep -E -q "^${lJNAME}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
        continue
      fi
    fi
    ((lS28_JAVA_SCRIPTS+=1))
    s28_java_decompile "$(echo "${lJAVA_BINARY}" | cut -d';' -f2)" &
    local lTMP_PID="$!"
    lWAIT_PIDS_S28+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S28
  done

  wait_for_pid "${lWAIT_PIDS_S28[@]}"

  sub_module_title "Java security analysis"
  local lJAVA_BIN_DIR=""
  mapfile -t lSEMGREP_SOURCES_ARR < <(find "${LOG_PATH_MODULE}/java_decompile/" -mindepth 1 -maxdepth 1 -type d)
  for lJAVA_BIN_DIR in "${lSEMGREP_SOURCES_ARR[@]}"; do
    s28_java_semgrep "${lJAVA_BIN_DIR}" &
    local lTMP_PID="$!"
    lWAIT_PIDS_S28+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S28
  done

  wait_for_pid "${lWAIT_PIDS_S28[@]}"

  local lSEMGREP_RESULTS_ARR=()
  local lSEMGREP_RESULT=""
  mapfile -t lSEMGREP_RESULTS_ARR < <(find "${LOG_PATH_MODULE}/java_semgrep/" -name "semgrep_*.json")
  for lSEMGREP_RESULT in "${lSEMGREP_RESULTS_ARR[@]}"; do
    if grep -q '\"results\":\['{'"' "${lSEMGREP_RESULT}"; then
      print_output "[+] Semgrep security scanning results for $(basename "${lSEMGREP_RESULT}")" "" "${lSEMGREP_RESULT}"
      # todo: count vulns to lJAVA_VULNS
    fi
  done

  local lJAVA_DECOMPILED=0
  lJAVA_DECOMPILED=$(find "${LOG_PATH_MODULE}/java_decompile/" -type f | wc -l)

  write_log ""
  write_log "[*] Statistics:${#lJAVA_BINS_ARR[@]}:${lJAVA_DECOMPILED}:${lJAVA_VULNS}"
  module_end_log "${FUNCNAME[0]}" "${lJAVA_DECOMPILED}"
}

s28_java_semgrep() {
  local lJAVA_BIN_DIR="${1:-}"
  print_output "[*] Analysing ${ORANGE}${lJAVA_BIN_DIR}${NC} with semgrep" "no_log"

  local lJ_ANALYSE_DIR="${LOG_PATH_MODULE}/java_semgrep/"
  [[ ! -d "${lJ_ANALYSE_DIR}" ]] && mkdir -p "${lJ_ANALYSE_DIR}"
  lJNAME="$(basename "${lJAVA_BIN_DIR}" 2> /dev/null)"
  local lJ_ANALYSE_RESULTS="${lJ_ANALYSE_DIR}/semgrep_${lJNAME}.json"

  semgrep --disable-version-check --metrics=off --severity ERROR --severity WARNING --json --config "${EXT_DIR}"/semgrep-rules/java "${lJAVA_BIN_DIR}" > "${lJ_ANALYSE_RESULTS}" || true
  if [[ -f "${lJ_ANALYSE_RESULTS}" ]] && [[ "$(grep -c '\"results\":\['{'"' "${lJ_ANALYSE_RESULTS}")" -eq 0 ]]; then
    rm "${lJ_ANALYSE_RESULTS}" || true
  fi
}

s28_java_decompile() {
  local lJAVA_BINARY="${1:-}"
  local lJNAME=""

  lJNAME=$(basename "${lJAVA_BINARY}" 2> /dev/null | sed -e 's/:/_/g')
  print_output "[*] Decompiling Java binary ${ORANGE}${lJNAME}${NC}" "no_log"
  local lJ_DECOMPILE_DIR="${LOG_PATH_MODULE}/java_decompile/${lJNAME}_${RANDOM}"
  [[ ! -d "${lJ_DECOMPILE_DIR}" ]] && mkdir -p "${lJ_DECOMPILE_DIR}"

  java -jar "${JAVA_DECOMPILER}" --silent "${lJAVA_BINARY}" "${lJ_DECOMPILE_DIR}" || true
}

