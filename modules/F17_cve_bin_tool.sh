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

# Description:  Based on the generated SBOM this module extracts known vulnerabilities
#               via cve-bin-tool
# shellcheck disable=SC2153

F17_cve_bin_tool() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final vulnerability aggregator"

  pre_module_reporter "${FUNCNAME[0]}"

  export MSF_INSTALL_PATH="/usr/share/metasploit-framework"

  # our first approach is to use our beautiful SBOM and walk through it
  # if for any reasons (disabled F15 module) there is no SBOM we check for s08_package_mgmt_extractor.csv

  local lEMBA_SBOM_JSON="${SBOM_LOG_PATH%\/}/EMBA_cyclonedx_sbom.json"
  local lSBOM_ARR=()
  local lSBOM_ENTRY=""
  local lWAIT_PIDS_F17_ARR=()
  local lVEX_JSON_ENTRIES_ARR=()
  local lVEX_FILE_ID=0
  local lVEX_FILE=""
  local lNEG_LOG=0
  local MAX_MOD_THREADS=$((MAX_MOD_THREADS*2))

  mkdir "${LOG_PATH_MODULE}/json/" || true
  mkdir "${LOG_PATH_MODULE}/cve_sum/" || true
  mkdir "${LOG_PATH_MODULE}/exploit/" || true

  print_output "[*] Loading SBOM ..."
  # read each item in the JSON array to an item in the Bash array
  readarray -t lSBOM_ARR < <(jq --compact-output '.components[]' "${lEMBA_SBOM_JSON}" || print_error "[-] SBOM loading error - Vulnerability analysis not available")

  print_output "[*] Analyzing SBOM ..."

  for lSBOM_ENTRY in "${lSBOM_ARR[@]}"; do
    local lNEG_LOG=1
    local lBOM_REF=""
    local lORIG_SOURCE=""
    local lMIN_IDENTIFIER=()
    local lVENDOR=""
    local lPROD=""
    local lVERS=""

    # we need └─$ jq --raw-output '.components[].properties[]' ~/Downloads/EMBA_cyclonedx_sbom.json
    # {
    # "name": "EMBA:sbom:2:minimal_identifier",
    # "value": "::debconf-i18n:1.5.82"
    # }
    lBOM_REF=$(jq --raw-output '."bom-ref"' <<< "${lSBOM_ENTRY}")
    lORIG_SOURCE=$(jq --raw-output '.group' <<< "${lSBOM_ENTRY}")
    mapfile -t lMIN_IDENTIFIER < <(jq --raw-output '.properties[] | select(.name | test("minimal_identifier")) | .value' <<< "${lSBOM_ENTRY}" | tr -d "'\\\\" | tr ':' '\n')
    lVENDOR="${lMIN_IDENTIFIER[*]:1:1}"
    lPROD="${lMIN_IDENTIFIER[*]:2:1}"
    lVERS="${lMIN_IDENTIFIER[*]:3:1}"
    cve_bin_tool_threader "${lBOM_REF}" "${lVENDOR}" "${lPROD}" "${lVERS}" "${lORIG_SOURCE}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_F17_ARR+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_F17_ARR[@]}"
  done
  wait_for_pid "${lWAIT_PIDS_F17_ARR[@]}"

  print_output "[*] Generating final VEX vulnerability json ..."
  # now we need to build our full vex json
  mapfile -t lVEX_JSON_ENTRIES_ARR < <(find "${LOG_PATH_MODULE}/json/" -name "*.json")
  if [[ "${#lVEX_JSON_ENTRIES_ARR[@]}" -gt 0 ]]; then
    local lNEG_LOG=1
    echo "[" > "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"

    for lVEX_FILE_ID in "${!lVEX_JSON_ENTRIES_ARR[@]}"; do
      lVEX_FILE="${lVEX_JSON_ENTRIES_ARR["${lVEX_FILE_ID}"]}"
      if [[ -s "${lVEX_FILE}" ]]; then
        if (json_pp < "${lVEX_FILE}" &> /dev/null); then
          cat "${lVEX_FILE}" >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
        else
          print_output "[!] WARNING: SBOM component ${lVEX_FILE} failed to validate with json_pp"
          continue
        fi
      else
        print_output "[!] WARNING: SBOM component ${lVEX_FILE} failed to decode"
        continue
      fi
      if [[ $((lVEX_FILE_ID+1)) -lt "${#lVEX_JSON_ENTRIES_ARR[@]}" ]]; then
        echo -n "," >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
      fi
    done

    echo -n "]" >> "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json"
    tr -d '\n' < "${SBOM_LOG_PATH}/EMBA_sbom_vex_tmp.json" > "${SBOM_LOG_PATH}/EMBA_sbom_vex_only.json"
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

cve_bin_tool_threader() {
  local lBOM_REF="${1:-}"
  local lVENDOR="${2:-}"
  local lPROD="${3:-}"
  local lVERS="${4:-}"
  local lORIG_SOURCE="${5:-}"
  local lWAIT_PIDS_F17_ARR_2=()
  local lCVE_BIN_TOOL="/external/cve-bin-tool/cve_bin_tool/cli.py"
  write_log "product,vendor,version,bom-ref" "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv"
  write_log "${lPROD},${lVENDOR:-NOTDEFINED},${lVERS},${lBOM_REF}" "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv"
  print_output "[*] Testing ${lPROD},${lVENDOR:-NOTDEFINED},${lVERS},${lBOM_REF}"

  python3 "${lCVE_BIN_TOOL}" -i "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" --disable-version-check --disable-validation-check --no-0-cve-report --offline -f csv -o "${LOG_PATH_MODULE}/${lBOM_REF}_${lPROD}_${lVERS}" || print_error "[-] cve_bin_tool error for ${lBOM_REF}_${lPROD}_${lVERS}"
  # benchmark no metric:
  # real    398.48s
  # with metric
  # real    1363.45s
  # if [[ -f "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" ]]; then
  #   rm "${LOG_PATH_MODULE}/${lBOM_REF}.tmp.csv" || true
  # fi

  # walk through "${LOG_PATH_MODULE}/${lBOM_REF}_${lPROD}_${lVERS}".csv and check for exploits, EPSS and print as in F20
  if [[ -f "${LOG_PATH_MODULE}/${lBOM_REF}_${lPROD}_${lVERS}.csv" ]]; then
    while read -r lCVE_LINE; do
      tear_down_cve_threader "${lBOM_REF},${lORIG_SOURCE},${lCVE_LINE}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_F17_ARR_2+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_F17_ARR_2[@]}"
    done < <(tail -n +2 "${LOG_PATH_MODULE}/${lBOM_REF}_${lPROD}_${lVERS}.csv")
  fi
  wait_for_pid "${lWAIT_PIDS_F17_ARR_2[@]}"

  # lets start the final logging per component

  # now we have our nice formatted logs somewhere over here: "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
  # lets build the final log for every binary:
  local lBIN_LOG="${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPROD}_${lVERS}_finished.txt"
  write_log "[*] Vulnerability details for ${ORANGE}${lPROD}${NC} / version ${ORANGE}${lVERS}${NC} / source ${ORANGE}${lORIG_SOURCE}${NC}:" "${lBIN_LOG}"
  local lANCHOR=""
  lANCHOR="${lPROD}_${lVERS}"
  lANCHOR="cve_${lANCHOR:0:20}"
  write_anchor "${lANCHOR}" "${lBIN_LOG}"

  local lEXPLOIT_COUNTER_VERSION=0
  local lCVE_COUNTER_VERSION=0
  if [[ -f "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPROD}_${lVERS}.txt" ]]; then
    lEXPLOIT_COUNTER_VERSION=$(grep -c "Exploit (" "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPROD}_${lVERS}.txt" || true)
    lCVE_COUNTER_VERSION=$(grep -c -E "CVE-[0-9]+-[0-9]+" "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPROD}_${lVERS}.txt" || true)
  fi
  # Todo: Include verified vulnerabilties

  if [[ "${lEXPLOIT_COUNTER_VERSION}" -gt 0 ]]; then
    write_log "" "${lBIN_LOG}"
    # write detailed log
    cat "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPROD}_${lVERS}.txt" >> "${lBIN_LOG}"
    write_log "" "${lBIN_LOG}"
    write_log "[+] Found ${RED}${BOLD}${lCVE_COUNTER_VERSION}${GREEN} CVEs and ${RED}${BOLD}${lEXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${lPROD}${GREEN} with version ${ORANGE}${lVERS}${GREEN} (source ${ORANGE}${lORIG_SOURCE}${GREEN}).${NC}" "${lBIN_LOG}"

    # write summary log:
    printf "[${MAGENTA}+${NC}]${MAGENTA} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${lPROD}" "${lVERS}" "${lCVE_COUNTER_VERSION}" "${lEXPLOIT_COUNTER_VERSION}" "${lORIG_SOURCE}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
  elif [[ "${lCVE_COUNTER_VERSION}" -gt 0 ]]; then
    write_log "" "${lBIN_LOG}"
    cat "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPROD}_${lVERS}.txt" >> "${lBIN_LOG}"
    write_log "" "${lBIN_LOG}"
    write_log "[+] Found ${ORANGE}${BOLD}${lCVE_COUNTER_VERSION}${GREEN} CVEs in ${ORANGE}${lPROD}${GREEN} with version ${ORANGE}${lVERS}${GREEN} (source ${ORANGE}${lORIG_SOURCE}${GREEN}).${NC}" "${lBIN_LOG}"

    # write summary log:
    printf "[${ORANGE}+${NC}]${ORANGE} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${lPROD}" "${lVERS}" "${lCVE_COUNTER_VERSION}" "${lEXPLOIT_COUNTER_VERSION}" "${lORIG_SOURCE}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
  else
    write_log "[+] Found ${GREEN}${BOLD}${lCVE_COUNTER_VERSION:-0}${GREEN} CVEs in ${ORANGE}${lPROD}${GREEN} with version ${ORANGE}${lVERS}${GREEN} (source ${ORANGE}${lORIG_SOURCE}${GREEN}).${NC}" "${lBIN_LOG}"
    printf "[${GREEN}+${NC}]${GREEN} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${lPROD}" "${lVERS}" "${lCVE_COUNTER_VERSION:-0}" "${lEXPLOIT_COUNTER_VERSION:-0}" "${lORIG_SOURCE}" >> "${LOG_PATH_MODULE}"/vuln_summary.txt
  fi

  # we can now delete the temp log file
  if [[ -f "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPROD}_${lVERS}.txt" ]]; then
    rm "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lPROD}_${lVERS}.txt" || true
  fi

  # now, lets write the main f20 log file with the results of the current binary:
  if [[ -f "${lBIN_LOG}" ]]; then
    tee -a "${LOG_FILE}" < "${lBIN_LOG}"
  fi
  
}

tear_down_cve_threader() {
  local lCVE_LINE="${1:-}"
  local lCVE_DATA_ARR=()

  mapfile -t lCVE_DATA_ARR < <(echo "${lCVE_LINE}" | tr ',' '\n')
  # echo "lCVE_LINE: ${lCVE_LINE}"
  local lBOM_REF="${lCVE_DATA_ARR[*]:0:1}"
  local lORIG_SOURCE="${lCVE_DATA_ARR[*]:1:1}"
  # local lBIN_VENDOR="${lCVE_DATA_ARR[*]:2:1}"
  local lBIN_NAME="${lCVE_DATA_ARR[*]:3:1}"
  local lBIN_VERS="${lCVE_DATA_ARR[*]:4:1}"
  local lCVE_ID="${lCVE_DATA_ARR[*]:6:1}"
  local lCVSS_SEVERITY="${lCVE_DATA_ARR[*]:7:1}"
  local lCVSS_SCORE="${lCVE_DATA_ARR[*]:8:1}"
  local lCVSS_VERS="${lCVE_DATA_ARR[*]:10:1}"
  local lCVSS_VECTOR="${lCVE_DATA_ARR[*]:11:1}"

  # if we find a blacklist file we check if the current CVE value is in the blacklist
  # if we find it this CVE is not further processed
  if [[ -f "${CVE_BLACKLIST}" ]]; then
    if grep -q ^"${lCVE_ID}"$ "${CVE_BLACKLIST}"; then
      print_output "[*] ${ORANGE}${lCVE_ID}${NC} for ${ORANGE}${lBIN_NAME}${NC} blacklisted and ignored." "no_log"
      return
    fi
  fi
  # if we find a whitelist file we check if the current CVE value is in the whitelist
  # only if we find this CVE in the whitelist it is further processed
  if [[ -f "${CVE_WHITELIST}" ]]; then
    # do a quick check if there is some data in the whitelist config file
    if [[ $(grep -E -c "^CVE-[0-9]+-[0-9]+$" "${CVE_WHITELIST}") -gt 0 ]]; then
      if ! grep -q ^"${lCVE_ID}"$ "${CVE_WHITELIST}"; then
        print_output "[*] ${ORANGE}${lCVE_ID}${NC} for ${ORANGE}${lBIN_NAME}${NC} not in whitelist -> ignored." "no_log"
        return
      fi
    fi
  fi

  # we get "EPSS;percentage" back
  local lFIRST_EPSS=""
  lFIRST_EPSS=$(get_epss_data "${lCVE_ID}")
  # local lFIRST_PERC="${lFIRST_EPSS/*\;}"
  lFIRST_EPSS="${lFIRST_EPSS/\;*}"

  # default value
  local lEXPLOIT="No exploit available"
  local lKNOWN_EXPLOITED=0
  local lKERNEL_VERIFIED_VULN=0
  local lKERNEL_VERIFIED="no"
  local lBUSYBOX_VERIFIED="no"
  local lEDB=0
  local lKERNEL_CVE_EXPLOIT=""

  local lEXPLOIT_AVAIL_EDB_ARR=()
  local lEXPLOIT_AVAIL_MSF_ARR=()
  local lEXPLOIT_MSF=""
  local lEXPLOIT_PATH=""
  local lEXPLOIT_NAME=""
  local lEXPLOIT_AVAIL_PACKETSTORM_ARR=()
  local lEXPLOIT_AVAIL_SNYK_ARR=()
  local lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR=()
  local lVEX_EXPLOIT_PROP_ARRAY_ARR=()
  local lEID_VALUE=""
  local lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR=()
  local lEXPLOIT_IDS_ARR=()
  local lEXPLOIT_ID=""
  local lLOCAL=0
  local lREMOTE=0
  local lDOS=0
  local lEXPLOIT_ENTRY=""
  local lE_FILE=""
  local lEXPLOIT_SNYK=""
  local lEXPLOIT_PS=""
  local lEXPLOIT_RS=""
  local lPS_TYPE=""

  # remote/local vulnerability
  local lTYPE="NA"
  if [[ "${lCVSS_VECTOR}" == *"AV:L"* ]]; then
    lTYPE="L"
  elif [[ "${lCVSS_VECTOR}" == *"AV:N"* ]]; then
    lTYPE="R"
  fi

  # check if the CVE is known as a knwon exploited vulnerability:
  if grep -q "^${lCVE_ID}," "${KNOWN_EXP_CSV}"; then
    write_log "[+] ${ORANGE}WARNING:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a known exploited vulnerability.${NC}" "${LOG_PATH_MODULE}/KEV.txt"

    if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
      lEXPLOIT="Exploit (KEV"
    else
      lEXPLOIT+=" / KEV"
    fi
    if [[ "${lTYPE}" != "NA" ]]; then
      lEXPLOIT+=" (${lTYPE})"
    fi
    lKNOWN_EXPLOITED=1
    lEDB=1
  fi

  if [[ "${lBIN_NAME}" == *kernel* ]]; then
    for lKERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS_ARR[@]}"; do
      lKERNEL_CVE_EXPLOIT=$(echo "${lKERNEL_CVE_EXPLOIT}" | cut -d\; -f3)
      if [[ "${lKERNEL_CVE_EXPLOIT}" == "${lCVE_ID}" ]]; then
        lEXPLOIT="Exploit (linux-exploit-suggester"
        if [[ "${lTYPE}" != "NA" ]]; then
          lEXPLOIT+=" (${lTYPE})"
        fi
        write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};kernel exploit" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
        lEDB=1
      fi
    done

    if [[ -f "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv ]]; then
      # check if the current CVE is a verified kernel CVE from s26 module
      if grep -q ";${lCVE_ID};.*;.*;1;1" "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols and kernel configuration${GREEN})!" "no_log"
        ((lKERNEL_VERIFIED_VULN+=1))
        lKERNEL_VERIFIED="yes"
      fi
      if grep -q ";${lCVE_ID};.*;.*;1;0" "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols${GREEN})!" "no_log"
        ((lKERNEL_VERIFIED_VULN+=1))
        lKERNEL_VERIFIED="yes"
      fi
      if grep -q ";${lCVE_ID};.*;.*;0;1" "${S26_LOG_DIR}"/cve_results_kernel_"${lBIN_VERS}".csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel configuration${GREEN})!" "no_log"
        ((lKERNEL_VERIFIED_VULN+=1))
        lKERNEL_VERIFIED="yes"
      fi
    fi
  fi

  if [[ -f "${CSV_DIR}"/s118_busybox_verifier.csv ]] && [[ "${lBIN_NAME}" == *"busybox"* ]]; then
    if grep -q ";${lCVE_ID};" "${CSV_DIR}"/s118_busybox_verifier.csv; then
      print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_ID}${GREEN} is a verified BusyBox vulnerability (${ORANGE}BusyBox applet${GREEN})!" "no_log"
      lBUSYBOX_VERIFIED="yes"
    fi
  fi

  mapfile -t lEXPLOIT_AVAIL_EDB_ARR < <(cve_searchsploit "${lCVE_ID}" 2>/dev/null || true)
  mapfile -t lEXPLOIT_AVAIL_MSF_ARR < <(grep -E "${lCVE_ID}"$ "${MSF_DB_PATH}" 2>/dev/null || true)
  mapfile -t lEXPLOIT_AVAIL_PACKETSTORM_ARR < <(grep -E "^${lCVE_ID}\;" "${CONFIG_DIR}"/PS_PoC_results.csv 2>/dev/null || true)
  mapfile -t lEXPLOIT_AVAIL_SNYK_ARR < <(grep -E "^${lCVE_ID}\;" "${CONFIG_DIR}"/Snyk_PoC_results.csv 2>/dev/null || true)
  mapfile -t lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR < <(grep -E "${lCVE_ID}"$ "${CONFIG_DIR}/routersploit_cve-db.txt" 2>/dev/null || true)

  # now, we check the exploit-db results if we have a routersploit module:
  if [[ " ${lEXPLOIT_AVAIL_EDB_ARR[*]} " =~ "Exploit DB Id:" ]]; then
    for lEID_VALUE in "${EXPLOIT_AVAIL_EDB_ARR[@]}"; do
      if ! echo "${lEID_VALUE}" | grep -q "Exploit DB Id:"; then
        continue
      fi
      lEID_VALUE=$(echo "${lEID_VALUE}" | grep "Exploit DB Id:" | cut -d: -f2)
      mapfile -t lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR < <(grep "${lEID_VALUE}" "${CONFIG_DIR}/routersploit_exploit-db.txt" 2>/dev/null || true)
    done

    readarray -t lEXPLOIT_IDS_ARR < <(echo "${lEXPLOIT_AVAIL_EDB_ARR[@]}" | grep "Exploit DB Id:" | cut -d ":" -f 2 | sed 's/[^0-9]*//g' | sed 's/\ //' | sort -u)
    if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
      lEXPLOIT="Exploit (EDB ID:"
    else
      lEXPLOIT+=" / EDB ID:"
    fi

    for lEXPLOIT_ID in "${lEXPLOIT_IDS_ARR[@]}" ; do
      lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:EDB:${lEXPLOIT_ID}" )
      lEXPLOIT+=" ${lEXPLOIT_ID}"
      write_log "[+] Exploit for ${lCVE_ID}:\\n" "${LOG_PATH_MODULE}""/exploit/""${lEXPLOIT_ID}"".txt"
      write_log "[+] EDB Exploit for ${lCVE_ID} identified"  "${LOG_PATH_MODULE}/exploit/EDB_${lEXPLOIT_ID}_notes.txt"
      write_log "${lEXPLOIT_AVAIL_EDB_ARR[*]/\ /\\n}" "${LOG_PATH_MODULE}/exploit/edb_${lEXPLOIT_ID}_notes.txt"
      # write_log "${lLINE}" "${LOG_PATH_MODULE}""/exploit/""${lEXPLOIT_ID}"".txt"
      if [[ "${lEXPLOIT_AVAIL_EDB_ARR[*]}" =~ "Type: local" && "${lLOCAL:-0}" -eq 0 ]]; then
        lEXPLOIT+=" (L)"
        lLOCAL=1
      fi
      if [[ "${lEXPLOIT_AVAIL_EDB_ARR[*]}" =~ "Type: remote" && "${lREMOTE:-0}" -eq 0 ]]; then
        lEXPLOIT+=" (R)"
        lREMOTE=1
      fi
      if [[ "${lEXPLOIT_AVAIL_EDB_ARR[*]}" =~ "Type: dos" && "${lDOS:-0}" -eq 0 ]]; then
        lEXPLOIT+=" (D)"
        lDOS=1
      fi
      lEDB=1
      write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};exploit_db" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
    done

    # copy the exploit-db exploits to the report
    for lEXPLOIT_ENTRY in "${lEXPLOIT_AVAIL_EDB_ARR[@]}"; do
      if [[ "${lEXPLOIT_ENTRY}" =~ "File:" ]]; then
        lE_FILE=$(echo "${lEXPLOIT_ENTRY}" | awk '{print $2}')
        if [[ -f "${lE_FILE}" ]] ; then
          cp "${lE_FILE}" "${LOG_PATH_MODULE}""/exploit/edb_""$(basename "${lE_FILE}")"
        fi
      fi
    done
  fi

  if [[ ${#lEXPLOIT_AVAIL_MSF_ARR[@]} -gt 0 ]]; then
    if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
      lEXPLOIT="Exploit (MSF:"
    else
      lEXPLOIT+=" / MSF:"
    fi

    for lEXPLOIT_MSF in "${lEXPLOIT_AVAIL_MSF_ARR[@]}" ; do
      if ! [[ -d "${MSF_INSTALL_PATH}" ]]; then
        lEXPLOIT_PATH=$(echo "${lEXPLOIT_MSF}" | cut -d: -f1)
      else
        lEXPLOIT_PATH="${MSF_INSTALL_PATH}"$(echo "${lEXPLOIT_MSF}" | cut -d: -f1)
      fi
      lEXPLOIT_NAME=$(basename -s .rb "${lEXPLOIT_PATH}")
      lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:MSF:${lEXPLOIT_NAME}" )
      lEXPLOIT+=" ${lEXPLOIT_NAME}"
      if [[ -f "${lEXPLOIT_PATH}" ]] ; then
        # for the web reporter we copy the original metasploit module into the EMBA log directory
        cp "${lEXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/msf_""${lEXPLOIT_NAME}".rb
        if grep -q "< Msf::Exploit::Remote" "${lEXPLOIT_PATH}"; then
          lEXPLOIT+=" (R)"
        fi
        if grep -q "< Msf::Exploit::Local" "${lEXPLOIT_PATH}"; then
          lEXPLOIT+=" (L)"
        fi
        if grep -q "include Msf::Auxiliary::Dos" "${lEXPLOIT_PATH}"; then
          lEXPLOIT+=" (D)"
        fi
      fi
    done

    if [[ ${lEDB} -eq 0 ]]; then
      # only count the msf exploit if we have not already count an other exploit
      # otherwise we count an exploit for one CVE multiple times
      write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};MSF" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
      lEDB=1
    fi
  fi

  if [[ ${#lEXPLOIT_AVAIL_SNYK_ARR[@]} -gt 0 ]]; then
    if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
      lEXPLOIT="Exploit (Snyk:"
    else
      lEXPLOIT+=" / Snyk:"
    fi

    for lEXPLOIT_SNYK in "${lEXPLOIT_AVAIL_SNYK_ARR[@]}" ; do
      lEXPLOIT_NAME=$(echo "${lEXPLOIT_SNYK}" | cut -d\; -f2)
      lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:SNYK:${lEXPLOIT_NAME}" )
      lEXPLOIT+=" ${lEXPLOIT_NAME}"
      if [[ "${lTYPE}" != "NA" ]]; then
        lEXPLOIT+=" (${lTYPE})"
      fi
    done

    if [[ ${lEDB} -eq 0 ]]; then
      # only count the snyk exploit if we have not already count an other exploit
      # otherwise we count an exploit for one CVE multiple times
      write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};SNYK" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
      lEDB=1
    fi
  fi

  if [[ ${#lEXPLOIT_AVAIL_PACKETSTORM_ARR[@]} -gt 0 ]]; then
    if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
      lEXPLOIT="Exploit (PS:"
    else
      lEXPLOIT+=" / PS:"
    fi

    for lEXPLOIT_PS in "${lEXPLOIT_AVAIL_PACKETSTORM_ARR[@]}" ; do
      # we use the html file as lEXPLOIT_NAME.
      lEXPLOIT_NAME=$(echo "${lEXPLOIT_PS}" | cut -d\; -f3 | rev | cut -d '/' -f1-2 | rev)
      lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:PS:${lEXPLOIT_NAME}" )
      lEXPLOIT+=" ${lEXPLOIT_NAME}"
      lPS_TYPE=$(grep "^${lCVE_ID};" "${CONFIG_DIR}"/PS_PoC_results.csv | grep "${lEXPLOIT_NAME}" | cut -d\; -f4 || true)
      if [[ "${lPS_TYPE}" == "remote" ]]; then
        lPS_TYPE="R"
      elif [[ "${lPS_TYPE}" == "local" ]]; then
        lPS_TYPE="L"
      elif [[ "${lPS_TYPE}" == "DoS" ]]; then
        lPS_TYPE="D"
      else
        # fallback to CVSS type
        if [[ "${lTYPE}" != "NA" ]]; then
          lPS_TYPE="${lTYPE}"
        fi
      fi
      lEXPLOIT+=" (${lPS_TYPE})"
    done

    if [[ ${lEDB} -eq 0 ]]; then
      # only count the packetstorm exploit if we have not already count an other exploit
      # otherwise we count an exploit for one CVE multiple times
      write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};PS" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
      lEDB=1
    fi
  fi

  if [[ "${#lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR[@]}" -gt 0 || "${#lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR[@]}" -gt 0 ]]; then
    if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
      lEXPLOIT="Exploit (Routersploit:"
    else
      lEXPLOIT+=" / Routersploit:"
    fi
    local lEXPLOIT_ROUTERSPLOIT_ARR=("${lEXPLOIT_AVAIL_ROUTERSPLOIT_ARR[@]}" "${lEXPLOIT_AVAIL_ROUTERSPLOIT1_ARR[@]}")

    for lEXPLOIT_RS in "${lEXPLOIT_ROUTERSPLOIT_ARR[@]}" ; do
      lEXPLOIT_PATH=$(echo "${lEXPLOIT_RS}" | cut -d: -f1)
      lEXPLOIT_NAME=$(basename -s .py "${lEXPLOIT_PATH}")
      lVEX_EXPLOIT_PROP_ARRAY_ARR+=( "exploit:RS:${lEXPLOIT_NAME}" )
      lEXPLOIT+=" ${lEXPLOIT_NAME}"
      if [[ -f "${lEXPLOIT_PATH}" ]] ; then
        # for the web reporter we copy the original metasploit module into the EMBA log directory
        cp "${lEXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/routersploit_""${lEXPLOIT_NAME}".py
        if grep -q Port "${lEXPLOIT_PATH}"; then
          lEXPLOIT+=" (R)"
        else
          # fallback to CVSS type
          if [[ "${lTYPE}" != "NA" ]]; then
            lEXPLOIT+=" (${lTYPE})"
          fi
        fi
      fi
    done

    if [[ ${lEDB} -eq 0 ]]; then
      # only count the routersploit exploit if we have not already count an other exploit
      # otherwise we count an exploit for one CVE multiple times
      write_log "${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lCVSS_SEVERITY};RS" "${LOG_PATH_MODULE}"/exploit_cnt.tmp
      lEDB=1
    fi
  fi

  if [[ ${lEDB} -eq 1 ]]; then
    lEXPLOIT+=")"
  fi

  # if this CVE is a kernel verified CVE we add a V to the CVE
  if [[ "${lKERNEL_VERIFIED}" == "yes" ]]; then lCVE_ID+=" (V)"; fi
  if [[ "${lBUSYBOX_VERIFIED}" == "yes" ]]; then lCVE_ID+=" (V)"; fi

  lCVE_ID_VERS="${lCVE_ID} (v${lCVSS_VERS})"

  # we do not deal with output formatting the usual way -> we use printf
  if [[ ! -f "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt" ]]; then
    printf "${GREEN}\t%-20.20s:   %-12.12s:   %-18.18s:  %-10.10s : %-4.4s :   %-15.15s:   %s${NC}\n" "BIN NAME" "BIN VERS" "CVE ID" "CVSS VALUE" "EPSS" "SOURCE" "EXPLOIT" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
  fi
  if [[ "${lCVSS_SEVERITY}" == "HIGH" || "${lCVSS_SEVERITY}" == "CRITICAL" ]]; then
    # put a note in the output if we have switched to CVSSv2
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID_VERS}" "${lCVSS_SCORE}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    else
      printf "${RED}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID_VERS}" "${lCVSS_SCORE}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  elif [[ "${lCVSS_SEVERITY}" == "MEDIUM" ]]; then
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID_VERS}" "${lCVSS_SCORE}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    else
      printf "${ORANGE}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID_VERS}" "${lCVSS_SCORE}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  else
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *PS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID_VERS}" "${lCVSS_SCORE}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    else
      printf "${GREEN}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_NAME}" "${lBIN_VERS}" "${lCVE_ID_VERS}" "${lCVSS_SCORE}" "${lFIRST_EPSS}" "${lORIG_SOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}/cve_sum/${lBOM_REF}_${lBIN_NAME}_${lBIN_VERS}.txt"
    fi
  fi

  # generate the vulnerability details for the SBOM (VEX)

  # external/nvd-json-data-feeds/CVE-2022/CVE-2022-25xx/CVE-2022-2586.json
  mapfile -t lCWE < <(grep -o -E "CWE-[0-9]+" "${NVD_DIR}/${lCVE_ID%-*}/${lCVE_ID:0:11}"*"xx/${lCVE_ID}.json" 2>/dev/null | sort -u || true)
  lCVE_DESC=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${lCVE_ID%-*}/${lCVE_ID:0:11}"*"xx/${lCVE_ID}.json" 2>/dev/null || true)

  lVULN_BOM_REF=$(uuidgen)
  build_sbom_json_properties_arr "${lVEX_EXPLOIT_PROP_ARRAY_ARR[@]}"
  # => we get PROPERTIES_JSON_ARR as global

  jo -p -n -- \
    bom-ref="${lVULN_BOM_REF}" \
    id="${lCVE_ID}" \
    source="$(jo -a "$(jo -n name="NVD" url="https://nvd.nist.gov/vuln/detail/${lCVE_ID}")")" \
    ratings="$(jo -a "$(jo -n score="${lCVSS_SCORE}" severity="${lCVSS_SEVERITY}" method="${lCVSS_VERS}" vector="${lCVSS_VECTOR}")")" \
    cwes="$(jo -a "${lCWE[@]:-null}")" \
    analysis="$(jo -a "$(jo -n state="not_verified")")" \
    description="${lCVE_DESC}" \
    affects="$(jo -a "$(jo -n ref="${lBOM_REF}" versions="$(jo -n component="${lPROD}" version="${lVERS}")")")" \
    properties="$(jo -a "${PROPERTIES_JSON_ARR[@]:-null}")" \
    > "${LOG_PATH_MODULE}/json/${lVULN_BOM_REF}_${lPROD}_${lVERS}.json"
  
  write_log "EXPLOIT entry: ${lBIN_NAME};${lBIN_VERS};${lCVE_ID};${lEXPLOIT}" "${LOG_PATH_MODULE}/exploit_notes.txt"
}

get_kernel_s25_data() {
  export KERNEL_CVE_EXPLOITS_ARR=()

  if [[ -f "${S25_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S25_LOG}")."
    readarray -t KERNEL_CVE_EXPLOITS_ARR < <(cut -d\; -f1-3 "${S25_LOG}" | tail -n +2 | sort -u || true)
    # we get something like this: ":linux:linux_kernel;5.10.59;CVE-2021-3490"
  fi
}

get_epss_data() {
  local lCVE_ID="${1:-}"
  local lCVE_EPSS_PATH=""
  local lEPSS_PERC=""
  local lEPSS_EPSS=""
  local lEPSS_DATA=""
  local lCVE_YEAR=""

  lCVE_YEAR="$(echo "${lCVE_ID}" | cut -d '-' -f2)"
  lCVE_EPSS_PATH="${EPSS_DATA_PATH}/CVE_${lCVE_YEAR}_EPSS.csv"
  if [[ -f "${lCVE_EPSS_PATH}" ]]; then
    lEPSS_DATA=$(grep "^${lCVE_ID};" "${lCVE_EPSS_PATH}" || true)
    lEPSS_PERC=$(echo "${lEPSS_DATA}" | cut -d ';' -f3)
    lEPSS_PERC=$(echo "${lEPSS_PERC} 100" | awk '{printf "%d", $1 * $2}')
    # just cut it for now ...
    lEPSS_EPSS=$(echo "${lEPSS_DATA}" | cut -d ';' -f2)
    lEPSS_EPSS=$(echo "${lEPSS_EPSS} 100" | awk '{printf "%d", $1 * $2}')
  fi
  [[ ! "${lEPSS_EPSS}" =~ ^[0-9]+$ ]] && lEPSS_EPSS="NA"
  [[ ! "${lEPSS_PERC}" =~ ^[0-9]+$ ]] && lEPSS_PERC="NA"
  echo "${lEPSS_EPSS};${lEPSS_PERC}"
}



