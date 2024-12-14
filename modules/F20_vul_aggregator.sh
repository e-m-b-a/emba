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

# Description:  Aggregates all found version numbers together from S06, S08, S09, S25, S26,
#               S115/S116 and L15.
#               The versions are used for identification of known vulnerabilities cve-search,
#               finally it creates a list of exploits that are matching for the CVEs.
# shellcheck disable=SC2153

F20_vul_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final vulnerability aggregator"

  pre_module_reporter "${FUNCNAME[0]}"

  # we use this for later decisions:
  export F20_DEEP=1
  export WAIT_PIDS_F19=()

  prepare_cve_search_module

  local lFOUND_CVE=0
  local lS26_LOGS_ARR=()

  if [[ -d "${S26_LOG_DIR}" ]]; then
    mapfile -t lS26_LOGS_ARR < <(find "${S26_LOG_DIR}" -name "cve_results_kernel_*.csv")
  fi

  local lCVE_MINIMAL_LOG="${LOG_PATH_MODULE}"/CVE_minimal.txt
  local lEXPLOIT_OVERVIEW_LOG="${LOG_PATH_MODULE}"/exploits-overview.txt

  export KERNEL_CVE_VERIFIED=()
  export KERNEL_CVE_VERIFIED_VERSION=()

  if [[ -f "${CVE_WHITELIST}" ]] && [[ $(grep -c -E "CVE-[0-9]+-[0-9]+" "${CVE_WHITELIST}") -gt 0 ]]; then
    print_output "[!] WARNING: CVE whitelisting activated"
  fi
  if [[ -f "${CVE_BLACKLIST}" ]] && [[ $(grep -c -E "CVE-[0-9]+-[0-9]+" "${CVE_BLACKLIST}") -gt 0 ]]; then
    print_output "[!] WARNING: CVE blacklisting activated"
  fi

  if [[ -d ${NVD_DIR} ]]; then
    print_output "[*] Aggregate vulnerability details"

    # get the kernel version from s24 and s25:
    get_kernel_check "${S24_CSV_LOG}" "${S25_CSV_LOG}"
    # if we found a kernel in the kernel checker module we are going to use this kernel version (usually this version is better)
    # [+] Found Version details (base check): Linux kernel version 2.6.33
    # vs:
    # [+] Found Version details (kernel): Linux kernel version 2.6.33.2
    if [[ -v KERNEL_CVE_EXPLOITS_ARR[@] ]]; then
      if [[ ${#KERNEL_CVE_EXPLOITS_ARR[@]} -ne 0 ]]; then
        # then we have found a kernel in our s25 kernel module
        KERNELV=1
      fi
    fi

    if [[ -v lS26_LOGS_ARR ]]; then
      get_kernel_verified "${lS26_LOGS_ARR[@]}"
    fi

    get_sbom_package_details "${S08_CSV_LOG}"

    get_busybox_verified "${S118_CSV_LOG}"
    get_uefi_details "${S02_CSV_LOG}"
    get_systemmode_emulator "${L15_CSV_LOG}"
    get_systemmode_webchecks "${L25_CSV_LOG}"
    get_msf_verified "${L35_CSV_LOG}"

    aggregate_versions

    write_csv_log "BINARY" "VERSION" "CVE identifier" "CVSS rating" "exploit db exploit available" "metasploit module" "trickest PoC" "Routersploit" "Snyk PoC" "Packetstormsecurity PoC" "local exploit" "remote exploit" "DoS exploit" "known exploited vuln" "kernel vulnerability verified" "FIRST EPSS" "FIRST PERC"

    if [[ "${#VERSIONS_AGGREGATED_ARR[@]}" -gt 0 ]]; then
      generate_cve_details_versions "${VERSIONS_AGGREGATED_ARR[@]}"
    fi
    if [[ "${#CVES_AGGREGATED[@]}" -gt 0 ]]; then
      generate_cve_details_cves "${CVES_AGGREGATED[@]}"
    fi

    generate_special_log "${lCVE_MINIMAL_LOG}" "${lEXPLOIT_OVERVIEW_LOG}"
  else
    print_output "[-] WARNING: No CVE datasources found in external directory"
  fi

  lFOUND_CVE=$(sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "${LOG_FILE}" | grep -c -E "\[\+\]\ Found\ " || true)

  rm -rf "${LOG_PATH_MODULE}"/cpe_search_tmp_dir || true

  module_end_log "${FUNCNAME[0]}" "${lFOUND_CVE}"
}

prepare_cve_search_module() {
  # we need to setup different exports for F20
  export CVE_COUNTER=0
  export KERNELV=0
  export CVE_SEARCHSPLOIT=0
  export RS_SEARCH=0
  export MSF_SEARCH=0
  export CVE_SEARCHSPLOIT=0
  export MSF_INSTALL_PATH="/usr/share/metasploit-framework"
  export BUSYBOX_VERIFIED_CVE_ARR=()

  if command -v cve_searchsploit > /dev/null ; then
    export CVE_SEARCHSPLOIT=1
  fi
  if [[ -f "${MSF_DB_PATH}" ]]; then
    export MSF_SEARCH=1
  fi
  if [[ -f "${CONFIG_DIR}"/routersploit_cve-db.txt || -f "${CONFIG_DIR}"/routersploit_exploit-db.txt ]]; then
    export RS_SEARCH=1
  fi
  if [[ -f "${CONFIG_DIR}"/PS_PoC_results.csv ]]; then
    export PS_SEARCH=1
  fi
  if [[ -f "${CONFIG_DIR}"/Snyk_PoC_results.csv ]]; then
    export SNYK_SEARCH=1
  fi

  if ! [[ -d "${LOG_PATH_MODULE}""/exploit/" ]]; then
    mkdir -p "${LOG_PATH_MODULE}""/exploit/"
  fi
  if ! [[ -d "${LOG_PATH_MODULE}""/cve_sum/" ]]; then
    mkdir -p "${LOG_PATH_MODULE}""/cve_sum/"
  fi
}

aggregate_versions() {
  sub_module_title "Software inventory generation."

  local lVERSION=""
  export VERSIONS_AGGREGATED_ARR=()
  local lVERSIONS_KERNEL_ARR=()
  local lKERNELS_ARR=()
  local lCVE_ENTRY=""

  if [[ "${#KERNEL_CVE_EXPLOITS_ARR[@]}" -gt 0 || "${#VERSIONS_SYS_EMULATOR_ARR[@]}" -gt 0 || "${#VERSIONS_S08_PACKAGE_DETAILS_ARR[@]}" -gt 0 || \
    "${#VERSIONS_SYS_EMULATOR_WEB_ARR[@]}" -gt 0 || "${#CVE_S02_DETAILS_ARR[@]}" -gt 0 || "${#CVE_L35_DETAILS_ARR[@]}" -gt 0 || \
    "${#KERNEL_CVE_VERIFIED[@]}" -gt 0 || "${#BUSYBOX_VERIFIED_CVE_ARR[@]}" -gt 0 ]]; then

    print_output "[*] Software inventory initial overview:"
    write_anchor "softwareinventoryinitialoverview"
    for lVERSION in "${VERSIONS_S08_PACKAGE_DETAILS_ARR[@]}"; do
      if [ -z "${lVERSION}" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}main SBOM environment${GREEN}): ""${ORANGE}${lVERSION}${NC}"
    done

    for lVERSION in "${VERSIONS_SYS_EMULATOR_ARR[@]}"; do
      if [ -z "${lVERSION}" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}system emulator${GREEN}): ""${ORANGE}${lVERSION}${NC}"
    done
    for lVERSION in "${VERSIONS_SYS_EMULATOR_WEB_ARR[@]}"; do
      if [ -z "${lVERSION}" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}system emulator - web${GREEN}): ""${ORANGE}${lVERSION}${NC}"
    done

    for lVERSION in "${KERNEL_CVE_EXPLOITS_ARR[@]}"; do
      if [ -z "${lVERSION}" ]; then
        continue
      fi
      lVERSION="$(echo "${lVERSION}" | cut -d\; -f1-2 | tr ';' ':')"
      print_output "[+] Found Version details (${ORANGE}kernel${GREEN}): ""${ORANGE}${lVERSION}${NC}"
      # we ensure that we search for the correct kernel version by adding a : at the end of the search string
      # lVERSION=${lVERSION/%/:}
      if ! [[ "${lVERSIONS_KERNEL_ARR[*]}" == *"${lVERSION}"* ]]; then
        lVERSIONS_KERNEL_ARR+=( "${lVERSION}" )
      fi
      # print_output "[+] Added modfied Kernel Version details (${ORANGE}kernel$GREEN): ""$ORANGE$lVERSION$NC"
    done

    # details from module s26
    for lVERSION in "${KERNEL_CVE_VERIFIED_VERSION[@]}"; do
      if [ -z "${lVERSION}" ]; then
        continue
      fi
      lVERSION="$(echo "${lVERSION}" | cut -d\; -f1 | sed 's/^/:linux:linux_kernel:/')"
      print_output "[+] Found Version details (${ORANGE}kernel - with verified vulnerability details${GREEN}): ""${ORANGE}${lVERSION}${NC}"
      # we ensure that we search for the correct kernel version by adding a : at the end of the search string
      # lVERSION=${lVERSION/%/:}
      if ! [[ "${lVERSIONS_KERNEL_ARR[*]}" == *"${lVERSION}"* ]]; then
        lVERSIONS_KERNEL_ARR+=( "${lVERSION}" )
      fi
      # print_output "[+] Added modfied Kernel Version details (${ORANGE}kernel$GREEN): ""$ORANGE$lVERSION$NC"
    done

    for lCVE_ENTRY in "${CVE_S02_DETAILS_ARR[@]}"; do
      if [ -z "${lCVE_ENTRY}" ]; then
        continue
      fi
      if ! [[ "${lCVE_ENTRY}" == *CVE-[0-9]* ]]; then
        print_output "[-] WARNING: Broken CVE identifier found: ${ORANGE}${lCVE_ENTRY}${NC}"
        continue
      fi
      print_output "[+] Found CVE details (${ORANGE}binarly UEFI module${GREEN}): ""${ORANGE}${lCVE_ENTRY}${NC}"
    done

    for lCVE_ENTRY in "${CVE_L35_DETAILS_ARR[@]}"; do
      if [ -z "${lCVE_ENTRY}" ]; then
        continue
      fi
      if ! [[ "${lCVE_ENTRY}" == *CVE-[0-9]* ]]; then
        print_output "[-] WARNING: Broken CVE identifier found: ${ORANGE}${lCVE_ENTRY}${NC}"
        continue
      fi
      print_output "[+] Found CVE details (${ORANGE}verified Metasploit exploits${GREEN}): ""${ORANGE}${lCVE_ENTRY}${NC}"
    done

    local lBUSYBOX_VERIFIED_VERSION_ARR=()
    local lENTRY=""
    for lENTRY in "${BUSYBOX_VERIFIED_CVE_ARR[@]}"; do
      lCVE_ENTRY="${lENTRY/*\;/}"
      if [ -z "${lCVE_ENTRY}" ]; then
        continue
      fi
      if ! [[ "${lCVE_ENTRY}" == *CVE-[0-9]* ]]; then
        print_output "[-] WARNING: Broken CVE identifier found: ${ORANGE}${lCVE_ENTRY}${NC}"
        continue
      fi
      print_output "[+] Found CVE details (${ORANGE}verified BusyBox CVE${GREEN}): ""${ORANGE}${lCVE_ENTRY}${NC}"
      print_output "[+] Found version details (${ORANGE}verified BusyBox CVE${GREEN}): ""${ORANGE}${lENTRY/\;*/}${NC}"
      # we create a quick temp array for adding the details to the VERSIONS_AGGREGATED_ARR array
      lBUSYBOX_VERIFIED_VERSION_ARR+=( "${lENTRY/\;*/}" )
    done

    VERSIONS_AGGREGATED_ARR=( "${lVERSIONS_KERNEL_ARR[@]}" "${VERSIONS_SYS_EMULATOR_ARR[@]}" "${VERSIONS_S08_PACKAGE_DETAILS_ARR[@]}" "${VERSIONS_SYS_EMULATOR_WEB_ARR[@]}" "${lBUSYBOX_VERIFIED_VERSION_ARR[@]}")

    # if we get from a module CVE details we also need to handle them
    CVES_AGGREGATED=("${CVE_S02_DETAILS_ARR[@]}" "${CVE_L35_DETAILS_ARR[@]}")
  fi

  # sorting and unique our versions array:
  eval "CVES_AGGREGATED=($(for i in "${CVES_AGGREGATED[@]}" ; do echo "\"${i}\"" ; done | sort -u))"
  eval "VERSIONS_AGGREGATED_ARR=($(for i in "${VERSIONS_AGGREGATED_ARR[@]}" ; do echo "\"${i}\"" ; done | sort -u))"

  if [[ -v VERSIONS_AGGREGATED_ARR[@] ]]; then
    for lVERSION in "${VERSIONS_AGGREGATED_ARR[@]}"; do
      if [ -z "${lVERSION}" ]; then
        continue
      fi
      if [[ "${lVERSION}" == *" "* ]]; then
        print_output "[-] WARNING: Broken version identifier found (space): ${ORANGE}${lVERSION}${NC}"
        continue
      fi
      if ! [[ "${lVERSION}" == *[0-9]* ]]; then
        print_output "[-] WARNING: Broken version identifier found (no number): ${ORANGE}${lVERSION}${NC}"
        continue
      fi
      if ! [[ "${lVERSION}" == *":"* ]]; then
        print_output "[-] WARNING: Broken version identifier found (no :): ${ORANGE}${lVERSION}${NC}"
        continue
      fi
      write_log "${lVERSION}" "${LOG_PATH_MODULE}"/versions.tmp
    done
  fi

  if [[ -f "${LOG_PATH_MODULE}"/versions.tmp ]]; then
    # on old kernels it takes a huge amount of time to query all kernel CVE's. So, we move the kernel entry to the begin of our versions array
    mapfile -t lKERNELS_ARR < <(grep kernel "${LOG_PATH_MODULE}"/versions.tmp | sort -u || true)
    grep -v kernel "${LOG_PATH_MODULE}"/versions.tmp | sort -u > "${LOG_PATH_MODULE}"/versions1.tmp || true

    for KERNEL in "${lKERNELS_ARR[@]}"; do
      if [[ -f "${LOG_PATH_MODULE}"/versions1.tmp ]]; then
        if [[ $( wc -l "${LOG_PATH_MODULE}"/versions1.tmp | awk '{print $1}') -eq 0 ]] ; then
          echo "${KERNEL}" > "${LOG_PATH_MODULE}"/versions1.tmp
        else
          sed -i "1s/^/${KERNEL}\n/" "${LOG_PATH_MODULE}"/versions1.tmp
        fi
      fi
    done

    if [[ -f "${LOG_PATH_MODULE}"/versions1.tmp ]]; then
      mapfile -t VERSIONS_AGGREGATED_ARR < <(cat "${LOG_PATH_MODULE}"/versions1.tmp)
    fi
    rm "${LOG_PATH_MODULE}"/versions*.tmp 2>/dev/null

    # leave this here for debugging reasons
    if [[ ${#VERSIONS_AGGREGATED_ARR[@]} -ne 0 ]]; then
      print_bar ""
      print_output "[*] Software inventory aggregated:"
      for lVERSION in "${VERSIONS_AGGREGATED_ARR[@]}"; do
        # ensure our set anchor is based on the binary name and is limited to 20 characters:
        local lANCHOR=""
        lANCHOR=$(echo "${lVERSION}" | cut -d ':' -f3-4)
        lANCHOR="${lANCHOR//:/_}"
        lANCHOR="cve_${lANCHOR:0:20}"
        print_output "[+] Found Version details (${ORANGE}aggregated${GREEN}): ""${ORANGE}${lVERSION}${NC}"
        write_link "f20#${lANCHOR}"
      done
      for lCVE_ENTRY in "${CVES_AGGREGATED[@]}"; do
        print_output "[+] Found CVE details (${ORANGE}aggregated${GREEN}): ""${ORANGE}${lCVE_ENTRY}${NC}"
      done
      print_bar ""
    else
      print_output "[-] No Version details found."
    fi
  else
    print_output "[-] No Version details found."
  fi
}

generate_special_log() {
  local lCVE_MINIMAL_LOG="${1:-}"
  local lEXPLOIT_OVERVIEW_LOG="${2:-}"

  if [[ $(grep -c "Found.*CVEs\ .*and" "${LOG_FILE}" || true) -gt 0 ]]; then
    sub_module_title "Minimal report of exploits and CVE's."
    write_anchor "minimalreportofexploitsandcves"

    local lEXPLOIT_HIGH=0
    local lEXPLOIT_MEDIUM=0
    local lEXPLOIT_LOW=0
    local lKNOWN_EXPLOITED_VULNS_ARR=()
    local lKNOWN_EXPLOITED_VULN=""
    local lFILES_ARR=()
    local lFILE=""
    local lFILE_NAME=""
    local lCVE_VALUES_ARR=""
    local lEXPLOIT=""
    local lEXPLOITS_AVAIL_ARR=()

    readarray -t lFILES_ARR < <(find "${LOG_PATH_MODULE}"/ -maxdepth 1 -type f -name "*.txt")
    print_ln
    print_output "[*] CVE log file generated."
    write_link "${lCVE_MINIMAL_LOG}"
    print_ln

    for lFILE in "${lFILES_ARR[@]}"; do
      if [[ "${lFILE}" == *"F20_summary"* ]]; then
        continue
      fi
      if [[ "${lFILE}" == *"exploits-overview"* ]]; then
        continue
      fi
      local lCVE_OUTPUT=""
      lFILE_NAME=$(basename "${lFILE}" | sed -e 's/\.txt//g' | sed -e 's/_/\ /g')
      mapfile -t lCVE_VALUES_ARR < <(cut -d ":" -f1 "${lFILE}") # | paste -s -d ',' || true)
      # we need to check the whitelisted and blacklisted CVEs here:
      for lCVE_VALUE in "${lCVE_VALUES_ARR[@]}"; do
        if grep -q "^${lCVE_VALUE}$" "${CVE_BLACKLIST}"; then
          continue
        fi
        if [[ $(grep -E -c "^CVE-[0-9]+-[0-9]+$" "${CVE_WHITELIST}") -gt 0 ]]; then
          if ! grep -q ^"${lCVE_VALUE}"$ "${CVE_WHITELIST}"; then
            continue
          fi
        fi
        lCVE_OUTPUT="${lCVE_OUTPUT}"",""${lCVE_VALUE}"
      done
      if [[ "${lCVE_OUTPUT}" == *CVE-* ]]; then
        lCVE_OUTPUT=${lCVE_OUTPUT#,}
        print_output "[*] CVE details for ${GREEN}${lFILE_NAME}${NC}:\\n"
        print_output "${lCVE_OUTPUT}"
        write_log "\n[*] CVE details for ${GREEN}${lFILE_NAME}${NC}:" "${lCVE_MINIMAL_LOG}"
        write_log "${lCVE_OUTPUT}" "${lCVE_MINIMAL_LOG}"
        print_ln
      fi
    done

    write_log "\n[*] Exploit summary:" "${lEXPLOIT_OVERVIEW_LOG}"
    grep -E "Exploit\ \(" "${F20_LOG}" | sort -t : -k 4 -h -r | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >> "${lEXPLOIT_OVERVIEW_LOG}" || true

    mapfile -t lEXPLOITS_AVAIL_ARR < <(grep -E "Exploit\ \(" "${F20_LOG}" | sort -t : -k 4 -h -r || true)
    if [[ "${#lEXPLOITS_AVAIL_ARR[@]}" -gt 0 ]]; then
      print_ln
      print_output "[*] Minimal exploit summary file generated."
      write_link "${lEXPLOIT_OVERVIEW_LOG}"
      print_ln
    fi

    for lEXPLOIT in "${lEXPLOITS_AVAIL_ARR[@]}"; do
      # remove color codes:
      lEXPLOIT=$(echo "${lEXPLOIT}" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
      # extract CVSS value:
      lCVSS_VALUE=$(echo "${lEXPLOIT}" | sed -E 's/.*[[:blank:]]CVE-[0-9]{4}-[0-9]+[[:blank:]]//g' | cut -d: -f2 | sed -E 's/\ \(v2\)//g' | sed -e 's/[[:blank:]]//g' | tr -dc '[:print:]')

      if (( $(echo "${lCVSS_VALUE} > 6.9" | bc -l) )); then
        print_output "${RED}${lEXPLOIT}${NC}"
        ((lEXPLOIT_HIGH+=1))
      elif (( $(echo "${lCVSS_VALUE} > 3.9" | bc -l) )); then
        print_output "${ORANGE}${lEXPLOIT}${NC}"
        ((lEXPLOIT_MEDIUM+=1))
      else
        print_output "${GREEN}${lEXPLOIT}${NC}"
        ((lEXPLOIT_LOW+=1))
      fi
    done

    if [[ -f "${LOG_PATH_MODULE}"/exploit/known_exploited_vulns.log ]]; then
      mapfile -t lKNOWN_EXPLOITED_VULNS_ARR < <(grep -E "known exploited" "${LOG_PATH_MODULE}"/exploit/known_exploited_vulns.log || true 2>/dev/null)
      if [[ -v lKNOWN_EXPLOITED_VULNS_ARR[@] ]]; then
        print_ln
        print_output "[*] Summary of known exploited vulnerabilities:"
        write_link "${LOG_PATH_MODULE}/exploit/known_exploited_vulns.log"
        for lKNOWN_EXPLOITED_VULN in "${lKNOWN_EXPLOITED_VULNS_ARR[@]}"; do
          print_output "${lKNOWN_EXPLOITED_VULN}"
        done
        print_ln
      fi
    fi

    echo "${lEXPLOIT_HIGH}" > "${TMP_DIR}"/EXPLOIT_HIGH_COUNTER.tmp
    echo "${lEXPLOIT_MEDIUM}" > "${TMP_DIR}"/EXPLOIT_MEDIUM_COUNTER.tmp
    echo "${lEXPLOIT_LOW}" > "${TMP_DIR}"/EXPLOIT_LOW_COUNTER.tmp
    echo "${#lKNOWN_EXPLOITED_VULNS_ARR[@]}" > "${TMP_DIR}"/KNOWN_EXPLOITED_COUNTER.tmp
  fi
}

generate_cve_details_cves() {
  sub_module_title "CVE and exploit details."
  write_anchor "cveandexploitdetails"

  local lCVES_AGGREGATED_ARR=("$@")
  local lCVE_ENTRY=""
  CVE_COUNTER=0

  for lCVE_ENTRY in "${lCVES_AGGREGATED_ARR[@]}"; do
    if [[ "${THREADED}" -eq 1 ]]; then
      cve_db_lookup_cve "${lCVE_ENTRY}" &
      WAIT_PIDS_F19+=( "$!" )
      max_pids_protection "$(("${MAX_MOD_THREADS}"*2))" "${WAIT_PIDS_F19[@]}"
    else
      cve_db_lookup_cve "${lCVE_ENTRY}"
    fi
  done

  if [[ "${THREADED}" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_F19[@]}"
  fi
}

generate_cve_details_versions() {
  sub_module_title "Collect CVE and exploit details from versions."
  write_anchor "collectcveandexploitdetails"

  CVE_COUNTER=0
  local lVERSIONS_AGGREGATED_ARR=("$@")
  local lBIN_VERSION=""

  # need to wait for finishing the copy process from initial loading in get_sbom_package_details
  print_output "[*] Probably we need to wait a bit for pre-processing the NVD data ..." "no_log"
  wait_for_pid "${WAIT_PIDS_CVE_COPY_ARR[@]}"
  export NVD_DIR="${LOG_PATH_MODULE}"/cpe_search_tmp_dir
  print_output "[*] Moving on with CVE queries ..." "no_log"

  for lBIN_VERSION in "${lVERSIONS_AGGREGATED_ARR[@]}"; do
    # lBIN_VERSION is something like "binary:1.2.3"
    if [[ "${THREADED}" -eq 1 ]]; then
      cve_db_lookup_version "${lBIN_VERSION}" &
      WAIT_PIDS_F19+=( "$!" )
      max_pids_protection "$(("${MAX_MOD_THREADS}"*2))" "${WAIT_PIDS_F19[@]}"
    else
      cve_db_lookup_version "${lBIN_VERSION}"
    fi
  done

  if [[ "${THREADED}" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_F19[@]}"
  fi
}

cve_db_lookup_cve() {
  local lCVE_ENTRY="${1:-}"
  local lCVE_ID=""
  local lCVE_V2=""
  local lCVE_V31=""
  print_output "[*] CVE database lookup with CVE information: ${ORANGE}${lCVE_ENTRY}${NC}" "no_log"

  # there should be only one CVE file available
  CVE_SOURCE=$(find "${NVD_DIR}" -name "${lCVE_ENTRY}.json" | sort -u | head -1)
  if [[ -f "${CVE_SOURCE}" ]]; then
    lCVE_ID=$(jq -r '.id' "${CVE_SOURCE}")
    lCVE_V2=$(jq -r '.metrics.cvssMetricV2[]?.cvssData.baseScore' "${CVE_SOURCE}")
    # lCVE_V31=$(jq -r '.metrics.cvssMetricV31[]?.cvssData.baseScore' "${CVE_SOURCE}"
    lCVE_V31=$(jq -r '.metrics.cvssMetricV31[]? | select(.type=="Primary") | .cvssData.baseScore' "${CVE_SOURCE}")
    echo "${lCVE_ID}:${lCVE_V2:-"NA"}:${lCVE_V31:-"NA"}" > "${LOG_PATH_MODULE}"/"${lCVE_ENTRY}".txt || true
  fi

  # only do further analysis if needed
  # in case we come from s26 module we do not need all the upcoming analysis
  if [[ "${F20_DEEP}" == 1 ]]; then
    cve_extractor "${lCVE_ENTRY}"
  fi
}

cve_db_lookup_version() {
  # lBIN_VERSION needs to be in the format ":vendor:binary:1.2.3:" or "::binary:1.2.3:" or "::binary:1.2.3"
  # somthing like "binary:1.2.3" or ":binary:1.2.3" results in unexpected behavior

  # function writes log files to "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt
  local lBIN_VERSION="${1:-}"

  if [[ "$(echo "${lBIN_VERSION}" | tr ':' '\n' | wc -l)" -lt 4 ]]; then
    print_output "[-] WARNING: Identifier ${lBIN_VERSION} is probably incorrect and should be in the following format:" "no_log"
    print_output "[-] :vendor:binary:1.2.3: or ::binary:1.2.3: or ::binary:1.2.3" "no_log"
  fi

  local lCVE_ID=""
  local lBIN_NAME=""
  # lBIN_NAME=$(echo "${lBIN_VERSION%:}" | rev | cut -d':' -f2 | rev)
  lBIN_NAME=$(echo "${lBIN_VERSION%:}" | cut -d':' -f1-3)
  # we create something like "binary_1.2.3" for log paths
  # remove last : if it is there
  local lVERSION_PATH=""
  lVERSION_PATH=$(echo "${lBIN_VERSION%:}" | cut -d':' -f2-4)
  lVERSION_PATH="${lVERSION_PATH//\.\*}"
  lVERSION_PATH="${lVERSION_PATH%:}"
  lVERSION_PATH="${lVERSION_PATH#:}"
  lVERSION_PATH="${lVERSION_PATH//:/_}"
  local lWAIT_PIDS_F19_CVE_SOURCE_ARR=()
  local lCVE_VER_SOURCES_ARR=()
  local lCVE_VER_SOURCES_ARR_DLINK=()
  local lVERSION_SEARCHx=""
  local lCVE_VER_SOURCES_FILE=""

  # if we did the CVE analysis already in module s26 and s118, we can use these results for our further analysis
  # -> we skip the complete CVE analysis here:
  if [[ "${lBIN_NAME}" == *"linux_kernel"* ]] && [[ -s "${LOG_DIR}"/s26_kernel_vuln_verifier/"${lVERSION_PATH}".txt ]]; then
    print_output "[*] Detected kernel vulnerability details from module S26 - going to use these details"
    cp "${LOG_DIR}"/s26_kernel_vuln_verifier/"${lVERSION_PATH}".txt "${LOG_PATH_MODULE}" || (print_output "[-] S26 kernel vulns file found, but something was going wrong")
    cve_extractor "${lBIN_VERSION}"
    return
  fi
  if [[ "${lBIN_NAME}" == *"busybox"* ]] && [[ -s "${LOG_DIR}"/s118_busybox_verifier/"${lVERSION_PATH}".txt ]]; then
    print_output "[*] Detected busybox vulnerability details from module S118 - going to use these details"
    cp "${LOG_DIR}"/s118_busybox_verifier/"${lVERSION_PATH}".txt "${LOG_PATH_MODULE}" || (print_output "[-] S118 kernel vulns file found, but something was going wrong")
    cve_extractor "${lBIN_VERSION}"
    return
  fi

  # we test for the binary_name:version and for binary_name:*:
  print_output "[*] CVE database lookup with version information: ${ORANGE}${lBIN_VERSION}${NC}" "no_log"
  local lCPE_BIN_VERSION_SEARCH=${lBIN_VERSION%:}
  lCPE_BIN_VERSION_SEARCH=${lCPE_BIN_VERSION_SEARCH//::/:\.\*:}

  local lCPE_BIN_NAME_SEARCH=${lBIN_NAME%:}
  lCPE_BIN_NAME_SEARCH=${lCPE_BIN_NAME_SEARCH//::/:\.\*:}

  print_output "[*] Testing: cpe:${CPE_VERSION}:[aoh]${lCPE_BIN_VERSION_SEARCH}:.*:.*:.*:.*:.*:" "no_log"
  # "criteria": "cpe:2.3:a:busybox:busybox:1.14.1:*:*:*:*:*:*:*",

  # we are looking for cpe:2.3:[aoh]:BINARY_NAME:BINARY_VERSION:.* and for cpe:2.3:[aoh]:BINARY_NAME:*:.*
  # with this we are also able to further process just BINARY_NAME with further version details which are not in the cpe identifier
  print_output "[*] Testing against NVD dir ${NVD_DIR}" "no_log"
  mapfile -t lCVE_VER_SOURCES_ARR < <(grep -l -r -E -e "cpe:${CPE_VERSION}:[aoh]${lCPE_BIN_VERSION_SEARCH}:.*:.*:.*:.*:.*:" -e "cpe:${CPE_VERSION}:[aoh]${lCPE_BIN_NAME_SEARCH}:\*:.*:.*:.*:.*:.*:" "${NVD_DIR}" | sort -u || true)
  print_output "[*] CVE database lookup with version information: ${ORANGE}${lCPE_BIN_VERSION_SEARCH}${NC} resulted in ${ORANGE}${#lCVE_VER_SOURCES_ARR[@]}${NC} possible vulnerabilities" "no_log"
  print_output "[*] Testing: cpe:${CPE_VERSION}:[aoh]${lCPE_BIN_NAME_SEARCH}:\*:.*:.*:.*:.*:.*:" "no_log"

  print_output "[*] CVE database lookup with version information: ${ORANGE}${lCPE_BIN_VERSION_SEARCH} / ${lCPE_BIN_NAME_SEARCH}${NC} resulted in ${ORANGE}${#lCVE_VER_SOURCES_ARR[@]}${NC} possible vulnerabilities" "no_log"

  if [[ "${lBIN_VERSION}" == *"dlink"* ]]; then
    # dlink extrawurst: dlink vs d-link
    # do a second cve-database check
    lVERSION_SEARCHx="$(echo "${lBIN_VERSION}" | sed 's/dlink/d-link/' | sed 's/_firmware//')"
    print_output "[*] CVE database lookup with version information: ${ORANGE}${lVERSION_SEARCHx}${NC}" "no_log"
    mapfile -t lCVE_VER_SOURCES_ARR_DLINK < <(grep -l -r "cpe:${CPE_VERSION}:[aoh]:.*${lVERSION_SEARCHx}" "${NVD_DIR}" || true)
    lCVE_VER_SOURCES_ARR+=( "${lCVE_VER_SOURCES_ARR_DLINK[@]}" )
  fi

  for lCVE_VER_SOURCES_FILE in "${lCVE_VER_SOURCES_ARR[@]}"; do
    lCVE_ID=$(jq -r '.id' "${lCVE_VER_SOURCES_FILE}")
    if [[ "${THREADED}" -eq 1 ]]; then
      # analysis of cve json files in parallel
      check_cve_sources "${lCVE_ID}" "${lBIN_VERSION}" "${lCVE_VER_SOURCES_FILE}" &
      lWAIT_PIDS_F19_CVE_SOURCE_ARR+=( "$!" )
      max_pids_protection "$(("${MAX_MOD_THREADS}"*3))" "${lWAIT_PIDS_F19_CVE_SOURCE_ARR[@]}"
    else
      check_cve_sources "${lCVE_ID}" "${lBIN_VERSION}" "${lCVE_VER_SOURCES_FILE}"
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_F19_CVE_SOURCE_ARR[@]}"

  # only do further analysis if needed
  # in case we come from s26 module we do not need all the upcoming analysis
  if [[ "${F20_DEEP}" == 1 ]]; then
    cve_extractor "${lBIN_VERSION}"
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

# Test the identified JSON files for CPE details and version information
# to ensure our lBIN_VERSION is affected
check_cve_sources() {
  local lCVE_ID="${1:-}"
  local lBIN_VERSION="${2:-}"
  local lCVE_VER_SOURCES_FILE="${3:-}"

  local lFIRST_EPSS=""
  local lBIN_VERSION_ONLY=""
  # if we have a version identifier like ::binary:1.2.3: we need to remove the last ':' before processing it correctly
  lBIN_VERSION_ONLY=$(echo "${lBIN_VERSION%:}" | cut -d':' -f4-5)
  lBIN_VERSION_ONLY="${lBIN_VERSION_ONLY%:}"

  local lBIN_NAME=""
  lBIN_NAME=$(echo "${lBIN_VERSION%:}" | cut -d':' -f1-3)
  lBIN_NAME="${lBIN_NAME%:}"
  lBIN_NAME="${lBIN_NAME#:}"

  # ensure we replace :: with :.*: to use the lBIN_VERSION in our grep command
  lBIN_VERSION=${lBIN_VERSION//::/:\.\*:}
  # print_output "[*] Testing binary ${lBIN_NAME} with version ${lBIN_VERSION_ONLY} (${lBIN_VERSION}) for CVE matches in ${lCVE_VER_SOURCES_FILE}" "no_log"

  lCVE_V2=$(jq -r '.metrics.cvssMetricV2[]?.cvssData.baseScore' "${lCVE_VER_SOURCES_FILE}" | tr -dc '[:print:]')
  # lCVE_V31=$(jq -r '.metrics.cvssMetricV31[]?.cvssData.baseScore' "${lCVE_VER_SOURCES_FILE}" | tr -dc '[:print:]')
  lCVE_V31=$(jq -r '.metrics.cvssMetricV31[]? | select(.type=="Primary") | .cvssData.baseScore' "${lCVE_VER_SOURCES_FILE}" | tr -dc '[:print:]')
  lCVE_SUMMARY=$(escape_echo "$(jq -r '.descriptions[] | select(.lang=="en") | .value' "${lCVE_VER_SOURCES_FILE}")")
  # we need to check if any cpe of the CVE is vulnerable
  # └─$ cat external/nvd-json-data-feeds/CVE-2011/CVE-2011-24xx/CVE-2011-2416.json | jq '.configurations[].nodes[].cpeMatch[] | select(.vulnerable==true) | .criteria' | grep linux

  # check if our binary name is somewhere in the cpe identifier - if not we can drop this vulnerability:
  if [[ "$(jq -r '.configurations[].nodes[].cpeMatch[] | select(.vulnerable==true) | .criteria' "${lCVE_VER_SOURCES_FILE}" | grep -c "${lBIN_NAME//\.\*}")" -eq 0 ]]; then
    # print_output "[-] No matching criteria found - binary ${lBIN_NAME} not vulnerable for CVE ${lCVE_ID}" "no_log"
    return
  fi

  # we get "EPSS;percentage" back
  lFIRST_EPSS=$(get_epss_data "${lCVE_ID}")

  # if our cpe with the binary version matches we have a vuln and we can continue
  if grep -q "cpe:${CPE_VERSION}:.*${lBIN_VERSION%:}:" "${lCVE_VER_SOURCES_FILE}"; then
    # print_output "[+] CPE matches - vulnerability identified - CVE: ${lCVE_ID} / BIN: ${lBIN_VERSION}" "no_log"
    write_cve_log "${lCVE_ID}" "${lCVE_V2:-"NA"}" "${lCVE_V31:-"NA"}" "${lFIRST_EPSS}" "${lCVE_SUMMARY:-NA}" "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt &
    return
  fi

  # extract valid CPEs matching our cpe.*:binary:*: from the CVE details
  # usually this should only one cpe but in case we are using ARR. With this cpe ARR we can further check for versions from the CVE details like
  #   .versionStartIncluding
  #   .versionStartExcluding
  #   .versionEndIncluding
  #   .versionEndExcluding
  #
  # lBIN_NAME is somthing like ".*:lBIN_NAME"
  mapfile -t lCVE_CPEs_vuln_ARR < <(jq -rc '.configurations[].nodes[].cpeMatch[] | select(.vulnerable==true)' "${lCVE_VER_SOURCES_FILE}" | grep "cpe:${CPE_VERSION}:[aoh]:.*${lBIN_NAME}:\*:" || true)
  # the result looks like the following:
  # └─$ jq -rc '.configurations[].nodes[].cpeMatch[] | select(.vulnerable==true)' external/nvd-json-data-feeds/CVE-2023/CVE-2023-02xx/CVE-2023-0215.json
  # {"vulnerable":true,"criteria":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0.2","versionEndExcluding":"1.0.2zg","matchCriteriaId":"70985D55-A574-4151-B451-4D500CBFC29A"}
  # {"vulnerable":true,"criteria":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","versionStartIncluding":"1.1.1","versionEndExcluding":"1.1.1t","matchCriteriaId":"DE0061D6-8F81-45D3-B254-82A94915FD08"}
  # {"vulnerable":true,"criteria":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","versionStartIncluding":"3.0.0","versionEndExcluding":"3.0.8","matchCriteriaId":"A6DC5D88-4E99-48F2-8892-610ACA9B5B86"}
  # {"vulnerable":true,"criteria":"cpe:2.3:a:stormshield:stormshield_management_center:*:*:*:*:*:*:*:*","versionEndExcluding":"3.3.3","matchCriteriaId":"62A933C5-C56E-485C-AD49-3B6A2C329131"}

  # Now we walk through all the CPEMatch entries and extract the version details for further analysis
  local lWAIT_PIDS_F20_tmp=()
  for lCVE_CPEMATCH in "${lCVE_CPEs_vuln_ARR[@]}"; do
    # print_output "[*] Testing ${lCVE_CPEMATCH} / ${lFIRST_EPSS} / ${lBIN_NAME} / ${lCVE_V2} / ${lCVE_V31} / ${lCVE_SUMMARY// /§}"
    cve_cpe_matcher_threading "${lCVE_CPEMATCH}" "${lFIRST_EPSS}" "${lBIN_NAME}" "${lCVE_V2}" "${lCVE_V31}" "${lCVE_SUMMARY// /§}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    lWAIT_PIDS_F20_tmp+=( "${lTMP_PID}" )
    max_pids_protection $(( "${MAX_MOD_THREADS}"*3 )) "${lWAIT_PIDS_F20_tmp[@]}"
  done
  wait_for_pid "${lWAIT_PIDS_F20_tmp[@]}"
}

cve_cpe_matcher_threading() {
  local lCVE_CPEMATCH="${1:-}"
  local lFIRST_EPSS="${2:-}"
  local lBIN_NAME="${3:-}"
  local lCVE_V2="${4:-}"
  local lCVE_V31="${5:-}"
  local lCVE_SUMMARY="${6:-}"
  lCVE_SUMMARY=${lCVE_SUMMARY//§/ }

  local lCVE_VER_START_INCL=""
  local lCVE_VER_START_EXCL=""
  local lCVE_VER_END_INCL=""
  local lCVE_VER_END_EXCL=""

  # we need to check the version more in details in case we have no version in our cpe identifier
  # └─$ jq -r '.configurations[].nodes[].cpeMatch[] | select(.criteria=="cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*") | .versionEndIncluding' external/nvd-json-data-feeds/CVE-2011/CVE-2011-27xx/CVE-2011-2716.json

  # print_output "[*] Binary ${lBIN_VERSION} - Found no version identifier in our cpe for ${lCVE_VER_SOURCES_FILE} - check for further version details with ${lCVE_CPEMATCH}" "no_log"

  # extract further version details form the current cpe under test
  lCVE_VER_START_INCL=$(echo "${lCVE_CPEMATCH}" | jq -r '.versionStartIncluding' | grep -v "null" || true)
  lCVE_VER_START_EXCL=$(echo "${lCVE_CPEMATCH}" | jq -r '.versionStartExcluding' | grep -v "null" || true)
  lCVE_VER_END_INCL=$(echo "${lCVE_CPEMATCH}" | jq -r '.versionEndIncluding' | grep -v "null" || true)
  lCVE_VER_END_EXCL=$(echo "${lCVE_CPEMATCH}" | jq -r '.versionEndExcluding' | grep -v "null" || true)

  # if we have found some version details we need to further check them now:
  if [[ -n "${lCVE_VER_START_INCL}" || -n "${lCVE_VER_START_EXCL}" || -n "${lCVE_VER_END_INCL}" || -n "${lCVE_VER_END_EXCL}" ]]; then
    # print_output "[*] Binary ${lBIN_VERSION} - CVE ${lCVE_ID} - lCVE_VER_START_INCL / lCVE_VER_START_EXCL / lCVE_VER_END_INCL / lCVE_VER_END_EXCL - ${lCVE_VER_START_INCL} / ${lCVE_VER_START_EXCL} / ${lCVE_VER_END_INCL} / ${lCVE_VER_END_EXCL}" "no_log"

    ## first check lCVE_VER_START_INCL >= lVERSION <= lCVE_VER_END_INCL
    if [[ -n "${lCVE_VER_START_INCL}" ]]; then
      # print_output "[*] ${lBIN_VERSION} - ${lCVE_ID} - lCVE_VER_START_INCL: ${lCVE_VER_START_INCL} - $(version "${lBIN_VERSION_ONLY}") vs $(version "${lCVE_VER_START_INCL}")" "no_log"
      # if [[ "$(version_extended "${lBIN_VERSION_ONLY}")" -lt "$(version_extended "${lCVE_VER_START_INCL}")" ]]; then
      if version_extended "${lBIN_VERSION_ONLY}" '<' "${lCVE_VER_START_INCL}"; then
        # lBIN_VERSION is lt lCVE_VER_START_INCL -> we can move on
        return
      fi

      # Case: if [[ "$(version "${lBIN_VERSION_ONLY}")" -ge "$(version "${lCVE_VER_START_INCL}")" ]]; then
      # print_output "[*] ${lCVE_ID} - lCVE_VER_START_INCL - binary ${lBIN_VERSION} version $(version "${lBIN_VERSION_ONLY}") is higher (incl) as CVE version $(version "${lCVE_VER_START_INCL}")" "no_log"
      if [[ -n "${lCVE_VER_END_INCL}" ]]; then
        if version_extended "${lBIN_VERSION_ONLY}" '<=' "${lCVE_VER_END_INCL}"; then
          # print_output "[+] Vulnerability identified - CVE: ${lCVE_ID} - binary ${lBIN_VERSION} - source file ${lCVE_VER_SOURCES_FILE} - lCVE_VER_START_INCL / lCVE_VER_END_INCL" "no_log"
          write_cve_log "${lCVE_ID}" "${lCVE_V2:-"NA"}" "${lCVE_V31:-"NA"}" "${lFIRST_EPSS}" "${lCVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt &
          if [[ "${lBIN_NAME}" == *"linux_kernel"* ]]; then
            check_kernel_major_v "${lBIN_VERSION_ONLY}" "${lCVE_VER_END_INCL}" "${lCVE_ID}" &
          fi
        fi
        return
      fi
      ## first check VERSION < lCVE_VER_END_EXCL
      if [[ -n "${lCVE_VER_END_EXCL}" ]]; then
        if version_extended "${lBIN_VERSION_ONLY}" '<' "${lCVE_VER_END_EXCL}"; then
          # print_output "[+] Vulnerability identified - CVE: ${lCVE_ID} - binary ${lBIN_VERSION} - source file ${lCVE_VER_SOURCES_FILE} - lCVE_VER_START_INCL / lCVE_VER_END_EXCL" "no_log"
          write_cve_log "${lCVE_ID}" "${lCVE_V2:-"NA"}" "${lCVE_V31:-"NA"}" "${lFIRST_EPSS}" "${lCVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt &
          if [[ "${lBIN_NAME}" == *"linux_kernel"* ]]; then
            check_kernel_major_v "${lBIN_VERSION_ONLY}" "${lCVE_VER_END_EXCL}" "${lCVE_ID}" &
          fi
        fi
        return
      fi

      # No end version is specified and start version already satisfied.
      # print_output "[+] Vulnerability identified - CVE: ${lCVE_ID} - binary ${lBIN_VERSION} - source file ${lCVE_VER_SOURCES_FILE} - lCVE_VER_START_INCL / lCVE_VER_END_EXCL: ${ORANGE}NA${GREEN} / lCVE_VER_END_INCL: ${ORANGE}NA${GREEN}" "no_log"
      write_cve_log "${lCVE_ID}" "${lCVE_V2:-"NA"}" "${lCVE_V31:-"NA"}" "${lFIRST_EPSS}" "${lCVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt &
      if [[ "${lBIN_NAME}" == *"linux_kernel"* ]]; then
        check_kernel_major_v "${lBIN_VERSION_ONLY}" "${lCVE_VER_START_INCL}" "${lCVE_ID}" &
      fi
      return
    fi

    if [[ -n "${lCVE_VER_START_EXCL}" ]]; then
      # print_output "[*] ${lBIN_VERSION_ONLY} - ${lCVE_ID} - lCVE_VER_START_EXCL: ${lCVE_VER_START_EXCL}" "no_log"
      if version_extended "${lBIN_VERSION_ONLY}" '<=' "${lCVE_VER_START_EXCL}"; then
        # lBIN_VERSION is le lCVE_VER_START_EXCL -> we can move on
        return
      fi

      # Case: if [[ "$(version "${lBIN_VERSION_ONLY}")" -gt "$(version "${lCVE_VER_START_EXCL}")" ]]; then
      # print_output "[*] ${lCVE_ID} - lCVE_VER_START_EXCL - binary ${lBIN_VERSION} version $(version "${lBIN_VERSION_ONLY}") is higher (excl) as CVE version $(version "${lCVE_VER_START_EXCL}")" "no_log"
      if [[ -n "${lCVE_VER_END_INCL}" ]]; then
        if version_extended "${lBIN_VERSION_ONLY}" '<=' "${lCVE_VER_END_INCL}"; then
          # print_output "[+] Vulnerability identified - CVE: ${lCVE_ID} - binary ${lBIN_VERSION} - source file ${lCVE_VER_SOURCES_FILE} - lCVE_VER_START_EXCL / lCVE_VER_END_INCL" "no_log"
          write_cve_log "${lCVE_ID}" "${lCVE_V2:-"NA"}" "${lCVE_V31:-"NA"}" "${lFIRST_EPSS}" "${lCVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt &
          if [[ "${lBIN_NAME}" == *"linux_kernel"* ]]; then
            check_kernel_major_v "${lBIN_VERSION_ONLY}" "${lCVE_VER_END_INCL}" "${lCVE_ID}" &
          fi
        fi
        return
      fi
      if [[ -n "${lCVE_VER_END_EXCL}" ]]; then
        if version_extended "${lBIN_VERSION_ONLY}" '<' "${lCVE_VER_END_EXCL}"; then
          # print_output "[+] Vulnerability identified - CVE: ${lCVE_ID} - binary ${lBIN_VERSION} - source file ${lCVE_VER_SOURCES_FILE} - lCVE_VER_START_EXCL / lCVE_VER_END_EXCL" "no_log"
          write_cve_log "${lCVE_ID}" "${lCVE_V2:-"NA"}" "${lCVE_V31:-"NA"}" "${lFIRST_EPSS}" "${lCVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt &
          if [[ "${lBIN_NAME}" == *"linux_kernel"* ]]; then
            check_kernel_major_v "${lBIN_VERSION_ONLY}" "${lCVE_VER_END_EXCL}" "${lCVE_ID}" &
          fi
        fi
        return
      fi

      # No end version is specified and start version already satisfied.
      # print_output "[+] Vulnerability identified - CVE: ${lCVE_ID} - binary ${lBIN_VERSION} - source file ${lCVE_VER_SOURCES_FILE} - lCVE_VER_START_EXCL / lCVE_VER_END_INCL: ${ORANGE}NA${GREEN} / lCVE_VER_END_EXCL: ${ORANGE}NA${GREEN}" "no_log"
      write_cve_log "${lCVE_ID}" "${lCVE_V2:-"NA"}" "${lCVE_V31:-"NA"}" "${lFIRST_EPSS}" "${lCVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt &
      if [[ "${lBIN_NAME}" == *"linux_kernel"* ]]; then
        check_kernel_major_v "${lBIN_VERSION_ONLY}" "${lCVE_VER_START_EXCL}" "${lCVE_ID}" &
      fi
      return
    fi

    # Last cases: no start version is specified. Check end version only.

    if [[ -n "${lCVE_VER_END_INCL}" ]]; then
      # print_output "[!] ${lCVE_ID} - lCVE_VER_END_INCL - binary ${lBIN_VERSION} - ${lBIN_VERSION_ONLY} - CVE version ${lCVE_VER_END_INCL}" "no_log"
      if version_extended "${lBIN_VERSION_ONLY}" '>' "${lCVE_VER_END_INCL}"; then
        # print_output "[!] ${lCVE_ID} - lCVE_VER_END_INCL - binary ${lBIN_VERSION} - ${lBIN_VERSION_ONLY} - CVE version ${lCVE_VER_END_INCL} - exit" "no_log"
        # lBIN_VERSION is gt lCVE_VER_END_INCL -> we can move on
        return
      fi

      # This is the case: if [[ "$(version "${lBIN_VERSION_ONLY}")" -le "$(version "${lCVE_VER_END_INCL}")" ]]; then
      # print_output "[*] ${lCVE_ID} - lCVE_VER_END_INCL - binary ${lBIN_VERSION} version $(version "${lBIN_VERSION_ONLY}") is lower (incl) CVE version $(version "${lCVE_VER_END_INCL}")" "no_log"

      # print_output "[+] Vulnerability identified - CVE: ${lCVE_ID} - binary ${lBIN_VERSION} - source file ${lCVE_VER_SOURCES_FILE} - lCVE_VER_START_INCL: ${ORANGE}NA${GREEN} / lCVE_VER_START_EXCL: ${ORANGE}NA${GREEN} / lCVE_VER_END_INCL" "no_log"
      write_cve_log "${lCVE_ID}" "${lCVE_V2:-"NA"}" "${lCVE_V31:-"NA"}" "${lFIRST_EPSS}" "${lCVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt &
      if [[ "${lBIN_NAME}" == *"linux_kernel"* ]]; then
        check_kernel_major_v "${lBIN_VERSION_ONLY}" "${lCVE_VER_END_INCL}" "${lCVE_ID}" &
      fi
      return
    fi

    if [[ -n "${lCVE_VER_END_EXCL}" ]]; then
      if version_extended "${lBIN_VERSION_ONLY}" '>=' "${lCVE_VER_END_EXCL}"; then
        # BIN_VERSION is ge lCVE_VER_END_EXCL -> we can move on
        return
      fi

      # Case handling: if [[ "$(version "${lBIN_VERSION_ONLY}")" -lt "$(version "${lCVE_VER_END_EXCL}")" ]]; then
      # print_output "[*] ${lCVE_ID} - lCVE_VER_END_EXCL - binary ${lBIN_VERSION} version $(version "${lBIN_VERSION_ONLY}") is lower (excl) CVE version $(version "${lCVE_VER_END_EXCL}")" "no_log"

      # print_output "[+] Vulnerability identified - CVE: ${lCVE_ID} - binary ${lBIN_VERSION} - source file ${lCVE_VER_SOURCES_FILE} - lCVE_VER_END_EXCL / lCVE_VER_START_EXCL: ${ORANGE}NA${GREEN} / lCVE_VER_START_INCL: ${ORANGE}NA${GREEN}" "no_log"
      write_cve_log "${lCVE_ID}" "${lCVE_V2:-"NA"}" "${lCVE_V31:-"NA"}" "${lFIRST_EPSS}" "${lCVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt &
      if [[ "${lBIN_NAME}" == *"linux_kernel"* ]]; then
        check_kernel_major_v "${lBIN_VERSION_ONLY}" "${lCVE_VER_END_EXCL}" "${lCVE_ID}" &
      fi
      return
    fi
  else
    # if we have not found further version limitations, we assume that all versions are vulnerable:
    # print_output "[+] CPE matches - vulnerability identified - CVE: ${lCVE_ID} - binary ${lBIN_VERSION} version $(version "${lBIN_VERSION_ONLY}") - no further version limitations detected" "no_log"
    write_cve_log "${lCVE_ID}" "${lCVE_V2:-"NA"}" "${lCVE_V31:-"NA"}" "${lFIRST_EPSS}" "${lCVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${lVERSION_PATH}".txt &
  fi
}

check_kernel_major_v() {
  local lBIN_VERSION_ONLY="${1:-}"
  local lKERNEL_CVE_VER="${2:-}"
  local lCVE_ID="${3:-}"
  if [[ "${lBIN_VERSION_ONLY:0:1}" != "${lKERNEL_CVE_VER:0:1}" ]]; then
    # print_output is for printing to cli
    # write_log is for writing the needed log file
    local lOUT_MESSAGE="[-] Info for CVE ${ORANGE}${lCVE_ID}${NC} - Major kernel version not matching ${ORANGE}${lKERNEL_CVE_VER}${NC} vs ${ORANGE}${lBIN_VERSION_ONLY}${NC} - Higher false positive risk"
    # print_output "${lOUT_MESSAGE}" "no_log"
    write_log "${lOUT_MESSAGE}" "${LOG_PATH_MODULE}/kernel_cve_version_issues.log"
  fi
}

write_cve_log() {
  local lCVE_ID="${1:-}"
  local lCVE_V2="${2:-}"
  local lCVE_V31="${3:-}"
  local lFIRST_EPSS="${4:-}"
  local lCVE_SUMMARY="${5:-}"
  local lCVE_LOG_FILE="${6:-}"

  if [[ -s "${lCVE_LOG_FILE}" ]]; then
    # check if we have already an entry for this CVE - if not, we will write it to the output file
    if ! grep -q "^${lCVE_ID}:" "${lCVE_LOG_FILE}" 2>/dev/null; then
      echo "${lCVE_ID}:${lCVE_V2:-"NA"}:${lCVE_V31:-"NA"}:${lFIRST_EPSS/;/:}:${lCVE_SUMMARY:-"NA"}" >> "${lCVE_LOG_FILE}" || true
    fi
  else
    echo "${lCVE_ID}:${lCVE_V2:-"NA"}:${lCVE_V31:-"NA"}:${lFIRST_EPSS/;/:}:${lCVE_SUMMARY:-"NA"}" > "${lCVE_LOG_FILE}" || true
  fi
}

cve_extractor() {
  # VERSION_orig is usually the BINARY_NAME:VERSION
  # in some cases it is only the CVE-Identifier
  local lVERSION_orig="${1:-}"

  local lVERSION=""
  local lBINARY=""
  export lCVE_VALUE=""
  local lCVSS_VALUE=""
  local lVSOURCE="unknown"
  export EXPLOIT_AVAIL=()
  export EXPLOIT_AVAIL_MSF=()
  export EXPLOIT_AVAIL_TRICKEST=()
  export EXPLOIT_AVAIL_ROUTERSPLOIT=()
  export EXPLOIT_AVAIL_ROUTERSPLOIT1=()
  export EXPLOIT_AVAIL_PACKETSTORM=()
  export EXPLOIT_AVAIL_SNYK=()
  export KNOWN_EXPLOITED_VULNS=()
  local lKNOWN_EXPLOITED=0
  local lLOCAL=0
  local lREMOTE=0
  local lDOS=0
  local lCVEs_OUTPUT_ARR=()
  local lCVE_OUTPUT=""
  local lKERNEL_VERIFIED_VULN=0

  if ! [[ "${lVERSION_orig}" == "CVE-"* ]]; then
    lBINARY=$(echo "${lVERSION_orig%:}" | rev | cut -d':' -f2 | rev)

    # if we have a version identifier like ::binary:1.2.3: we need to remove the last ':' before processing it correctly
    lVERSION=$(echo "${lVERSION_orig%:}" | cut -d':' -f4-5)
    lVERSION="${lVERSION%:}"

    lBINARY=$(echo "${lVERSION_orig%:}" | cut -d':' -f1-3)
    lBINARY="${lBINARY%:}"
    lBINARY="${lBINARY#:}"

    export AGG_LOG_FILE="${lVERSION_PATH}".txt
  else
    export AGG_LOG_FILE="${lVERSION_orig}".txt
  fi

  # lVSOURCE is used to track the source of version details, this is relevant for the
  # final report. With this in place we know if it is from live testing via the network
  # or if it is found via static analysis or via user-mode emulation
  if [[ -f "${S06_CSV_LOG}" || -f "${S09_CSV_LOG}" || -f "${S118_CSV_LOG}" ]]; then
    if grep -q "${lVERSION_orig}" "${S06_CSV_LOG}" 2>/dev/null || grep -q "${lVERSION_orig}" "${S09_CSV_LOG}" 2>/dev/null || grep -q "${lVERSION_orig}" "${S118_CSV_LOG}" 2>/dev/null; then
      if [[ "${lVSOURCE}" == "unknown" ]]; then
        lVSOURCE="STAT"
      else
        lVSOURCE+="/STAT"
      fi
    fi
  fi

  if [[ -f "${S25_CSV_LOG}" ]]; then
    if [[ "${lBINARY}" == *"kernel"* ]]; then
      if grep -q "kernel;${lVERSION};" "${S25_CSV_LOG}" 2>/dev/null; then
        if [[ "${lVSOURCE}" == "unknown" ]]; then
          lVSOURCE="STAT"
        elif ! [[ "${lVSOURCE}" =~ .*STAT.* ]]; then
          lVSOURCE+="/STAT"
        fi
      fi
    fi
  fi

  if [[ -f "${S24_CSV_LOG}" ]]; then
    if [[ "${lBINARY}" == *"kernel"* ]]; then
      if tail -n +2 "${S24_CSV_LOG}" | grep -i -q "linux.*${lVERSION}" 2>/dev/null; then
        if [[ "${lVSOURCE}" == "unknown" ]]; then
          lVSOURCE="STAT"
        elif ! [[ "${lVSOURCE}" =~ .*STAT.* ]]; then
          lVSOURCE+="/STAT"
        fi
      fi
    fi
  fi

  if [[ -f "${S116_CSV_LOG}" ]]; then
    if grep -q "${lVERSION_orig}" "${S116_CSV_LOG}" 2>/dev/null; then
      if [[ "${lVSOURCE}" == "unknown" ]]; then
        lVSOURCE="UEMU"
      else
        lVSOURCE+="/UEMU"
      fi
    fi
  fi

  if [[ -f "${S02_CSV_LOG}" ]]; then
    if grep -q "${lVERSION_orig}" "${S02_CSV_LOG}" 2>/dev/null; then
      if [[ "${lVSOURCE}" == "unknown" ]]; then
        lVSOURCE="FwHunt"
      else
        lVSOURCE+="/FwHunt"
      fi
      lBINARY="UEFI firmware"
      lVERSION="unknown"
    fi
  fi

  if [[ -f "${S06_CSV_LOG}" ]]; then
    if grep -q "${lVERSION_orig}" "${S06_CSV_LOG}" 2>/dev/null; then
      if [[ "${lVSOURCE}" == "unknown" ]]; then
        lVSOURCE="STAT"
      else
        lVSOURCE+="/STAT"
      fi
    fi
  fi

  if [[ -f "${L35_CSV_LOG}" ]]; then
    if grep -q "${lVERSION_orig}" "${L35_CSV_LOG}" 2>/dev/null; then
      if [[ "${lVSOURCE}" == "unknown" ]]; then
        lVSOURCE="MSF verified"
      else
        lVSOURCE+="/MSF verified"
      fi
      lBINARY="unknown"
      lVERSION="unknown"
    fi
  fi

  if [[ -f "${S08_CSV_LOG}" ]]; then
    if grep -q "${lBINARY};.*${lVERSION}" "${S08_CSV_LOG}" 2>/dev/null; then
      if [[ "${lVSOURCE}" == "unknown" ]]; then
        lVSOURCE="SBOM"
      else
        lVSOURCE+="/SBOM"
      fi
    fi
  fi

  if [[ -f "${S36_CSV_LOG}" ]]; then
    if grep -q "${lBINARY};.*${lVERSION}" "${S36_CSV_LOG}" 2>/dev/null; then
      if [[ "${lVSOURCE}" == "unknown" ]]; then
        lVSOURCE="STAT"
      elif ! [[ "${lVSOURCE}" =~ .*STAT.* ]]; then
        lVSOURCE+="/STAT"
      fi
    fi
  fi

  if [[ -f "${L15_CSV_LOG}" && -f "${L25_CSV_LOG}" ]]; then
    if grep -q "${lVERSION_orig}" "${L15_CSV_LOG}" 2>/dev/null || grep -q "${lVERSION_orig}" "${L25_CSV_LOG}" 2>/dev/null; then
      if [[ "${lVSOURCE}" == "unknown" ]]; then
        lVSOURCE="SEMU"
      else
        lVSOURCE+="/SEMU"
      fi
    fi
  fi

  export EXPLOIT_COUNTER_VERSION=0
  local lCVE_COUNTER_VERSION=0
  if [[ -f "${LOG_PATH_MODULE}"/"${AGG_LOG_FILE}" ]]; then
    readarray -t lCVEs_OUTPUT_ARR < <(cut -d ':' -f1-5 "${LOG_PATH_MODULE}"/"${AGG_LOG_FILE}" | grep "^CVE-" || true)
  fi

  # if cve-search does not show results we could use the results of linux-exploit-suggester
  # but in our experience these results are less accurate as the results from cve-search.
  # Show me that I'm wrong and we could include and adjust the imports from s25 here:
  # On the other hand, do not forget that we are also using the s25 results if we can find the
  # same CVE here via version detection.

  # if [[ "${lBINARY}" == *kernel* ]]; then
  #  if [[ -f "${S25_CSV_LOG}" ]]; then
  #    for lKERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS_ARR[@]}"; do
  #      KCVE_VALUE=$(echo "${lKERNEL_CVE_EXPLOIT}" | cut -d\; -f3)
  #    done
  #  fi
  # fi

  if [[ "${#lCVEs_OUTPUT_ARR[@]}" == 0 ]]; then
    write_csv_log "${lBINARY}" "${lVERSION}" "${lCVE_VALUE:-NA}" "${lCVSS_VALUE:-NA}" "${#EXPLOIT_AVAIL[@]}" "${#EXPLOIT_AVAIL_MSF[@]}" "${#EXPLOIT_AVAIL_TRICKEST[@]}" "${#EXPLOIT_AVAIL_ROUTERSPLOIT[@]}/${#EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}" "${#EXPLOIT_AVAIL_SNYK[@]}" "${#EXPLOIT_AVAIL_PACKETSTORM[@]}" "${lLOCAL:-NA}" "${lREMOTE:-NA}" "${lDOS:-NA}" "${#KNOWN_EXPLOITED_VULNS[@]}" "${lKERNEL_VERIFIED:-NA}" "${FIRST_EPSS:-NA}" "${FIRST_PERC:-NA}"
  fi

  if [[ -f "${LOG_PATH_MODULE}"/"${AGG_LOG_FILE}" ]]; then
    local lWAIT_PIDS_TACTOR_ARR=()
    for lCVE_OUTPUT in "${lCVEs_OUTPUT_ARR[@]}"; do
      # lCVE_OUTPUT is for one CVE value
      ((CVE_COUNTER+=1))
      ((lCVE_COUNTER_VERSION+=1))
      if [[ "${THREADED}" -eq 1 ]]; then
        cve_extractor_thread_actor "${lBINARY}" "${lVERSION}" "${lCVE_OUTPUT}" &
        lWAIT_PIDS_TACTOR_ARR+=( "$!" )
        max_pids_protection "$(("${MAX_MOD_THREADS}"*3))" "${lWAIT_PIDS_TACTOR_ARR[@]}"
      else
        cve_extractor_thread_actor "${lBINARY}" "${lVERSION}" "${lCVE_OUTPUT}"
      fi
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_TACTOR_ARR[@]}"
  fi

  local lKNOWN_EXPLOITED=0
  local lKERNEL_VERIFIED_VULN=0
  local EXPLOIT_COUNTER_VERSION=0

  if [[ -s "${LOG_PATH_MODULE}"/exploit/known_exploited_vulns.log ]]; then
    lKNOWN_EXPLOITED=1
  fi
  if [[ -f "${F20_CSV_LOG}" ]]; then
    # very weak search for the end of the entry - if yes we have a verified kernel vuln
    # Todo: Improve this search on field base
    lKERNEL_VERIFIED_VULN=$(grep -c "^${lBINARY};.*;yes;$" "${F20_CSV_LOG}" || true)
  fi

  if [[ -f "${TMP_DIR}/exploit_cnt.tmp" ]]; then
    # this counter is wrong as soon as we have the same binary in multiple versions!
    EXPLOIT_COUNTER_VERSION=$(grep -c "^${lBINARY};${lVERSION};" "${TMP_DIR}/exploit_cnt.tmp" || true)
  fi

  { echo ""
    echo "[+] Statistics:${lCVE_COUNTER_VERSION}|${EXPLOIT_COUNTER_VERSION}|${lVERSION_orig}"
  } >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"

  local lBIN_LOG="${LOG_PATH_MODULE}/cve_details_${lBINARY}_${lVERSION}.log"
  write_log "[*] Vulnerability details for ${ORANGE}${lBINARY}${NC} / version ${ORANGE}${lVERSION}${NC} / source ${ORANGE}${lVSOURCE}${NC}:" "${lBIN_LOG}"
  local lANCHOR=""
  local lBINARY_NAME="${lBINARY/*:}"
  lANCHOR="${lBINARY_NAME}_${lVERSION}"
  lANCHOR="cve_${lANCHOR:0:20}"
  write_anchor "${lANCHOR}" "${lBIN_LOG}"
  # print_output "[*] ${lBINARY} / ${lVERSION} / ${#BUSYBOX_VERIFIED_CVE_ARR[@]}"
  if [[ "${EXPLOIT_COUNTER_VERSION}" -gt 0 ]]; then
    write_log "" "${lBIN_LOG}"
    grep -v "Statistics" "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}" >> "${lBIN_LOG}" || true
    if [[ "${lKERNEL_VERIFIED_VULN}" -gt 0 ]]; then
      write_log "[+] Found ${RED}${BOLD}${lCVE_COUNTER_VERSION}${GREEN} CVEs (${RED}${lKERNEL_VERIFIED_VULN} verified${GREEN}) and ${RED}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${lBINARY}${GREEN} with version ${ORANGE}${lVERSION}${GREEN} (source ${ORANGE}${lVSOURCE}${GREEN}).${NC}" "${lBIN_LOG}"
    elif [[ "${#BUSYBOX_VERIFIED_CVE_ARR[@]}" -gt 0 ]] && [[ "${lBINARY}" == *"busybox"* ]]; then
      # we currently do not check for the specific BB version in here. This results in false results on multiple detected BB binaries
      write_log "[+] Found ${RED}${BOLD}${lCVE_COUNTER_VERSION}${GREEN} CVEs (${RED}${#BUSYBOX_VERIFIED_CVE_ARR[@]} verified${GREEN}) and ${RED}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${lBINARY}${GREEN} with version ${ORANGE}${lVERSION}${GREEN} (source ${ORANGE}${lVSOURCE}${GREEN}).${NC}" "${lBIN_LOG}"
    else
      write_log "[+] Found ${RED}${BOLD}${lCVE_COUNTER_VERSION}${GREEN} CVEs and ${RED}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${lBINARY}${GREEN} with version ${ORANGE}${lVERSION}${GREEN} (source ${ORANGE}${lVSOURCE}${GREEN}).${NC}" "${lBIN_LOG}"
    fi
    write_log "" "${lBIN_LOG}"
  elif [[ "${lCVE_COUNTER_VERSION}" -gt 0 ]]; then
    write_log "" "${lBIN_LOG}"
    grep -v "Statistics" "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}" >> "${lBIN_LOG}" || true
    if [[ "${lKERNEL_VERIFIED_VULN}" -gt 0 ]]; then
      write_log "[+] Found ${ORANGE}${BOLD}${lCVE_COUNTER_VERSION}${GREEN} CVEs (${ORANGE}${lKERNEL_VERIFIED_VULN} verified${GREEN}) and ${ORANGE}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${lBINARY}${GREEN} with version ${ORANGE}${lVERSION}${GREEN} (source ${ORANGE}${lVSOURCE}${GREEN}).${NC}" "${lBIN_LOG}"
    elif [[ "${#BUSYBOX_VERIFIED_CVE_ARR[@]}" -gt 0 ]] && [[ "${lBINARY}" == *"busybox"* ]]; then
      write_log "[+] Found ${ORANGE}${BOLD}${lCVE_COUNTER_VERSION}${GREEN} CVEs (${ORANGE}${#BUSYBOX_VERIFIED_CVE_ARR[@]} verified${GREEN}) and ${ORANGE}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${lBINARY}${GREEN} with version ${ORANGE}${lVERSION}${GREEN} (source ${ORANGE}${lVSOURCE}${GREEN}).${NC}" "${lBIN_LOG}"
    else
      write_log "[+] Found ${ORANGE}${BOLD}${lCVE_COUNTER_VERSION}${GREEN} CVEs and ${ORANGE}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${lBINARY}${GREEN} with version ${ORANGE}${lVERSION}${GREEN} (source ${ORANGE}${lVSOURCE}${GREEN}).${NC}" "${lBIN_LOG}"
    fi
    write_log "" "${lBIN_LOG}"
  else
    write_log "[-] Found ${ORANGE}${BOLD}NO${NC}${NC} CVEs and ${ORANGE}${BOLD}NO${NC}${NC} exploits (including POC's) in ${ORANGE}${lBINARY}${NC} with version ${ORANGE}${lVERSION}${NC} (source ${ORANGE}${lVSOURCE}${NC})." "${lBIN_LOG}"
    write_log "" "${lBIN_LOG}"
  fi

  # normally we only print the number of CVEs. If we have verified CVEs in the Linux Kernel or BusyBox we also add this detail
  local lCVEs="${lCVE_COUNTER_VERSION}"
  if [[ "${lKERNEL_VERIFIED_VULN}" -gt 0 ]] && [[ "${lBINARY}" == *"kernel"* ]]; then
    lCVEs+=" (${lKERNEL_VERIFIED_VULN})"
  fi
  if [[ "${#BUSYBOX_VERIFIED_CVE_ARR[@]}" -gt 0 ]] && [[ "${lBINARY}" == *"busybox"* ]]; then
    lCVEs+=" (${#BUSYBOX_VERIFIED_CVE_ARR[@]})"
  fi
  local lEXPLOITS="${EXPLOIT_COUNTER_VERSION:-0}"

  if [[ "${lCVE_COUNTER_VERSION}" -gt 0 || "${EXPLOIT_COUNTER_VERSION}" -gt 0 ]]; then
    if ! [[ -f "${LOG_PATH_MODULE}"/F20_summary.csv ]]; then
      write_log "BINARY;VERSION;Number of CVEs;Number of EXPLOITS" "${LOG_PATH_MODULE}"/F20_summary.csv
    fi
    if [[ "${EXPLOIT_COUNTER_VERSION}" -gt 0 || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "[${MAGENTA}+${NC}]${MAGENTA} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${lBINARY_NAME}" "${lVERSION}" "${lCVEs}" "${lEXPLOITS}" "${lVSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
      write_log "${lBINARY};${lVERSION};${lCVEs};${lEXPLOITS}" "${LOG_PATH_MODULE}"/F20_summary.csv
    else
      printf "[${ORANGE}+${NC}]${ORANGE} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${lBINARY_NAME}" "${lVERSION}" "${lCVEs}" "${lEXPLOITS}" "${lVSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
      write_log "${lBINARY};${lVERSION};${lCVEs};${lEXPLOITS}" "${LOG_PATH_MODULE}"/F20_summary.csv
    fi
  elif [[ "${lCVEs/\ */}" -eq 0 && "${lEXPLOITS}" -eq 0 ]]; then
    printf "[${GREEN}+${NC}]${GREEN} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${lBINARY_NAME}" "${lVERSION}" "${lCVEs/\ */}" "${lEXPLOITS}" "${lVSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
    write_log "${lBINARY};${lVERSION};${lCVEs/\ */};${lEXPLOITS}" "${LOG_PATH_MODULE}"/F20_summary.csv
  else
    # this should never happen ...
    printf "[+] Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-5.5s:   Exploits: %-10.10s:   Source: %-15.15s\n" "${lBINARY_NAME}" "${lVERSION}" "${lCVEs/\ */}" "${lEXPLOITS}" "${lVSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
    write_log "${lBINARY};${lVERSION};${lCVEs/\ */};${lEXPLOITS}" "${LOG_PATH_MODULE}"/F20_summary.csv
  fi

  # now, lets write the main f20 log file with the results of the current binary:
  tee -a "${LOG_FILE}" < "${lBIN_LOG}"
}

cve_extractor_thread_actor() {
  local lBIN_BINARY="${1:-}"
  local lBIN_BINARY_NAME="${lBIN_BINARY/*:}"
  local lBIN_VERSION="${2:-}"
  local lCVE_OUTPUT="${3:-}"

  local lCVEv2_TMP=0
  local lKERNEL_VERIFIED="no"
  local lKERNEL_CVE_EXPLOIT=""
  local lBUSYBOX_VERIFIED="no"
  local lCVE_VALUE=""
  local lCVSSv2_VALUE=""
  local lCVSS_VALUE=""
  local lKNOWN_EXPLOITED=0
  local lHIGH_CVE_COUNTER=0
  local lMEDIUM_CVE_COUNTER=0
  local lLOW_CVE_COUNTER=0
  local lEID_VALUE=""
  local lEXPLOIT=""
  local lEXPLOIT_IDS_ARR=()
  local lEXPLOIT_ID=""
  local lEXPLOIT_MSF=""
  local lEXPLOIT_SNYK=""
  local lEXPLOIT_PS=""
  local lEXPLOIT_RS=""
  local lEXPLOIT_ROUTERSPLOIT=()
  local lEXPLOIT_PATH=""
  local lEXPLOIT_NAME=""
  local lE_FILE=""
  local lTYPE=""
  local lLINE=""
  local lFIRST_EPSS=""
  local lFIRST_PERC=""

  lCVE_VALUE=$(echo "${lCVE_OUTPUT}" | cut -d: -f1 | tr -dc '[:print:]' | grep "^CVE-" || true)
  if [[ -z "${lCVE_VALUE}" ]]; then
    return
  fi

  # if we find a blacklist file we check if the current CVE value is in the blacklist
  # if we find it this CVE is not further processed
  if [[ -f "${CVE_BLACKLIST}" ]]; then
    if grep -q ^"${lCVE_VALUE}"$ "${CVE_BLACKLIST}"; then
      print_output "[*] ${ORANGE}${lCVE_VALUE}${NC} for ${ORANGE}${lBIN_BINARY}${NC} blacklisted and ignored." "no_log"
      return
    fi
  fi
  # if we find a whitelist file we check if the current CVE value is in the whitelist
  # only if we find this CVE in the whitelist it is further processed
  if [[ -f "${CVE_WHITELIST}" ]]; then
    # do a quick check if there is some data in the whitelist config file
    if [[ $(grep -E -c "^CVE-[0-9]+-[0-9]+$" "${CVE_WHITELIST}") -gt 0 ]]; then
      if ! grep -q ^"${lCVE_VALUE}"$ "${CVE_WHITELIST}"; then
        print_output "[*] ${ORANGE}${lCVE_VALUE}${NC} for ${ORANGE}${lBIN_BINARY}${NC} not in whitelist -> ignored." "no_log"
        return
      fi
    fi
  fi

  lCVSSv2_VALUE=$(echo "${lCVE_OUTPUT}" | cut -d: -f2)
  lCVSS_VALUE=$(echo "${lCVE_OUTPUT}" | cut -d: -f3)
  lFIRST_EPSS=$(echo "${lCVE_OUTPUT}" | cut -d: -f4)
  lFIRST_PERC=$(echo "${lCVE_OUTPUT}" | cut -d: -f5)

  # default value
  lEXPLOIT="No exploit available"

  # check if the CVE is known as a knwon exploited vulnerability:
  if [[ -f "${KNOWN_EXP_CSV}" ]]; then
    # if grep -q \""${lCVE_VALUE}"\", "${KNOWN_EXP_CSV}"; then
    if grep -q "^${lCVE_VALUE}," "${KNOWN_EXP_CSV}"; then
      print_output "[+] ${ORANGE}WARNING:${GREEN} Vulnerability ${ORANGE}${lCVE_VALUE}${GREEN} is a known exploited vulnerability."
      write_log "[+] ${ORANGE}WARNING:${GREEN} Vulnerability ${ORANGE}${lCVE_VALUE}${GREEN} is a known exploited vulnerability." "${LOG_PATH_MODULE}"/exploit/known_exploited_vulns.log

      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (KEV"
      else
        lEXPLOIT+=" / KEV"
      fi
      lKNOWN_EXPLOITED=1
    fi
  fi

  local lEDB=0
  # as we already know about a bunch of kernel exploits - lets search them first
  if [[ "${lBIN_BINARY}" == *kernel* ]]; then
    for lKERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS_ARR[@]}"; do
      lKERNEL_CVE_EXPLOIT=$(echo "${lKERNEL_CVE_EXPLOIT}" | cut -d\; -f3)
      if [[ "${lKERNEL_CVE_EXPLOIT}" == "${lCVE_VALUE}" ]]; then
        lEXPLOIT="Exploit (linux-exploit-suggester"
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${lCVE_VALUE};kernel exploit" "${TMP_DIR}"/exploit_cnt.tmp
        lEDB=1
      fi
    done

    if [[ -f "${S26_LOG_DIR}"/cve_results_kernel_"${lVERSION}".csv ]]; then
      # check if the current CVE is a verified kernel CVE from s26 module
      if grep -q ";${lCVE_VALUE};.*;.*;1;1" "${S26_LOG_DIR}"/cve_results_kernel_"${lVERSION}".csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_VALUE}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols and kernel configuration${GREEN})!" "no_log"
        ((lKERNEL_VERIFIED_VULN+=1))
        lKERNEL_VERIFIED="yes"
      fi
      if grep -q ";${lCVE_VALUE};.*;.*;1;0" "${S26_LOG_DIR}"/cve_results_kernel_"${lVERSION}".csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_VALUE}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols${GREEN})!" "no_log"
        ((lKERNEL_VERIFIED_VULN+=1))
        lKERNEL_VERIFIED="yes"
      fi
      if grep -q ";${lCVE_VALUE};.*;.*;0;1" "${S26_LOG_DIR}"/cve_results_kernel_"${lVERSION}".csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_VALUE}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel configuration${GREEN})!" "no_log"
        ((lKERNEL_VERIFIED_VULN+=1))
        lKERNEL_VERIFIED="yes"
      fi
    fi
  fi

  if [[ -f "${CSV_DIR}"/s118_busybox_verifier.csv ]] && [[ "${lBIN_BINARY}" == *"busybox"* ]]; then
    if grep -q ";${lCVE_VALUE};" "${CSV_DIR}"/s118_busybox_verifier.csv; then
      print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${lCVE_VALUE}${GREEN} is a verified BusyBox vulnerability (${ORANGE}BusyBox applet${GREEN})!" "no_log"
      lBUSYBOX_VERIFIED="yes"
    fi
  fi

  if [[ "${CVE_SEARCHSPLOIT}" -eq 1 || "${MSF_SEARCH}" -eq 1 || "${SNYK_SEARCH}" -eq 1 || "${PS_SEARCH}" -eq 1 ]] ; then
    if [[ ${CVE_SEARCHSPLOIT} -eq 1 ]]; then
      mapfile -t EXPLOIT_AVAIL < <(cve_searchsploit "${lCVE_VALUE}" 2>/dev/null || true)
    fi

    if [[ ${MSF_SEARCH} -eq 1 ]]; then
      mapfile -t EXPLOIT_AVAIL_MSF < <(grep -E "${lCVE_VALUE}"$ "${MSF_DB_PATH}" 2>/dev/null || true)
    fi

    if [[ ${PS_SEARCH} -eq 1 ]]; then
      mapfile -t EXPLOIT_AVAIL_PACKETSTORM < <(grep -E "^${lCVE_VALUE}\;" "${CONFIG_DIR}"/PS_PoC_results.csv 2>/dev/null || true)
    fi

    if [[ ${SNYK_SEARCH} -eq 1 ]]; then
      mapfile -t EXPLOIT_AVAIL_SNYK < <(grep -E "^${lCVE_VALUE}\;" "${CONFIG_DIR}"/Snyk_PoC_results.csv 2>/dev/null || true)
    fi
    # routersploit db search
    if [[ ${RS_SEARCH} -eq 1 ]]; then
      mapfile -t EXPLOIT_AVAIL_ROUTERSPLOIT < <(grep -E "${lCVE_VALUE}"$ "${CONFIG_DIR}/routersploit_cve-db.txt" 2>/dev/null || true)

      # now, we check the exploit-db results if we have a routersploit module:
      if [[ " ${EXPLOIT_AVAIL[*]} " =~ "Exploit DB Id:" ]]; then
        for lEID_VALUE in "${EXPLOIT_AVAIL[@]}"; do
          if ! echo "${lEID_VALUE}" | grep -q "Exploit DB Id:"; then
            continue
          fi
          lEID_VALUE=$(echo "${lEID_VALUE}" | grep "Exploit DB Id:" | cut -d: -f2)
          mapfile -t EXPLOIT_AVAIL_ROUTERSPLOIT1 < <(grep "${lEID_VALUE}" "${CONFIG_DIR}/routersploit_exploit-db.txt" 2>/dev/null || true)
        done
      fi
    fi

    if [[ " ${EXPLOIT_AVAIL[*]} " =~ "Exploit DB Id:" ]]; then
      readarray -t lEXPLOIT_IDS_ARR < <(echo "${EXPLOIT_AVAIL[@]}" | grep "Exploit DB Id:" | cut -d ":" -f 2 | sed 's/[^0-9]*//g' | sed 's/\ //' | sort -u)
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (EDB ID:"
      else
        lEXPLOIT+=" / EDB ID:"
      fi

      for lEXPLOIT_ID in "${lEXPLOIT_IDS_ARR[@]}" ; do
        lLOCAL=0
        lREMOTE=0
        lDOS=0
        lEXPLOIT="${lEXPLOIT}"" ""${lEXPLOIT_ID}"
        write_log "[+] Exploit for ${lCVE_VALUE}:\\n" "${LOG_PATH_MODULE}""/exploit/""${lEXPLOIT_ID}"".txt"
        for lLINE in "${EXPLOIT_AVAIL[@]}"; do
          write_log "${lLINE}" "${LOG_PATH_MODULE}""/exploit/""${lEXPLOIT_ID}"".txt"
          if [[ "${lLINE}" =~ "Platform: local" && "${lLOCAL}" -eq 0 ]]; then
            lEXPLOIT+=" (L)"
            lLOCAL=1
          fi
          if [[ "${lLINE}" =~ "Platform: remote" && "${lREMOTE}" -eq 0 ]]; then
            lEXPLOIT+=" (R)"
            lREMOTE=1
          fi
          if [[ "${lLINE}" =~ "Platform: dos" && "${lDOS}" -eq 0 ]]; then
            lEXPLOIT+=" (D)"
            lDOS=1
          fi
        done
        lEDB=1
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${lCVE_VALUE};exploit_db" "${TMP_DIR}"/exploit_cnt.tmp
      done

      # copy the exploit-db exploits to the report
      for lLINE in "${EXPLOIT_AVAIL[@]}"; do
        if [[ "${lLINE}" =~ "File:" ]]; then
          lE_FILE=$(echo "${lLINE}" | awk '{print $2}')
          if [[ -f "${lE_FILE}" ]] ; then
            cp "${lE_FILE}" "${LOG_PATH_MODULE}""/exploit/edb_""$(basename "${lE_FILE}")"
          fi
        fi
      done
    fi

    if [[ ${#EXPLOIT_AVAIL_MSF[@]} -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (MSF:"
      else
        lEXPLOIT+=" / MSF:"
      fi

      for lEXPLOIT_MSF in "${EXPLOIT_AVAIL_MSF[@]}" ; do
        if ! [[ -d "${MSF_INSTALL_PATH}" ]]; then
          lEXPLOIT_PATH=$(echo "${lEXPLOIT_MSF}" | cut -d: -f1)
        else
          lEXPLOIT_PATH="${MSF_INSTALL_PATH}"$(echo "${lEXPLOIT_MSF}" | cut -d: -f1)
        fi
        lEXPLOIT_NAME=$(basename -s .rb "${lEXPLOIT_PATH}")
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
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${lCVE_VALUE};MSF" "${TMP_DIR}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    if [[ ${#EXPLOIT_AVAIL_SNYK[@]} -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (Snyk:"
      else
        lEXPLOIT+=" / Snyk:"
      fi

      for lEXPLOIT_SNYK in "${EXPLOIT_AVAIL_SNYK[@]}" ; do
        lEXPLOIT_NAME=$(echo "${lEXPLOIT_SNYK}" | cut -d\; -f2)
        lEXPLOIT+=" ${lEXPLOIT_NAME} (S)"
      done

      if [[ ${lEDB} -eq 0 ]]; then
        # only count the snyk exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${lCVE_VALUE};SNYK" "${TMP_DIR}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    if [[ ${#EXPLOIT_AVAIL_PACKETSTORM[@]} -gt 0 ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (PSS:"
      else
        lEXPLOIT+=" / PSS:"
      fi

      for lEXPLOIT_PS in "${EXPLOIT_AVAIL_PACKETSTORM[@]}" ; do
        # we use the html file as lEXPLOIT_NAME.
        lEXPLOIT_NAME=$(echo "${lEXPLOIT_PS}" | cut -d\; -f3 | rev | cut -d '/' -f1-2 | rev)
        lEXPLOIT+=" ${lEXPLOIT_NAME}"
        lTYPE=$(grep "^${lCVE_VALUE};" "${CONFIG_DIR}"/PS_PoC_results.csv | grep "${lEXPLOIT_NAME}" | cut -d\; -f4 || true)
        if [[ "${lTYPE}" == "remote" ]]; then
          lTYPE="R"
        elif [[ "${lTYPE}" == "local" ]]; then
          lTYPE="L"
        elif [[ "${lTYPE}" == "DoS" ]]; then
          lTYPE="D"
        else
          # fallback to P for packetstorm exploit with unknownt type
          lTYPE="P"
        fi
        lEXPLOIT+=" (${lTYPE})"
      done

      if [[ ${lEDB} -eq 0 ]]; then
        # only count the packetstorm exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${lCVE_VALUE};PS" "${TMP_DIR}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi

    if [[ -v EXPLOIT_AVAIL_ROUTERSPLOIT[@] || -v EXPLOIT_AVAIL_ROUTERSPLOIT1[@] ]]; then
      if [[ "${lEXPLOIT}" == "No exploit available" ]]; then
        lEXPLOIT="Exploit (Routersploit:"
      else
        lEXPLOIT+=" / Routersploit:"
      fi
      lEXPLOIT_ROUTERSPLOIT=("${EXPLOIT_AVAIL_ROUTERSPLOIT[@]}" "${EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}")

      for lEXPLOIT_RS in "${lEXPLOIT_ROUTERSPLOIT[@]}" ; do
        lEXPLOIT_PATH=$(echo "${lEXPLOIT_RS}" | cut -d: -f1)
        lEXPLOIT_NAME=$(basename -s .py "${lEXPLOIT_PATH}")
        lEXPLOIT+=" ${lEXPLOIT_NAME}"
        if [[ -f "${lEXPLOIT_PATH}" ]] ; then
          # for the web reporter we copy the original metasploit module into the EMBA log directory
          cp "${lEXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/routersploit_""${lEXPLOIT_NAME}".py
          if grep -q Port "${lEXPLOIT_PATH}"; then
            lEXPLOIT+=" (R)"
          fi
        fi
      done

      if [[ ${lEDB} -eq 0 ]]; then
        # only count the routersploit exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${lCVE_VALUE};PS" "${TMP_DIR}"/exploit_cnt.tmp
        lEDB=1
      fi
    fi
  fi

  if [[ ${lKNOWN_EXPLOITED} -eq 1 ]]; then
    lEXPLOIT+=" (X)"
  fi

  if [[ ${lEDB} -eq 1 ]]; then
    lEXPLOIT+=")"
  fi

  # just in case CVSSv3 value is missing -> switch to CVSSv2
  if [[ "${lCVSS_VALUE}" == "NA" ]]; then
    # print_output "[*] Missing CVSSv3 value for vulnerability ${ORANGE}${lCVE_VALUE}${NC} - setting default CVSS to CVSSv2 ${ORANGE}${lCVSSv2_VALUE}${NC}" "no_log"
    lCVSS_VALUE="${lCVSSv2_VALUE}"
    lCVEv2_TMP=1
  fi

  # if this CVE is a kernel verified CVE we add a V to the CVE
  if [[ "${lKERNEL_VERIFIED}" == "yes" ]]; then lCVE_VALUE+=" (V)"; fi
  if [[ "${lBUSYBOX_VERIFIED}" == "yes" ]]; then lCVE_VALUE+=" (V)"; fi

  # we do not deal with output formatting the usual way -> we use printf
  if [[ ! -f "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}" ]]; then
    printf "${GREEN}\t%-20.20s:   %-12.12s:   %-18.18s:  %-10.10s : %-4.4s :   %-15.15s:   %s${NC}\n" "BIN NAME" "BIN VERS" "CVE ID" "CVSS VALUE" "EPSS" "SOURCE" "lEXPLOIT" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
  fi
  if (( $(echo "${lCVSS_VALUE} > 6.9" | bc -l) )); then
    # put a note in the output if we have switched to CVSSv2
    if [[ "${lCVEv2_TMP}" -eq 1 ]]; then lCVSS_VALUE="${lCVSS_VALUE}"" (v2)"; fi
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *Github* || "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY_NAME}" "${lBIN_VERSION}" "${lCVE_VALUE}" "${lCVSS_VALUE}" "${lFIRST_EPSS}" "${lVSOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    else
      printf "${RED}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY_NAME}" "${lBIN_VERSION}" "${lCVE_VALUE}" "${lCVSS_VALUE}" "${lFIRST_EPSS}" "${lVSOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    fi
    ((lHIGH_CVE_COUNTER+=1))
  elif (( $(echo "${lCVSS_VALUE} > 3.9" | bc -l) )); then
    if [[ "${lCVEv2_TMP}" -eq 1 ]]; then lCVSS_VALUE="${lCVSS_VALUE}"" (v2)"; fi
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *Github* || "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY_NAME}" "${lBIN_VERSION}" "${lCVE_VALUE}" "${lCVSS_VALUE}" "${lFIRST_EPSS}" "${lVSOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    else
      printf "${ORANGE}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY_NAME}" "${lBIN_VERSION}" "${lCVE_VALUE}" "${lCVSS_VALUE}" "${lFIRST_EPSS}" "${lVSOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    fi
    ((lMEDIUM_CVE_COUNTER+=1))
  else
    if [[ "${lCVEv2_TMP}" -eq 1 ]]; then lCVSS_VALUE="${lCVSS_VALUE}"" (v2)"; fi
    if [[ "${lEXPLOIT}" == *MSF* || "${lEXPLOIT}" == *EDB\ ID* || "${lEXPLOIT}" == *linux-exploit-suggester* || "${lEXPLOIT}" == *Routersploit* || \
      "${lEXPLOIT}" == *Github* || "${lEXPLOIT}" == *PSS* || "${lEXPLOIT}" == *Snyk* || "${lKNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY_NAME}" "${lBIN_VERSION}" "${lCVE_VALUE}" "${lCVSS_VALUE}" "${lFIRST_EPSS}" "${lVSOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    else
      printf "${GREEN}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY_NAME}" "${lBIN_VERSION}" "${lCVE_VALUE}" "${lCVSS_VALUE}" "${lFIRST_EPSS}" "${lVSOURCE}" "${lEXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    fi
    ((lLOW_CVE_COUNTER+=1))
  fi

  if [[ ${lLOW_CVE_COUNTER} -gt 0 ]]; then
    write_log "${lLOW_CVE_COUNTER}" "${TMP_DIR}"/LOW_CVE_COUNTER.tmp
  fi
  if [[ ${lMEDIUM_CVE_COUNTER} -gt 0 ]]; then
    write_log "${lMEDIUM_CVE_COUNTER}" "${TMP_DIR}"/MEDIUM_CVE_COUNTER.tmp
  fi
  if [[ ${lHIGH_CVE_COUNTER} -gt 0 ]]; then
    write_log "${lHIGH_CVE_COUNTER}" "${TMP_DIR}"/HIGH_CVE_COUNTER.tmp
  fi

  write_csv_log "${lBIN_BINARY}" "${lBIN_VERSION}" "${lCVE_VALUE}" "${lCVSS_VALUE}" "${#EXPLOIT_AVAIL[@]}" "${#EXPLOIT_AVAIL_MSF[@]}" "${#EXPLOIT_AVAIL_TRICKEST[@]}" "${#EXPLOIT_AVAIL_ROUTERSPLOIT[@]}/${#EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}" "${#EXPLOIT_AVAIL_SNYK[@]}" "${#EXPLOIT_AVAIL_PACKETSTORM[@]}" "${lLOCAL}" "${lREMOTE}" "${lDOS}" "${#KNOWN_EXPLOITED_VULNS[@]}" "${lKERNEL_VERIFIED}" "${lFIRST_EPSS:-NA}" "${lFIRST_PERC:-NA}"
}

get_kernel_check() {
  local lS24_LOG="${1:-}"
  local lS25_LOG="${2:-}"
  local lKERNEL_VERSION_S24_ARR=()
  export KERNEL_CVE_EXPLOITS_ARR=()

  if [[ -f "${lS25_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${lS25_LOG}")."
    readarray -t KERNEL_CVE_EXPLOITS_ARR < <(cut -d\; -f1-3 "${lS25_LOG}" | tail -n +2 | sort -u || true)
    # we get something like this: ":linux:linux_kernel;5.10.59;CVE-2021-3490"
  fi
  if [[ -f "${lS24_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${lS24_LOG}")."
    readarray -t lKERNEL_VERSION_S24_ARR < <(cut -d\; -f2 "${lS24_LOG}" | tail -n +2 | sort -u | sed 's/^/:linux:linux_kernel;/' | sed 's/$/;NA/' || true)
    # we get something like this: ":linux:linux_kernel;5.10.59;NA"
    KERNEL_CVE_EXPLOITS_ARR+=( "${lKERNEL_VERSION_S24_ARR[@]}" )
  fi
}

get_busybox_verified() {
  local lS118_CSV_LOG="${1:-}"
  export BUSYBOX_VERIFIED_CVE_ARR=()

  if [[ -f "${lS118_CSV_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${lS118_CSV_LOG}")."
    readarray -t BUSYBOX_VERIFIED_CVE_ARR < <(cut -d\; -f1,3 "${lS118_CSV_LOG}" | tail -n +2 | sort -u || true)
  fi
}

get_kernel_verified() {
  local lS26_LOGS_ARR=("$@")
  local lKERNEL_CVE_VERIFIEDX_ARR=()

  for S26_LOG in "${lS26_LOGS_ARR[@]}"; do
    if [[ -f "${S26_LOG}" ]]; then
      print_output "[*] Collect verified kernel details of module $(basename "${S26_LOG}")."
      readarray -t lKERNEL_CVE_VERIFIEDX_ARR < <(tail -n +2 "${S26_LOG}" | sort -u || true)
    fi
    KERNEL_CVE_VERIFIED+=("${lKERNEL_CVE_VERIFIEDX_ARR[@]}")
  done
  mapfile -t KERNEL_CVE_VERIFIED_VERSION < <(find "${S26_LOG_DIR}" -name "cve_results_kernel_*.csv" -exec cut -d\; -f1 {} \; | grep -v "Kernel version" | sort -u)
}

get_systemmode_emulator() {
  local lL15_LOG="${1:-}"
  export VERSIONS_SYS_EMULATOR_ARR=()

  if [[ -f "${lL15_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${lL15_LOG}")."
    readarray -t VERSIONS_SYS_EMULATOR_ARR < <(cut -d\; -f4 "${lL15_LOG}" | tail -n +2 | sort -u || true)
  fi
}

get_systemmode_webchecks() {
  local lL25_LOG="${1:-}"
  export VERSIONS_SYS_EMULATOR_WEB_ARR=()

  # disabled for now
  if [[ -f "${lL25_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${lL25_LOG}")."
  #  readarray -t VERSIONS_SYS_EMULATOR_WEB_ARR < <(cut -d\; -f4 "${lL25_LOG}" | tail -n +2 | sort -u || true)
  fi
}

get_msf_verified() {
  local lL35_LOG="${1:-}"
  export CVE_L35_DETAILS_ARR=()

  if [[ -f "${lL35_LOG}" ]]; then
    print_output "[*] Collect CVE details of module $(basename "${lL35_LOG}")."
    readarray -t CVE_L35_DETAILS_ARR < <(cut -d\; -f3 "${lL35_LOG}" | tail -n +2 | grep -v "NA" | sort -u || true)
  fi
}

get_uefi_details() {
  local lS02_LOG="${1:-}"
  export CVE_S02_DETAILS_ARR=()

  if [[ -f "${lS02_LOG}" ]]; then
    print_output "[*] Collect CVE details of module $(basename "${lS02_LOG}")."
    readarray -t CVE_S02_DETAILS_ARR < <(cut -d\; -f3 "${lS02_LOG}" | tail -n +2 | sort -u | grep "^CVE-" || true)
  fi
}

get_sbom_package_details() {
  local lS08_LOG="${1:-}"
  export VERSIONS_S08_PACKAGE_DETAILS_ARR=()
  export WAIT_PIDS_CVE_COPY_ARR=()

  if [[ -f "${lS08_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${lS08_LOG}")."
    readarray -t VERSIONS_S08_PACKAGE_DETAILS_ARR < <(cut -d\; -f6 "${lS08_LOG}" | tail -n +2 | sort -u | grep -v "NA" | tr ';' ':' | tr ' ' '_' || true)

    # prepare a smaller subset of cve sources
    # we write only the binary names to a file and use this file later on for grep
    # in the file we have entries like "cpe:2.3:.*binary_name"
    cut -d\; -f6 "${S08_CSV_LOG}" | tail -n +2 | cut -d : -f3 | grep -v NA | uniq | sed 's/^/cpe:2.3:.*/' > "${LOG_PATH_MODULE}"/cpe_search_grep.tmp || true
    # next step is to search for possible CVE source files and copy it to a temp directory. This temp directory will
    # be used for searching the real CVEs later on
    mkdir "${LOG_PATH_MODULE}"/cpe_search_tmp_dir || true
    (grep -r -l -f "${LOG_PATH_MODULE}"/cpe_search_grep.tmp "${NVD_DIR}" | xargs cp -f -t "${LOG_PATH_MODULE}"/cpe_search_tmp_dir || true)&
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    WAIT_PIDS_CVE_COPY_ARR=( "${lTMP_PID}" )
  fi
}
