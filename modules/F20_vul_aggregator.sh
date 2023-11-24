#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Aggregates all found version numbers together from S06, S08, S09, S25, S26,
#               S115/S116 and L15.
#               The versions are used for identification of known vulnerabilities cve-search,
#               finally it creates a list of exploits that are matching for the CVEs.

F20_vul_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final vulnerability aggregator"

  pre_module_reporter "${FUNCNAME[0]}"
  print_ln

  if [[ -d "${LOG_PATH_MODULE}"/cve_sum ]]; then
    rm -r "${LOG_PATH_MODULE}"/cve_sum
  fi
  mkdir "${LOG_PATH_MODULE}"/cve_sum

  if [[ -d "${LOG_PATH_MODULE}"/exploit ]]; then
    rm -r "${LOG_PATH_MODULE}"/exploit
  fi
  mkdir "${LOG_PATH_MODULE}"/exploit

  KERNELV=0
  HIGH_CVE_COUNTER=0
  MEDIUM_CVE_COUNTER=0
  LOW_CVE_COUNTER=0
  CVE_SEARCHSPLOIT=0
  RS_SEARCH=0
  MSF_SEARCH=0
  TRICKEST_SEARCH=0
  CVE_SEARCHSPLOIT=0
  MSF_INSTALL_PATH="/usr/share/metasploit-framework"

  local FOUND_CVE=0
  local S26_LOGS_ARR=()

  CVE_AGGREGATOR_LOG="f20_vul_aggregator.txt"

  local S02_LOG="${CSV_DIR}"/s02_uefi_fwhunt.csv
  local S06_LOG="${CSV_DIR}"/s06_distribution_identification.csv
  local S08_LOG="${CSV_DIR}"/s08_package_mgmt_extractor.csv
  local S09_LOG="${CSV_DIR}"/s09_firmware_base_version_check.csv
  local S25_LOG="${CSV_DIR}"/s25_kernel_check.csv
  local S26_LOG_DIR="${LOG_DIR}""/s26_kernel_vuln_verifier/"
  local S116_LOG="${CSV_DIR}"/s116_qemu_version_detection.csv
  local L15_LOG="${CSV_DIR}"/l15_emulated_checks_nmap.csv
  local L25_LOG="${CSV_DIR}"/l25_web_checks.csv
  local L35_LOG="${CSV_DIR}"/l35_metasploit_check.csv

  if [[ -d "${S26_LOG_DIR}" ]]; then
    mapfile -t S26_LOGS_ARR < <(find "${S26_LOG_DIR}" -name "cve_results_kernel_*.csv")
  fi

  local CVE_MINIMAL_LOG="${LOG_PATH_MODULE}"/CVE_minimal.txt
  local EXPLOIT_OVERVIEW_LOG="${LOG_PATH_MODULE}"/exploits-overview.txt

  export KERNEL_CVE_VERIFIED=()
  export KERNEL_CVE_VERIFIED_VERSION=()

  if [[ -f "${CVE_WHITELIST}" ]] && [[ $(grep -c -E "CVE-[0-9]+-[0-9]+" "${CVE_WHITELIST}") -gt 0 ]]; then
    print_output "[!] WARNING: CVE whitelisting activated"
  fi
  if [[ -f "${CVE_BLACKLIST}" ]] && [[ $(grep -c -E "CVE-[0-9]+-[0-9]+" "${CVE_BLACKLIST}") -gt 0 ]]; then
    print_output "[!] WARNING: CVE blacklisting activated"
  fi

  if [[ -f ${PATH_CVE_SEARCH} ]]; then
    print_output "[*] Aggregate vulnerability details"

    # get the kernel version from s25:
    get_kernel_check "${S25_LOG}"
    # if we found a kernel in the kernel checker module we are going to use this kernel version (usually this version is better)
    # [+] Found Version details (base check): Linux kernel version 2.6.33
    # vs:
    # [+] Found Version details (kernel): Linux kernel version 2.6.33.2
    if [[ -v KERNEL_CVE_EXPLOITS[@] ]]; then
      if [[ ${#KERNEL_CVE_EXPLOITS[@]} -ne 0 ]]; then
        # then we have found a kernel in our s25 kernel module
        KERNELV=1
      fi
    fi

    if [[ -v S26_LOGS_ARR ]]; then
      get_kernel_verified "${S26_LOGS_ARR[@]}"
    fi

    get_uefi_details "${S02_LOG}"
    get_firmware_details "${S06_LOG}"
    get_package_details "${S08_LOG}"
    get_firmware_base_version_check "${S09_LOG}"
    get_usermode_emulator "${S116_LOG}"
    get_systemmode_emulator "${L15_LOG}"
    get_systemmode_webchecks "${L25_LOG}"
    get_msf_verified "${L35_LOG}"

    aggregate_versions

    CVE_SEARCH=1
    if [[ "${CVE_SEARCH}" -eq 1 ]]; then
      if command -v cve_searchsploit > /dev/null ; then
        CVE_SEARCHSPLOIT=1
      fi
      if [[ -f "${MSF_DB_PATH}" ]]; then
        MSF_SEARCH=1
      fi
      if [[ -f "${CONFIG_DIR}"/routersploit_cve-db.txt || -f "${CONFIG_DIR}"/routersploit_exploit-db.txt ]]; then
        RS_SEARCH=1
      fi
      if [[ -f "${CONFIG_DIR}"/PS_PoC_results.csv ]]; then
        PS_SEARCH=1
      fi
      if [[ -f "${CONFIG_DIR}"/Snyk_PoC_results.csv ]]; then
        SNYK_SEARCH=1
      fi

      write_csv_log "BINARY" "VERSION" "CVE identifier" "CVSS rating" "exploit db exploit available" "metasploit module" "trickest PoC" "Routersploit" "Snyk PoC" "Packetstormsecurity PoC" "local exploit" "remote exploit" "DoS exploit" "known exploited vuln" "kernel vulnerability verified"

      if [[ "${#VERSIONS_AGGREGATED[@]}" -gt 0 ]]; then
        generate_cve_details_versions "${VERSIONS_AGGREGATED[@]}"
      fi
      if [[ "${#CVES_AGGREGATED[@]}" -gt 0 ]]; then
        generate_cve_details_cves "${CVES_AGGREGATED[@]}"
      fi

      generate_special_log "${CVE_MINIMAL_LOG}" "${EXPLOIT_OVERVIEW_LOG}"
    else
      print_cve_search_failure
      CVE_SEARCH=0
    fi
  fi

  FOUND_CVE=$(sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "${LOG_FILE}" | grep -c -E "\[\+\]\ Found\ " || true)

  write_log ""
  write_log "[*] Statistics:${CVE_SEARCH}"

  module_end_log "${FUNCNAME[0]}" "${FOUND_CVE}"
}

aggregate_versions() {
  sub_module_title "Software inventory generation."

  local VERSION=""
  export VERSIONS_AGGREGATED=()
  VERSIONS_KERNEL=()

  if [[ ${#VERSIONS_STAT_CHECK[@]} -gt 0 || ${#VERSIONS_EMULATOR[@]} -gt 0 || ${#KERNEL_CVE_EXPLOITS[@]} -gt 0 || ${#VERSIONS_SYS_EMULATOR[@]} -gt 0 || \
    ${#VERSIONS_S06_FW_DETAILS[@]} -gt 0 || ${#VERSIONS_SYS_EMULATOR_WEB[@]} -gt 0 || "${#CVE_S02_DETAILS[@]}" -gt 0 || "${#CVE_L35_DETAILS[@]}" -gt 0 || \
    ${#KERNEL_CVE_VERIFIED[@]} -gt 0 ]]; then

    print_output "[*] Software inventory initial overview:"
    write_anchor "softwareinventoryinitialoverview"
    for VERSION in "${VERSIONS_S06_FW_DETAILS[@]}"; do
      if [ -z "${VERSION}" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}firmware details check${GREEN}): ""${ORANGE}${VERSION}${NC}"
    done
    for VERSION in "${VERSIONS_S08_PACKAGE_DETAILS[@]}"; do
      if [ -z "${VERSION}" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}package management system check${GREEN}): ""${ORANGE}${VERSION}${NC}"
    done
    for VERSION in "${VERSIONS_STAT_CHECK[@]}"; do
      if [ -z "${VERSION}" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}statical check${GREEN}): ""${ORANGE}${VERSION}${NC}"
    done
    for VERSION in "${VERSIONS_EMULATOR[@]}"; do
      if [ -z "${VERSION}" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}emulator${GREEN}): ""${ORANGE}${VERSION}${NC}"
    done
    for VERSION in "${VERSIONS_SYS_EMULATOR[@]}"; do
      if [ -z "${VERSION}" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}system emulator${GREEN}): ""${ORANGE}${VERSION}${NC}"
    done
    for VERSION in "${VERSIONS_SYS_EMULATOR_WEB[@]}"; do
      if [ -z "${VERSION}" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}system emulator - web${GREEN}): ""${ORANGE}${VERSION}${NC}"
    done

    for VERSION in "${KERNEL_CVE_EXPLOITS[@]}"; do
      if [ -z "${VERSION}" ]; then
        continue
      fi
      VERSION="$(echo "${VERSION}" | cut -d\; -f1-2 | tr ';' ':')"
      print_output "[+] Found Version details (${ORANGE}kernel${GREEN}): ""${ORANGE}${VERSION}${NC}"
      # we ensure that we search for the correct kernel version by adding a : at the end of the search string
      VERSION=${VERSION/%/:}
      VERSIONS_KERNEL+=( "${VERSION}" )
      # print_output "[+] Added modfied Kernel Version details (${ORANGE}kernel$GREEN): ""$ORANGE$VERSION$NC"
    done

    # details from module s26
    for VERSION in "${KERNEL_CVE_VERIFIED_VERSION[@]}"; do
      if [ -z "${VERSION}" ]; then
        continue
      fi
      VERSION="$(echo "${VERSION}" | cut -d\; -f1 | sed 's/^/kernel:/')"
      print_output "[+] Found Version details (${ORANGE}kernel - with verified vulnerability details${GREEN}): ""${ORANGE}${VERSION}${NC}"
      # we ensure that we search for the correct kernel version by adding a : at the end of the search string
      VERSION=${VERSION/%/:}
      VERSIONS_KERNEL+=( "${VERSION}" )
      # print_output "[+] Added modfied Kernel Version details (${ORANGE}kernel$GREEN): ""$ORANGE$VERSION$NC"
    done

    for CVE_ENTRY in "${CVE_S02_DETAILS[@]}"; do
      if [ -z "${CVE_ENTRY}" ]; then
        continue
      fi
      if ! [[ "${CVE_ENTRY}" == *CVE-[0-9]* ]]; then
        print_output "[-] WARNING: Broken CVE identifier found: ${ORANGE}${VERSION}${NC}"
        continue
      fi
      print_output "[+] Found CVE details (${ORANGE}binarly UEFI module${GREEN}): ""${ORANGE}${CVE_ENTRY}${NC}"
    done

    for CVE_ENTRY in "${CVE_L35_DETAILS[@]}"; do
      if [ -z "${CVE_ENTRY}" ]; then
        continue
      fi
      if ! [[ "${CVE_ENTRY}" == *CVE-[0-9]* ]]; then
        print_output "[-] WARNING: Broken CVE identifier found: ${ORANGE}${VERSION}${NC}"
        continue
      fi
      print_output "[+] Found CVE details (${ORANGE}verified Metasploit exploits${GREEN}): ""${ORANGE}${CVE_ENTRY}${NC}"
    done

    print_ln
    VERSIONS_AGGREGATED=("${VERSIONS_EMULATOR[@]}" "${VERSIONS_KERNEL[@]}" "${VERSIONS_STAT_CHECK[@]}" "${VERSIONS_SYS_EMULATOR[@]}" "${VERSIONS_S06_FW_DETAILS[@]}" "${VERSIONS_S08_PACKAGE_DETAILS[@]}" "${VERSIONS_SYS_EMULATOR_WEB[@]}")

    # if we get from a module CVE details we also need to handle them
    CVES_AGGREGATED=("${CVE_S02_DETAILS[@]}" "${CVE_L35_DETAILS[@]}")
  fi

  # sorting and unique our versions array:
  eval "CVES_AGGREGATED=($(for i in "${CVES_AGGREGATED[@]}" ; do echo "\"${i}\"" ; done | sort -u))"
  eval "VERSIONS_AGGREGATED=($(for i in "${VERSIONS_AGGREGATED[@]}" ; do echo "\"${i}\"" ; done | sort -u))"

  if [[ -v VERSIONS_AGGREGATED[@] ]]; then
    for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
      if [ -z "${VERSION}" ]; then
        continue
      fi
      if [[ "${VERSION}" == *" "* ]]; then
        print_output "[-] WARNING: Broken version identifier found: ${ORANGE}${VERSION}${NC}"
        continue
      fi
      if ! [[ "${VERSION}" == *[0-9]* ]]; then
        print_output "[-] WARNING: Broken version identifier found: ${ORANGE}${VERSION}${NC}"
        continue
      fi
      if ! [[ "${VERSION}" == *":"* ]]; then
        print_output "[-] WARNING: Broken version identifier found: ${ORANGE}${VERSION}${NC}"
        continue
      fi
      echo "${VERSION}" >> "${LOG_PATH_MODULE}"/versions.tmp
    done
  fi

  if [[ -f "${LOG_PATH_MODULE}"/versions.tmp ]]; then
    # on old kernels it takes a huge amount of time to query all kernel CVE's. So, we move the kernel entry to the begin of our versions array
    mapfile -t KERNELS < <(grep kernel "${LOG_PATH_MODULE}"/versions.tmp | sort -u || true)
    grep -v kernel "${LOG_PATH_MODULE}"/versions.tmp | sort -u > "${LOG_PATH_MODULE}"/versions1.tmp || true

    for KERNEL in "${KERNELS[@]}"; do
      if [[ -f "${LOG_PATH_MODULE}"/versions1.tmp ]]; then
        if [[ $( wc -l "${LOG_PATH_MODULE}"/versions1.tmp | awk '{print $1}') -eq 0 ]] ; then
          echo "${KERNEL}" > "${LOG_PATH_MODULE}"/versions1.tmp
        else
          sed -i "1s/^/${KERNEL}\n/" "${LOG_PATH_MODULE}"/versions1.tmp
        fi
      fi
    done

    if [[ -f "${LOG_PATH_MODULE}"/versions1.tmp ]]; then
      mapfile -t VERSIONS_AGGREGATED < <(cat "${LOG_PATH_MODULE}"/versions1.tmp)
    fi
    rm "${LOG_PATH_MODULE}"/versions*.tmp 2>/dev/null

    # leave this here for debugging reasons
    if [[ ${#VERSIONS_AGGREGATED[@]} -ne 0 ]]; then
      print_bar ""
      print_output "[*] Software inventory aggregated:"
      for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
        print_output "[+] Found Version details (${ORANGE}aggregated${GREEN}): ""${ORANGE}${VERSION}${NC}"
      done
      for CVE_ENTRY in "${CVES_AGGREGATED[@]}"; do
        print_output "[+] Found CVE details (${ORANGE}aggregated${GREEN}): ""${ORANGE}${CVE_ENTRY}${NC}"
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
  local CVE_MINIMAL_LOG="${1:-}"
  local EXPLOIT_OVERVIEW_LOG="${2:-}"

  if [[ $(grep -c "Found.*CVEs\ .*and" "${LOG_FILE}" || true) -gt 0 ]]; then
    sub_module_title "Minimal report of exploits and CVE's."
    write_anchor "minimalreportofexploitsandcves"

    local EXPLOIT_HIGH=0
    local EXPLOIT_MEDIUM=0
    local EXPLOIT_LOW=0
    local KNOWN_EXPLOITED_VULNS=()
    local KNOWN_EXPLOITED_VULN=""
    local FILES=()
    local FILE=""
    local NAME=""
    local CVE_VALUES=""
    local EXPLOIT_=""
    local EXPLOITS_AVAIL=()

    readarray -t FILES < <(find "${LOG_PATH_MODULE}"/ -maxdepth 1 -type f -name "*.txt")
    print_ln
    print_output "[*] CVE log file generated."
    write_link "${CVE_MINIMAL_LOG}"
    print_ln

    for FILE in "${FILES[@]}"; do
      if [[ "${FILE}" == *"F20_summary"* ]]; then
        continue
      fi
      if [[ "${FILE}" == *"exploits-overview"* ]]; then
        continue
      fi
      local CVE_OUTPUT=""
      NAME=$(basename "${FILE}" | sed -e 's/\.txt//g' | sed -e 's/_/\ /g')
      mapfile -t CVE_VALUES < <(cut -d ":" -f1 "${FILE}") # | paste -s -d ',' || true)
      # we need to check the whitelisted and blacklisted CVEs here:
      for CVE_VALUE in "${CVE_VALUES[@]}"; do
        if grep -q "^${CVE_VALUE}$" "${CVE_BLACKLIST}"; then
          continue
        fi
        if [[ $(grep -E -c "^CVE-[0-9]+-[0-9]+$" "${CVE_WHITELIST}") -gt 0 ]]; then
          if ! grep -q ^"${CVE_VALUE}"$ "${CVE_WHITELIST}"; then
            continue
          fi
        fi
        CVE_OUTPUT="${CVE_OUTPUT}"",""${CVE_VALUE}"
      done
      if [[ "${CVE_OUTPUT}" == *CVE-* ]]; then
        CVE_OUTPUT=${CVE_OUTPUT#,}
        print_output "[*] CVE details for ${GREEN}${NAME}${NC}:\\n"
        print_output "${CVE_OUTPUT}"
        echo -e "\n[*] CVE details for ${GREEN}${NAME}${NC}:" >> "${CVE_MINIMAL_LOG}"
        echo "${CVE_OUTPUT}" >> "${CVE_MINIMAL_LOG}"
        print_ln
      fi
    done

    echo -e "\n[*] Exploit summary:" >> "${EXPLOIT_OVERVIEW_LOG}"
    grep -E "Exploit\ \(" "${LOG_DIR}"/"${CVE_AGGREGATOR_LOG}" | sort -t : -k 4 -h -r | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >> "${EXPLOIT_OVERVIEW_LOG}" || true

    mapfile -t EXPLOITS_AVAIL < <(grep -E "Exploit\ \(" "${LOG_DIR}"/"${CVE_AGGREGATOR_LOG}" | sort -t : -k 4 -h -r || true)
    if [[ "${#EXPLOITS_AVAIL[@]}" -gt 0 ]]; then
      print_ln
      print_output "[*] Minimal exploit summary file generated."
      write_link "${EXPLOIT_OVERVIEW_LOG}"
      print_ln
    fi

    for EXPLOIT_ in "${EXPLOITS_AVAIL[@]}"; do
      # remove color codes:
      EXPLOIT_=$(echo "${EXPLOIT_}" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
      # extract CVSS value:
      CVSS_VALUE=$(echo "${EXPLOIT_}" | sed -E 's/.*[[:blank:]]CVE-[0-9]{4}-[0-9]+[[:blank:]]//g' | cut -d: -f2 | sed -E 's/\ \(v2\)//g' | sed -e 's/[[:blank:]]//g' | tr -dc '[:print:]')

      if (( $(echo "${CVSS_VALUE} > 6.9" | bc -l) )); then
        print_output "${RED}${EXPLOIT_}${NC}"
        ((EXPLOIT_HIGH+=1))
      elif (( $(echo "${CVSS_VALUE} > 3.9" | bc -l) )); then
        print_output "${ORANGE}${EXPLOIT_}${NC}"
        ((EXPLOIT_MEDIUM+=1))
      else
        print_output "${GREEN}${EXPLOIT_}${NC}"
        ((EXPLOIT_LOW+=1))
      fi
    done

    if [[ -f "${LOG_PATH_MODULE}"/exploit/known_exploited_vulns.log ]]; then
      mapfile -t KNOWN_EXPLOITED_VULNS < <(grep -E "known exploited" "${LOG_PATH_MODULE}"/exploit/known_exploited_vulns.log || true 2>/dev/null)
      if [[ -v KNOWN_EXPLOITED_VULNS[@] ]]; then
        print_ln
        print_output "[*] Summary of known exploited vulnerabilities:"
        write_link "${LOG_PATH_MODULE}/exploit/known_exploited_vulns.log"
        for KNOWN_EXPLOITED_VULN in "${KNOWN_EXPLOITED_VULNS[@]}"; do
          print_output "${KNOWN_EXPLOITED_VULN}"
        done
        print_ln
      fi
    fi

    echo "${EXPLOIT_HIGH}" > "${TMP_DIR}"/EXPLOIT_HIGH_COUNTER.tmp
    echo "${EXPLOIT_MEDIUM}" > "${TMP_DIR}"/EXPLOIT_MEDIUM_COUNTER.tmp
    echo "${EXPLOIT_LOW}" > "${TMP_DIR}"/EXPLOIT_LOW_COUNTER.tmp
    echo "${#KNOWN_EXPLOITED_VULNS[@]}" > "${TMP_DIR}"/KNOWN_EXPLOITED_COUNTER.tmp
  fi
}

generate_cve_details_cves() {
  sub_module_title "Collect CVE and exploit details from CVEs."
  write_anchor "collectcveandexploitdetails_cves"

  local CVES_AGGREGATED=("$@")
  local CVE_ENTRY=""
  CVE_COUNTER=0

  for CVE_ENTRY in "${CVES_AGGREGATED[@]}"; do
    if [[ "${THREADED}" -eq 1 ]]; then
      # cve-search/mongodb calls called in parallel
      cve_db_lookup_cve "${CVE_ENTRY}" &
      WAIT_PIDS_F19+=( "$!" )
      max_pids_protection "${MAX_MODS}" "${WAIT_PIDS_F19[@]}"
    else
      cve_db_lookup_cve "${CVE_ENTRY}"
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_F19[@]}"
}

generate_cve_details_versions() {
  sub_module_title "Collect CVE and exploit details from versions."
  write_anchor "collectcveandexploitdetails"

  CVE_COUNTER=0
  local VERSIONS_AGGREGATED=("$@")
  local BIN_VERSION=""

  for BIN_VERSION in "${VERSIONS_AGGREGATED[@]}"; do
    # BIN_VERSION is something like "binary:1.2.3"
    # we can use this format in cve-search
    if [[ "${THREADED}" -eq 1 ]]; then
      # cve-search/mongodb calls called in parallel
      cve_db_lookup_version "${BIN_VERSION}" &
      WAIT_PIDS_F19+=( "$!" )
      max_pids_protection "${MAX_MODS}" "${WAIT_PIDS_F19[@]}"
    else
      cve_db_lookup_version "${BIN_VERSION}"
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_F19[@]}"
}

cve_db_lookup_cve () {
  local CVE_ENTRY="${1:-}"
  local CVE_ID=""
  local CVE_V2=""
  local CVE_V31=""
  print_output "[*] CVE database lookup with CVE information: ${ORANGE}${CVE_ENTRY}${NC}" "no_log"

  CVE_SOURCE=$(find "${NVD_DIR}" -name "${CVE_ENTRY}.json" | sort -u)
  if [[ -f "${CVE_SOURCE}" ]]; then
    CVE_ID=$(jq -r '.id' "${CVE_SOURCE}")
    CVE_V2=$(jq -r '.metrics.cvssMetricV2[]?.cvssData.baseScore' "${CVE_SOURCE}")
    CVE_V31=$(jq -r '.metrics.cvssMetricV31[]?.cvssData.baseScore' "${CVE_SOURCE}")
    echo "${CVE_ID}:${CVE_V2:-"NA"}:${CVE_V31:-"NA"}" > "${LOG_PATH_MODULE}"/"${CVE_ENTRY}".txt || true
  fi

  if [[ "${THREADED}" -eq 1 ]]; then
    cve_extractor "${CVE_ENTRY}" &
    WAIT_PIDS_F19_2+=( "$!" )
  else
    cve_extractor "${CVE_ENTRY}"
  fi

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_F19_2[@]}"
}

cve_db_lookup_version() {
  # BIN_VERSION_ is something like "binary:1.2.3"
  local BIN_VERSION_="${1:-}"
  local CVE_ID=""
  local CVE_V2=""
  local CVE_V31=""

  # we create something like "binary_1.2.3" for log paths
  local VERSION_PATH="${BIN_VERSION_//:/_}"
  print_output "[*] CVE database lookup with version information: ${ORANGE}${BIN_VERSION_}${NC}" "no_log"

  mapfile -t CVE_VER_SOURCES_ARR < <(grep -l -r "cpe.*${BIN_VERSION_}" "${NVD_DIR}")

  if [[ "${BIN_VERSION_}" == *"dlink"* ]]; then
    # dlink extrawurst: dlink vs d-link
    # do a second cve-database check
    VERSION_SEARCHx="$(echo "${BIN_VERSION_}" | sed 's/dlink/d-link/' | sed 's/_firmware//')"
    print_output "[*] CVE database lookup with version information: ${ORANGE}${VERSION_SEARCHx}${NC}" "no_log"
    mapfile -t CVE_VER_SOURCES_ARR_DLINK < <(grep -l -r "cpe.*${VERSION_SEARCHx}" "${NVD_DIR}")
    CVE_VER_SOURCES_ARR+=( "${CVE_VER_SOURCES_ARR_DLINK[@]}" )
  fi

  eval "CVE_VER_SOURCES_ARR=($(for i in "${CVE_VER_SOURCES_ARR[@]}" ; do echo "\"${i}\"" ; done | sort -u))"

  for CVE_VER_SOURCES_FILE in "${CVE_VER_SOURCES_ARR[@]}"; do
    CVE_ID=$(jq -r '.id' "${CVE_VER_SOURCES_FILE}")
    CVE_V2=$(jq -r '.metrics.cvssMetricV2[]?.cvssData.baseScore' "${CVE_VER_SOURCES_FILE}")
    CVE_V31=$(jq -r '.metrics.cvssMetricV31[]?.cvssData.baseScore' "${CVE_VER_SOURCES_FILE}")
    if [[ -f "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt ]]; then
      # check if we have already an entry for this CVE - if not, we will write it to the output file
      if ! grep -q "^${CVE_ID}:" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt; then
        echo "${CVE_ID}:${CVE_V2:-"NA"}:${CVE_V31:-"NA"}" >> "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt || true
      fi
    else
      echo "${CVE_ID}:${CVE_V2:-"NA"}:${CVE_V31:-"NA"}" > "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt || true
    fi
  done

  if [[ "${THREADED}" -eq 1 ]]; then
    cve_extractor "${BIN_VERSION_}" &
    WAIT_PIDS_F19_2+=( "$!" )
  else
    cve_extractor "${BIN_VERSION_}"
  fi

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_F19_2[@]}"
}

cve_extractor() {
  # VERSION_orig is usually the BINARY_NAME:VERSION
  # in some cases it is only the CVE-Identifier
  local VERSION_orig="${1:-}"
  local VERSION=""
  local BINARY=""
  local CVE_VALUE=""
  local CVSS_VALUE=""
  local VSOURCE="unknown"
  local EXPLOIT_AVAIL=()
  local EXPLOIT_AVAIL_MSF=()
  local EXPLOIT_AVAIL_TRICKEST=()
  local EXPLOIT_AVAIL_ROUTERSPLOIT=()
  local EXPLOIT_AVAIL_ROUTERSPLOIT1=()
  local KNOWN_EXPLOITED_VULNS=()
  local KNOWN_EXPLOITED=0
  local LOCAL=0
  local REMOTE=0
  local DOS=0
  local CVEs_OUTPUT=()
  local CVE_OUTPUT=""
  local S26_LOG_DIR="${LOG_DIR}""/s26_kernel_vuln_verifier"
  local KERNEL_VERIFIED_VULN=0

  if ! [[ "${VERSION_orig}" == "CVE-"* ]]; then
    if [[ "$(echo "${VERSION_orig}" | sed 's/:$//' | grep -o ":" | wc -l || true)" -eq 1 ]]; then
      BINARY="$(echo "${VERSION_orig}" | cut -d ":" -f1)"
      VERSION="$(echo "${VERSION_orig}" | cut -d ":" -f2)"
    else
      # DETAILS="$(echo "$VERSION_orig" | cut -d ":" -f1)"
      BINARY="$(echo "${VERSION_orig}" | cut -d ":" -f2)"
      VERSION="$(echo "${VERSION_orig}" | cut -d ":" -f3-)"
    fi
    local VERSION_PATH="${VERSION_orig//:/_}"
    AGG_LOG_FILE="${VERSION_PATH}".txt
  else
    AGG_LOG_FILE="${VERSION_orig}".txt
  fi

  # VSOURCE is used to track the source of version details, this is relevant for the
  # final report. With this in place we know if it is from live testing via the network
  # or if it is found via static analysis or via user-mode emulation
  if [[ -v S06_LOG && -v S09_LOG ]]; then
    if grep -q "${VERSION_orig}" "${S06_LOG}" 2>/dev/null || grep -q "${VERSION_orig}" "${S09_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="STAT"
      else
        VSOURCE="${VSOURCE}""/STAT"
      fi
    fi
  fi

  if [[ -v S25_LOG ]]; then
    if [[ "${BINARY}" == *"kernel"* ]]; then
      if grep -q "kernel;${VERSION};" "${S25_LOG}" 2>/dev/null; then
        if [[ "${VSOURCE}" == "unknown" ]]; then
          VSOURCE="STAT"
        elif ! [[ "${VSOURCE}" =~ .*STAT.* ]]; then
          VSOURCE="${VSOURCE}""/STAT"
        fi
      fi
    fi
  fi

  if [[ -v S116_LOG ]]; then
    if grep -q "${VERSION_orig}" "${S116_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="UEMU"
      else
        VSOURCE="${VSOURCE}""/UEMU"
      fi
    fi
  fi

  if [[ -v S02_LOG ]]; then
    if grep -q "${VERSION_orig}" "${S02_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="FwHunt"
      else
        VSOURCE="${VSOURCE}""/FwHunt"
      fi
      BINARY="UEFI firmware"
      VERSION="unknown"
    fi
  fi

  if [[ -v L35_LOG ]]; then
    if grep -q "${VERSION_orig}" "${L35_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="MSF verified"
      else
        VSOURCE="${VSOURCE}""/MSF verified"
      fi
      BINARY="unknown"
      VERSION="unknown"
    fi
  fi

  if [[ -v S08_LOG ]]; then
    if grep -q "${BINARY};.*${VERSION}" "${S08_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="PACK"
      else
        VSOURCE="${VSOURCE}""/PACK"
      fi
    fi
  fi

  if [[ -v L15_LOG && -v L25_LOG ]]; then
    if grep -q "${VERSION_orig}" "${L15_LOG}" 2>/dev/null || grep -q "${VERSION_orig}" "${L25_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="SEMU"
      else
        VSOURCE="${VSOURCE}""/SEMU"
      fi
    fi
  fi


  EXPLOIT_COUNTER_VERSION=0
  CVE_COUNTER_VERSION=0
  if [[ -f "${LOG_PATH_MODULE}"/"${AGG_LOG_FILE}" ]]; then
    readarray -t CVEs_OUTPUT < "${LOG_PATH_MODULE}"/"${AGG_LOG_FILE}" || true
  fi

  # if cve-search does not show results we could use the results of linux-exploit-suggester
  # but in our experience these results are less accurate as the results from cve-search.
  # Show me that I'm wrong and we could include and adjust the imports from s25 here:
  # On the other hand, do not forget that we are also using the s25 results if we can find the
  # same CVE here via version detection.

  # if [[ "${BINARY}" == *kernel* ]]; then
  #  if [[ -f "${S25_LOG}" ]]; then
  #    for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
  #      KCVE_VALUE=$(echo "${KERNEL_CVE_EXPLOIT}" | cut -d\; -f3)
  #    done
  #  fi
  # fi

  if [[ -f "${LOG_PATH_MODULE}"/"${AGG_LOG_FILE}" ]]; then
    if [[ "${#CVEs_OUTPUT[@]}" == 0 ]]; then
      write_csv_log "${BINARY}" "${VERSION}" "${CVE_VALUE:-NA}" "${CVSS_VALUE:-NA}" "${#EXPLOIT_AVAIL[@]}" "${#EXPLOIT_AVAIL_MSF[@]}" "${#EXPLOIT_AVAIL_TRICKEST[@]}" "${#EXPLOIT_AVAIL_ROUTERSPLOIT[@]}/${#EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}" "${EXPLOIT_AVAIL_SNYK[@]}" "${EXPLOIT_AVAIL_PACKETSTORM[@]}" "${LOCAL:-NA}" "${REMOTE:-NA}" "${DOS:-NA}" "${#KNOWN_EXPLOITED_VULNS[@]}" "${KERNEL_VERIFIED:-NA}"
    fi
    for CVE_OUTPUT in "${CVEs_OUTPUT[@]}"; do
      local CVEv2_TMP=0
      local KERNEL_VERIFIED="no"
      CVE_VALUE=$(echo "${CVE_OUTPUT}" | cut -d: -f1)

      # if we find a blacklist file we check if the current CVE value is in the blacklist
      # if we find it this CVE is not further processed
      if [[ -f "${CVE_BLACKLIST}" ]]; then
        if grep -q ^"${CVE_VALUE}"$ "${CVE_BLACKLIST}"; then
          print_output "[*] ${ORANGE}${CVE_VALUE}${NC} for ${ORANGE}${BINARY}${NC} blacklisted and ignored." "no_log"
          continue
        fi
      fi
      # if we find a whitelist file we check if the current CVE value is in the whitelist
      # only if we find this CVE in the whitelist it is further processed
      if [[ -f "${CVE_WHITELIST}" ]]; then
        # do a quick check if there is some data in the whitelist config file
        if [[ $(grep -E -c "^CVE-[0-9]+-[0-9]+$" "${CVE_WHITELIST}") -gt 0 ]]; then
          if ! grep -q ^"${CVE_VALUE}"$ "${CVE_WHITELIST}"; then
            print_output "[*] ${ORANGE}${CVE_VALUE}${NC} for ${ORANGE}${BINARY}${NC} not in whitelist -> ignored." "no_log"
            continue
          fi
        fi
      fi

      ((CVE_COUNTER+=1))
      ((CVE_COUNTER_VERSION+=1))
      KNOWN_EXPLOITED=0
      CVSSv2_VALUE=$(echo "${CVE_OUTPUT}" | cut -d: -f2)
      CVSS_VALUE=$(echo "${CVE_OUTPUT}" | cut -d: -f3)

      # check if the CVE is known as a knwon exploited vulnerability:
      if [[ -f "${KNOWN_EXP_CSV}" ]]; then
        if grep -q \""${CVE_VALUE}"\", "${KNOWN_EXP_CSV}"; then
          print_output "[+] ${ORANGE}WARNING:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a known exploited vulnerability."
          echo -e "[+] ${ORANGE}WARNING:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a known exploited vulnerability." >> "${LOG_PATH_MODULE}"/exploit/known_exploited_vulns.log
          KNOWN_EXPLOITED=1
        fi
      fi

      # default value
      EXPLOIT="No exploit available"

      EDB=0
      # as we already know about a bunch of kernel exploits - lets search them first
      if [[ "${BINARY}" == *kernel* ]]; then
        for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
          KERNEL_CVE_EXPLOIT=$(echo "${KERNEL_CVE_EXPLOIT}" | cut -d\; -f3)
          if [[ "${KERNEL_CVE_EXPLOIT}" == "${CVE_VALUE}" ]]; then
            EXPLOIT="Exploit (linux-exploit-suggester"
            ((EXPLOIT_COUNTER_VERSION+=1))
            EDB=1
          fi
        done

        if [[ -f "${S26_LOG_DIR}"/cve_results_kernel_"${VERSION}".csv ]]; then
          # check if the current CVE is a verified kernel CVE from s26 module
          if grep -q ";${CVE_VALUE};.*;.*;1;1" "${S26_LOG_DIR}"/cve_results_kernel_"${VERSION}".csv; then
            print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols and kernel configuration${GREEN})!"
            ((KERNEL_VERIFIED_VULN+=1))
            KERNEL_VERIFIED="yes"
          fi
          if grep -q ";${CVE_VALUE};.*;.*;1;0" "${S26_LOG_DIR}"/cve_results_kernel_"${VERSION}".csv; then
            print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols${GREEN})!"
            ((KERNEL_VERIFIED_VULN+=1))
            KERNEL_VERIFIED="yes"
          fi
          if grep -q ";${CVE_VALUE};.*;.*;0;1" "${S26_LOG_DIR}"/cve_results_kernel_"${VERSION}".csv; then
            print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel configuration${GREEN})!"
            ((KERNEL_VERIFIED_VULN+=1))
            KERNEL_VERIFIED="yes"
          fi
        fi
      fi

      if [[ "${CVE_SEARCHSPLOIT}" -eq 1 || "${MSF_SEARCH}" -eq 1 || "${TRICKEST_SEARCH}" -eq 1 || "${SNYK_SEARCH}" -eq 1 || "${PS_SEARCH}" -eq 1 ]] ; then
        if [[ ${CVE_SEARCHSPLOIT} -eq 1 ]]; then
          mapfile -t EXPLOIT_AVAIL < <(cve_searchsploit "${CVE_VALUE}" 2>/dev/null || true)
        fi

        if [[ ${MSF_SEARCH} -eq 1 ]]; then
          mapfile -t EXPLOIT_AVAIL_MSF < <(grep -E "${CVE_VALUE}"$ "${MSF_DB_PATH}" 2>/dev/null || true)
        fi

        if [[ ${TRICKEST_SEARCH} -eq 1 ]]; then
          mapfile -t EXPLOIT_AVAIL_TRICKEST < <(grep -E "${CVE_VALUE}\.md" "${TRICKEST_DB_PATH}" 2>/dev/null | sort -u || true)
        fi

        if [[ ${PS_SEARCH} -eq 1 ]]; then
          mapfile -t EXPLOIT_AVAIL_PACKETSTORM < <(grep -E "^${CVE_VALUE}\;" "${CONFIG_DIR}"/PS_PoC_results.csv 2>/dev/null || true)
        fi

        if [[ ${SNYK_SEARCH} -eq 1 ]]; then
          mapfile -t EXPLOIT_AVAIL_SNYK < <(grep -E "^${CVE_VALUE}\;" "${CONFIG_DIR}"/Snyk_PoC_results.csv 2>/dev/null || true)
        fi
        # routersploit db search
        if [[ ${RS_SEARCH} -eq 1 ]]; then
          mapfile -t EXPLOIT_AVAIL_ROUTERSPLOIT < <(grep -E "${CVE_VALUE}"$ "${CONFIG_DIR}/routersploit_cve-db.txt" 2>/dev/null || true)

          # now, we check the exploit-db results if we have a routersploit module:
          if [[ " ${EXPLOIT_AVAIL[*]} " =~ "Exploit DB Id:" ]]; then
            for EID_VALUE in "${EXPLOIT_AVAIL[@]}"; do
              if ! echo "${EID_VALUE}" | grep -q "Exploit DB Id:"; then
                continue
              fi
              EID_VALUE=$(echo "${EID_VALUE}" | grep "Exploit DB Id:" | cut -d: -f2)
              mapfile -t EXPLOIT_AVAIL_ROUTERSPLOIT1 < <(grep "${EID_VALUE}" "${CONFIG_DIR}/routersploit_exploit-db.txt" 2>/dev/null || true)
            done
          fi
        fi

        if [[ " ${EXPLOIT_AVAIL[*]} " =~ "Exploit DB Id:" ]]; then
          readarray -t EXPLOIT_IDS < <(echo "${EXPLOIT_AVAIL[@]}" | grep "Exploit DB Id:" | cut -d ":" -f 2 | sed 's/[^0-9]*//g' | sed 's/\ //' | sort -u)
          if [[ "${EXPLOIT}" == "No exploit available" ]]; then
            EXPLOIT="Exploit (EDB ID:"
          else
            EXPLOIT="${EXPLOIT}"" / EDB ID:"
          fi

          for EXPLOIT_ID in "${EXPLOIT_IDS[@]}" ; do
            LOCAL=0
            REMOTE=0
            DOS=0
            EXPLOIT="${EXPLOIT}"" ""${EXPLOIT_ID}"
            echo -e "[+] Exploit for ${CVE_VALUE}:\\n" >> "${LOG_PATH_MODULE}""/exploit/""${EXPLOIT_ID}"".txt"
            for LINE in "${EXPLOIT_AVAIL[@]}"; do
              echo "${LINE}" >> "${LOG_PATH_MODULE}""/exploit/""${EXPLOIT_ID}"".txt"
              if [[ "${LINE}" =~ "Platform: local" && "${LOCAL}" -eq 0 ]]; then
                EXPLOIT="${EXPLOIT}"" (L)"
                LOCAL=1
              fi
              if [[ "${LINE}" =~ "Platform: remote" && "${REMOTE}" -eq 0 ]]; then
                EXPLOIT="${EXPLOIT}"" (R)"
                REMOTE=1
              fi
              if [[ "${LINE}" =~ "Platform: dos" && "${DOS}" -eq 0 ]]; then
                EXPLOIT="${EXPLOIT}"" (D)"
                DOS=1
              fi
            done
            EDB=1
            ((EXPLOIT_COUNTER_VERSION+=1))
          done

          # copy the exploit-db exploits to the report
          for LINE in "${EXPLOIT_AVAIL[@]}"; do
            if [[ "${LINE}" =~ "File:" ]]; then
              E_FILE=$(echo "${LINE}" | awk '{print $2}')
              if [[ -f "${E_FILE}" ]] ; then
                cp "${E_FILE}" "${LOG_PATH_MODULE}""/exploit/edb_""$(basename "${E_FILE}")"
              fi
            fi
          done
        fi

        if [[ ${#EXPLOIT_AVAIL_MSF[@]} -gt 0 ]]; then
          if [[ "${EXPLOIT}" == "No exploit available" ]]; then
            EXPLOIT="Exploit (MSF:"
          else
            EXPLOIT="${EXPLOIT}"" ""/ MSF:"
          fi

          for EXPLOIT_MSF in "${EXPLOIT_AVAIL_MSF[@]}" ; do
            if ! [[ -d "${MSF_INSTALL_PATH}" ]]; then
              EXPLOIT_PATH=$(echo "${EXPLOIT_MSF}" | cut -d: -f1)
            else
              EXPLOIT_PATH="${MSF_INSTALL_PATH}"$(echo "${EXPLOIT_MSF}" | cut -d: -f1)
            fi
            EXPLOIT_NAME=$(basename -s .rb "${EXPLOIT_PATH}")
            EXPLOIT="${EXPLOIT}"" ""${EXPLOIT_NAME}"
            if [[ -f "${EXPLOIT_PATH}" ]] ; then
              # for the web reporter we copy the original metasploit module into the EMBA log directory
              cp "${EXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/msf_""${EXPLOIT_NAME}".rb
              if grep -q "< Msf::Exploit::Remote" "${EXPLOIT_PATH}"; then
                EXPLOIT="${EXPLOIT}"" (R)"
              fi
              if grep -q "< Msf::Exploit::Local" "${EXPLOIT_PATH}"; then
                EXPLOIT="${EXPLOIT}"" (L)"
              fi
              if grep -q "include Msf::Auxiliary::Dos" "${EXPLOIT_PATH}"; then
                EXPLOIT="${EXPLOIT}"" (D)"
              fi
            fi
          done

          if [[ ${EDB} -eq 0 ]]; then
            # only count the msf exploit if we have not already count an other exploit
            # otherwise we count an exploit for one CVE multiple times
            ((EXPLOIT_COUNTER_VERSION+=1))
            EDB=1
          fi
        fi

        if [[ ${#EXPLOIT_AVAIL_SNYK[@]} -gt 0 ]]; then
          if [[ "${EXPLOIT}" == "No exploit available" ]]; then
            EXPLOIT="Exploit (Snyk:"
          else
            EXPLOIT="${EXPLOIT}"" ""/ Snyk:"
          fi

          for EXPLOIT_SNYK in "${EXPLOIT_AVAIL_SNYK[@]}" ; do
            EXPLOIT_NAME=$(echo "${EXPLOIT_SNYK}" | cut -d\; -f2)
            EXPLOIT="${EXPLOIT}"" ""${EXPLOIT_NAME}"" (S)"
          done

          if [[ ${EDB} -eq 0 ]]; then
            # only count the snyk exploit if we have not already count an other exploit
            # otherwise we count an exploit for one CVE multiple times
            ((EXPLOIT_COUNTER_VERSION+=1))
            EDB=1
          fi
        fi

        if [[ ${#EXPLOIT_AVAIL_PACKETSTORM[@]} -gt 0 ]]; then
          if [[ "${EXPLOIT}" == "No exploit available" ]]; then
            EXPLOIT="Exploit (PSS:"
          else
            EXPLOIT="${EXPLOIT}"" ""/ PSS:"
          fi

          for EXPLOIT_PS in "${EXPLOIT_AVAIL_PACKETSTORM[@]}" ; do
            # we use the html file as EXPLOIT_NAME.
            EXPLOIT_NAME=$(echo "${EXPLOIT_PS}" | cut -d\; -f3 | rev | cut -d '/' -f1-2 | rev)
            EXPLOIT="${EXPLOIT}"" ""${EXPLOIT_NAME}"
            TYPE=$(grep "^${CVE_VALUE};" "${CONFIG_DIR}"/PS_PoC_results.csv | grep "${EXPLOIT_NAME}" | cut -d\; -f4 || true)
            if [[ "${TYPE}" == "remote" ]]; then
              TYPE="R"
            elif [[ "${TYPE}" == "local" ]]; then
              TYPE="L"
            elif [[ "${TYPE}" == "DoS" ]]; then
              TYPE="D"
            else
              # fallback to P for packetstorm exploit with unknownt type
              TYPE="P"
            fi
            EXPLOIT="${EXPLOIT}"" (${TYPE})"
          done

          if [[ ${EDB} -eq 0 ]]; then
            # only count the packetstorm exploit if we have not already count an other exploit
            # otherwise we count an exploit for one CVE multiple times
            ((EXPLOIT_COUNTER_VERSION+=1))
            EDB=1
          fi
        fi

        if [[ ${#EXPLOIT_AVAIL_TRICKEST[@]} -gt 0 ]]; then
          if [[ "${EXPLOIT}" == "No exploit available" ]]; then
            EXPLOIT="Exploit (Github:"
          else
            EXPLOIT="${EXPLOIT}"" ""/ Github:"
          fi

          for EXPLOIT_TRICKEST in "${EXPLOIT_AVAIL_TRICKEST[@]}" ; do
            EXPLOIT_PATH=$(echo "${EXPLOIT_TRICKEST}" | cut -d: -f1)
            EXPLOIT_NAME=$(echo "${EXPLOIT_TRICKEST}" | cut -d: -f2- | sed -e 's/https\:\/\/github\.com\///g')
            EXPLOIT="${EXPLOIT}"" ""${EXPLOIT_NAME}"" (G)"
            # we remove slashes from the github url and use this as exploit name:
            EXPLOIT_NAME_=$(echo "${EXPLOIT_TRICKEST}" | cut -d: -f2- | sed -e 's/https\:\/\/github\.com\///g' | tr '/' '_')
            if [[ -f "${EXPLOIT_PATH}" ]] ; then
              # for the web reporter we copy the original metasploit module into the EMBA log directory
              if ! [[ -d "${LOG_PATH_MODULE}""/exploit/" ]]; then
                mkdir "${LOG_PATH_MODULE}""/exploit/"
              fi
              cp "${EXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/trickest_""${EXPLOIT_NAME_}".md
            fi
          done

          if [[ ${EDB} -eq 0 ]]; then
            # only count the github exploit if we have not already count an other exploit
            # otherwise we count an exploit for one CVE multiple times
            ((EXPLOIT_COUNTER_VERSION+=1))
            EDB=1
          fi
        fi

        if [[ -v EXPLOIT_AVAIL_ROUTERSPLOIT[@] || -v EXPLOIT_AVAIL_ROUTERSPLOIT1[@] ]]; then
          if [[ "${EXPLOIT}" == "No exploit available" ]]; then
            EXPLOIT="Exploit (Routersploit:"
          else
            EXPLOIT="${EXPLOIT}"" ""/ Routersploit:"
          fi
          EXPLOIT_ROUTERSPLOIT=("${EXPLOIT_AVAIL_ROUTERSPLOIT[@]}" "${EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}")
          for EXPLOIT_RS in "${EXPLOIT_ROUTERSPLOIT[@]}" ; do
            EXPLOIT_PATH=$(echo "${EXPLOIT_RS}" | cut -d: -f1)
            EXPLOIT_NAME=$(basename -s .py "${EXPLOIT_PATH}")
            EXPLOIT="${EXPLOIT}"" ""${EXPLOIT_NAME}"
            if [[ -f "${EXPLOIT_PATH}" ]] ; then
              # for the web reporter we copy the original metasploit module into the EMBA log directory
              cp "${EXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/routersploit_""${EXPLOIT_NAME}".py
              if grep -q Port "${EXPLOIT_PATH}"; then
                EXPLOIT="${EXPLOIT}"" (R)"
              fi
            fi
          done

          if [[ ${EDB} -eq 0 ]]; then
            # only count the routersploit exploit if we have not already count an other exploit
            # otherwise we count an exploit for one CVE multiple times
            ((EXPLOIT_COUNTER_VERSION+=1))
            EDB=1
          fi
        fi
      fi

      if [[ ${KNOWN_EXPLOITED} -eq 1 ]]; then
        EXPLOIT="${EXPLOIT}"" (X)"
      fi

      if [[ ${EDB} -eq 1 ]]; then
        EXPLOIT="${EXPLOIT}"")"
      fi

      # just in case CVSSv3 value is missing -> switch to CVSSv2
      if [[ "${CVSS_VALUE}" == "null" ]]; then
        print_output "[*] Missing CVSSv3 value for vulnerability ${ORANGE}${CVE_VALUE}${NC} - setting default CVSS to CVSSv2 ${ORANGE}${CVSSv2_VALUE}${NC}" "no_log"
        CVSS_VALUE="${CVSSv2_VALUE}"
        CVEv2_TMP=1
      fi

      # if this CVE is a kernel verified CVE we add a V to the CVE
      if [[ "${KERNEL_VERIFIED}" == "yes" ]]; then CVE_VALUE="${CVE_VALUE}"" (V)"; fi

      # we do not deal with output formatting the usual way -> we use printf
      if (( $(echo "${CVSS_VALUE} > 6.9" | bc -l) )); then
        # put a note in the output if we have switched to CVSSv2
        if [[ "${CVEv2_TMP}" -eq 1 ]]; then CVSS_VALUE="${CVSS_VALUE}"" (v2)"; fi
        if [[ "${EXPLOIT}" == *MSF* || "${EXPLOIT}" == *EDB\ ID* || "${EXPLOIT}" == *linux-exploit-suggester* || "${EXPLOIT}" == *Routersploit* || \
          "${EXPLOIT}" == *Github* || "${EXPLOIT}" == *PSS* || "${EXPLOIT}" == *Snyk* || "${KNOWN_EXPLOITED}" -eq 1 ]]; then
          printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:   %-15.15s:   %s${NC}\n" "${BINARY}" "${VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
        else
          printf "${RED}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:   %-15.15s:   %s${NC}\n" "${BINARY}" "${VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
        fi
        ((HIGH_CVE_COUNTER+=1))
      elif (( $(echo "${CVSS_VALUE} > 3.9" | bc -l) )); then
        if [[ "${CVEv2_TMP}" -eq 1 ]]; then CVSS_VALUE="${CVSS_VALUE}"" (v2)"; fi
        if [[ "${EXPLOIT}" == *MSF* || "${EXPLOIT}" == *EDB\ ID* || "${EXPLOIT}" == *linux-exploit-suggester* || "${EXPLOIT}" == *Routersploit* || \
          "${EXPLOIT}" == *Github* || "${EXPLOIT}" == *PSS* || "${EXPLOIT}" == *Snyk* || "${KNOWN_EXPLOITED}" -eq 1 ]]; then
          printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:   %-15.15s:   %s${NC}\n" "${BINARY}" "${VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
        else
          printf "${ORANGE}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:   %-15.15s:   %s${NC}\n" "${BINARY}" "${VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
        fi
        ((MEDIUM_CVE_COUNTER+=1))
      else
        if [[ "${CVEv2_TMP}" -eq 1 ]]; then CVSS_VALUE="${CVSS_VALUE}"" (v2)"; fi
        if [[ "${EXPLOIT}" == *MSF* || "${EXPLOIT}" == *EDB\ ID* || "${EXPLOIT}" == *linux-exploit-suggester* || "${EXPLOIT}" == *Routersploit* || \
          "${EXPLOIT}" == *Github* || "${EXPLOIT}" == *PSS* || "${EXPLOIT}" == *Snyk* || "${KNOWN_EXPLOITED}" -eq 1 ]]; then
          printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:   %-15.15s:   %s${NC}\n" "${BINARY}" "${VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
        else
          printf "${GREEN}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:   %-15.15s:   %s${NC}\n" "${BINARY}" "${VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
        fi
        ((LOW_CVE_COUNTER+=1))
      fi
      write_csv_log "${BINARY}" "${VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${#EXPLOIT_AVAIL[@]}" "${#EXPLOIT_AVAIL_MSF[@]}" "${#EXPLOIT_AVAIL_TRICKEST[@]}" "${#EXPLOIT_AVAIL_ROUTERSPLOIT[@]}/${#EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}" "${EXPLOIT_AVAIL_SNYK[@]}" "${EXPLOIT_AVAIL_PACKETSTORM[@]}" "${LOCAL}" "${REMOTE}" "${DOS}" "${#KNOWN_EXPLOITED_VULNS[@]}" "${KERNEL_VERIFIED}"
    done
  fi

  { echo ""
    echo "[+] Statistics:${CVE_COUNTER_VERSION}|${EXPLOIT_COUNTER_VERSION}|${VERSION_orig}"
  } >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"

  if [[ ${LOW_CVE_COUNTER} -gt 0 ]]; then
    echo "${LOW_CVE_COUNTER}" >> "${TMP_DIR}"/LOW_CVE_COUNTER.tmp
  fi
  if [[ ${MEDIUM_CVE_COUNTER} -gt 0 ]]; then
    echo "${MEDIUM_CVE_COUNTER}" >> "${TMP_DIR}"/MEDIUM_CVE_COUNTER.tmp
  fi
  if [[ ${HIGH_CVE_COUNTER} -gt 0 ]]; then
    echo "${HIGH_CVE_COUNTER}" >> "${TMP_DIR}"/HIGH_CVE_COUNTER.tmp
  fi

  print_output "[*] Vulnerability details for ${ORANGE}${BINARY}${NC} / version ${ORANGE}${VERSION}${NC} / source ${ORANGE}${VSOURCE}${NC}:"
  write_anchor "cve_${BINARY}"
  if [[ "${EXPLOIT_COUNTER_VERSION}" -gt 0 ]]; then
    print_ln
    grep -v "Statistics" "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}" | tee -a "${LOG_FILE}" || true
    if [[ "${KERNEL_VERIFIED_VULN}" -gt 0 ]]; then
      print_output "[+] Found ${RED}${BOLD}${CVE_COUNTER_VERSION}${GREEN} CVEs (${RED}${KERNEL_VERIFIED_VULN} verified${GREEN}) and ${RED}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}"
    else
      print_output "[+] Found ${RED}${BOLD}${CVE_COUNTER_VERSION}${GREEN} CVEs and ${RED}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}"
    fi
    print_ln
  elif [[ "${CVE_COUNTER_VERSION}" -gt 0 ]]; then
    print_ln
    grep -v "Statistics" "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}" | tee -a "${LOG_FILE}" || true
    if [[ "${KERNEL_VERIFIED_VULN}" -gt 0 ]]; then
      print_output "[+] Found ${ORANGE}${BOLD}${CVE_COUNTER_VERSION}${GREEN} CVEs (${ORANGE}${KERNEL_VERIFIED_VULN} verified${GREEN}) and ${ORANGE}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}"
    else
      print_output "[+] Found ${ORANGE}${BOLD}${CVE_COUNTER_VERSION}${GREEN} CVEs and ${ORANGE}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}"
    fi
    print_ln
  else
    print_ln
    print_output "[+] Found ${ORANGE}${BOLD}NO${NC}${GREEN} CVEs and ${ORANGE}${BOLD}NO${NC}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}"
    print_ln
  fi

  # normally we only print the number of CVEs. If we have verified CVEs in the Linux Kernel we also add this detail
  CVEs="${CVE_COUNTER_VERSION}"
  if [[ "${KERNEL_VERIFIED_VULN}" -gt 0 ]] && [[ "${BINARY}" == *"kernel"* ]]; then
    CVEs="${CVEs}"" (${KERNEL_VERIFIED_VULN})"
  fi
  EXPLOITS="${EXPLOIT_COUNTER_VERSION}"

  if [[ "${CVE_COUNTER_VERSION}" -gt 0 || "${EXPLOIT_COUNTER_VERSION}" -gt 0 ]]; then
    if ! [[ -f "${LOG_PATH_MODULE}"/F20_summary.csv ]]; then
      echo "BINARY;VERSION;Number of CVEs;Number of EXPLOITS" >> "${LOG_PATH_MODULE}"/F20_summary.csv
    fi
    if [[ "${EXPLOIT_COUNTER_VERSION}" -gt 0 || "${KNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "[${MAGENTA}+${NC}]${MAGENTA} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${BINARY}" "${VERSION}" "${CVEs}" "${EXPLOITS}" "${VSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
      echo "${BINARY};${VERSION};${CVEs};${EXPLOITS}" >> "${LOG_PATH_MODULE}"/F20_summary.csv
    else
      printf "[${ORANGE}+${NC}]${ORANGE} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${BINARY}" "${VERSION}" "${CVEs}" "${EXPLOITS}" "${VSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
      echo "${BINARY};${VERSION};${CVEs};${EXPLOITS}" >> "${LOG_PATH_MODULE}"/F20_summary.csv
    fi
  elif [[ "${CVEs}" -eq 0 && "${EXPLOITS}" -eq 0 ]]; then
      printf "[${GREEN}+${NC}]${GREEN} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${BINARY}" "${VERSION}" "${CVEs}" "${EXPLOITS}" "${VSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
    echo "${BINARY};${VERSION};${CVEs};${EXPLOITS}" >> "${LOG_PATH_MODULE}"/F20_summary.csv
  else
    # this should never happen ...
    printf "[+] Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-5.5s:   Exploits: %-10.10s:   Source: %-15.15s\n" "${BINARY}" "${VERSION}" "${CVEs}" "${EXPLOITS}" "${VSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
    echo "${BINARY};${VERSION};${CVEs};${EXPLOITS}" >> "${LOG_PATH_MODULE}"/F20_summary.csv
  fi
}

get_firmware_base_version_check() {
  local S09_LOG="${1:-}"
  export VERSIONS_STAT_CHECK=()

  if [[ -f "${S09_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S09_LOG}")."
    # if we have already kernel information:
    if [[ "${KERNELV}" -eq 1 ]]; then
      readarray -t VERSIONS_STAT_CHECK < <(cut -d\; -f4 "${S09_LOG}" | tail -n +2 | grep -v "kernel" | sort -u  || true)
    else
      readarray -t VERSIONS_STAT_CHECK < <(cut -d\; -f4 "${S09_LOG}" | tail -n +2 | sort -u || true)
    fi
  fi
}

get_kernel_check() {
  local S25_LOG="${1:-}"
  export KERNEL_CVE_EXPLOITS=()

  if [[ -f "${S25_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S25_LOG}")."
    readarray -t KERNEL_CVE_EXPLOITS < <(cut -d\; -f1-3 "${S25_LOG}" | tail -n +2 | sort -u || true)
    # we get something like this: "kernel;5.10.59;CVE-2021-3490"
  fi
}

get_kernel_verified() {
  local S26_LOGS_ARR=("$@")
  local KERNEL_CVE_VERIFIEDX=()
  local S26_LOG_DIR="${LOG_DIR}""/s26_kernel_vuln_verifier/"

  for S26_LOG in "${S26_LOGS_ARR[@]}"; do
    if [[ -f "${S26_LOG}" ]]; then
      print_output "[*] Collect verified kernel details of module $(basename "${S26_LOG}")."
      readarray -t KERNEL_CVE_VERIFIEDX < <(tail -n +2 "${S26_LOG}" | sort -u || true)
    fi
    KERNEL_CVE_VERIFIED+=("${KERNEL_CVE_VERIFIEDX[@]}")
  done
  mapfile -t KERNEL_CVE_VERIFIED_VERSION < <(find "${S26_LOG_DIR}" -name "cve_results_kernel_*.csv" -exec cut -d\; -f1 {} \; | grep -v "Kernel version" | sort -u)
}

get_usermode_emulator() {
  local S116_LOG="${1:-}"
  export VERSIONS_EMULATOR=()

  if [[ -f "${S116_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S116_LOG}")."
    readarray -t VERSIONS_EMULATOR < <(cut -d\; -f4 "${S116_LOG}" | tail -n +2 | sort -u || true)
  fi
}

get_systemmode_emulator() {
  local L15_LOG="${1:-}"
  export VERSIONS_SYS_EMULATOR=()

  if [[ -f "${L15_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${L15_LOG}")."
    readarray -t VERSIONS_SYS_EMULATOR < <(cut -d\; -f4 "${L15_LOG}" | tail -n +2 | sort -u || true)
  fi
}

get_systemmode_webchecks() {
  local L25_LOG="${1:-}"
  export VERSIONS_SYS_EMULATOR_WEB=()

  # disabled for now
  # if [[ -f "${L25_LOG}" ]]; then
  #  print_output "[*] Collect version details of module $(basename "${L25_LOG}")."
  #  readarray -t VERSIONS_SYS_EMULATOR_WEB < <(cut -d\; -f4 "${L25_LOG}" | tail -n +2 | sort -u || true)
  # fi
}

get_msf_verified() {
  local L35_LOG="${1:-}"
  export CVE_L35_DETAILS=()

  if [[ -f "${L35_LOG}" ]]; then
    print_output "[*] Collect CVE details of module $(basename "${L35_LOG}")."
    readarray -t CVE_L35_DETAILS < <(cut -d\; -f3 "${L35_LOG}" | tail -n +2 | grep -v "NA" | sort -u || true)
  fi
}

get_uefi_details() {
  local S02_LOG="${1:-}"
  export CVE_S02_DETAILS=()

  if [[ -f "${S02_LOG}" ]]; then
    print_output "[*] Collect CVE details of module $(basename "${S02_LOG}")."
    readarray -t CVE_S02_DETAILS < <(cut -d\; -f3 "${S02_LOG}" | tail -n +2 | sort -u | grep "^CVE-" || true)
  fi
}

get_firmware_details() {
  local S06_LOG="${1:-}"
  export VERSIONS_S06_FW_DETAILS=()

  if [[ -f "${S06_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S06_LOG}")."
    readarray -t VERSIONS_S06_FW_DETAILS < <(cut -d\; -f4 "${S06_LOG}" | tail -n +2 | sort -u || true)
  fi
}

get_package_details() {
  local S08_LOG="${1:-}"
  export VERSIONS_S08_PACKAGE_DETAILS=()

  if [[ -f "${S08_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S08_LOG}")."
    readarray -t VERSIONS_S08_PACKAGE_DETAILS < <(cut -d\; -f3,5 "${S08_LOG}" | tail -n +2 | sort -u | tr ';' ':'|| true)
  fi
}
