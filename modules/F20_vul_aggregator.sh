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

  local FOUND_CVE=0
  local S26_LOGS_ARR=()

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

  if [[ -d ${NVD_DIR} ]]; then
    print_output "[*] Aggregate vulnerability details"

    # get the kernel version from s24 and s25:
    get_kernel_check "${S24_CSV_LOG}" "${S25_CSV_LOG}"
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

    get_uefi_details "${S02_CSV_LOG}"
    get_firmware_details "${S06_CSV_LOG}"
    get_sbom_package_details "${S08_CSV_LOG}"
    get_lighttpd_details "${S36_CSV_LOG}"
    get_firmware_base_version_check "${S09_CSV_LOG}"
    get_usermode_emulator "${S116_CSV_LOG}"
    get_systemmode_emulator "${L15_CSV_LOG}"
    get_systemmode_webchecks "${L25_CSV_LOG}"
    get_msf_verified "${L35_CSV_LOG}"
    get_busybox_verified "${S118_CSV_LOG}"

    aggregate_versions

    write_csv_log "BINARY" "VERSION" "CVE identifier" "CVSS rating" "exploit db exploit available" "metasploit module" "trickest PoC" "Routersploit" "Snyk PoC" "Packetstormsecurity PoC" "local exploit" "remote exploit" "DoS exploit" "known exploited vuln" "kernel vulnerability verified" "FIRST EPSS" "FIRST PERC"

    if [[ "${#VERSIONS_AGGREGATED[@]}" -gt 0 ]]; then
      generate_cve_details_versions "${VERSIONS_AGGREGATED[@]}"
    fi
    if [[ "${#CVES_AGGREGATED[@]}" -gt 0 ]]; then
      generate_cve_details_cves "${CVES_AGGREGATED[@]}"
    fi

    generate_special_log "${CVE_MINIMAL_LOG}" "${EXPLOIT_OVERVIEW_LOG}"
  else
    print_output "[-] WARNING: No CVE datasources found in external directory"
  fi

  FOUND_CVE=$(sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "${LOG_FILE}" | grep -c -E "\[\+\]\ Found\ " || true)

  module_end_log "${FUNCNAME[0]}" "${FOUND_CVE}"
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
  export BUSYBOX_VERIFIED_CVE=()

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

  local VERSION=""
  export VERSIONS_AGGREGATED=()
  local VERSIONS_KERNEL=()
  local KERNELS=()

  if [[ "${#VERSIONS_STAT_CHECK[@]}" -gt 0 || "${#VERSIONS_EMULATOR[@]}" -gt 0 || "${#KERNEL_CVE_EXPLOITS[@]}" -gt 0 || "${#VERSIONS_SYS_EMULATOR[@]}" -gt 0 || \
    "${#VERSIONS_S06_FW_DETAILS[@]}" -gt 0 || "${#VERSIONS_SYS_EMULATOR_WEB[@]}" -gt 0 || "${#CVE_S02_DETAILS[@]}" -gt 0 || "${#CVE_L35_DETAILS[@]}" -gt 0 || \
    "${#VERSIONS_S36_DETAILS[@]}" -gt 0 || "${#KERNEL_CVE_VERIFIED[@]}" -gt 0 || "${#BUSYBOX_VERIFIED_CVE[@]}" -gt 0 || "${#VERSIONS_S08_PACKAGE_DETAILS[@]}" -gt 0 ]]; then

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
      print_output "[+] Found Version details (${ORANGE}SBOM environment${GREEN}): ""${ORANGE}${VERSION}${NC}"
    done
    for VERSION in "${VERSIONS_S36_DETAILS[@]}"; do
      if [ -z "${VERSION}" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}lighttpd statical check${GREEN}): ""${ORANGE}${VERSION}${NC}"
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
      VERSION="$(echo "${VERSION}" | cut -d\; -f1 | sed 's/^/linux_kernel:/')"
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
        print_output "[-] WARNING: Broken CVE identifier found: ${ORANGE}${CVE_ENTRY}${NC}"
        continue
      fi
      print_output "[+] Found CVE details (${ORANGE}binarly UEFI module${GREEN}): ""${ORANGE}${CVE_ENTRY}${NC}"
    done

    for CVE_ENTRY in "${CVE_L35_DETAILS[@]}"; do
      if [ -z "${CVE_ENTRY}" ]; then
        continue
      fi
      if ! [[ "${CVE_ENTRY}" == *CVE-[0-9]* ]]; then
        print_output "[-] WARNING: Broken CVE identifier found: ${ORANGE}${CVE_ENTRY}${NC}"
        continue
      fi
      print_output "[+] Found CVE details (${ORANGE}verified Metasploit exploits${GREEN}): ""${ORANGE}${CVE_ENTRY}${NC}"
    done

    local BUSYBOX_VERIFIED_VERSION=()
    for ENTRY in "${BUSYBOX_VERIFIED_CVE[@]}"; do
      CVE_ENTRY="${ENTRY/*\;/}"
      if [ -z "${CVE_ENTRY}" ]; then
        continue
      fi
      if ! [[ "${CVE_ENTRY}" == *CVE-[0-9]* ]]; then
        print_output "[-] WARNING: Broken CVE identifier found: ${ORANGE}${CVE_ENTRY}${NC}"
        continue
      fi
      print_output "[+] Found CVE details (${ORANGE}verified BusyBox CVE${GREEN}): ""${ORANGE}${CVE_ENTRY}${NC}"
      print_output "[+] Found version details (${ORANGE}verified BusyBox CVE${GREEN}): ""${ORANGE}${ENTRY/\;*/}${NC}"
      # we create a quick temp array for adding the details to the VERSIONS_AGGREGATED array
      BUSYBOX_VERIFIED_VERSION+=( "${ENTRY/\;*/}" )
    done

    VERSIONS_AGGREGATED=("${VERSIONS_EMULATOR[@]}" "${VERSIONS_KERNEL[@]}" "${VERSIONS_STAT_CHECK[@]}" "${VERSIONS_SYS_EMULATOR[@]}" "${VERSIONS_S06_FW_DETAILS[@]}" "${VERSIONS_S08_PACKAGE_DETAILS[@]}" "${VERSIONS_S36_DETAILS[@]}" "${VERSIONS_SYS_EMULATOR_WEB[@]}" "${BUSYBOX_VERIFIED_VERSION[@]}")

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
        print_output "[-] WARNING: Broken version identifier found (space): ${ORANGE}${VERSION}${NC}"
        continue
      fi
      if ! [[ "${VERSION}" == *[0-9]* ]]; then
        print_output "[-] WARNING: Broken version identifier found (no number): ${ORANGE}${VERSION}${NC}"
        continue
      fi
      if ! [[ "${VERSION}" == *":"* ]]; then
        print_output "[-] WARNING: Broken version identifier found (no :): ${ORANGE}${VERSION}${NC}"
        continue
      fi
      write_log "${VERSION}" "${LOG_PATH_MODULE}"/versions.tmp
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
        # ensure our set anchor is based on the binary name and is limited to 20 characters:
        local ANCHOR="${VERSION/:*/}"
        ANCHOR="cve_${ANCHOR:0:20}"
        print_output "[+] Found Version details (${ORANGE}aggregated${GREEN}): ""${ORANGE}${VERSION}${NC}"
        write_link "f20#${ANCHOR}"
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
        write_log "\n[*] CVE details for ${GREEN}${NAME}${NC}:" "${CVE_MINIMAL_LOG}"
        write_log "${CVE_OUTPUT}" "${CVE_MINIMAL_LOG}"
        print_ln
      fi
    done

    write_log "\n[*] Exploit summary:" "${EXPLOIT_OVERVIEW_LOG}"
    grep -E "Exploit\ \(" "${F20_LOG}" | sort -t : -k 4 -h -r | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >> "${EXPLOIT_OVERVIEW_LOG}" || true

    mapfile -t EXPLOITS_AVAIL < <(grep -E "Exploit\ \(" "${F20_LOG}" | sort -t : -k 4 -h -r || true)
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
  sub_module_title "CVE and exploit details."
  write_anchor "cveandexploitdetails"

  local CVES_AGGREGATED=("$@")
  local CVE_ENTRY=""
  CVE_COUNTER=0

  for CVE_ENTRY in "${CVES_AGGREGATED[@]}"; do
    if [[ "${THREADED}" -eq 1 ]]; then
      cve_db_lookup_cve "${CVE_ENTRY}" &
      WAIT_PIDS_F19+=( "$!" )
      max_pids_protection "$(("${MAX_MOD_THREADS}"*2))" "${WAIT_PIDS_F19[@]}"
    else
      cve_db_lookup_cve "${CVE_ENTRY}"
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
  local VERSIONS_AGGREGATED=("$@")
  local BIN_VERSION=""

  for BIN_VERSION in "${VERSIONS_AGGREGATED[@]}"; do
    # BIN_VERSION is something like "binary:1.2.3"
    if [[ "${THREADED}" -eq 1 ]]; then
      cve_db_lookup_version "${BIN_VERSION}" &
      WAIT_PIDS_F19+=( "$!" )
      max_pids_protection "$(("${MAX_MOD_THREADS}"*2))" "${WAIT_PIDS_F19[@]}"
    else
      cve_db_lookup_version "${BIN_VERSION}"
    fi
  done

  if [[ "${THREADED}" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_F19[@]}"
  fi
}

cve_db_lookup_cve() {
  local CVE_ENTRY="${1:-}"
  local CVE_ID=""
  local CVE_V2=""
  local CVE_V31=""
  print_output "[*] CVE database lookup with CVE information: ${ORANGE}${CVE_ENTRY}${NC}" "no_log"

  # there should be only one CVE file available
  CVE_SOURCE=$(find "${NVD_DIR}" -name "${CVE_ENTRY}.json" | sort -u | head -1)
  if [[ -f "${CVE_SOURCE}" ]]; then
    CVE_ID=$(jq -r '.id' "${CVE_SOURCE}")
    CVE_V2=$(jq -r '.metrics.cvssMetricV2[]?.cvssData.baseScore' "${CVE_SOURCE}")
    # CVE_V31=$(jq -r '.metrics.cvssMetricV31[]?.cvssData.baseScore' "${CVE_SOURCE}"
    CVE_V31=$(jq -r '.metrics.cvssMetricV31[]? | select(.type=="Primary") | .cvssData.baseScore' "${CVE_SOURCE}")
    echo "${CVE_ID}:${CVE_V2:-"NA"}:${CVE_V31:-"NA"}" > "${LOG_PATH_MODULE}"/"${CVE_ENTRY}".txt || true
  fi

  # only do further analysis if needed
  # in case we come from s26 module we do not need all the upcoming analysis
  if [[ "${F20_DEEP}" == 1 ]]; then
    cve_extractor "${CVE_ENTRY}"
  fi
}

cve_db_lookup_version() {
  # BIN_VERSION_ needs to be in the format ":vendor:binary:1.2.3:" or "::binary:1.2.3:" or "::binary:1.2.3"
  # somthing like "binary:1.2.3" or ":binary:1.2.3" results in unexpected behavior

  # function writes log files to "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt
  local BIN_VERSION_="${1:-}"

  if [[ "$(echo "${BIN_VERSION_}" | tr ':' '\n' | wc -l)" -lt 4 ]]; then
    print_output "[-] WARNING: Identifier ${BIN_VERSION_} is probably incorrect and should be in the following format:" "no_log"
    print_output "[-] :vendor:binary:1.2.3: or ::binary:1.2.3: or ::binary:1.2.3" "no_log"
  fi

  local CVE_ID=""
  local BIN_NAME=""
  # BIN_NAME=$(echo "${BIN_VERSION_%:}" | rev | cut -d':' -f2 | rev)
  BIN_NAME=$(echo "${BIN_VERSION_%:}" | cut -d':' -f1-3)
  # we create something like "binary_1.2.3" for log paths
  # remove last : if it is there
  local VERSION_PATH=""
  VERSION_PATH=$(echo "${BIN_VERSION_%:}" | cut -d':' -f2-4)
  VERSION_PATH="${VERSION_PATH//\.\*}"
  VERSION_PATH="${VERSION_PATH%:}"
  VERSION_PATH="${VERSION_PATH#:}"
  VERSION_PATH="${VERSION_PATH//:/_}"
  local WAIT_PIDS_F19_CVE_SOURCE=()
  local CVE_VER_SOURCES_ARR=()
  local CVE_VER_SOURCES_ARR_DLINK=()
  local VERSION_SEARCHx=""

  # if we did the CVE analysis already in module s26, we can just use these results for our further analysis
  # -> we skip the complete CVE analysis here:
  if [[ "${BIN_NAME}" == *"linux_kernel"* ]] && [[ -s "${LOG_DIR}"/s26_kernel_vuln_verifier/"${VERSION_PATH}".txt ]]; then
    print_output "[*] Detected kernel vulnerability details from module S26 - going to use these details"
    cp "${LOG_DIR}"/s26_kernel_vuln_verifier/"${VERSION_PATH}".txt "${LOG_PATH_MODULE}" || (print_output "[-] S26 kernel vulns file found, but something was going wrong")
    cve_extractor "${BIN_VERSION_}"
    return
  fi
  # we test for the binary_name:version and for binary_name:*:
  print_output "[*] CVE database lookup with version information: ${ORANGE}${BIN_VERSION_}${NC}" "no_log"
  local lCPE_BIN_VERSION_SEARCH=${BIN_VERSION_%:}
  lCPE_BIN_VERSION_SEARCH=${lCPE_BIN_VERSION_SEARCH//::/:\.\*:}

  local lCPE_BIN_NAME_SEARCH=${BIN_NAME%:}
  lCPE_BIN_NAME_SEARCH=${lCPE_BIN_NAME_SEARCH//::/:\.\*:}

  print_output "[*] Testing: cpe:${CPE_VERSION}:[aoh]${lCPE_BIN_VERSION_SEARCH}:.*:.*:.*:.*:.*:" "no_log"
  # "criteria": "cpe:2.3:a:busybox:busybox:1.14.1:*:*:*:*:*:*:*",

  local lCVE_VER_SOURCES_ARR_tmp=""
  mapfile -t CVE_VER_SOURCES_ARR < <(grep -l -r -E "cpe:${CPE_VERSION}:.*${lCPE_BIN_VERSION_SEARCH}:.*:.*:.*:.*:.*:" "${NVD_DIR}" | sort -u || true)
  print_output "[*] CVE database lookup with version information: ${ORANGE}${lCPE_BIN_VERSION_SEARCH}${NC} resulted in ${ORANGE}${#CVE_VER_SOURCES_ARR[@]}${NC} possible vulnerabilities" "no_log"
  print_output "[*] Testing: cpe:${CPE_VERSION}:[aoh]${lCPE_BIN_NAME_SEARCH}:\*:.*:.*:.*:.*:.*:" "no_log"
  # "criteria": "cpe:2.3:a:busybox:busybox:1.14.1:*:*:*:*:*:*:*",
  mapfile -t lCVE_VER_SOURCES_ARR_tmp < <(grep -l -r -E "cpe:${CPE_VERSION}:[aoh]${lCPE_BIN_NAME_SEARCH}:\*:.*:.*:.*:.*:.*:" "${NVD_DIR}" | sort -u || true)
  print_output "[*] CVE database lookup with version information: ${ORANGE}${lCPE_BIN_NAME_SEARCH}${NC} resulted in ${ORANGE}${#lCVE_VER_SOURCES_ARR_tmp[@]}${NC} possible vulnerabilities" "no_log"

  CVE_VER_SOURCES_ARR+=( "${lCVE_VER_SOURCES_ARR_tmp[@]}" )

  print_output "[*] CVE database lookup with version information: ${ORANGE}${lCPE_BIN_VERSION_SEARCH} / ${lCPE_BIN_NAME_SEARCH}${NC} resulted in ${ORANGE}${#CVE_VER_SOURCES_ARR[@]}${NC} possible vulnerabilities" "no_log"

  if [[ "${BIN_VERSION_}" == *"dlink"* ]]; then
    # dlink extrawurst: dlink vs d-link
    # do a second cve-database check
    VERSION_SEARCHx="$(echo "${BIN_VERSION_}" | sed 's/dlink/d-link/' | sed 's/_firmware//')"
    print_output "[*] CVE database lookup with version information: ${ORANGE}${VERSION_SEARCHx}${NC}" "no_log"
    mapfile -t CVE_VER_SOURCES_ARR_DLINK < <(grep -l -r "cpe:${CPE_VERSION}:[aoh]:.*${VERSION_SEARCHx}" "${NVD_DIR}" || true)
    CVE_VER_SOURCES_ARR+=( "${CVE_VER_SOURCES_ARR_DLINK[@]}" )
  fi

  for CVE_VER_SOURCES_FILE in "${CVE_VER_SOURCES_ARR[@]}"; do
    CVE_ID=$(jq -r '.id' "${CVE_VER_SOURCES_FILE}")
    if [[ "${THREADED}" -eq 1 ]]; then
      # analysis of cve json files in parallel
      check_cve_sources "${CVE_ID}" "${BIN_VERSION_}" "${CVE_VER_SOURCES_FILE}" &
      WAIT_PIDS_F19_CVE_SOURCE+=( "$!" )
      max_pids_protection "$(("${MAX_MOD_THREADS}"*2))" "${WAIT_PIDS_F19_CVE_SOURCE[@]}"
    else
      check_cve_sources "${CVE_ID}" "${BIN_VERSION_}" "${CVE_VER_SOURCES_FILE}"
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_F19_CVE_SOURCE[@]}"

  # only do further analysis if needed
  # in case we come from s26 module we do not need all the upcoming analysis
  if [[ "${F20_DEEP}" == 1 ]]; then
    cve_extractor "${BIN_VERSION_}"
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
# to ensure our BIN_VERSION is affected
check_cve_sources() {
  local CVE_ID="${1:-}"
  local BIN_VERSION_="${2:-}"
  local CVE_VER_SOURCES_FILE="${3:-}"

  local BIN_VERSION_ONLY=""
  # if we have a version identifier like ::binary:1.2.3: we need to remove the last ':' before processing it correctly
  BIN_VERSION_ONLY=$(echo "${BIN_VERSION_%:}" | cut -d':' -f4-5)
  BIN_VERSION_ONLY="${BIN_VERSION_ONLY%:}"

  local BIN_NAME=""
  BIN_NAME=$(echo "${BIN_VERSION_%:}" | cut -d':' -f1-3)
  BIN_NAME="${BIN_NAME%:}"
  BIN_NAME="${BIN_NAME#:}"

  local CVE_VER_START_INCL=""
  local CVE_VER_START_EXCL=""
  local CVE_VER_END_INCL=""
  local CVE_VER_END_EXCL=""
  local CVE_V2=""
  local CVE_V31=""
  local CVE_CPEs_vuln_ARR=()
  local CVE_CPEMATCH=""
  local CVE_SUMMARY=""
  local lFIRST_EPSS=""

  # ensure we replace :: with :.*: to use the BIN_VERSION_ in our grep command
  BIN_VERSION_=${BIN_VERSION_//::/:\.\*:}
  print_output "[*] Testing binary ${BIN_NAME} with version ${BIN_VERSION_ONLY} (${BIN_VERSION_}) for CVE matches in ${CVE_VER_SOURCES_FILE}" "no_log"

  CVE_V2=$(jq -r '.metrics.cvssMetricV2[]?.cvssData.baseScore' "${CVE_VER_SOURCES_FILE}" | tr -dc '[:print:]')
  # CVE_V31=$(jq -r '.metrics.cvssMetricV31[]?.cvssData.baseScore' "${CVE_VER_SOURCES_FILE}" | tr -dc '[:print:]')
  CVE_V31=$(jq -r '.metrics.cvssMetricV31[]? | select(.type=="Primary") | .cvssData.baseScore' "${CVE_VER_SOURCES_FILE}" | tr -dc '[:print:]')
  CVE_SUMMARY=$(escape_echo "$(jq -r '.descriptions[] | select(.lang=="en") | .value' "${CVE_VER_SOURCES_FILE}")")
  # we need to check if any cpe of the CVE is vulnerable
  # └─$ cat external/nvd-json-data-feeds/CVE-2011/CVE-2011-24xx/CVE-2011-2416.json | jq '.configurations[].nodes[].cpeMatch[] | select(.vulnerable==true) | .criteria' | grep linux

  # check if our binary name is somewhere in the cpe identifier - if not we can drop this vulnerability:
  if [[ "$(jq -r '.configurations[].nodes[].cpeMatch[] | select(.vulnerable==true) | .criteria' "${CVE_VER_SOURCES_FILE}" | grep -c "${BIN_NAME//\.\*}")" -eq 0 ]]; then
    print_output "[-] No matching criteria found - binary ${BIN_NAME} not vulnerable for CVE ${CVE_ID}" "no_log"
    return
  fi

  # we get "EPSS;percentage" back
  lFIRST_EPSS=$(get_epss_data "${CVE_ID}")

  # if our cpe with the binary version matches we have a vuln and we can continue
  if grep -q "cpe:${CPE_VERSION}:.*${BIN_VERSION_%:}:" "${CVE_VER_SOURCES_FILE}"; then
    # print_output "[+] CPE matches - vulnerability identified - CVE: ${CVE_ID} / BIN: ${BIN_VERSION_}" "no_log"
    write_cve_log "${CVE_ID}" "${CVE_V2:-"NA"}" "${CVE_V31:-"NA"}" "${lFIRST_EPSS}" "${CVE_SUMMARY:-NA}" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt &
    return
  fi

  # extract valid CPEs matching our cpe.*:binary:*: from the CVE details
  # usually this should only one cpe but in case we are using ARR. With this cpe ARR we can further check for versions from the CVE details like
  #   .versionStartIncluding
  #   .versionStartExcluding
  #   .versionEndIncluding
  #   .versionEndExcluding
  #
  # BIN_NAME is somthing like ".*:BIN_NAME"
  mapfile -t CVE_CPEs_vuln_ARR < <(jq -rc '.configurations[].nodes[].cpeMatch[] | select(.vulnerable==true)' "${CVE_VER_SOURCES_FILE}" | grep "cpe:${CPE_VERSION}:[aoh]:.*${BIN_NAME}:\*:" || true)
  # the result looks like the following:
  # └─$ jq -rc '.configurations[].nodes[].cpeMatch[] | select(.vulnerable==true)' external/nvd-json-data-feeds/CVE-2023/CVE-2023-02xx/CVE-2023-0215.json
  # {"vulnerable":true,"criteria":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0.2","versionEndExcluding":"1.0.2zg","matchCriteriaId":"70985D55-A574-4151-B451-4D500CBFC29A"}
  # {"vulnerable":true,"criteria":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","versionStartIncluding":"1.1.1","versionEndExcluding":"1.1.1t","matchCriteriaId":"DE0061D6-8F81-45D3-B254-82A94915FD08"}
  # {"vulnerable":true,"criteria":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","versionStartIncluding":"3.0.0","versionEndExcluding":"3.0.8","matchCriteriaId":"A6DC5D88-4E99-48F2-8892-610ACA9B5B86"}
  # {"vulnerable":true,"criteria":"cpe:2.3:a:stormshield:stormshield_management_center:*:*:*:*:*:*:*:*","versionEndExcluding":"3.3.3","matchCriteriaId":"62A933C5-C56E-485C-AD49-3B6A2C329131"}


  # Now we walk through all the CPEMatch entries and extract the version details for further analysis
  for CVE_CPEMATCH in "${CVE_CPEs_vuln_ARR[@]}"; do
    # we need to check the version more in details in case we have no version in our cpe identifier
    # └─$ jq -r '.configurations[].nodes[].cpeMatch[] | select(.criteria=="cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*") | .versionEndIncluding' external/nvd-json-data-feeds/CVE-2011/CVE-2011-27xx/CVE-2011-2716.json

    # print_output "[*] Binary ${BIN_VERSION_} - Found no version identifier in our cpe for ${CVE_VER_SOURCES_FILE} - check for further version details with ${CVE_CPEMATCH}" "no_log"

    # extract further version details form the current cpe under test
    CVE_VER_START_INCL=$(echo "${CVE_CPEMATCH}" | jq -r '.versionStartIncluding' | grep -v "null" || true)
    CVE_VER_START_EXCL=$(echo "${CVE_CPEMATCH}" | jq -r '.versionStartExcluding' | grep -v "null" || true)
    CVE_VER_END_INCL=$(echo "${CVE_CPEMATCH}" | jq -r '.versionEndIncluding' | grep -v "null" || true)
    CVE_VER_END_EXCL=$(echo "${CVE_CPEMATCH}" | jq -r '.versionEndExcluding' | grep -v "null" || true)

    # if we have found some version details we need to further check them now:
    if [[ -n "${CVE_VER_START_INCL}" || -n "${CVE_VER_START_EXCL}" || -n "${CVE_VER_END_INCL}" || -n "${CVE_VER_END_EXCL}" ]]; then
      # print_output "[*] Binary ${BIN_VERSION_} - CVE ${CVE_ID} - CVE_VER_START_INCL / CVE_VER_START_EXCL / CVE_VER_END_INCL / CVE_VER_END_EXCL - ${CVE_VER_START_INCL} / ${CVE_VER_START_EXCL} / ${CVE_VER_END_INCL} / ${CVE_VER_END_EXCL}" "no_log"

      ## first check CVE_VER_START_INCL >= VERSION <= CVE_VER_END_INCL
      if [[ -n "${CVE_VER_START_INCL}" ]]; then
        # print_output "[*] ${BIN_VERSION_} - ${CVE_ID} - CVE_VER_START_INCL: ${CVE_VER_START_INCL} - $(version "${BIN_VERSION_ONLY}") vs $(version "${CVE_VER_START_INCL}")" "no_log"
        # if [[ "$(version_extended "${BIN_VERSION_ONLY}")" -lt "$(version_extended "${CVE_VER_START_INCL}")" ]]; then
        if version_extended "${BIN_VERSION_ONLY}" '<' "${CVE_VER_START_INCL}"; then
          # BIN_VERSION is lt CVE_VER_START_INCL -> we can move on
          continue
        fi

        # Case: if [[ "$(version "${BIN_VERSION_ONLY}")" -ge "$(version "${CVE_VER_START_INCL}")" ]]; then
        # print_output "[*] ${CVE_ID} - CVE_VER_START_INCL - binary ${BIN_VERSION_} version $(version "${BIN_VERSION_ONLY}") is higher (incl) as CVE version $(version "${CVE_VER_START_INCL}")" "no_log"
        if [[ -n "${CVE_VER_END_INCL}" ]]; then
          if version_extended "${BIN_VERSION_ONLY}" '<=' "${CVE_VER_END_INCL}"; then
            # print_output "[+] Vulnerability identified - CVE: ${CVE_ID} - binary ${BIN_VERSION_} - source file ${CVE_VER_SOURCES_FILE} - CVE_VER_START_INCL / CVE_VER_END_INCL" "no_log"
            write_cve_log "${CVE_ID}" "${CVE_V2:-"NA"}" "${CVE_V31:-"NA"}" "${lFIRST_EPSS}" "${CVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt &
            if [[ "${BIN_NAME}" == *"linux_kernel"* ]]; then
              check_kernel_major_v "${BIN_VERSION_ONLY}" "${CVE_VER_END_INCL}" "${CVE_ID}"
            fi
          fi
          continue
        fi
        ## first check VERSION < CVE_VER_END_EXCL
        if [[ -n "${CVE_VER_END_EXCL}" ]]; then
          if version_extended "${BIN_VERSION_ONLY}" '<' "${CVE_VER_END_EXCL}"; then
            # print_output "[+] Vulnerability identified - CVE: ${CVE_ID} - binary ${BIN_VERSION_} - source file ${CVE_VER_SOURCES_FILE} - CVE_VER_START_INCL / CVE_VER_END_EXCL" "no_log"
            write_cve_log "${CVE_ID}" "${CVE_V2:-"NA"}" "${CVE_V31:-"NA"}" "${lFIRST_EPSS}" "${CVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt &
            if [[ "${BIN_NAME}" == *"linux_kernel"* ]]; then
              check_kernel_major_v "${BIN_VERSION_ONLY}" "${CVE_VER_END_EXCL}" "${CVE_ID}"
            fi
          fi
          continue
        fi

        # No end version is specified and start version already satisfied.
        # print_output "[+] Vulnerability identified - CVE: ${CVE_ID} - binary ${BIN_VERSION_} - source file ${CVE_VER_SOURCES_FILE} - CVE_VER_START_INCL / CVE_VER_END_EXCL: ${ORANGE}NA${GREEN} / CVE_VER_END_INCL: ${ORANGE}NA${GREEN}" "no_log"
        write_cve_log "${CVE_ID}" "${CVE_V2:-"NA"}" "${CVE_V31:-"NA"}" "${lFIRST_EPSS}" "${CVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt &
        if [[ "${BIN_NAME}" == *"linux_kernel"* ]]; then
          check_kernel_major_v "${BIN_VERSION_ONLY}" "${CVE_VER_START_INCL}" "${CVE_ID}"
        fi
        continue
      fi

      if [[ -n "${CVE_VER_START_EXCL}" ]]; then
        # print_output "[*] ${BIN_VERSION_ONLY} - ${CVE_ID} - CVE_VER_START_EXCL: ${CVE_VER_START_EXCL}" "no_log"
        if version_extended "${BIN_VERSION_ONLY}" '<=' "${CVE_VER_START_EXCL}"; then
          # BIN_VERSION is le CVE_VER_START_EXCL -> we can move on
          continue
        fi

        # Case: if [[ "$(version "${BIN_VERSION_ONLY}")" -gt "$(version "${CVE_VER_START_EXCL}")" ]]; then
        # print_output "[*] ${CVE_ID} - CVE_VER_START_EXCL - binary ${BIN_VERSION_} version $(version "${BIN_VERSION_ONLY}") is higher (excl) as CVE version $(version "${CVE_VER_START_EXCL}")" "no_log"
        if [[ -n "${CVE_VER_END_INCL}" ]]; then
          if version_extended "${BIN_VERSION_ONLY}" '<=' "${CVE_VER_END_INCL}"; then
            # print_output "[+] Vulnerability identified - CVE: ${CVE_ID} - binary ${BIN_VERSION_} - source file ${CVE_VER_SOURCES_FILE} - CVE_VER_START_EXCL / CVE_VER_END_INCL" "no_log"
            write_cve_log "${CVE_ID}" "${CVE_V2:-"NA"}" "${CVE_V31:-"NA"}" "${lFIRST_EPSS}" "${CVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt &
            if [[ "${BIN_NAME}" == *"linux_kernel"* ]]; then
              check_kernel_major_v "${BIN_VERSION_ONLY}" "${CVE_VER_END_INCL}" "${CVE_ID}"
            fi
          fi
          continue
        fi
        if [[ -n "${CVE_VER_END_EXCL}" ]]; then
          if version_extended "${BIN_VERSION_ONLY}" '<' "${CVE_VER_END_EXCL}"; then
            # print_output "[+] Vulnerability identified - CVE: ${CVE_ID} - binary ${BIN_VERSION_} - source file ${CVE_VER_SOURCES_FILE} - CVE_VER_START_EXCL / CVE_VER_END_EXCL" "no_log"
            write_cve_log "${CVE_ID}" "${CVE_V2:-"NA"}" "${CVE_V31:-"NA"}" "${lFIRST_EPSS}" "${CVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt &
            if [[ "${BIN_NAME}" == *"linux_kernel"* ]]; then
              check_kernel_major_v "${BIN_VERSION_ONLY}" "${CVE_VER_END_EXCL}" "${CVE_ID}"
            fi
          fi
          continue
        fi

        # No end version is specified and start version already satisfied.
        # print_output "[+] Vulnerability identified - CVE: ${CVE_ID} - binary ${BIN_VERSION_} - source file ${CVE_VER_SOURCES_FILE} - CVE_VER_START_EXCL / CVE_VER_END_INCL: ${ORANGE}NA${GREEN} / CVE_VER_END_EXCL: ${ORANGE}NA${GREEN}" "no_log"
        write_cve_log "${CVE_ID}" "${CVE_V2:-"NA"}" "${CVE_V31:-"NA"}" "${lFIRST_EPSS}" "${CVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt &
        if [[ "${BIN_NAME}" == *"linux_kernel"* ]]; then
          check_kernel_major_v "${BIN_VERSION_ONLY}" "${CVE_VER_START_EXCL}" "${CVE_ID}"
        fi
        continue
      fi

      # Last cases: no start version is specified. Check end version only.

      if [[ -n "${CVE_VER_END_INCL}" ]]; then
        # print_output "[!] ${CVE_ID} - CVE_VER_END_INCL - binary ${BIN_VERSION_} - ${BIN_VERSION_ONLY} - CVE version ${CVE_VER_END_INCL}" "no_log"
        if version_extended "${BIN_VERSION_ONLY}" '>' "${CVE_VER_END_INCL}"; then
          # print_output "[!] ${CVE_ID} - CVE_VER_END_INCL - binary ${BIN_VERSION_} - ${BIN_VERSION_ONLY} - CVE version ${CVE_VER_END_INCL} - exit" "no_log"
          # BIN_VERSION is gt CVE_VER_END_INCL -> we can move on
          continue
        fi

        # This is the case: if [[ "$(version "${BIN_VERSION_ONLY}")" -le "$(version "${CVE_VER_END_INCL}")" ]]; then
        # print_output "[*] ${CVE_ID} - CVE_VER_END_INCL - binary ${BIN_VERSION_} version $(version "${BIN_VERSION_ONLY}") is lower (incl) CVE version $(version "${CVE_VER_END_INCL}")" "no_log"

        # print_output "[+] Vulnerability identified - CVE: ${CVE_ID} - binary ${BIN_VERSION_} - source file ${CVE_VER_SOURCES_FILE} - CVE_VER_START_INCL: ${ORANGE}NA${GREEN} / CVE_VER_START_EXCL: ${ORANGE}NA${GREEN} / CVE_VER_END_INCL" "no_log"
        write_cve_log "${CVE_ID}" "${CVE_V2:-"NA"}" "${CVE_V31:-"NA"}" "${lFIRST_EPSS}" "${CVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt &
        if [[ "${BIN_NAME}" == *"linux_kernel"* ]]; then
          check_kernel_major_v "${BIN_VERSION_ONLY}" "${CVE_VER_END_INCL}" "${CVE_ID}"
        fi
        continue
      fi

      if [[ -n "${CVE_VER_END_EXCL}" ]]; then
        if version_extended "${BIN_VERSION_ONLY}" '>=' "${CVE_VER_END_EXCL}"; then
          # BIN_VERSION is ge CVE_VER_END_EXCL -> we can move on
          continue
        fi

        # Case handling: if [[ "$(version "${BIN_VERSION_ONLY}")" -lt "$(version "${CVE_VER_END_EXCL}")" ]]; then
        # print_output "[*] ${CVE_ID} - CVE_VER_END_EXCL - binary ${BIN_VERSION_} version $(version "${BIN_VERSION_ONLY}") is lower (excl) CVE version $(version "${CVE_VER_END_EXCL}")" "no_log"

        # print_output "[+] Vulnerability identified - CVE: ${CVE_ID} - binary ${BIN_VERSION_} - source file ${CVE_VER_SOURCES_FILE} - CVE_VER_END_EXCL / CVE_VER_START_EXCL: ${ORANGE}NA${GREEN} / CVE_VER_START_INCL: ${ORANGE}NA${GREEN}" "no_log"
        write_cve_log "${CVE_ID}" "${CVE_V2:-"NA"}" "${CVE_V31:-"NA"}" "${lFIRST_EPSS}" "${CVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt &
        if [[ "${BIN_NAME}" == *"linux_kernel"* ]]; then
          check_kernel_major_v "${BIN_VERSION_ONLY}" "${CVE_VER_END_EXCL}" "${CVE_ID}"
        fi
        continue
      fi
    else
      # if we have not found further version limitations, we assume that all versions are vulnerable:
      # print_output "[+] CPE matches - vulnerability identified - CVE: ${CVE_ID} - binary ${BIN_VERSION_} version $(version "${BIN_VERSION_ONLY}") - no further version limitations detected" "no_log"
      write_cve_log "${CVE_ID}" "${CVE_V2:-"NA"}" "${CVE_V31:-"NA"}" "${lFIRST_EPSS}" "${CVE_SUMMARY:-"NA"}" "${LOG_PATH_MODULE}"/"${VERSION_PATH}".txt &
    fi
  done
}

check_kernel_major_v() {
  local lBIN_VERSION_ONLY="${1:-}"
  local lKERNEL_CVE_VER="${2:-}"
  local lCVE_ID="${3:-}"
  if [[ "${lBIN_VERSION_ONLY:0:1}" != "${lKERNEL_CVE_VER:0:1}" ]]; then
    # print_output is for printing to cli
    # write_log is for writing the needed log file
    local OUT_MESSAGE="[-] Info for CVE ${ORANGE}${lCVE_ID}${NC} - Major kernel version not matching ${ORANGE}${lKERNEL_CVE_VER}${NC} vs ${ORANGE}${lBIN_VERSION_ONLY}${NC} - Higher false positive risk"
    print_output "${OUT_MESSAGE}" "no_log"
    write_log "${OUT_MESSAGE}" "${LOG_PATH_MODULE}/kernel_cve_version_issues.log"
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
  local VERSION_orig="${1:-}"

  local VERSION=""
  local BINARY=""
  export CVE_VALUE=""
  local CVSS_VALUE=""
  local VSOURCE="unknown"
  export EXPLOIT_AVAIL=()
  export EXPLOIT_AVAIL_MSF=()
  export EXPLOIT_AVAIL_TRICKEST=()
  export EXPLOIT_AVAIL_ROUTERSPLOIT=()
  export EXPLOIT_AVAIL_ROUTERSPLOIT1=()
  export EXPLOIT_AVAIL_PACKETSTORM=()
  export EXPLOIT_AVAIL_SNYK=()
  export KNOWN_EXPLOITED_VULNS=()
  local KNOWN_EXPLOITED=0
  local LOCAL=0
  local REMOTE=0
  local DOS=0
  local CVEs_OUTPUT=()
  local CVE_OUTPUT=""
  local KERNEL_VERIFIED_VULN=0


  if ! [[ "${VERSION_orig}" == "CVE-"* ]]; then
    # remove last : if it is there
    VERSION=$(echo "${BIN_VERSION_%:}" | rev | cut -d':' -f1 | rev)
    BINARY=$(echo "${BIN_VERSION_%:}" | rev | cut -d':' -f2 | rev)
    export AGG_LOG_FILE="${VERSION_PATH}".txt
  else
    export AGG_LOG_FILE="${VERSION_orig}".txt
  fi

  # VSOURCE is used to track the source of version details, this is relevant for the
  # final report. With this in place we know if it is from live testing via the network
  # or if it is found via static analysis or via user-mode emulation
  if [[ -f "${S06_CSV_LOG}" && -f "${S09_CSV_LOG}" ]]; then
    if grep -q "${VERSION_orig}" "${S06_CSV_LOG}" 2>/dev/null || grep -q "${VERSION_orig}" "${S09_CSV_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="STAT"
      else
        VSOURCE+="/STAT"
      fi
    fi
  fi

  if [[ -v "${S25_CSV_LOG}" ]]; then
    if [[ "${BINARY}" == *"kernel"* ]]; then
      if grep -q "kernel;${VERSION};" "${S25_CSV_LOG}" 2>/dev/null; then
        if [[ "${VSOURCE}" == "unknown" ]]; then
          VSOURCE="STAT"
        elif ! [[ "${VSOURCE}" =~ .*STAT.* ]]; then
          VSOURCE+="/STAT"
        fi
      fi
    fi
  fi

  if [[ -f "${S24_CSV_LOG}" ]]; then
    if [[ "${BINARY}" == *"kernel"* ]]; then
      if tail -n +2 "${S24_CSV_LOG}" | grep -i -q "linux.*${VERSION}" 2>/dev/null; then
        if [[ "${VSOURCE}" == "unknown" ]]; then
          VSOURCE="STAT"
        elif ! [[ "${VSOURCE}" =~ .*STAT.* ]]; then
          VSOURCE+="/STAT"
        fi
      fi
    fi
  fi

  if [[ -f "${S116_CSV_LOG}" ]]; then
    if grep -q "${VERSION_orig}" "${S116_CSV_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="UEMU"
      else
        VSOURCE+="/UEMU"
      fi
    fi
  fi

  if [[ -f "${S02_CSV_LOG}" ]]; then
    if grep -q "${VERSION_orig}" "${S02_CSV_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="FwHunt"
      else
        VSOURCE+="/FwHunt"
      fi
      BINARY="UEFI firmware"
      VERSION="unknown"
    fi
  fi

  if [[ -f "${L35_CSV_LOG}" ]]; then
    if grep -q "${VERSION_orig}" "${L35_CSV_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="MSF verified"
      else
        VSOURCE+="/MSF verified"
      fi
      BINARY="unknown"
      VERSION="unknown"
    fi
  fi

  if [[ -f "${S08_CSV_LOG}" ]]; then
    if grep -q "${BINARY};.*${VERSION}" "${S08_CSV_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="PACK"
      else
        VSOURCE+="/PACK"
      fi
    fi
  fi

  if [[ -f "${S36_CSV_LOG}" ]]; then
    if grep -q "${BINARY};.*${VERSION}" "${S36_CSV_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="STAT"
      elif ! [[ "${VSOURCE}" =~ .*STAT.* ]]; then
        VSOURCE+="/STAT"
      fi
    fi
  fi

  if [[ -f "${L15_CSV_LOG}" && -f "${L25_CSV_LOG}" ]]; then
    if grep -q "${VERSION_orig}" "${L15_CSV_LOG}" 2>/dev/null || grep -q "${VERSION_orig}" "${L25_CSV_LOG}" 2>/dev/null; then
      if [[ "${VSOURCE}" == "unknown" ]]; then
        VSOURCE="SEMU"
      else
        VSOURCE+="/SEMU"
      fi
    fi
  fi

  export EXPLOIT_COUNTER_VERSION=0
  local CVE_COUNTER_VERSION=0
  if [[ -f "${LOG_PATH_MODULE}"/"${AGG_LOG_FILE}" ]]; then
    readarray -t CVEs_OUTPUT < <(cut -d ':' -f1-5 "${LOG_PATH_MODULE}"/"${AGG_LOG_FILE}" | grep "^CVE-" || true)
  fi

  # if cve-search does not show results we could use the results of linux-exploit-suggester
  # but in our experience these results are less accurate as the results from cve-search.
  # Show me that I'm wrong and we could include and adjust the imports from s25 here:
  # On the other hand, do not forget that we are also using the s25 results if we can find the
  # same CVE here via version detection.

  # if [[ "${BINARY}" == *kernel* ]]; then
  #  if [[ -f "${S25_CSV_LOG}" ]]; then
  #    for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
  #      KCVE_VALUE=$(echo "${KERNEL_CVE_EXPLOIT}" | cut -d\; -f3)
  #    done
  #  fi
  # fi

  if [[ "${#CVEs_OUTPUT[@]}" == 0 ]]; then
    write_csv_log "${BINARY}" "${VERSION}" "${CVE_VALUE:-NA}" "${CVSS_VALUE:-NA}" "${#EXPLOIT_AVAIL[@]}" "${#EXPLOIT_AVAIL_MSF[@]}" "${#EXPLOIT_AVAIL_TRICKEST[@]}" "${#EXPLOIT_AVAIL_ROUTERSPLOIT[@]}/${#EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}" "${#EXPLOIT_AVAIL_SNYK[@]}" "${#EXPLOIT_AVAIL_PACKETSTORM[@]}" "${LOCAL:-NA}" "${REMOTE:-NA}" "${DOS:-NA}" "${#KNOWN_EXPLOITED_VULNS[@]}" "${KERNEL_VERIFIED:-NA}" "${FIRST_EPSS:-NA}" "${FIRST_PERC:-NA}"
  fi

  if [[ -f "${LOG_PATH_MODULE}"/"${AGG_LOG_FILE}" ]]; then
    local WAIT_PIDS_TACTOR=()
    for CVE_OUTPUT in "${CVEs_OUTPUT[@]}"; do
      # CVE_OUTPUT is for one CVE value
      ((CVE_COUNTER+=1))
      ((CVE_COUNTER_VERSION+=1))
      if [[ "${THREADED}" -eq 1 ]]; then
        cve_extractor_thread_actor "${BINARY}" "${VERSION}" "${CVE_OUTPUT}" &
        WAIT_PIDS_TACTOR+=( "$!" )
        max_pids_protection "$(("${MAX_MOD_THREADS}"*3))" "${WAIT_PIDS_TACTOR[@]}"
      else
        cve_extractor_thread_actor "${BINARY}" "${VERSION}" "${CVE_OUTPUT}"
      fi
    done

    [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_TACTOR[@]}"
  fi

  local KNOWN_EXPLOITED=0
  local KERNEL_VERIFIED_VULN=0
  local EXPLOIT_COUNTER_VERSION=0

  if [[ -s "${LOG_PATH_MODULE}"/exploit/known_exploited_vulns.log ]]; then
    KNOWN_EXPLOITED=1
  fi
  if [[ -f "${CSV_LOG}" ]]; then
    # very weak search for the end of the entry - if yes we have a verified kernel vuln
    # Todo: Improve this search on field base
    KERNEL_VERIFIED_VULN=$(grep -c "^${BINARY};.*;yes;$" "${CSV_LOG}" || true)
  fi

  if [[ -f "${TMP_DIR}/exploit_cnt.tmp" ]]; then
    # this counter is wrong as soon as we have the same binary in multiple versions!
    EXPLOIT_COUNTER_VERSION=$(grep -c "^${BINARY};${VERSION};" "${TMP_DIR}/exploit_cnt.tmp" || true)
  fi

  { echo ""
    echo "[+] Statistics:${CVE_COUNTER_VERSION}|${EXPLOIT_COUNTER_VERSION}|${VERSION_orig}"
  } >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"

  local BIN_LOG="${LOG_PATH_MODULE}/cve_details_${BINARY}_${VERSION}.log"
  write_log "[*] Vulnerability details for ${ORANGE}${BINARY}${NC} / version ${ORANGE}${VERSION}${NC} / source ${ORANGE}${VSOURCE}${NC}:" "${BIN_LOG}"
  write_anchor "cve_${BINARY:0:20}" "${BIN_LOG}"
  if [[ "${EXPLOIT_COUNTER_VERSION}" -gt 0 ]]; then
    write_log "" "${BIN_LOG}"
    grep -v "Statistics" "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}" >> "${BIN_LOG}" || true
    if [[ "${KERNEL_VERIFIED_VULN}" -gt 0 ]]; then
      write_log "[+] Found ${RED}${BOLD}${CVE_COUNTER_VERSION}${GREEN} CVEs (${RED}${KERNEL_VERIFIED_VULN} verified${GREEN}) and ${RED}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}" "${BIN_LOG}"
    elif [[ "${#BUSYBOX_VERIFIED_CVE[@]}" -gt 0 ]] && [[ "${BINARY}" == *"busybox"* ]]; then
      # we currently do not check for the specific BB version in here. This results in false results on multiple detected BB binaries
      write_log "[+] Found ${RED}${BOLD}${CVE_COUNTER_VERSION}${GREEN} CVEs (${RED}${#BUSYBOX_VERIFIED_CVE[@]} verified${GREEN}) and ${RED}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}" "${BIN_LOG}"
    else
      write_log "[+] Found ${RED}${BOLD}${CVE_COUNTER_VERSION}${GREEN} CVEs and ${RED}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}" "${BIN_LOG}"
    fi
    write_log "" "${BIN_LOG}"
  elif [[ "${CVE_COUNTER_VERSION}" -gt 0 ]]; then
    write_log "" "${BIN_LOG}"
    grep -v "Statistics" "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}" >> "${BIN_LOG}" || true
    if [[ "${KERNEL_VERIFIED_VULN}" -gt 0 ]]; then
      write_log "[+] Found ${ORANGE}${BOLD}${CVE_COUNTER_VERSION}${GREEN} CVEs (${ORANGE}${KERNEL_VERIFIED_VULN} verified${GREEN}) and ${ORANGE}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}" "${BIN_LOG}"
    elif [[ "${#BUSYBOX_VERIFIED_CVE[@]}" -gt 0 ]] && [[ "${BINARY}" == *"busybox"* ]]; then
      write_log "[+] Found ${ORANGE}${BOLD}${CVE_COUNTER_VERSION}${GREEN} CVEs (${ORANGE}${#BUSYBOX_VERIFIED_CVE[@]} verified${GREEN}) and ${ORANGE}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}" "${BIN_LOG}"
    else
      write_log "[+] Found ${ORANGE}${BOLD}${CVE_COUNTER_VERSION}${GREEN} CVEs and ${ORANGE}${BOLD}${EXPLOIT_COUNTER_VERSION}${GREEN} exploits (including POC's) in ${ORANGE}${BINARY}${GREEN} with version ${ORANGE}${VERSION}${GREEN} (source ${ORANGE}${VSOURCE}${GREEN}).${NC}" "${BIN_LOG}"
    fi
    write_log "" "${BIN_LOG}"
  else
    write_log "[-] Found ${ORANGE}${BOLD}NO${NC}${NC} CVEs and ${ORANGE}${BOLD}NO${NC}${NC} exploits (including POC's) in ${ORANGE}${BINARY}${NC} with version ${ORANGE}${VERSION}${NC} (source ${ORANGE}${VSOURCE}${NC})." "${BIN_LOG}"
    write_log "" "${BIN_LOG}"
  fi

  # normally we only print the number of CVEs. If we have verified CVEs in the Linux Kernel or BusyBox we also add this detail
  CVEs="${CVE_COUNTER_VERSION}"
  if [[ "${KERNEL_VERIFIED_VULN}" -gt 0 ]] && [[ "${BINARY}" == *"kernel"* ]]; then
    CVEs+=" (${KERNEL_VERIFIED_VULN})"
  fi
  if [[ "${#BUSYBOX_VERIFIED_CVE[@]}" -gt 0 ]] && [[ "${BINARY}" == *"busybox"* ]]; then
    CVEs+=" (${#BUSYBOX_VERIFIED_CVE[@]})"
  fi
  EXPLOITS="${EXPLOIT_COUNTER_VERSION}"

  if [[ "${CVE_COUNTER_VERSION}" -gt 0 || "${EXPLOIT_COUNTER_VERSION}" -gt 0 ]]; then
    if ! [[ -f "${LOG_PATH_MODULE}"/F20_summary.csv ]]; then
      write_log "BINARY;VERSION;Number of CVEs;Number of EXPLOITS" "${LOG_PATH_MODULE}"/F20_summary.csv
    fi
    if [[ "${EXPLOIT_COUNTER_VERSION}" -gt 0 || "${KNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "[${MAGENTA}+${NC}]${MAGENTA} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${BINARY}" "${VERSION}" "${CVEs}" "${EXPLOITS}" "${VSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
      write_log "${BINARY};${VERSION};${CVEs};${EXPLOITS}" "${LOG_PATH_MODULE}"/F20_summary.csv
    else
      printf "[${ORANGE}+${NC}]${ORANGE} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${BINARY}" "${VERSION}" "${CVEs}" "${EXPLOITS}" "${VSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
      write_log "${BINARY};${VERSION};${CVEs};${EXPLOITS}" "${LOG_PATH_MODULE}"/F20_summary.csv
    fi
  elif [[ "${CVEs/\ */}" -eq 0 && "${EXPLOITS}" -eq 0 ]]; then
    printf "[${GREEN}+${NC}]${GREEN} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-10.10s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "${BINARY}" "${VERSION}" "${CVEs/\ */}" "${EXPLOITS}" "${VSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
    write_log "${BINARY};${VERSION};${CVEs/\ */};${EXPLOITS}" "${LOG_PATH_MODULE}"/F20_summary.csv
  else
    # this should never happen ...
    printf "[+] Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-5.5s:   Exploits: %-10.10s:   Source: %-15.15s\n" "${BINARY}" "${VERSION}" "${CVEs/\ */}" "${EXPLOITS}" "${VSOURCE}" >> "${LOG_PATH_MODULE}"/F20_summary.txt
    write_log "${BINARY};${VERSION};${CVEs/\ */};${EXPLOITS}" "${LOG_PATH_MODULE}"/F20_summary.csv
  fi

  # now, lets write the main f20 log file with the results of the current binary:
  tee -a "${LOG_FILE}" < "${BIN_LOG}"
}

cve_extractor_thread_actor() {
  local lBIN_BINARY="${1:-}"
  local lBIN_VERSION="${2:-}"
  local CVE_OUTPUT="${3:-}"

  local CVEv2_TMP=0
  local KERNEL_VERIFIED="no"
  local BUSYBOX_VERIFIED="no"
  local CVE_VALUE=""
  local CVSSv2_VALUE=""
  local CVSS_VALUE=""
  local KNOWN_EXPLOITED=0
  local HIGH_CVE_COUNTER=0
  local MEDIUM_CVE_COUNTER=0
  local LOW_CVE_COUNTER=0
  local EID_VALUE=""
  local EXPLOIT_ID=""
  local EXPLOIT_MSF=""
  local EXPLOIT_SNYK=""
  local EXPLOIT_PS=""
  local EXPLOIT_RS=""
  local EXPLOIT_ROUTERSPLOIT=""
  local EXPLOIT_PATH=""
  local EXPLOIT_NAME=""
  local E_FILE=""
  local TYPE=""
  local LINE=""
  local lFIRST_EPSS=""
  local lFIRST_PERC=""

  CVE_VALUE=$(echo "${CVE_OUTPUT}" | cut -d: -f1 | tr -dc '[:print:]' | grep "^CVE-" || true)
  if [[ -z "${CVE_VALUE}" ]]; then
    return
  fi

  # if we find a blacklist file we check if the current CVE value is in the blacklist
  # if we find it this CVE is not further processed
  if [[ -f "${CVE_BLACKLIST}" ]]; then
    if grep -q ^"${CVE_VALUE}"$ "${CVE_BLACKLIST}"; then
      print_output "[*] ${ORANGE}${CVE_VALUE}${NC} for ${ORANGE}${lBIN_BINARY}${NC} blacklisted and ignored." "no_log"
      return
    fi
  fi
  # if we find a whitelist file we check if the current CVE value is in the whitelist
  # only if we find this CVE in the whitelist it is further processed
  if [[ -f "${CVE_WHITELIST}" ]]; then
    # do a quick check if there is some data in the whitelist config file
    if [[ $(grep -E -c "^CVE-[0-9]+-[0-9]+$" "${CVE_WHITELIST}") -gt 0 ]]; then
      if ! grep -q ^"${CVE_VALUE}"$ "${CVE_WHITELIST}"; then
        print_output "[*] ${ORANGE}${CVE_VALUE}${NC} for ${ORANGE}${lBIN_BINARY}${NC} not in whitelist -> ignored." "no_log"
        return
      fi
    fi
  fi

  CVSSv2_VALUE=$(echo "${CVE_OUTPUT}" | cut -d: -f2)
  CVSS_VALUE=$(echo "${CVE_OUTPUT}" | cut -d: -f3)
  lFIRST_EPSS=$(echo "${CVE_OUTPUT}" | cut -d: -f4)
  lFIRST_PERC=$(echo "${CVE_OUTPUT}" | cut -d: -f5)

  # default value
  EXPLOIT="No exploit available"

  # check if the CVE is known as a knwon exploited vulnerability:
  if [[ -f "${KNOWN_EXP_CSV}" ]]; then
    # if grep -q \""${CVE_VALUE}"\", "${KNOWN_EXP_CSV}"; then
    if grep -q "^${CVE_VALUE}," "${KNOWN_EXP_CSV}"; then
      print_output "[+] ${ORANGE}WARNING:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a known exploited vulnerability."
      write_log "[+] ${ORANGE}WARNING:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a known exploited vulnerability." "${LOG_PATH_MODULE}"/exploit/known_exploited_vulns.log

      if [[ "${EXPLOIT}" == "No exploit available" ]]; then
        EXPLOIT="Exploit (KEV"
      else
        EXPLOIT+=" / KEV"
      fi
      KNOWN_EXPLOITED=1
    fi
  fi

  local EDB=0
  # as we already know about a bunch of kernel exploits - lets search them first
  if [[ "${lBIN_BINARY}" == *kernel* ]]; then
    for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
      KERNEL_CVE_EXPLOIT=$(echo "${KERNEL_CVE_EXPLOIT}" | cut -d\; -f3)
      if [[ "${KERNEL_CVE_EXPLOIT}" == "${CVE_VALUE}" ]]; then
        EXPLOIT="Exploit (linux-exploit-suggester"
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${CVE_VALUE};kernel exploit" "${TMP_DIR}"/exploit_cnt.tmp
        EDB=1
      fi
    done

    if [[ -f "${S26_LOG_DIR}"/cve_results_kernel_"${VERSION}".csv ]]; then
      # check if the current CVE is a verified kernel CVE from s26 module
      if grep -q ";${CVE_VALUE};.*;.*;1;1" "${S26_LOG_DIR}"/cve_results_kernel_"${VERSION}".csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols and kernel configuration${GREEN})!" "no_log"
        ((KERNEL_VERIFIED_VULN+=1))
        KERNEL_VERIFIED="yes"
      fi
      if grep -q ";${CVE_VALUE};.*;.*;1;0" "${S26_LOG_DIR}"/cve_results_kernel_"${VERSION}".csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel symbols${GREEN})!" "no_log"
        ((KERNEL_VERIFIED_VULN+=1))
        KERNEL_VERIFIED="yes"
      fi
      if grep -q ";${CVE_VALUE};.*;.*;0;1" "${S26_LOG_DIR}"/cve_results_kernel_"${VERSION}".csv; then
        print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a verified kernel vulnerability (${ORANGE}kernel configuration${GREEN})!" "no_log"
        ((KERNEL_VERIFIED_VULN+=1))
        KERNEL_VERIFIED="yes"
      fi
    fi
  fi

  if [[ -f "${CSV_DIR}"/s118_busybox_verifier.csv ]] && [[ "${lBIN_BINARY}" == "busybox" ]]; then
    if grep -q ";${CVE_VALUE};" "${CSV_DIR}"/s118_busybox_verifier.csv; then
      print_output "[+] ${ORANGE}INFO:${GREEN} Vulnerability ${ORANGE}${CVE_VALUE}${GREEN} is a verified BusyBox vulnerability (${ORANGE}BusyBox applet${GREEN})!" "no_log"
      BUSYBOX_VERIFIED="yes"
    fi
  fi

  if [[ "${CVE_SEARCHSPLOIT}" -eq 1 || "${MSF_SEARCH}" -eq 1 || "${SNYK_SEARCH}" -eq 1 || "${PS_SEARCH}" -eq 1 ]] ; then
    if [[ ${CVE_SEARCHSPLOIT} -eq 1 ]]; then
      mapfile -t EXPLOIT_AVAIL < <(cve_searchsploit "${CVE_VALUE}" 2>/dev/null || true)
    fi

    if [[ ${MSF_SEARCH} -eq 1 ]]; then
      mapfile -t EXPLOIT_AVAIL_MSF < <(grep -E "${CVE_VALUE}"$ "${MSF_DB_PATH}" 2>/dev/null || true)
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
        EXPLOIT+=" / EDB ID:"
      fi

      for EXPLOIT_ID in "${EXPLOIT_IDS[@]}" ; do
        LOCAL=0
        REMOTE=0
        DOS=0
        EXPLOIT="${EXPLOIT}"" ""${EXPLOIT_ID}"
        write_log "[+] Exploit for ${CVE_VALUE}:\\n" "${LOG_PATH_MODULE}""/exploit/""${EXPLOIT_ID}"".txt"
        for LINE in "${EXPLOIT_AVAIL[@]}"; do
          write_log "${LINE}" "${LOG_PATH_MODULE}""/exploit/""${EXPLOIT_ID}"".txt"
          if [[ "${LINE}" =~ "Platform: local" && "${LOCAL}" -eq 0 ]]; then
            EXPLOIT+=" (L)"
            LOCAL=1
          fi
          if [[ "${LINE}" =~ "Platform: remote" && "${REMOTE}" -eq 0 ]]; then
            EXPLOIT+=" (R)"
            REMOTE=1
          fi
          if [[ "${LINE}" =~ "Platform: dos" && "${DOS}" -eq 0 ]]; then
            EXPLOIT+=" (D)"
            DOS=1
          fi
        done
        EDB=1
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${CVE_VALUE};exploit_db" "${TMP_DIR}"/exploit_cnt.tmp
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
        EXPLOIT+=" / MSF:"
      fi

      for EXPLOIT_MSF in "${EXPLOIT_AVAIL_MSF[@]}" ; do
        if ! [[ -d "${MSF_INSTALL_PATH}" ]]; then
          EXPLOIT_PATH=$(echo "${EXPLOIT_MSF}" | cut -d: -f1)
        else
          EXPLOIT_PATH="${MSF_INSTALL_PATH}"$(echo "${EXPLOIT_MSF}" | cut -d: -f1)
        fi
        EXPLOIT_NAME=$(basename -s .rb "${EXPLOIT_PATH}")
        EXPLOIT+=" ${EXPLOIT_NAME}"
        if [[ -f "${EXPLOIT_PATH}" ]] ; then
          # for the web reporter we copy the original metasploit module into the EMBA log directory
          cp "${EXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/msf_""${EXPLOIT_NAME}".rb
          if grep -q "< Msf::Exploit::Remote" "${EXPLOIT_PATH}"; then
            EXPLOIT+=" (R)"
          fi
          if grep -q "< Msf::Exploit::Local" "${EXPLOIT_PATH}"; then
            EXPLOIT+=" (L)"
          fi
          if grep -q "include Msf::Auxiliary::Dos" "${EXPLOIT_PATH}"; then
            EXPLOIT+=" (D)"
          fi
        fi
      done

      if [[ ${EDB} -eq 0 ]]; then
        # only count the msf exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${CVE_VALUE};MSF" "${TMP_DIR}"/exploit_cnt.tmp
        EDB=1
      fi
    fi

    if [[ ${#EXPLOIT_AVAIL_SNYK[@]} -gt 0 ]]; then
      if [[ "${EXPLOIT}" == "No exploit available" ]]; then
        EXPLOIT="Exploit (Snyk:"
      else
        EXPLOIT+=" / Snyk:"
      fi

      for EXPLOIT_SNYK in "${EXPLOIT_AVAIL_SNYK[@]}" ; do
        EXPLOIT_NAME=$(echo "${EXPLOIT_SNYK}" | cut -d\; -f2)
        EXPLOIT+=" ${EXPLOIT_NAME} (S)"
      done

      if [[ ${EDB} -eq 0 ]]; then
        # only count the snyk exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${CVE_VALUE};SNYK" "${TMP_DIR}"/exploit_cnt.tmp
        EDB=1
      fi
    fi

    if [[ ${#EXPLOIT_AVAIL_PACKETSTORM[@]} -gt 0 ]]; then
      if [[ "${EXPLOIT}" == "No exploit available" ]]; then
        EXPLOIT="Exploit (PSS:"
      else
        EXPLOIT+=" / PSS:"
      fi

      for EXPLOIT_PS in "${EXPLOIT_AVAIL_PACKETSTORM[@]}" ; do
        # we use the html file as EXPLOIT_NAME.
        EXPLOIT_NAME=$(echo "${EXPLOIT_PS}" | cut -d\; -f3 | rev | cut -d '/' -f1-2 | rev)
        EXPLOIT+=" ${EXPLOIT_NAME}"
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
        EXPLOIT+=" (${TYPE})"
      done

      if [[ ${EDB} -eq 0 ]]; then
        # only count the packetstorm exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${CVE_VALUE};PS" "${TMP_DIR}"/exploit_cnt.tmp
        EDB=1
      fi
    fi

    if [[ -v EXPLOIT_AVAIL_ROUTERSPLOIT[@] || -v EXPLOIT_AVAIL_ROUTERSPLOIT1[@] ]]; then
      if [[ "${EXPLOIT}" == "No exploit available" ]]; then
        EXPLOIT="Exploit (Routersploit:"
      else
        EXPLOIT+=" / Routersploit:"
      fi
      EXPLOIT_ROUTERSPLOIT=("${EXPLOIT_AVAIL_ROUTERSPLOIT[@]}" "${EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}")

      for EXPLOIT_RS in "${EXPLOIT_ROUTERSPLOIT[@]}" ; do
        EXPLOIT_PATH=$(echo "${EXPLOIT_RS}" | cut -d: -f1)
        EXPLOIT_NAME=$(basename -s .py "${EXPLOIT_PATH}")
        EXPLOIT+=" ${EXPLOIT_NAME}"
        if [[ -f "${EXPLOIT_PATH}" ]] ; then
          # for the web reporter we copy the original metasploit module into the EMBA log directory
          cp "${EXPLOIT_PATH}" "${LOG_PATH_MODULE}""/exploit/routersploit_""${EXPLOIT_NAME}".py
          if grep -q Port "${EXPLOIT_PATH}"; then
            EXPLOIT+=" (R)"
          fi
        fi
      done

      if [[ ${EDB} -eq 0 ]]; then
        # only count the routersploit exploit if we have not already count an other exploit
        # otherwise we count an exploit for one CVE multiple times
        ((EXPLOIT_COUNTER_VERSION+=1))
        write_log "${lBIN_BINARY};${lBIN_VERSION};${CVE_VALUE};PS" "${TMP_DIR}"/exploit_cnt.tmp
        EDB=1
      fi
    fi
  fi

  if [[ ${KNOWN_EXPLOITED} -eq 1 ]]; then
    EXPLOIT+=" (X)"
  fi

  if [[ ${EDB} -eq 1 ]]; then
    EXPLOIT+=")"
  fi

  # just in case CVSSv3 value is missing -> switch to CVSSv2
  if [[ "${CVSS_VALUE}" == "NA" ]]; then
    # print_output "[*] Missing CVSSv3 value for vulnerability ${ORANGE}${CVE_VALUE}${NC} - setting default CVSS to CVSSv2 ${ORANGE}${CVSSv2_VALUE}${NC}" "no_log"
    CVSS_VALUE="${CVSSv2_VALUE}"
    CVEv2_TMP=1
  fi

  # if this CVE is a kernel verified CVE we add a V to the CVE
  if [[ "${KERNEL_VERIFIED}" == "yes" ]]; then CVE_VALUE+=" (V)"; fi
  if [[ "${BUSYBOX_VERIFIED}" == "yes" ]]; then CVE_VALUE+=" (V)"; fi

  # we do not deal with output formatting the usual way -> we use printf
  if [[ ! -f "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}" ]]; then
    printf "${GREEN}\t%-20.20s:   %-12.12s:   %-18.18s:  %-10.10s : %-4.4s :   %-15.15s:   %s${NC}\n" "BIN NAME" "BIN VERS" "CVE ID" "CVSS VALUE" "EPSS" "SOURCE" "EXPLOIT" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
  fi
  if (( $(echo "${CVSS_VALUE} > 6.9" | bc -l) )); then
    # put a note in the output if we have switched to CVSSv2
    if [[ "${CVEv2_TMP}" -eq 1 ]]; then CVSS_VALUE="${CVSS_VALUE}"" (v2)"; fi
    if [[ "${EXPLOIT}" == *MSF* || "${EXPLOIT}" == *EDB\ ID* || "${EXPLOIT}" == *linux-exploit-suggester* || "${EXPLOIT}" == *Routersploit* || \
      "${EXPLOIT}" == *Github* || "${EXPLOIT}" == *PSS* || "${EXPLOIT}" == *Snyk* || "${KNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY}" "${lBIN_VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${lFIRST_EPSS}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    else
      printf "${RED}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY}" "${lBIN_VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${lFIRST_EPSS}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    fi
    ((HIGH_CVE_COUNTER+=1))
  elif (( $(echo "${CVSS_VALUE} > 3.9" | bc -l) )); then
    if [[ "${CVEv2_TMP}" -eq 1 ]]; then CVSS_VALUE="${CVSS_VALUE}"" (v2)"; fi
    if [[ "${EXPLOIT}" == *MSF* || "${EXPLOIT}" == *EDB\ ID* || "${EXPLOIT}" == *linux-exploit-suggester* || "${EXPLOIT}" == *Routersploit* || \
      "${EXPLOIT}" == *Github* || "${EXPLOIT}" == *PSS* || "${EXPLOIT}" == *Snyk* || "${KNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY}" "${lBIN_VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${lFIRST_EPSS}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    else
      printf "${ORANGE}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY}" "${lBIN_VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${lFIRST_EPSS}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    fi
    ((MEDIUM_CVE_COUNTER+=1))
  else
    if [[ "${CVEv2_TMP}" -eq 1 ]]; then CVSS_VALUE="${CVSS_VALUE}"" (v2)"; fi
    if [[ "${EXPLOIT}" == *MSF* || "${EXPLOIT}" == *EDB\ ID* || "${EXPLOIT}" == *linux-exploit-suggester* || "${EXPLOIT}" == *Routersploit* || \
      "${EXPLOIT}" == *Github* || "${EXPLOIT}" == *PSS* || "${EXPLOIT}" == *Snyk* || "${KNOWN_EXPLOITED}" -eq 1 ]]; then
      printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY}" "${lBIN_VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${lFIRST_EPSS}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    else
      printf "${GREEN}\t%-20.20s:   %-12.12s:   %-18.18s:   %-10.10s:  %-3.3s :   %-15.15s:   %s${NC}\n" "${lBIN_BINARY}" "${lBIN_VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${lFIRST_EPSS}" "${VSOURCE}" "${EXPLOIT}" >> "${LOG_PATH_MODULE}"/cve_sum/"${AGG_LOG_FILE}"
    fi
    ((LOW_CVE_COUNTER+=1))
  fi

  if [[ ${LOW_CVE_COUNTER} -gt 0 ]]; then
    write_log "${LOW_CVE_COUNTER}" "${TMP_DIR}"/LOW_CVE_COUNTER.tmp
  fi
  if [[ ${MEDIUM_CVE_COUNTER} -gt 0 ]]; then
    write_log "${MEDIUM_CVE_COUNTER}" "${TMP_DIR}"/MEDIUM_CVE_COUNTER.tmp
  fi
  if [[ ${HIGH_CVE_COUNTER} -gt 0 ]]; then
    write_log "${HIGH_CVE_COUNTER}" "${TMP_DIR}"/HIGH_CVE_COUNTER.tmp
  fi

  write_csv_log "${lBIN_BINARY}" "${lBIN_VERSION}" "${CVE_VALUE}" "${CVSS_VALUE}" "${#EXPLOIT_AVAIL[@]}" "${#EXPLOIT_AVAIL_MSF[@]}" "${#EXPLOIT_AVAIL_TRICKEST[@]}" "${#EXPLOIT_AVAIL_ROUTERSPLOIT[@]}/${#EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}" "${#EXPLOIT_AVAIL_SNYK[@]}" "${#EXPLOIT_AVAIL_PACKETSTORM[@]}" "${LOCAL}" "${REMOTE}" "${DOS}" "${#KNOWN_EXPLOITED_VULNS[@]}" "${KERNEL_VERIFIED}" "${lFIRST_EPSS:-NA}" "${lFIRST_PERC:-NA}"
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
  local S24_LOG="${1:-}"
  local S25_LOG="${2:-}"
  local KERNEL_VERSION_S24=()
  export KERNEL_CVE_EXPLOITS=()

  if [[ -f "${S25_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S25_LOG}")."
    readarray -t KERNEL_CVE_EXPLOITS < <(cut -d\; -f1-3 "${S25_LOG}" | tail -n +2 | sort -u || true)
    # we get something like this: "linux_kernel;5.10.59;CVE-2021-3490"
  fi
  if [[ -f "${S24_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S24_LOG}")."
    readarray -t KERNEL_VERSION_S24 < <(cut -d\; -f2 "${S24_LOG}" | tail -n +2 | sort -u | sed 's/^/linux_kernel;/' | sed 's/$/;NA/' || true)
    # we get something like this: "linux_kernel;5.10.59;NA"
    KERNEL_CVE_EXPLOITS+=( "${KERNEL_VERSION_S24[@]}" )
  fi
}

get_busybox_verified() {
  local lS118_CSV_LOG="${1:-}"
  export BUSYBOX_VERIFIED_CVE=()

  if [[ -f "${lS118_CSV_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${lS118_CSV_LOG}")."
    readarray -t BUSYBOX_VERIFIED_CVE < <(cut -d\; -f1,3 "${lS118_CSV_LOG}" | tail -n +2 | grep -v "BusyBox VERSION;Verified CVE" | sort -u || true)
  fi
}

get_kernel_verified() {
  local S26_LOGS_ARR=("$@")
  local KERNEL_CVE_VERIFIEDX=()

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
  if [[ -f "${L25_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${L25_LOG}")."
  #  readarray -t VERSIONS_SYS_EMULATOR_WEB < <(cut -d\; -f4 "${L25_LOG}" | tail -n +2 | sort -u || true)
  fi
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

get_lighttpd_details() {
  local S36_LOG="${1:-}"
  export VERSIONS_S36_DETAILS=()

  if [[ -f "${S36_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S36_LOG}")."
    # └─$ cat ~/firmware-stuff/emba_logs_cve/csv_logs/s36_lighttpd.csv | grep ";CVE-" | cut -d\; -f1-2 | sort -u
    readarray -t VERSIONS_S36_DETAILS < <(grep ";CVE-" "${S36_LOG}" | cut -d\; -f1-2 | sort -u | tr ';' ':'|| true)
  fi
}

get_sbom_package_details() {
  local S08_LOG="${1:-}"
  export VERSIONS_S08_PACKAGE_DETAILS=()

  if [[ -f "${S08_LOG}" ]]; then
    print_output "[*] Collect version details of module $(basename "${S08_LOG}")."
    readarray -t VERSIONS_S08_PACKAGE_DETAILS < <(cut -d\; -f6 "${S08_LOG}" | tail -n +2 | sort -u | grep -v "NA" | tr ';' ':' | tr ' ' '_' || true)
  fi
}
