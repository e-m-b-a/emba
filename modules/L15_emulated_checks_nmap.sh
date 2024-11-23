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

# Description:  Tests the emulated live system which is build and started in L10
#               Currently this is an experimental module and needs to be activated separately via the -Q switch.
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

L15_emulated_checks_nmap() {

  local lMODULE_END=0
  export NMAP_PORTS_SERVICES_ARR=()

  if [[ "${SYS_ONLINE}" -eq 1 ]] && [[ "${TCP}" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Nmap scans of emulated device."

    pre_module_reporter "${FUNCNAME[0]}"

    if [[ -v IP_ADDRESS_ ]]; then
      check_live_nmap_basic "${IP_ADDRESS_}"
      lMODULE_END=1
    else
      print_output "[!] No IP address found"
    fi
    write_log ""
    write_log "[*] Statistics:${#NMAP_PORTS_SERVICES_ARR[@]}"
    module_end_log "${FUNCNAME[0]}" "${lMODULE_END}"
  fi
}

check_live_nmap_basic() {
  local lIP_ADDRESS="${1:-}"
  local lNMAP_RESULT_FILES_ARR=()
  local lNMAP_RESULTF=""
  local lNMAP_SERVICES_ARR=()
  local lS09_L15_CHECK_ARR=()
  local lS116_L15_CHECK_ARR=()
  local lSERVICE=""
  local lSERVICE_NAME=""
  local lTYPE=""
  local lNMAP_CPE_DETECTION_ARR=()
  local lNMAP_CPE=""
  local lNMAP_CPES=""
  local lNMAP_CPES_ARR=()
  local lS09_L15_MATCH=""
  local lS116_L15_MATCH=""
  export NMAP_PORTS_SERVICES_ARR=()

  sub_module_title "Nmap portscans for emulated system with IP ${ORANGE}${lIP_ADDRESS}${NC}"

  cp "${ARCHIVE_PATH}"/nmap_emba_[0-9]-"${lIP_ADDRESS}"*.gnmap "${LOG_PATH_MODULE}" 2>/dev/null || true
  cp "${ARCHIVE_PATH}"/nmap_emba_[0-9]-"${lIP_ADDRESS}"*.nmap "${LOG_PATH_MODULE}" 2>/dev/null || true

  # find all Nmap results
  mapfile -t lNMAP_RESULT_FILES_ARR < <(find "${LOG_PATH_MODULE}" -name "*.nmap")
  write_csv_log "---" "service identifier" "version_detected" "csv_rule" "license" "static/emulation/nmap/nikto"

  if [[ -v lNMAP_RESULT_FILES_ARR[@] ]]; then
    for lNMAP_RESULTF in "${lNMAP_RESULT_FILES_ARR[@]}"; do
      print_output "[*] Found Nmap results ${ORANGE}$(basename "${lNMAP_RESULTF}")${NC}:"
      tee -a "${LOG_FILE}" < "${lNMAP_RESULTF}"
      print_ln
    done
  else
    # if no Nmap results are found we initiate a scan
    if ! system_online_check "${lIP_ADDRESS}" ; then
      if ! restart_emulation "${lIP_ADDRESS}" "${IMAGE_NAME}" 1 "${STATE_CHECK_MECHANISM}"; then
        print_output "[-] System not responding - Not performing Nmap checks"
        return
      fi
    fi
    nmap -Pn -n -sSV -A --host-timeout 30m "${lIP_ADDRESS}" -oA "${LOG_PATH_MODULE}"/nmap-basic-"${lIP_ADDRESS}" | tee -a "${LOG_FILE}"
  fi
  print_ln

  # extract only the service details from gnmap output file:
  mapfile -t lNMAP_SERVICES_ARR < <(grep -h -a "open" "${LOG_PATH_MODULE}"/*.gnmap | cut -d: -f3- | sed s/'\t'/'\n\t'/g | sed s/'\/, '/'\n\t\t'/g | sed s/'Ports: '/'Ports:\n\t\t'/g | grep -v "/closed/\|filtered/" | grep -v "Host: \|Ports:\|Ignored State:\|OS: \|Seq Index: \|Status: \|IP ID Seq: \|^# " | sed 's/^[[:blank:]].*\/\///' | sed 's/\/$//g'| sort -u || true)
  mapfile -t NMAP_PORTS_SERVICES_ARR < <(grep -h -a "open" "${LOG_PATH_MODULE}"/*.nmap | awk '{print $1,$3}' | grep "[0-9]" | sort -u || true)
  # extract cpe information like the following:
  # Service Info: OS: Linux; Device: WAP; CPE: cpe:/h:dlink:dir-300:2.14, cpe:/o:linux:linux_kernel, cpe:/h:d-link:dir-300
  mapfile -t lNMAP_CPE_DETECTION_ARR < <(grep -ah "Service Info: " "${LOG_PATH_MODULE}"/*.nmap | grep -a "CPE: .*" | sort -u || true)

  lTYPE="Nmap scan (Scan info)"

  if [[ "${#lNMAP_CPE_DETECTION_ARR[@]}" -gt 0 ]]; then
    for lNMAP_CPES in "${lNMAP_CPE_DETECTION_ARR[@]}"; do
      lNMAP_CPES=$(echo "${lNMAP_CPES}" | grep -o "cpe:.*" || true)
      # rewrite the string into an array:
      readarray -d ', ' -t lNMAP_CPES_ARR < <(printf "%s" "${lNMAP_CPES}")
      for lNMAP_CPE in "${lNMAP_CPES_ARR[@]}"; do
        if [[ "${lNMAP_CPE}" == *"windows"* ]]; then
          # we emulate only Linux -> if windows is detected this is a FP
          continue
        fi
        lNMAP_CPE=${lNMAP_CPE/ /}
        lNMAP_CPE=${lNMAP_CPE//cpe:\/}
        # remove h/o/b from start -> we need to start with :
        lNMAP_CPE=${lNMAP_CPE#[hob]}
        # just to ensure there is some kind of version information in our entry
        if [[ "$(echo "${lBIN_VERSION}" | tr ':' '\n' | wc -l)" -lt 4 ]]; then
          # if the length does not match we can drop these results
          print_output "[-] WARNING: Identifier ${lBIN_VERSION} is probably incorrect and will be removed" "no_log"
          continue
        fi
        if [[ "${lNMAP_CPE}" =~ :.*[0-9].* ]]; then
          print_output "[*] CPE details detected: ${ORANGE}${lNMAP_CPE}${NC}"
          write_csv_log "---" "NA" "NA" "${lNMAP_CPE}" "NA" "${lTYPE}"
        fi
      done
    done
  fi

  lTYPE="Nmap scan (Service info)"

  if [[ "${#NMAP_PORTS_SERVICES_ARR[@]}" -gt 0 ]]; then
    for lSERVICE in "${NMAP_PORTS_SERVICES_ARR[@]}"; do
      print_output "[*] Service detected: ${ORANGE}${lSERVICE}${NC}"
      lSERVICE_NAME="$(escape_echo "$(echo "${lSERVICE}" | awk '{print $2}')")"
      # just in case we have a / in our lSERVICE_NAME
      lSERVICE_NAME="${lSERVICE_NAME/\//\\\/}"
      if [[ "${lSERVICE_NAME}" == "unknown" ]] || [[ "${lSERVICE_NAME}" == "tcpwrapped" ]] || [[ -z "${lSERVICE_NAME}" ]]; then
        continue
      fi

      if [[ -f "${S09_CSV_LOG}" ]]; then
        # Let's check if we have already found details about this service in our other modules (S09, S115/S116)
        mapfile -t lS09_L15_CHECK_ARR < <(awk -v IGNORECASE=1 -F\; '$2 $3 ~ /'"${lSERVICE_NAME}"'/' "${S09_CSV_LOG}" || true)
        if [[ "${#lS09_L15_CHECK_ARR[@]}" -gt 0 ]]; then
          for lS09_L15_MATCH in "${lS09_L15_CHECK_ARR[@]}"; do
            echo "${lS09_L15_MATCH}" >> "${L15_CSV_LOG}"
            lS09_L15_MATCH=$(echo "${lS09_L15_MATCH}" | cut -d ';' -f3)
            print_output "[+] Service also detected with static analysis (S09): ${ORANGE}${lS09_L15_MATCH}${NC}"
          done
        fi
      fi

      if [[ -f "${S116_CSV_LOG}" ]]; then
        mapfile -t lS116_L15_CHECK_ARR < <(awk -v IGNORECASE=1 -F\; '$2 $3 ~ /'"${lSERVICE_NAME}"'/' "${S116_CSV_LOG}" || true)
        if [[ "${#lS116_L15_CHECK_ARR[@]}" -gt 0 ]]; then
          for lS116_L15_MATCH in "${lS116_L15_CHECK_ARR[@]}"; do
            echo "${lS116_L15_MATCH}" >> "${L15_CSV_LOG}"
            lS116_L15_MATCH=$(echo "${lS116_L15_MATCH}" | cut -d ';' -f3)
            print_output "[+] Service also detected with dynamic user-mode emulation (S115/S116): ${ORANGE}${lS116_L15_MATCH}${NC}"
          done
        fi
      fi
    done
  fi

  if [[ "${#lNMAP_SERVICES_ARR[@]}" -gt 0 ]]; then
    print_ln
    for lSERVICE in "${lNMAP_SERVICES_ARR[@]}"; do
      if ! echo "${lSERVICE}" | grep -q "[0-9]"; then
        continue
      fi
      l15_version_detector "${lSERVICE}" "${lTYPE}"
    done
  fi

  print_ln
  print_output "[*] Nmap portscans for emulated system with IP ${ORANGE}${lIP_ADDRESS}${NC} finished"
}

l15_version_detector() {
  local lSERVICE="${1:-}"
  local lTYPE="${2:-}"

  local lVERSION_LINE=""
  local lSTRICT=""
  local lIDENTIFIER=""
  local lLIC=""
  local lCSV_REGEX=""
  local lCSV_RULE=""
  local lVERSION_IDENTIFIER=""
  local lVERSION_FINDER=""

  print_output "[*] Testing detected service ${ORANGE}${lSERVICE}${NC}" "no_log"

  local lVERSION_IDENTIFIER_CFG="${CONFIG_DIR}"/bin_version_strings.cfg
  if [[ "${QUICK_SCAN:-0}" -eq 1 ]] && [[ -f "${CONFIG_DIR}"/bin_version_strings_quick.cfg ]]; then
    # the quick scan configuration has only entries that have known vulnerabilities in the CVE database
    local lVERSION_IDENTIFIER_CFG="${CONFIG_DIR}"/bin_version_strings_quick.cfg
    local lV_CNT=0
    lV_CNT=$(wc -l "${CONFIG_DIR}"/bin_version_strings_quick.cfg)
    print_output "[*] Quick scan enabled - ${lV_CNT/\ *} version identifiers loaded"
  fi

  while read -r lVERSION_LINE; do
    if echo "${lVERSION_LINE}" | grep -v -q "^[^#*/;]"; then
      continue
    fi
    if echo "${lVERSION_LINE}" | grep -q "no_static"; then
      continue
    fi

    lSTRICT="$(echo "${lVERSION_LINE}" | cut -d\; -f2)"
    lIDENTIFIER="$(echo "${lVERSION_LINE}" | cut -d\; -f1)"

    if [[ ${lSTRICT} == *"strict"* ]]; then
      continue
    elif [[ ${lSTRICT} == "zgrep" ]]; then
      continue
    fi

    lLIC="$(echo "${lVERSION_LINE}" | cut -d\; -f3)"
    lCSV_REGEX="$(echo "${lVERSION_LINE}" | cut -d\; -f5)"
    # lVERSION_IDENTIFIER="$(echo "${lVERSION_LINE}" | cut -d\; -f4 | sed s/^\"// | sed s/\"$//)"
    lVERSION_IDENTIFIER="$(echo "${lVERSION_LINE}" | cut -d\; -f4)"
    lVERSION_IDENTIFIER="${lVERSION_IDENTIFIER/\"}"
    lVERSION_IDENTIFIER="${lVERSION_IDENTIFIER%\"}"

    lVERSION_FINDER=$(echo "${lSERVICE}" | grep -o -a -E "${lVERSION_IDENTIFIER}" | head -1 2>/dev/null || true)
    if [[ -n ${lVERSION_FINDER} ]]; then
      print_output "[+] Version information found ${RED}""${lVERSION_FINDER}""${NC}${GREEN} in ${lTYPE} log."
      # use get_csv_rule from s09:
      lCSV_RULE=$(get_csv_rule "${lVERSION_FINDER}" "${lCSV_REGEX}")
      # get rid of ; which destroys our csv:
      lVERSION_FINDER="${lVERSION_FINDER/;}"
      write_csv_log "---" "${lIDENTIFIER}" "${lVERSION_FINDER}" "${lCSV_RULE}" "${lLIC}" "${lTYPE}"
      continue
    fi
  done  < "${lVERSION_IDENTIFIER_CFG}"
}

