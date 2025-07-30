#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
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
  export CONFIDENCE_LEVEL=3

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

  cp "${ARCHIVE_PATH}"/*_nmap_emba_[0-9]-"${lIP_ADDRESS}"*.gnmap "${LOG_PATH_MODULE}" 2>/dev/null || true
  cp "${ARCHIVE_PATH}"/*_nmap_emba_[0-9]-"${lIP_ADDRESS}"*.nmap "${LOG_PATH_MODULE}" 2>/dev/null || true

  # find all Nmap results
  mapfile -t lNMAP_RESULT_FILES_ARR < <(find "${LOG_PATH_MODULE}" -name "*.nmap")

  if [[ "${#lNMAP_RESULT_FILES_ARR[@]}" -gt 0 ]]; then
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
        if [[ "$(echo "${lNMAP_CPE}" | tr ':' '\n' | wc -l)" -lt 4 ]]; then
          # if the length does not match we can drop these results
          print_output "[-] WARNING: Identifier ${lNMAP_CPE} is probably incorrect and will be removed" "no_log"
          continue
        fi
        if [[ "${lNMAP_CPE}" =~ :.*[0-9].* ]]; then
          print_output "[*] CPE details detected: ${ORANGE}${lNMAP_CPE}${NC}"
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
        mapfile -t lS09_L15_CHECK_ARR < <(awk -v IGNORECASE=1 -F\; '$3 $4 ~ /'"${lSERVICE_NAME}"'/' "${S09_CSV_LOG}" | sort -u || true)
        if [[ "${#lS09_L15_CHECK_ARR[@]}" -gt 0 ]]; then
          for lS09_L15_MATCH in "${lS09_L15_CHECK_ARR[@]}"; do
            lS09_L15_MATCH=$(echo "${lS09_L15_MATCH}" | cut -d ';' -f4)
            if ! grep -q ";${lS09_L15_MATCH};" "${L15_CSV_LOG}"; then
              print_output "[+] Service also detected with static analysis (S09): ${ORANGE}${lS09_L15_MATCH}${NC}"
              echo "${lS09_L15_MATCH}" >> "${L15_CSV_LOG}"
            fi
          done
        fi
      fi

      if [[ -f "${S116_CSV_LOG}" ]]; then
        mapfile -t lS116_L15_CHECK_ARR < <(awk -v IGNORECASE=1 -F\; '$3 $4 ~ /'"${lSERVICE_NAME}"'/' "${S116_CSV_LOG}" | sort -u || true)
        if [[ "${#lS116_L15_CHECK_ARR[@]}" -gt 0 ]]; then
          for lS116_L15_MATCH in "${lS116_L15_CHECK_ARR[@]}"; do
            lS116_L15_MATCH=$(echo "${lS116_L15_MATCH}" | cut -d ';' -f4)
            if ! grep -q ";${lS116_L15_MATCH};" "${L15_CSV_LOG}"; then
              print_output "[+] Service also detected with dynamic user-mode emulation (S115/S116): ${ORANGE}${lS116_L15_MATCH}${NC}"
              echo "${lS116_L15_MATCH}" >> "${L15_CSV_LOG}"
            fi
          done
        fi
      fi
    done
  fi

  if [[ "${#lNMAP_SERVICES_ARR[@]}" -gt 0 ]]; then
    print_ln
    local lWAIT_PIDS_L15_ARR=()
    for lSERVICE in "${lNMAP_SERVICES_ARR[@]}"; do
      if ! echo "${lSERVICE}" | grep -q "[0-9]"; then
        continue
      fi
      l15_version_detector "${lSERVICE}" "${lTYPE}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_L15_ARR+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_L15_ARR
    done
    wait_for_pid "${lWAIT_PIDS_L15_ARR[@]}"
  fi

  print_ln
  print_output "[*] Nmap portscans for emulated system with IP ${ORANGE}${lIP_ADDRESS}${NC} finished"
}

l15_version_detector() {
  local lSERVICE="${1:-}"
  local lTYPE="${2:-}"

  local lVERSION_IDENTIFIER_ARR=()
  local lVERSION_IDENTIFIER=""

  print_output "[*] Testing detected service ${ORANGE}${lSERVICE}${NC}" "no_log"

  local lVERSION_IDENTIFIER_CFG_PATH="${CONFIG_DIR}"/bin_version_identifiers
  local lVERSION_IDENTIFIER_CFG_ARR=()
  local lVERSION_JSON_CFG=""
  local lWAIT_PIDS_L15_ARR_02=()
  mapfile -t lVERSION_IDENTIFIER_CFG_ARR < <(find "${lVERSION_IDENTIFIER_CFG_PATH}" -name "*.json")

  for lVERSION_JSON_CFG in "${lVERSION_IDENTIFIER_CFG_ARR[@]}"; do
    l15_version_detector_threader "${lVERSION_JSON_CFG}" "${lSERVICE}" "${lTYPE}" &
    local lTMP_PID="$!"
    store_kill_pids "${lTMP_PID}"
    WAIT_PIDS_L15_ARR_02+=( "${lTMP_PID}" )
    max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_L15_ARR_02
  done
  wait_for_pid "${lWAIT_PIDS_L15_ARR_02[@]}"
}

l15_version_detector_threader() {
  local lVERSION_JSON_CFG="${1:-}"
  local lSERVICE="${2:-}"
  local lTYPE="${3:-}"

  local lVERSION_IDENTIFIED=""

  # print_output "[*] Testing json config ${ORANGE}${lVERSION_JSON_CFG}${NC}" "no_log"
  local lRULE_IDENTIFIER=""
  lRULE_IDENTIFIER=$(jq -r .identifier "${lVERSION_JSON_CFG}" || print_error "[-] Error in parsing ${lVERSION_JSON_CFG}")
  local lLICENSES_ARR=()
  mapfile -t lLICENSES_ARR < <(jq -r .licenses[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  local lPRODUCT_NAME_ARR=()
  # shellcheck disable=SC2034
  mapfile -t lPRODUCT_NAME_ARR < <(jq -r .product_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  local lVENDOR_NAME_ARR=()
  # shellcheck disable=SC2034
  mapfile -t lVENDOR_NAME_ARR < <(jq -r .vendor_names[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  local lCSV_REGEX_ARR=()
  # shellcheck disable=SC2034
  mapfile -t lCSV_REGEX_ARR < <(jq -r .version_extraction[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)
  local lVERSION_IDENTIFIER_ARR=()
  mapfile -t lVERSION_IDENTIFIER_ARR < <(jq -r .grep_commands[] "${lVERSION_JSON_CFG}" 2>/dev/null || true)

  for lVERSION_IDENTIFIER in "${lVERSION_IDENTIFIER_ARR[@]}"; do
    lVERSION_IDENTIFIED=$(echo "${lSERVICE}" | grep -o -a -E "${lVERSION_IDENTIFIER}" | head -1 2>/dev/null || true)
    if [[ -n ${lVERSION_IDENTIFIED} ]]; then
      print_output "[+] Version information found ${RED}${lVERSION_IDENTIFIED}${GREEN} in emulated service ${ORANGE}${lSERVICE}${GREEN} (license: ${ORANGE}${lLICENSES_ARR[*]}${GREEN}) (${ORANGE}${lTYPE}${GREEN})."
      export TYPE="${lTYPE}"
      export PACKAGING_SYSTEM="system_emulation"
      if version_parsing_logging "${S09_CSV_LOG}" "L15_emulated_checks_nmap" "${lVERSION_IDENTIFIED}" "NA" "${lRULE_IDENTIFIER}" "lVENDOR_NAME_ARR" "lPRODUCT_NAME_ARR" "lLICENSES_ARR" "lCSV_REGEX_ARR"; then
        # print_output "[*] back from logging for ${lVERSION_IDENTIFIED} -> continue to next service -> return"
        return
      fi
    fi
  done
}
