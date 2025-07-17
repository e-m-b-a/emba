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

# Description:  Tests the emulated live system which is build and started in L10 with Metasploit
#               Currently this is an experimental module and needs to be activated separately via the -Q switch.
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

L35_metasploit_check() {

  local lMODULE_END=0
  if [[ "${SYS_ONLINE}" -eq 1 ]] && [[ "${TCP}" == "ok" ]]; then
    if ! command -v msfconsole > /dev/null; then
      print_output "[-] Metasploit not available - Not performing Metasploit checks"
      return
    fi
    if ! [[ -f "${HELP_DIR}""/l35_msf_check.rc" ]]; then
      print_output "[-] Metasploit resource script not available - Not performing Metasploit checks"
      return
    fi

    module_log_init "${FUNCNAME[0]}"
    module_title "Metasploit exploit checks of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ ${IN_DOCKER} -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi

    if [[ -v IP_ADDRESS_ ]]; then
      if ! system_online_check "${IP_ADDRESS_}"; then
        if ! restart_emulation "${IP_ADDRESS_}" "${IMAGE_NAME}" 1 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System not responding - Not performing Metasploit checks"
          module_end_log "${FUNCNAME[0]}" "${lMODULE_END}"
          return
        fi
      fi

      check_live_metasploit
      lMODULE_END=1
    else
      print_output "[!] No IP address found"
    fi
    write_log ""
    module_end_log "${FUNCNAME[0]}" "${lMODULE_END}"
  fi
}

check_live_metasploit() {
  sub_module_title "Metasploit tests for emulated system with IP ${ORANGE}${IP_ADDRESS_}${NC}"
  local lPORTS=""
  local lPORTS_ARR=()
  local lMSF_VULN=""
  local lMSF_VULNS_VERIFIED_ARR=()
  local lMSF_CVEs_ARR=()
  local lMSF_MODULE=""
  local lARCH_END=""
  local lD_END=""

  if [[ -v ARCHIVE_PATH ]]; then
    mapfile -t lPORTS_ARR < <(find "${ARCHIVE_PATH}" -name "*.xml" -exec grep -a -h "<state state=\"open\"" {} \; | grep -o -E "portid=\"[0-9]+" | cut -d\" -f2 | sort -u || true)
  else
    print_output "[-] Warning: No ARCHIVE_PATH found"
    mapfile -t lPORTS_ARR < <(find "${LOG_DIR}"/l10_system_emulation/ -name "*.xml" -exec grep -a -h "<state state=\"open\"" {} \; | grep -o -E "portid=\"[0-9]+" | cut -d\" -f2 | sort -u || true)
  fi
  if [[ "${#lPORTS_ARR[@]}" -eq 0 ]]; then
    print_output "[-] No open ports identified ..."
    return
  fi

  printf -v lPORTS "%s " "${lPORTS_ARR[@]}"
  lPORTS=${lPORTS//\ /,}
  lPORTS="${lPORTS%,}"
  print_output "[*] Testing system with IP address ${ORANGE}${IP_ADDRESS_}${NC} and ports ${ORANGE}${lPORTS}${NC}."

  # metasploit tries to parse env variables and our environment is wasted!
  export PORT=""
  # lD_END="$(echo "${lD_END}" | tr '[:upper:]' '[:lower:]')"
  lD_END="${lD_END,,}"
  if [[ "${lD_END}" == "el" ]]; then lD_END="le"; fi
  if [[ "${lD_END}" == "eb" ]]; then lD_END="be"; fi
  # lARCH_END="$(echo "${ARCH}" | tr '[:upper:]' '[:lower:]')$(echo "${lD_END}" | tr '[:upper:]' '[:lower:]')"
  lARCH_END="${ARCH,,}""${lD_END,,}"

  timeout --signal SIGINT -k 60 60m msfconsole -q -n -r "${HELP_DIR}"/l35_msf_check.rc "${IP_ADDRESS_}" "${lPORTS}" "${lARCH_END}"| tee -a "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt || true

  if [[ -f "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt ]] && [[ $(grep -a -i -c "Vulnerability identified for module" "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt) -gt 0 ]]; then
    write_csv_log "Source" "Module" "CVE" "ARCH_END" "IP_ADDRESS" "PORTS"
    print_ln
    print_output "[+] Metasploit results for verification" "" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"
    mapfile -t lMSF_VULNS_VERIFIED_ARR < <(grep -a -i "Vulnerability identified for module" "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt || true)
    for lMSF_VULN in "${lMSF_VULNS_VERIFIED_ARR[@]}"; do
      local lMSF_CVE=""
      lMSF_MODULE="$(echo "${lMSF_VULN}" | sed 's/.*module\ //' | sed 's/\ -\ .*//')"
      mapfile -t lMSF_CVEs_ARR < <(grep "${lMSF_MODULE}" "${MSF_DB_PATH}" | cut -d: -f2 || true)
      printf -v lMSF_CVE "%s " "${lMSF_CVEs_ARR[@]}"
      lMSF_CVE="${lMSF_CVE%\ }"
      if [[ -n "${lMSF_CVE}" ]]; then
        print_output "[+] Vulnerability verified: ${ORANGE}${lMSF_MODULE}${GREEN} / ${ORANGE}${lMSF_CVE}${GREEN}."
        write_link "https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/${lMSF_MODULE}.rb"
        # we write our csv entry later for every CVE entry
      else
        print_output "[+] Vulnerability verified: ${ORANGE}${lMSF_MODULE}${GREEN}."
        write_link "https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/${lMSF_MODULE}.rb"
        lMSF_CVE="NA"
        # if we have no CVE entry we can directly write our csv entry:
        write_csv_log "Metasploit framework" "${lMSF_MODULE}" "${lMSF_CVE}" "${lARCH_END}" "${IP_ADDRESS_}" "${lPORTS}"
      fi
      for lMSF_CVE in "${lMSF_CVEs_ARR[@]}"; do
        # per CVE one csv entry:
        write_csv_log "Metasploit framework" "${lMSF_MODULE}" "${lMSF_CVE}" "${lARCH_END}" "${IP_ADDRESS_}" "${lPORTS}"
      done
    done

    # color results:
    sed -i -r 's/.*Vulnerability identified.*/\x1b[32m&\x1b[0m/' "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt
    sed -i -r 's/.*Session state.*for module.*/\x1b[32m&\x1b[0m/' "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt
    sed -i -r 's/Active sessions/\x1b[32m&\x1b[0m/' "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt
    sed -i -r 's/Via:\ .*/\x1b[32m&\x1b[0m/' "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt

    print_ln

    if grep -q "Active sessions" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"; then
      print_ln
      print_output "[+] Possible Metasploit sessions for verification:" "" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"
      # sometimes we need two print_ln to get one in the web report?!?
      print_ln
      print_ln
      # Print the session output from the metasploit log:
      sed -n '/Active sessions/,/Stopping all jobs/p' "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt | tee -a "${LOG_FILE}" || true
      print_ln
    elif grep -q "session .* opened" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"; then
      print_ln
      print_output "[+] Possible Metasploit sessions for verification - check the log" "" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"
      print_ln
    else
      print_output "[-] No Metasploit session detected"
    fi
  elif [[ -f "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt ]]; then
    # just for link the log file in the web reporter
    print_output "[-] No Metasploit results detected" "" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"
  else
    print_output "[-] No Metasploit results detected"
  fi
  print_output "[*] Metasploit tests for emulated system with IP ${ORANGE}${IP_ADDRESS_}${NC} finished"
}
