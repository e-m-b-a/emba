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

# Description:  Tests the emulated live system which is build and started in L10 with Metasploit
#               Currently this is an experimental module and needs to be activated separately via the -Q switch.
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

L35_metasploit_check() {

  local MODULE_END=0
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
          module_end_log "${FUNCNAME[0]}" "${MODULE_END}"
          return
        fi
      fi

      check_live_metasploit
      MODULE_END=1
    else
      print_output "[!] No IP address found"
    fi
    write_log ""
    module_end_log "${FUNCNAME[0]}" "${MODULE_END}"
  fi
}

check_live_metasploit() {
  sub_module_title "Metasploit tests for emulated system with IP ${ORANGE}${IP_ADDRESS_}${NC}"
  local PORTS=""
  local PORTS_ARR=()
  local MSF_VULN=""
  local MSF_VULNS_VERIFIED=()
  local MSF_CVEs=()
  local MSF_MODULE=""
  local ARCH_END=""
  local D_END=""

  if [[ -v ARCHIVE_PATH ]]; then
    mapfile -t PORTS_ARR < <(find "${ARCHIVE_PATH}" -name "*.xml" -exec grep -a -h "<state state=\"open\"" {} \; | grep -o -E "portid=\"[0-9]+" | cut -d\" -f2 | sort -u || true)
  else
    print_output "[-] Warning: No ARCHIVE_PATH found"
    mapfile -t PORTS_ARR < <(find "${LOG_DIR}"/l10_system_emulation/ -name "*.xml" -exec grep -a -h "<state state=\"open\"" {} \; | grep -o -E "portid=\"[0-9]+" | cut -d\" -f2 | sort -u || true)
  fi
  if [[ "${#PORTS_ARR[@]}" -eq 0 ]]; then
    print_output "[-] No open ports identified ..."
    return
  fi

  printf -v PORTS "%s " "${PORTS_ARR[@]}"
  PORTS=${PORTS//\ /,}
  PORTS="${PORTS%,}"
  print_output "[*] Testing system with IP address ${ORANGE}${IP_ADDRESS_}${NC} and ports ${ORANGE}${PORTS}${NC}."

  # metasploit tries to parse env variables and our environment is wasted!
  export PORT=""
  # D_END="$(echo "${D_END}" | tr '[:upper:]' '[:lower:]')"
  D_END="${D_END,,}"
  if [[ "${D_END}" == "el" ]]; then D_END="le"; fi
  if [[ "${D_END}" == "eb" ]]; then D_END="be"; fi
  # ARCH_END="$(echo "${ARCH}" | tr '[:upper:]' '[:lower:]')$(echo "${D_END}" | tr '[:upper:]' '[:lower:]')"
  ARCH_END="${ARCH,,}""${D_END,,}"

  timeout --preserve-status --signal SIGINT -k 60 2000 msfconsole -q -n -r "${HELP_DIR}"/l35_msf_check.rc "${IP_ADDRESS_}" "${PORTS}" "${ARCH_END}"| tee -a "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt || true

  if [[ -f "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt ]] && [[ $(grep -a -i -c "Vulnerability identified for module" "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt) -gt 0 ]]; then
    write_csv_log "Source" "Module" "CVE" "ARCH_END" "IP_ADDRESS" "PORTS"
    print_ln
    print_output "[+] Metasploit results for verification" "" "${LOG_PATH_MODULE}/metasploit-check-${IP_ADDRESS_}.txt"
    mapfile -t MSF_VULNS_VERIFIED < <(grep -a -i "Vulnerability identified for module" "${LOG_PATH_MODULE}"/metasploit-check-"${IP_ADDRESS_}".txt || true)
    for MSF_VULN in "${MSF_VULNS_VERIFIED[@]}"; do
      local MSF_CVE=""
      MSF_MODULE="$(echo "${MSF_VULN}" | sed 's/.*module\ //' | sed 's/\ -\ .*//')"
      mapfile -t MSF_CVEs < <(grep "${MSF_MODULE}" "${MSF_DB_PATH}" | cut -d: -f2 || true)
      printf -v MSF_CVE "%s " "${MSF_CVEs[@]}"
      MSF_CVE="${MSF_CVE%\ }"
      if [[ -n "${MSF_CVE}" ]]; then
        print_output "[+] Vulnerability verified: ${ORANGE}${MSF_MODULE}${GREEN} / ${ORANGE}${MSF_CVE}${GREEN}."
        write_link "https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/${MSF_MODULE}.rb"
        # we write our csv entry later for every CVE entry
      else
        print_output "[+] Vulnerability verified: ${ORANGE}${MSF_MODULE}${GREEN}."
        write_link "https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/${MSF_MODULE}.rb"
        MSF_CVE="NA"
        # if we have no CVE entry we can directly write our csv entry:
        write_csv_log "Metasploit framework" "${MSF_MODULE}" "${MSF_CVE}" "${ARCH_END}" "${IP_ADDRESS_}" "${PORTS}"
      fi
      for MSF_CVE in "${MSF_CVEs[@]}"; do
        # per CVE one csv entry:
        write_csv_log "Metasploit framework" "${MSF_MODULE}" "${MSF_CVE}" "${ARCH_END}" "${IP_ADDRESS_}" "${PORTS}"
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
