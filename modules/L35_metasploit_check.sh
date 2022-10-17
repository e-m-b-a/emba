#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Tests the emulated live system which is build and started in L10 with Metasploit
#               Currently this is an experimental module and needs to be activated separately via the -Q switch. 
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

L35_metasploit_check() {

  local MODULE_END=0
  if [[ "$SYS_ONLINE" -eq 1 ]] && [[ "$TCP" == "ok" ]]; then
    if ! command -v msfconsole > /dev/null; then
      print_output "[-] Metasploit not available - Not performing metasploit checks"
      return
    fi
    if ! [[ -f "$HELP_DIR""/l35_msf_check.rc" ]]; then
      print_output "[-] Metasploit resource script not available - Not performing metasploit checks"
      return
    fi

    module_log_init "${FUNCNAME[0]}"
    module_title "Metasploit exploit checks of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ $IN_DOCKER -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi
    if [[ -n "$IP_ADDRESS_" ]]; then
      if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then

        check_live_metasploit
        MODULE_END=1
      else
        print_output "[-] System not responding - Not performing routersploit checks"
      fi
    else
      print_output "[!] No IP address found"
    fi
    write_log ""
    module_end_log "${FUNCNAME[0]}" "$MODULE_END"
  fi
}

check_live_metasploit() {
  sub_module_title "Metasploit tests for emulated system with IP $ORANGE$IP_ADDRESS_$NC"
  local PORTS=""
  local PORTS_ARR=()
  local MSF_VULN=""
  local MSF_VULNS_VERIFIED=()
  local MSF_MODULE=""
  local ARCH_END=""

  mapfile -t PORTS_ARR < <(grep -a -h "<state state=\"open\"" "$LOG_DIR"/l10_system_emulation/*.xml | grep -o -E "portid=\"[0-9]+" | cut -d\" -f2 | sort -u || true)
  printf -v PORTS "%s " "${PORTS_ARR[@]}"
  PORTS=${PORTS//\ /,}
  PORTS="${PORTS%,}"
  print_output "[*] Testing system with IP address $ORANGE$IP_ADDRESS_$NC and ports $ORANGE$PORTS$NC."

  # metasploit tries to parse env variables and our environment is wasted!
  export PORT=""
  D_END="$(echo "$D_END" | tr '[:upper:]' '[:lower:]')"
  if [[ "$D_END" == "el" ]]; then D_END="le"; fi
  if [[ "$D_END" == "eb" ]]; then D_END="be"; fi
  ARCH_END="$(echo "$ARCH" | tr '[:upper:]' '[:lower:]')$(echo "$D_END" | tr '[:upper:]' '[:lower:]')"

  timeout --preserve-status --signal SIGINT 2000 msfconsole -q -n -r "$HELP_DIR"/l35_msf_check.rc "$IP_ADDRESS_" "$PORTS" "$ARCH_END"| tee -a "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt || true

  if [[ -f "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt ]] && [[ $(grep -a -i -c "Vulnerability identified for module" "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt) -gt 0 ]]; then
    write_csv_log "Source" "Module" "CVE" "ARCH_END" "IP_ADDRESS" "PORTS"
    print_ln
    print_output "[+] Possible Metasploit results for verification:" "" "$LOG_PATH_MODULE/metasploit-check-$IP_ADDRESS_.txt"
    mapfile -t MSF_VULNS_VERIFIED < <(grep -a -i "Vulnerability identified for module" "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt || true)
    for MSF_VULN in "${MSF_VULNS_VERIFIED[@]}"; do
      local MSF_CVE=""
      MSF_MODULE="$(echo "$MSF_VULN" | sed 's/.*module\ //' | sed 's/\ -\ .*//')"
      mapfile -t MSF_CVEs < <(grep "$MSF_MODULE" "$MSF_DB_PATH" | cut -d: -f2 || true)
      printf -v MSF_CVE "%s " "${MSF_CVEs[@]}"
      MSF_CVE="${MSF_CVE%\ }"
      if [[ -n "$MSF_CVE" ]]; then
        print_output "[+] Vulnerability verified: $ORANGE$MSF_MODULE$GREEN / $ORANGE$MSF_CVE$NC."
      else
        print_output "[+] Vulnerability verified: $ORANGE$MSF_MODULE$NC."
        MSF_CVE="NA"
        # if we have not CVE entry we can directly write our csv entry:
        write_csv_log "Metasploit framework" "$MSF_MODULE" "$MSF_CVE" "$ARCH_END" "$IP_ADDRESS_" "$PORTS"
      fi
      for MSF_CVE in "${MSF_CVEs[@]}"; do
        # per CVE one csv entry:
        write_csv_log "Metasploit framework" "$MSF_MODULE" "$MSF_CVE" "$ARCH_END" "$IP_ADDRESS_" "$PORTS"
      done
    done

    print_ln

    print_output "[+] Possible Metasploit sessions for verification." "" "$LOG_PATH_MODULE/metasploit-check-$IP_ADDRESS_.txt"
    print_ln
    # Print the session output from the metasploit log:
    sed -n '/Active sessions/,/Stopping all jobs/p' "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt || true
    print_ln
  else
    print_output "[-] No Metasploit results detected"
  fi
  print_output "[*] Metasploit tests for emulated system with IP $ORANGE$IP_ADDRESS_$NC finished"
}
