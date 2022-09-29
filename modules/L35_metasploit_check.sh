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

  mapfile -t PORTS_ARR < <(grep -a -h "<state state=\"open\"" "$LOG_DIR"/l10_system_emulation/*.xml | grep -o -E "portid=\"[0-9]+" | cut -d\" -f2 | sort -u || true)
  printf -v PORTS "%s " "${PORTS_ARR[@]}"
  PORTS=${PORTS//\ /,}
  PORTS="${PORTS%,}"
  print_output "[*] Testing system with IP address $ORANGE$IP_ADDRESS_$NC and ports $ORANGE$PORTS$NC."

  # timeout --preserve-status --signal SIGINT 1000 msfconsole -r ./helpers/l35_msf_check.rc "$IP_ADDRESS_" "$PORTS" | tee -a "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt || true
  echo "PORTS: $PORTS"
  echo "IP_ADDRESS_: $IP_ADDRESS_"
  echo "HELP_DIR: $HELP_DIR"
  msfconsole -r "$HELP_DIR""/l35_msf_check.rc" "$IP_ADDRESS_" "$PORTS"

  if [[ -f "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt ]] && [[ $(grep -a -i -c "\[+\]\|stager" "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt) -gt 0 ]]; then
    print_ln
    print_output "[+] Possible Metasploit results for verification." "" "$LOG_PATH_MODULE/metasploit-check-$IP_ADDRESS_.txt"

    grep -a -i "\[+\]\|stager" "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt || true

    print_ln
  else
    print_output "[-] No Metasploit results detected"
  fi
  print_output "[*] Metasploit tests for emulated system with IP $ORANGE$IP_ADDRESS_$NC finished"
}
