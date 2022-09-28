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
    if ! [[ -f "./helpers/l35_msf_check.rc" ]]; then
      print_output "[-] Metasploit resource script not available - Not performing metasploit checks"
      return
    fi
    if [[ "$IN_DOCKER" -eq 1 ]]; then
      print_output "[-] Metasploit module currently only in full installation mode supported - Not performing metasploit checks"
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
        prepare_metasploit

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

  mapfile -t NMAP_XML_FILES < <(find "$LOG_DIR"/l10_system_emulation/ -iname "nmap_emba_*.xml")
  for NMAP_XML in "${NMAP_XML_FILES[@]}"; do
    timeout --preserve-status --signal SIGINT 600 msfconsole -r ./helpers/l35_msf_check.rc msf msf msf "$NMAP_XML" | tee -a "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt || true
  done

  if [[ -f "$LOG_PATH_MODULE"/metasploit-check-"$IP_ADDRESS_".txt ]]; then
    print_ln
  fi
  print_output "[*] Metasploit tests for emulated system with IP $ORANGE$IP_ADDRESS_$NC finished"
}

prepare_metasploit() {
  print_output "[*] Stop the metasploit database"
  msfdb stop
  print_output "[*] Initialize the metasploit database"
  msfdb init
  print_output "[*] Start the metasploit database"
  msfdb start
  print_output "[*] Status of the metasploit database"
  msfdb status
}
