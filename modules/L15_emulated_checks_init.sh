#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Tests the emulated live system which is build and started in S150
#               Currently this is an experimental module and needs to be activated separately via the -Q switch. 
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

L15_emulated_checks_init() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Live tests of emulated device."

  if [[ "$SYS_ONLINE" -eq 1 ]]; then

    if [[ $IN_DOCKER -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi

    check_nmap_basic
    check_snmp
    check_nikto
    MODULE_END=1

    pkill -f "qemu-system-.*$IMAGE_NAME.*"
    reset_network
  else
    MODULE_END=0
  fi

  module_end_log "${FUNCNAME[0]}" "$MODULE_END"

}

check_nikto() {
  sub_module_title "Nikto web checks for emulated system with IP $IP"

  nikto -host "$IP" | tee -a "$LOG_FILE"
  print_output ""
  print_output "[*] Nikto web checks for emulated system with IP $IP finished"
}

check_nmap_basic() {
  sub_module_title "Nmap portscans for emulated system with IP $IP"

  nmap -sSV "$IP" | tee -a "$LOG_FILE"
  print_output ""
  print_output "[*] Nmap portscans for emulated system with IP $IP finished"
}

check_snmp() {
  sub_module_title "SNMP enumeration for emulated system with IP $IP"

  print_output "[*] SNMP scan with community name public"
  snmpwalk -v2c -c public "$IP" .iso | tee -a "$LOG_FILE"
  print_output ""
  print_output "[*] SNMP scan with community name private"
  snmpwalk -v2c -c private "$IP" .iso | tee -a "$LOG_FILE"

  print_output ""
  print_output "[*] SNMP tests for emulated system with IP $IP finished"
}
