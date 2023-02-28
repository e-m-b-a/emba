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

# Description:  Tests the emulated live system which is build and started in L10
#               Currently this is an experimental module and needs to be activated separately via the -Q switch. 
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

L20_snmp_checks() {

  export SNMP_UP=0

  if [[ "$SYS_ONLINE" -eq 1 ]] && [[ "$TCP" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Live SNMP tests of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ $IN_DOCKER -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi

    if [[ -v IP_ADDRESS_ ]]; then
      if ! ping -c 2 "$IP_ADDRESS_" &> /dev/null; then
        restart_emulation "$IP_ADDRESS_" "$IMAGE_NAME"
        if ! ping -c 2 "$IP_ADDRESS_" &> /dev/null; then
          print_output "[-] System not responding - Not performing SNMP checks"
          module_end_log "${FUNCNAME[0]}" "$SNMP_UP"
          return
        fi
      fi
      check_live_snmp "$IP_ADDRESS_"
    else
      print_output "[!] No IP address found"
    fi

    write_log ""
    write_log "Statistics:$SNMP_UP"
    module_end_log "${FUNCNAME[0]}" "$SNMP_UP"
  fi
}

check_live_snmp() {
  local IP_ADDRESS_="${1:-}"

  sub_module_title "SNMP enumeration for emulated system with IP $ORANGE$IP_ADDRESS_$NC"

  if command -v snmp-check > /dev/null; then
    print_output "[*] SNMP scan with community name ${ORANGE}public$NC"
    snmp-check -w "$IP_ADDRESS_"| tee "$LOG_PATH_MODULE"/snmp-check-public-"$IP_ADDRESS_".txt
    if [[ -f "$LOG_PATH_MODULE"/snmp-check-public-"$IP_ADDRESS_".txt ]]; then
      cat "$LOG_PATH_MODULE"/snmp-check-public-"$IP_ADDRESS_".txt >> "$LOG_FILE"
    fi
    print_ln
    print_output "[*] SNMP scan with community name ${ORANGE}private$NC"
    snmp-check -c private -w "$IP_ADDRESS_"| tee "$LOG_PATH_MODULE"/snmp-check-private-"$IP_ADDRESS_".txt
    if [[ -f "$LOG_PATH_MODULE"/snmp-check-private-"$IP_ADDRESS_".txt ]]; then
      cat "$LOG_PATH_MODULE"/snmp-check-private-"$IP_ADDRESS_".txt >> "$LOG_FILE"
    fi
  else
    print_output "[*] SNMP scan with community name ${ORANGE}public$NC"
    snmpwalk -v2c -c public "$IP_ADDRESS_" .iso | tee "$LOG_PATH_MODULE"/snmpwalk-public-"$IP_ADDRESS_".txt || true
    if [[ -f "$LOG_PATH_MODULE"/snmp-check-public-"$IP_ADDRESS_".txt ]]; then
      cat "$LOG_PATH_MODULE"/snmpwalk-public-"$IP_ADDRESS_".txt >> "$LOG_FILE"
    fi
    print_ln
    print_output "[*] SNMP scan with community name ${ORANGE}private$NC"
    snmpwalk -v2c -c private "$IP_ADDRESS_" .iso | tee "$LOG_PATH_MODULE"/snmapwalk-private-"$IP_ADDRESS_".txt || true
    if [[ -f "$LOG_PATH_MODULE"/snmp-check-private-"$IP_ADDRESS_".txt ]]; then
      cat "$LOG_PATH_MODULE"/snmpwalk-private-"$IP_ADDRESS_".txt >> "$LOG_FILE"
    fi
  fi
  SNMP_UP=$(wc -l "$LOG_PATH_MODULE"/snmp* | tail -1 | awk '{print $1}')

  if [[ "$SNMP_UP" -gt 20 ]]; then
    SNMP_UP=1
  else
    SNMP_UP=0
  fi

  print_ln
  print_output "[*] SNMP tests for emulated system with IP $ORANGE$IP_ADDRESS_$NC finished"
}

