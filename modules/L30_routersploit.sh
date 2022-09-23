#!/bin/bash

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

# Description:  Tests the emulated live system which is build and started in L10
#               Currently this is an experimental module and needs to be activated separately via the -Q switch. 
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

L30_routersploit() {

  local MODULE_END=0

  if [[ "$SYS_ONLINE" -eq 1 ]] && [[ "$TCP" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Routersploit tests of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ $IN_DOCKER -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi
    if [[ -n "$IP_ADDRESS_" ]]; then

      if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
        check_live_routersploit
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

check_live_routersploit() {
  sub_module_title "Routersploit tests for emulated system with IP $ORANGE$IP_ADDRESS_$NC"

  if [[ -f /tmp/routersploit.log ]]; then
    rm /tmp/routersploit.log
  fi

  timeout --preserve-status --signal SIGINT 300 "$EXT_DIR"/routersploit/rsf.py "$IP_ADDRESS_" 2>&1 | tee -a "$LOG_PATH_MODULE"/routersploit-"$IP_ADDRESS_".txt || true

  if [[ -f /tmp/routersploit.log ]]; then
    mv /tmp/routersploit.log "$LOG_PATH_MODULE"/routersploit-detail-"$IP_ADDRESS_".txt
  fi

  cat "$LOG_PATH_MODULE"/routersploit-"$IP_ADDRESS_".txt >> "$LOG_FILE"
  print_ln
  if grep -q "Target is vulnerable" "$LOG_PATH_MODULE"/routersploit-"$IP_ADDRESS_".txt; then
    print_output "[+] Found the following vulnerabilities:"
    grep -B 1 "Target is vulnerable" "$LOG_PATH_MODULE"/routersploit-"$IP_ADDRESS_".txt | tee -a "$LOG_FILE"
  fi
  if grep -q "Target seems to be vulnerable" "$LOG_PATH_MODULE"/routersploit-"$IP_ADDRESS_".txt; then
    print_output "[+] Found the following possible vulnerabilities:"
    grep -B 1 "Target seems to be vulnerable" "$LOG_PATH_MODULE"/routersploit-"$IP_ADDRESS_".txt | tee -a "$LOG_FILE"
  fi
  print_output "[*] Routersploit tests for emulated system with IP $ORANGE$IP_ADDRESS_$NC finished"
}

