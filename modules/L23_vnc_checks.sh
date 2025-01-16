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

L23_vnc_checks() {
  if [[ "${SYS_ONLINE}" -eq 1 ]] && [[ "${TCP}" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Live VNC tests of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ "${IN_DOCKER}" -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi
    local lVNC_PORT_ARR=()
    local lVNC_PORT=""
    export VNC_UP=0

    if [[ -v IP_ADDRESS_ ]]; then
      if ! system_online_check "${IP_ADDRESS_}"; then
        if ! restart_emulation "${IP_ADDRESS_}" "${IMAGE_NAME}" 1 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System not responding - Not performing UPnP/HNAP checks"
          module_end_log "${FUNCNAME[0]}" "${VNC_UP}"
          return
        fi
      fi
      if [[ "$(grep -c "open.*vnc" "${LOG_DIR}"/l15_emulated_checks_nmap/nmap_emba_*.nmap 2>/dev/null | cut -d ':' -f2 | awk '{s+=$1} END {print s}')" -gt 0 ]]; then
        mapfile -t lVNC_PORT_ARR < <(grep -h "open.*vnc" "${LOG_DIR}"/l15_emulated_checks_nmap/nmap_emba_*.nmap | awk '{print $1}' | cut -d '/' -f1 | sort -u || true)
        for lVNC_PORT in "${lVNC_PORT_ARR[@]}"; do
          check_basic_vnc "${lVNC_PORT}"
          check_msf_vnc "${lVNC_PORT}"
        done
      else
        print_output "[!] No network interface found"
      fi
    else
      print_output "[!] No IP address found"
    fi

    write_log ""
    write_log "Statistics:${VNC_UP}"
    module_end_log "${FUNCNAME[0]}" "${VNC_UP}"
  fi
}

check_basic_vnc() {
  local lVNC_PORT="${1:-}"

  sub_module_title "Nmap VNC enumeration for emulated system ${ORANGE}${IP_ADDRESS_} / ${lVNC_PORT}${NC}"

  nmap -sV --script=*vnc* -p "${lVNC_PORT}" "${IP_ADDRESS_}" >> "${LOG_PATH_MODULE}"/vnc_basic-check.txt || true

  if [[ -f "${LOG_PATH_MODULE}"/vnc_basic-check.txt ]]; then
    if [[ "$(grep -c "vnc" "${LOG_PATH_MODULE}"/vnc_basic-check.txt)" -gt 0 ]]; then
      VNC_UP=1
      print_output "[+] VNC service successfully identified"
      print_ln
      tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/vnc_basic-check.txt
      print_ln
    fi
  fi

  print_ln
  print_output "[*] VNC basic enumeration for ${ORANGE}${IP_ADDRESS_} / ${lVNC_PORT}${NC} finished"
}

check_msf_vnc() {
  local lVNC_PORT="${1:-}"

  sub_module_title "Metasploit VNC enumeration for emulated system ${ORANGE}${IP_ADDRESS_} / ${lVNC_PORT}${NC}"

  if ! [[ -f "${HELP_DIR}""/l23_vnc_msf_check.rc" ]]; then
    print_output "[-] Metasploit VNC resource script not available - Not performing Metasploit checks"
    return
  fi

  # Metasploit modules:
  # auxiliary/scanner/http/thinvnc_traversal
  # auxiliary/scanner/vnc/vnc_none_auth

  timeout --preserve-status --signal SIGINT 600 msfconsole -q -n -r "${HELP_DIR}"/l23_vnc_msf_check.rc "${IP_ADDRESS_}" "${lVNC_PORT}" | tee -a "${LOG_PATH_MODULE}"/metasploit-vnc-check-"${IP_ADDRESS_}".txt || true

  print_output "[*] VNC Metasploit enumeration for ${ORANGE}${IP_ADDRESS_} / ${lVNC_PORT}${NC} finished"
}
