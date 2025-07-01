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

# Description:  Helper functions for system emulation

restart_emulation() {
  local lIP_ADDRESS="${1:-}"
  local lIMAGE_NAME="${2:-}"
  # restart_scan is used to indicate a restarted scan. For this we do not need to restart the network
  local lRESTART_SCAN="${3:-0}"
  local lSTATE_CHECK_MECHANISM="${4:-"PING"}"

  local lHOME_PATH=""

  if ping -c 1 "${lIP_ADDRESS}" &> /dev/null; then
    print_output "[+] System with ${ORANGE}${lIP_ADDRESS}${GREEN} responding again - probably it recovered automatically.${NC}" "no_log"
    return
  fi

  if ! [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
    print_output "[!] Warning: Auto-maintaining not possible - emulation archive not available"
    return
  fi

  print_output "[!] Warning: System with ${ORANGE}${lIP_ADDRESS}${MAGENTA} not responding." "no_log"
  print_output "[*] Trying to auto-maintain emulated system now ..." "no_log"

  stopping_emulation_process "${lIMAGE_NAME}"
  [[ "${lRESTART_SCAN}" -eq 0 ]] && reset_network_emulation 2

  check_qemu_instance_l10

  # what an ugly hack - probably we are going to improve this later on
  lHOME_PATH="$(pwd)"
  cd "${ARCHIVE_PATH}" || (print_output "[-] Emulation archive path not found")
  ./run.sh &
  cd "${lHOME_PATH}" || (print_output "[-] EMBA path not available?")

  if [[ "${lSTATE_CHECK_MECHANISM}" == "PING" ]]; then
    ping_check "${lIP_ADDRESS}" 1
    return "$?"
  elif [[ "${lSTATE_CHECK_MECHANISM}" == "HPING" ]]; then
    hping_check "${lIP_ADDRESS}" 1
    return "$?"
  elif [[ "${lSTATE_CHECK_MECHANISM}" == "TCP" ]]; then
    # local PORT=80
    print_output "[-] TCP check currently not implemented!" "no_log"
    # tcp_check "${lIP_ADDRESS}" "${PORT}"
    return 1
  fi
  return 0
}

system_online_check() {
  local lIP_ADDRESS="${1:-}"

  # STATE_CHECK_MECHANISM is exported by l10

  if [[ "${STATE_CHECK_MECHANISM:-PING}" == "PING" ]]; then
    ping_check "${lIP_ADDRESS}" 0
    return "$?"
  elif [[ "${STATE_CHECK_MECHANISM:-PING}" == "HPING" ]]; then
    hping_check "${lIP_ADDRESS}" 0
    return "$?"
  elif [[ "${STATE_CHECK_MECHANISM:-PING}" == "TCP" ]]; then
    # local PORT=80
    print_output "[-] TCP check is not implemented. Falling back to HPING check." "no_log"
    # tcp_check "${lIP_ADDRESS}" "${PORT}"
    hping_check "${lIP_ADDRESS}" 0
    return "$?"
  fi
}

hping_check() {
  local lIP_ADDRESS="${1:-}"
  # print details or do it silent
  local lPRINT_OUTPUT="${2:-1}"
  local lCOUNTER=0
  # RESTARTER is used to indicate a non reachable system for another wait period after the system is recovered
  local lRESTARTER=0

  while ! [[ "$(hping3 -n -c 1 "${lIP_ADDRESS}" 2> /dev/null | grep -c "^len=")" -gt 0 ]]; do
    lRESTARTER=1
    [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[*] Waiting for restarted system ... hping mode" "no_log"
    ((lCOUNTER+=1))
    if [[ "${lCOUNTER}" -gt 50 ]]; then
      [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[-] System not recovered" "no_log"
      break
    fi
    sleep 6
  done

  if [[ "$(hping3 -n -c 1 "${lIP_ADDRESS}" 2>/dev/null | grep -c "^len=")" -gt 0 ]]; then
    [[ "${lPRINT_OUTPUT}" -eq 1 || "${lRESTARTER}" -eq 1 ]] && print_output "[*] System automatically maintained and should be available again in a few moments ... check ip address ${ORANGE}${lIP_ADDRESS}${NC}" "no_log"
    [[ "${lRESTARTER}" -eq 1 ]] && sleep 60
    export SYS_ONLINE=1
    export TCP="ok"
    return 0
  else
    export SYS_ONLINE=0
    export TCP="not ok"
    return 1
  fi
}

ping_check() {
  local lIP_ADDRESS="${1:-}"
  # print details or do it silent
  local lPRINT_OUTPUT="${2:-1}"
  local lCOUNTER=0
  local lRESTARTER=0

  while ! ping -c 1 "${lIP_ADDRESS}" &> /dev/null; do
    lRESTARTER=1
    [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[*] Waiting for restarted system ..." "no_log"
    ((lCOUNTER+=1))
    if [[ "${lCOUNTER}" -gt 50 ]]; then
      [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[-] System not recovered" "no_log"
      break
    fi
    sleep 6
  done

  if ping -c 1 "${lIP_ADDRESS}" &> /dev/null; then
    [[ "${lPRINT_OUTPUT}" -eq 1 || "${lRESTARTER}" -eq 1 ]] && print_output "[*] System automatically maintained and should be available again in a few moments ... check ip address ${ORANGE}${lIP_ADDRESS}${NC}" "no_log"
    [[ "${lRESTARTER}" -eq 1 ]] && sleep 60
    export SYS_ONLINE=1
    export TCP="ok"
    return 0
  else
    export SYS_ONLINE=0
    export TCP="not ok"
    return 1
  fi
}

check_qemu_instance_l10() {
  export DEP_ERROR=0
  # using the dependency checker helper module:
  check_emulation_port "Running Qemu service" "2001"
  if [[ "${DEP_ERROR}" -eq 1 ]]; then
    while true; do
      DEP_ERROR=0
      check_emulation_port "Running Qemu service" "2001"
      if [[ "${DEP_ERROR}" -ne 1 ]]; then
        break
      fi
      if ! [[ -d "${LOG_DIR}" ]]; then
        # this usually happens if we automate analysis and remove the logging directory while this module was not finished at all
        break
      fi
      print_output "[-] Is there some Qemu instance already running?"
      print_output "[-] Check TCP ports 2000 - 2003!"
      sleep 10
    done
  fi
}

check_emulation_port() {
  local lTOOL_NAME="${1:-}"
  local lPORT_NR="${2:-}"

  print_output "    ""${lTOOL_NAME}"" - \\c" "no_log"
  if netstat -anpt | grep -q "${lPORT_NR}"; then
    echo -e "${RED}""not ok""${NC}"
    echo -e "${RED}""    System emulation services detected - check for running Qemu processes""${NC}"
    export DEP_ERROR=1
  else
    echo -e "${GREEN}""ok""${NC}"
  fi
}
