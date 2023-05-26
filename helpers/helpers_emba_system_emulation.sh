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

# Description:  Helper functions for system emulation

restart_emulation() {
  local IP_ADDRESS_="${1:-}"
  local IMAGE_NAME_="${2:-}"
  # restart_scan is used to indicate a restarted scan. For this we do not need to restart the network
  local RESTART_SCAN="${3:-0}"
  local STATE_CHECK_MECHANISM="${4:-"PING"}"

  if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
    print_output "[+] System with $ORANGE$IP_ADDRESS_$GREEN responding again - probably it recovered automatically.$NC" "no_log"
    return
  fi

  if ! [[ -f "$ARCHIVE_PATH"/run.sh ]]; then
    print_output "[!] Warning: Auto-maintaining not possible - emulation archive not available"
    return
  fi

  print_output "[!] Warning: System with $ORANGE$IP_ADDRESS_$MAGENTA not responding." "no_log"
  print_output "[*] Trying to auto-maintain emulated system now ..." "no_log"

  stopping_emulation_process "$IMAGE_NAME_"
  [[ "$RESTART_SCAN" -eq 0 ]] && reset_network_emulation 2

  check_qemu_instance_l10

  # what an ugly hack - probably we are going to improve this later on
  local HOME_PATH=""
  HOME_PATH="$(pwd)"
  cd "$ARCHIVE_PATH" || (print_output "[-] Emulation archive path not found")
  ./run.sh &
  cd "$HOME_PATH" || (print_output "[-] EMBA path not available?")

  if [[ "$STATE_CHECK_MECHANISM" == "PING" ]]; then
    ping_check "${IP_ADDRESS_}" 1
    return "$?"
  elif [[ "$STATE_CHECK_MECHANISM" == "HPING" ]]; then
    hping_check "${IP_ADDRESS_}" 1
    return "$?"
  elif [[ "$STATE_CHECK_MECHANISM" == "TCP" ]]; then
    # local PORT=80
    print_output "[-] Check currently not implemented!" "no_log"
    # tcp_check "${IP_ADDRESS_}" "${PORT}"
  fi
  return 0
}

system_online_check() {
  local IP_ADDRESS_="${1:-}"

  if [[ "$STATE_CHECK_MECHANISM" == "PING" ]]; then
    ping_check "${IP_ADDRESS_}" 0
    return "$?"
  elif [[ "$STATE_CHECK_MECHANISM" == "HPING" ]]; then
    hping_check "${IP_ADDRESS_}" 0
    return "$?"
  elif [[ "$STATE_CHECK_MECHANISM" == "TCP" ]]; then
    # local PORT=80
    print_output "[-] Check currently not implemented ... we do a hping check" "no_log"
    # tcp_check "${IP_ADDRESS_}" "${PORT}"
    hping_check "${IP_ADDRESS_}" 0
    return "$?"
  fi
}

hping_check() {
  local IP_ADDRESS_="${1:-}"
  # print details or do it silent
  local PRINT_OUTPUT="${2:-1}"
  local COUNTER=0
  # RESTARTER is used to indicate a non reachable system for another wait period after the system is recovered
  local RESTARTER=0

  while ! [[ "$(hping3 -n -c 1 "$IP_ADDRESS_" 2> /dev/null | grep -c "^len=")" -gt 0 ]]; do
    RESTARTER=1
    [[ "${PRINT_OUTPUT}" -eq 1 ]] && print_output "[*] Waiting for restarted system ... hping mode" "no_log"
    ((COUNTER+=1))
    if [[ "$COUNTER" -gt 50 ]]; then
      [[ "${PRINT_OUTPUT}" -eq 1 ]] && print_output "[-] System not recovered" "no_log"
      break
    fi
    sleep 6
  done

  if [[ "$(hping3 -n -c 1 "$IP_ADDRESS_" 2>/dev/null | grep -c "^len=")" -gt 0 ]]; then
    [[ "${PRINT_OUTPUT}" -eq 1 || "${RESTARTER}" -eq 1 ]] && print_output "[*] System automatically maintained and should be available again in a few moments ... check ip address $ORANGE$IP_ADDRESS_$NC" "no_log"
    [[ "$RESTARTER" -eq 1 ]] && sleep 60
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
  local IP_ADDRESS_="${1:-}"
  # print details or do it silent
  local PRINT_OUTPUT="${2:-1}"
  local COUNTER=0
  local RESTARTER=0

  while ! ping -c 1 "$IP_ADDRESS_" &> /dev/null; do
    RESTARTER=1
    [[ "${PRINT_OUTPUT}" -eq 1 ]] && print_output "[*] Waiting for restarted system ..." "no_log"
    ((COUNTER+=1))
    if [[ "$COUNTER" -gt 50 ]]; then
      [[ "${PRINT_OUTPUT}" -eq 1 ]] && print_output "[-] System not recovered" "no_log"
      break
    fi
    sleep 6
  done

  if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
    [[ "${PRINT_OUTPUT}" -eq 1 || "${RESTARTER}" -eq 1 ]] && print_output "[*] System automatically maintained and should be available again in a few moments ... check ip address $ORANGE$IP_ADDRESS_$NC" "no_log"
    [[ "$RESTARTER" -eq 1 ]] && sleep 60
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
  DEP_ERROR=0
  # using the dependency checker helper module:
  check_emulation_port "Running Qemu service" "2001"
  if [[ "$DEP_ERROR" -eq 1 ]]; then
    while true; do
      DEP_ERROR=0
      check_emulation_port "Running Qemu service" "2001"
      if [[ "$DEP_ERROR" -ne 1 ]]; then
        break
      fi
      print_output "[-] Is there some Qemu instance already running?"
      print_output "[-] Check TCP ports 2000 - 2003!"
      sleep 10
    done
  fi
}

check_emulation_port() {
  TOOL_NAME="${1:-}"
  PORT_NR="${2:-}"
  print_output "    ""$TOOL_NAME"" - \\c" "no_log"
  if netstat -anpt | grep -q "$PORT_NR"; then
    echo -e "$RED""not ok""$NC"
    echo -e "$RED""    System emulation services detected - check for running Qemu processes""$NC"
  else
    echo -e "$GREEN""ok""$NC"
  fi
}
