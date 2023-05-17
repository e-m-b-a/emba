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
  local STATE_CHECK="${4:-"PING"}"

  if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
    print_output "[+] System with $ORANGE$IP_ADDRESS_$GREEN responding again - probably it recovered automatically.$NC"
    return
  fi

  if ! [[ -f "$ARCHIVE_PATH"/run.sh ]]; then
    print_output "[-] Warning: Auto-maintaining not possible - emulation archive not available"
    return
  fi

  print_output "[!] Warning: System with $ORANGE$IP_ADDRESS_$MAGENTA not responding."
  print_output "[*] Trying to auto-maintain emulated system now ..."

  stopping_emulation_process "$IMAGE_NAME_"
  [[ "$RESTART_SCAN" -eq 0 ]] && reset_network_emulation 2

  # what an ugly hack - probably we are going to improve this later on
  local HOME_PATH=""
  HOME_PATH="$(pwd)"
  cd "$ARCHIVE_PATH" || (print_output "[-] Emulation archive path not found")
  ./run.sh &
  cd "$HOME_PATH" || (print_output "[-] EMBA path not available?")

  if [[ "$STATE_CHECK" == "PING" ]]; then
    ping_check "${IP_ADDRESS}"
  elif [[ "$STATE_CHECK" == "HPING" ]]; then
    hping_check "${IP_ADDRESS}"
  elif [[ "$STATE_CHECK" == "TCP" ]]; then
    local PORT=80
    print_output "[-] Check currently not implemented!"
    # tcp_check "${IP_ADDRESS}" "${PORT}"
  fi
}

ping_check() {
  local IP_ADDRESS="${1:-}"
  local COUNTER=0

  while ! [[ "$(hping3 -n -c 1 "$IP_ADDRESS_" 2> /dev/null | grep -c "^len=")" -gt 0 ]]; do
    print_output "[*] Waiting for restarted system ..."
    ((COUNTER+=1))
    if [[ "$COUNTER" -gt 50 ]]; then
      print_output "[-] System not recovered"
      break
    fi
    sleep 6
  done

  if [[ "$(hping3 -n -c 1 "$IP_ADDRESS_" 2>/dev/null | grep -c "^len=")" -gt 0 ]]; then
    print_output "[*] System automatically maintained and should be available again in a few moments ... check ip address $ORANGE$IP_ADDRESS_$NC"
    sleep 60
    export SYS_ONLINE=1
    export TCP="ok"
  else
    export SYS_ONLINE=0
    export TCP="not ok"
  fi
}

hping_check() {
  local IP_ADDRESS="${1:-}"
  local COUNTER=0

  while ! ping -c 1 "$IP_ADDRESS_" &> /dev/null; do
    print_output "[*] Waiting for restarted system ..."
    ((COUNTER+=1))
    if [[ "$COUNTER" -gt 50 ]]; then
      print_output "[-] System not recovered"
      break
    fi
    sleep 6
  done

  if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
    print_output "[*] System automatically maintained and should be available again in a few moments ... check ip address $ORANGE$IP_ADDRESS_$NC"
    sleep 60
    export SYS_ONLINE=1
    export TCP="ok"
  else
    export SYS_ONLINE=0
    export TCP="not ok"
  fi
}
