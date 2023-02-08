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

  if ping -c 1 "$IP_ADDRESS_" &> /dev/null; then
    print_output "[+] System with $ORANGE$IP_ADDRESS_$NC responding again - probably it recovered automatically."
    return
  fi

  if ! [[ -f "$ARCHIVE_PATH"/run.sh ]]; then
    print_output "[-] Warning: Auto-maintaining not possible - emulation archive not available"
    return
  fi

  print_output "[!] Warning: System with $ORANGE$IP_ADDRESS_$MAGENTA not responding."
  print_output "[*] Trying to auto-maintain emulated system now ..."

  stopping_emulation_process "$IMAGE_NAME_"
  reset_network_emulation 2

  # what an ugly hack - probably we are going to improve this later on
  cd "$ARCHIVE_PATH" || (print_output "[-] Emulation archive path not found")
  ./run.sh &
  cd "$INVOCATION_PATH" || (print_output "[-] EMBA path not available?")

  COUNTER=0
  while ! ping -c 1 "$IP_ADDRESS_" &> /dev/null; do
    print_output "[*] Waiting for restarted system ..."
    ((COUNTER+=1))
    [[ "$COUNTER" -gt 50 ]] && (print_output "[-] System not recovered" && return)
    sleep 6
  done
  print_output "[*] System automatically maintained and should be available again in a few moments ..."
  sleep 60
}
