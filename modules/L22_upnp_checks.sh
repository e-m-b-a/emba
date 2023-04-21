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

L22_upnp_checks() {

  export UPNP_UP=0

  if [[ "$SYS_ONLINE" -eq 1 ]] && [[ "$TCP" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Live UPnP tests of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ $IN_DOCKER -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi

    if [[ -v IP_ADDRESS_ ]]; then
      if ! ping -c 2 "$IP_ADDRESS_" &> /dev/null; then
        restart_emulation "$IP_ADDRESS_" "$IMAGE_NAME"
        if ! ping -c 2 "$IP_ADDRESS_" &> /dev/null; then
          print_output "[-] System not responding - Not performing UPnP checks"
          module_end_log "${FUNCNAME[0]}" "$UPNP_UP"
          return
        fi
      fi
      if [[ -v HOSTNETDEV_0 ]]; then
        check_basic_upnp "$HOSTNETDEV_0"
      else
        print_output "[!] No network interface found"
      fi
    else
      print_output "[!] No IP address found"
    fi

    write_log ""
    write_log "Statistics:$UPNP_UP"
    module_end_log "${FUNCNAME[0]}" "$UPNP_UP"
  fi
}

check_basic_upnp() {
  local INTERFACE="${1:-}"

  sub_module_title "UPnP enumeration for emulated system with IP $ORANGE$IP_ADDRESS_$NC"

  if command -v upnpc > /dev/null; then
    print_output "[*] UPnP scan with upnpc"
    upnpc -m "$INTERFACE" -P >> "$LOG_PATH_MODULE"/upnp-discovery-check.txt
    if [[ -f "$LOG_PATH_MODULE"/upnp-discovery-check.txt ]]; then
      print_ln
      tee -a "$LOG_FILE" < "$LOG_PATH_MODULE"/upnp-discovery-check.txt
    fi
    print_ln

    UPNP_UP=$(grep -c "desc\|IGD" "$LOG_PATH_MODULE"/upnp-discovery-check.txt)
  fi

  if [[ "$UPNP_UP" -gt 0 ]]; then
    UPNP_UP=1
  fi

  print_ln
  print_output "[*] UPnP basic enumeration finished"
}

