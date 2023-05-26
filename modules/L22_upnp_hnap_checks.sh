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

L22_upnp_hnap_checks() {

  export UPNP_UP=0
  export HNAP_UP=0

  if [[ "$SYS_ONLINE" -eq 1 ]] && [[ "$TCP" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Live UPnP/HNAP tests of emulated device."
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ $IN_DOCKER -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi

    if [[ -v IP_ADDRESS_ ]]; then
      if ! system_online_check "${IP_ADDRESS_}"; then
        if ! restart_emulation "$IP_ADDRESS_" "$IMAGE_NAME" 1 "${STATE_CHECK_MECHANISM}"; then
          print_output "[-] System not responding - Not performing UPnP/HNAP checks"
          module_end_log "${FUNCNAME[0]}" "$UPNP_UP"
          return
        fi
      fi
      if [[ -v HOSTNETDEV_ARR ]]; then
        check_basic_upnp "${HOSTNETDEV_ARR[@]}"
        check_basic_hnap
      else
        print_output "[!] No network interface found"
      fi
    else
      print_output "[!] No IP address found"
    fi

    write_log ""
    write_log "Statistics:$UPNP_UP:$HNAP_UP"
    module_end_log "${FUNCNAME[0]}" "$UPNP_UP"
  fi
}

check_basic_upnp() {
  local INTERFACE_ARR=("$@")

  sub_module_title "UPnP enumeration for emulated system with IP $ORANGE$IP_ADDRESS_$NC"

  if command -v upnpc > /dev/null; then
    for INTERFACE in "${INTERFACE_ARR[@]}"; do
      print_output "[*] UPnP scan with upnpc on local network interface $ORANGE$INTERFACE$NC"
      upnpc -m "$INTERFACE" -P >> "$LOG_PATH_MODULE"/upnp-discovery-check.txt || true
      if [[ -f "$LOG_PATH_MODULE"/upnp-discovery-check.txt ]]; then
        print_ln
        tee -a "$LOG_FILE" < "$LOG_PATH_MODULE"/upnp-discovery-check.txt
        print_ln
      fi
    done
    UPNP_UP=$(grep -c "desc\|IGD" "$LOG_PATH_MODULE"/upnp-discovery-check.txt || true)
  fi

  if [[ "$UPNP_UP" -gt 0 ]]; then
    UPNP_UP=1
    print_output "[+] UPnP service successfully identified"
  fi

  print_ln
  print_output "[*] UPnP basic enumeration finished"
}

check_basic_hnap() {
  local PORT=""
  local SERVICE=""
  local SSL=0

  sub_module_title "HNAP enumeration for emulated system with IP $ORANGE$IP_ADDRESS_$NC"

  if [[ "${#NMAP_PORTS_SERVICES[@]}" -gt 0 ]]; then
    for PORT_SERVICE in "${NMAP_PORTS_SERVICES[@]}"; do
      [[ "$HNAP_UP" -eq 1 ]] && break

      PORT=$(echo "$PORT_SERVICE" | cut -d/ -f1 | tr -d "[:blank:]")
      SERVICE=$(echo "$PORT_SERVICE" | awk '{print $2}' | tr -d "[:blank:]")
      if [[ "$SERVICE" == "unknown" ]] || [[ "$SERVICE" == "tcpwrapped" ]]; then
        continue
      fi

      if [[ "$SERVICE" == *"ssl|http"* ]] || [[ "$SERVICE" == *"ssl/http"* ]];then
        SSL=1
      elif [[ "$SERVICE" == *"http"* ]];then
        SSL=0
      else
        # no http service - check the next one
        continue
      fi

      print_output "[*] Analyzing service $ORANGE$SERVICE - $PORT - $IP_ADDRESS_$NC" "no_log"

      if ! command -v curl > /dev/null; then
        print_output "[-] WARNING: No curl command available - your installation seems to be weird"
        return
      fi

      if [[ "$SSL" -eq 0 ]]; then
        curl -v -L --max-redir 0 -f -m 5 -s -X GET http://"${IP_ADDRESS_}":"${PORT}"/HNAP/ >> "$LOG_PATH_MODULE"/hnap-discovery-check.txt || true
        curl -v -L --max-redir 0 -f -m 5 -s -X GET http://"${IP_ADDRESS_}":"${PORT}"/HNAP1/ >> "$LOG_PATH_MODULE"/hnap-discovery-check.txt || true
      else
        curl -v -L --max-redir 0 -f -m 5 -s -X GET https://"${IP_ADDRESS_}":"${PORT}"/HNAP/ >> "$LOG_PATH_MODULE"/hnap-discovery-check.txt || true
        curl -v -L --max-redir 0 -f -m 5 -s -X GET https://"${IP_ADDRESS_}":"${PORT}"/HNAP1/ >> "$LOG_PATH_MODULE"/hnap-discovery-check.txt || true
      fi

      if [[ -f "$LOG_PATH_MODULE"/hnap-discovery-check.txt ]]; then
        print_ln
        # tee -a "$LOG_FILE" < "$LOG_PATH_MODULE"/hnap-discovery-check.txt
        sed 's/></>\n</g' "$LOG_PATH_MODULE"/hnap-discovery-check.txt | tee -a "$LOG_FILE"
        print_ln

        HNAP_UP=$(grep -c "HNAP1" "$LOG_PATH_MODULE"/hnap-discovery-check.txt || true)
      fi

      if [[ "$HNAP_UP" -gt 0 ]]; then
        HNAP_UP=1
        print_output "[+] HNAP service successfully identified"
      fi

    done
  fi

  print_ln
  print_output "[*] HNAP basic enumeration finished"
}

