#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Tests the emulated live system which is build and started in L10
#               Currently this is an experimental module and needs to be activated separately via the -Q switch. 
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

L15_emulated_checks_init() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Live tests of emulated device."

  SNMP_UP=0
  NIKTO_UP=0
  NMAP_PORTS_SERVICES=()
  MODULE_END=0

  if [[ "$SYS_ONLINE" -eq 1 ]]; then
    pre_module_reporter "${FUNCNAME[0]}"

    if [[ $IN_DOCKER -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi

    check_live_nmap_basic
    check_live_snmp
    # running into issues with nikto on different systems -> disabling for now:
    # check_live_nikto
    check_live_routersploit
    MODULE_END=1
    pkill -f "qemu-system-.*$IMAGE_NAME.*" || true
    reset_network 2
  fi

  write_log ""
  write_log "[*] Statistics:${#NMAP_PORTS_SERVICES[@]}:$SNMP_UP:$NIKTO_UP"
  module_end_log "${FUNCNAME[0]}" "$MODULE_END"

}

check_live_nmap_basic() {
  sub_module_title "Nmap portscans for emulated system with IP $IP"

  nmap -sSV "$IP" -oA "$LOG_PATH_MODULE"/nmap-basic-"$IP" | tee -a "$LOG_FILE"
  if [[ -f "$LOG_PATH_MODULE"/nmap-basic-"$IP".nmap ]]; then
    mapfile -t NMAP_PORTS_SERVICES < <(grep "open" "$LOG_PATH_MODULE"/nmap-basic-"$IP".nmap | awk '{print $4,$5,$6}' | sort -u)
    mapfile -t NMAP_PORTS < <(grep "open" "$LOG_PATH_MODULE"/nmap-basic-"$IP".nmap | awk '{print $1}' | cut -d '/' -f1 | sort -u)
  fi

  TYPE="Nmap"

  if [[ -v NMAP_PORTS_SERVICES[@] ]]; then
    write_csv_log "---" "---" "version_detected" "csv_rule" "license" "static/emulation/nmap"
    print_output ""
    for SERVICE in "${NMAP_PORTS_SERVICES[@]}"; do
      while read -r VERSION_LINE; do
        if echo "$VERSION_LINE" | grep -v -q "^[^#*/;]"; then
          continue
        fi
        if echo "$VERSION_LINE" | grep -q "no_static"; then
          continue
        fi

        STRICT="$(echo "$VERSION_LINE" | cut -d\; -f2)"

        if [[ $STRICT == *"strict"* ]]; then
          continue
        elif [[ $STRICT == "zgrep" ]]; then
          continue
        fi

        LIC="$(echo "$VERSION_LINE" | cut -d\; -f3)"
        # BIN_NAME="$(echo "$VERSION_LINE" | cut -d\; -f1)"
        CSV_REGEX="$(echo "$VERSION_LINE" | cut -d\; -f5)"
        VERSION_IDENTIFIER="$(echo "$VERSION_LINE" | cut -d\; -f4 | sed s/^\"// | sed s/\"$//)"

        VERSION_FINDER=$(echo "$SERVICE" | grep -o -a -E "$VERSION_IDENTIFIER" | head -1 2>/dev/null || true)
        if [[ -n $VERSION_FINDER ]]; then
          print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in Nmap port scanning logs."
          # use get_csv_rule from s09:
          get_csv_rule "$VERSION_FINDER" "$CSV_REGEX"
          write_csv_log "---" "---" "$VERSION_FINDER" "$CSV_RULE" "$LIC" "$TYPE"
          continue
        fi
      done  < "$CONFIG_DIR"/bin_version_strings.cfg
    done
  fi

  print_output ""
  print_output "[*] Nmap portscans for emulated system with IP $IP finished"
}

check_live_snmp() {
  sub_module_title "SNMP enumeration for emulated system with IP $IP"

  if command snmp-check > /dev/null; then
    print_output "[*] SNMP scan with community name public"
    snmp-check -w "$IP"| tee "$LOG_PATH_MODULE"/snmp-check-public-"$IP".txt
    if [[ -f "$LOG_PATH_MODULE"/snmp-check-public-"$IP".txt ]]; then
      cat "$LOG_PATH_MODULE"/snmp-check-public-"$IP".txt >> "$LOG_FILE"
    fi
    print_output ""
    print_output "[*] SNMP scan with community name private"
    snmp-check -c private -w "$IP"| tee "$LOG_PATH_MODULE"/snmp-check-private-"$IP".txt
    if [[ -f "$LOG_PATH_MODULE"/snmp-check-private-"$IP".txt ]]; then
      cat "$LOG_PATH_MODULE"/snmp-check-private-"$IP".txt >> "$LOG_FILE"
    fi
  else
    print_output "[*] SNMP scan with community name public"
    snmpwalk -v2c -c public "$IP" .iso | tee "$LOG_PATH_MODULE"/snmpwalk-public-"$IP".txt
    if [[ -f "$LOG_PATH_MODULE"/snmp-check-public-"$IP".txt ]]; then
      cat "$LOG_PATH_MODULE"/snmpwalk-public-"$IP".txt >> "$LOG_FILE"
    fi
    print_output ""
    print_output "[*] SNMP scan with community name private"
    snmpwalk -v2c -c private "$IP" .iso | tee "$LOG_PATH_MODULE"/snmapwalk-private-"$IP".txt
    if [[ -f "$LOG_PATH_MODULE"/snmp-check-private-"$IP".txt ]]; then
      cat "$LOG_PATH_MODULE"/snmpwalk-private-"$IP".txt >> "$LOG_FILE"
    fi
  fi
  SNMP_UP=$(wc -l "$LOG_PATH_MODULE"/snmp* | tail -1 | awk '{print $1}')

  if [[ "$SNMP_UP" -gt 20 ]]; then
    SNMP_UP=1
  else
    SNMP_UP=0
  fi

  print_output ""
  print_output "[*] SNMP tests for emulated system with IP $IP finished"
}

check_live_nikto() {
  sub_module_title "Nikto web checks for emulated system with IP $IP"

  NIKTO_UP=0
  NIKTO_DONE=0

  if [[ "${#NMAP_PORTS[@]}" -gt 0 ]]; then
    for PORT in "${NMAP_PORTS[@]}"; do
      #PORT=$(echo "$SERVICE" | cut -d/ -f1 | tr -d "[:blank:]")
      NIKTO_OPTS="-timeout 3 -nointeractive -maxtime 8m"
      if [[ "$SERVICE" == *"ssl|http"* ]];then
        #shellcheck disable=SC2086
        nikto $NIKTO_OPTS -ssl -port "$PORT" -host "$IP" | tee -a "$LOG_PATH_MODULE"/nikto-scan-"$IP".txt
        NIKTO_DONE=1
      elif [[ "$SERVICE" == *"http"* ]];then
        #shellcheck disable=SC2086
        nikto $NIKTO_OPTS -port "$PORT" -host "$IP" | tee -a "$LOG_PATH_MODULE"/nikto-scan-"$IP".txt
        NIKTO_DONE=1
      fi
      if [[ "$NIKTO_DONE" -eq 1 ]]; then
        break
      fi
    done
    if [[ -f "$LOG_PATH_MODULE"/nikto-scan-"$IP".txt ]]; then
      cat "$LOG_PATH_MODULE"/nikto-scan-"$IP".txt >> "$LOG_FILE"
      print_output ""
      mapfile -t VERSIONS < <(grep "Server" "$LOG_PATH_MODULE"/nikto-scan-"$IP".txt | cut -d: -f2 | sort -u | grep -v "null" | sed 's/^\ //')
      for VERSION in "${VERSIONS[@]}"; do
        if [[ "$VERSION" != *"Server banner has changed from"* ]]; then
          print_output "[+] Version information found ${RED}""$VERSION""${NC}${GREEN} in Nikto web server scanning logs."
        fi
      done

      mapfile -t VERSIONS < <(grep "Retrieved x-powered-by header" "$LOG_PATH_MODULE"/nikto-scan-"$IP".txt | cut -d: -f2 | sort -u | sed 's/^\ //')
      for VERSION in "${VERSIONS[@]}"; do
        print_output "[+] Version information found ${RED}""$VERSION""${NC}${GREEN} in Nikto web server scanning logs."
      done

      print_output ""
      if [[ $(grep -c "+ [1-9] host(s) tested" "$LOG_PATH_MODULE"/nikto-scan-"$IP".txt || true) -gt 0 ]]; then
        NIKTO_UP=1
      fi
    fi
  fi

  print_output "[*] Nikto web checks for emulated system with IP $IP finished"
}

check_live_routersploit() {
  sub_module_title "Routersploit tests for emulated system with IP $IP"

  if [[ -f /tmp/routersploit.log ]]; then
    rm /tmp/routersploit.log
  fi

  timeout --preserve-status --signal SIGINT 300 "$EXT_DIR"/routersploit/rsf.py "$IP" 2>&1 | tee -a "$LOG_PATH_MODULE"/routersploit-"$IP".txt

  if [[ -f /tmp/routersploit.log ]]; then
    mv /tmp/routersploit.log "$LOG_PATH_MODULE"/routersploit-detail-"$IP".txt
  fi

  cat "$LOG_PATH_MODULE"/routersploit-"$IP".txt >> "$LOG_FILE"
  print_output ""
  print_output "[*] Routersploit tests for emulated system with IP $IP finished"
}

