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

L15_emulated_checks_nmap() {

  MODULE_END=0
  export NMAP_SERVICES=()
  export NMAP_PORTS_SERVICES=()

  if [[ "$SYS_ONLINE" -eq 1 ]] && [[ "$TCP" == "ok" ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Nmap scans of emulated device."

    pre_module_reporter "${FUNCNAME[0]}"

    if [[ -n "$IP_ADDRESS_" ]]; then

      check_live_nmap_basic "$IP_ADDRESS_"

      MODULE_END=1
    else
      print_output "[!] No IP address found"
    fi
    write_log ""
    write_log "[*] Statistics:${#NMAP_SERVICES[@]}"
    module_end_log "${FUNCNAME[0]}" "$MODULE_END"
  fi

}

check_live_nmap_basic() {
  local IP_ADDRESS_="${1:-}"
  local NMAP_RESULT_FILES=()
  local NMAP_RESULTF=""
  local NMAP_SERVICES=()
  local S09_L15_CHECK=()
  local S116_L15_CHECK=()
  local SERVICE=""
  local SERVICE_NAME=""
  local TYPE=""
  export NMAP_PORTS_SERVICES=()

  sub_module_title "Nmap portscans for emulated system with IP $ORANGE$IP_ADDRESS_$NC"

  cp "$LOG_DIR"/l10_system_emulation/nmap_emba_"$IP_ADDRESS_"*.gnmap "$LOG_PATH_MODULE" || true
  cp "$LOG_DIR"/l10_system_emulation/nmap_emba_"$IP_ADDRESS_"*.nmap "$LOG_PATH_MODULE" || true

  # find all Nmap results
  mapfile -t NMAP_RESULT_FILES < <(find "$LOG_PATH_MODULE" -name "*.nmap")
  write_csv_log "---" "service identifier" "version_detected" "csv_rule" "license" "static/emulation/nmap/nikto"

  if [[ -v NMAP_RESULT_FILES[@] ]]; then
    for NMAP_RESULTF in "${NMAP_RESULT_FILES[@]}"; do
      print_output "[*] Found Nmap results $ORANGE$(basename "$NMAP_RESULTF")$NC:"
      tee -a "$LOG_FILE" < "$NMAP_RESULTF"
      print_ln
    done
  else
    # if no Nmap results are found we initiate a scan
    nmap -Pn -n -sSV -A "$IP_ADDRESS_" -oA "$LOG_PATH_MODULE"/nmap-basic-"$IP_ADDRESS_" | tee -a "$LOG_FILE"
  fi
  print_ln

  # extract only the service details from gnmap output file:
  mapfile -t NMAP_SERVICES < <(grep "open" "$LOG_PATH_MODULE"/*.gnmap | cut -d: -f2- | sed s/'\t'/'\n\t'/g | sed s/'\/, '/'\n\t\t'/g | sed s/'Ports: '/'Ports:\n\t\t'/g | grep -v "/closed/\|filtered/" | grep -v "Host: \|Ports:\|Ignored State:\|OS: \|Seq Index: \|Status: \|IP ID Seq: \|^# " | sed 's/^[[:blank:]].*\/\///' | sed 's/\/$//g'| sort -u || true)
  mapfile -t NMAP_PORTS_SERVICES < <(grep "open" "$LOG_PATH_MODULE"/*.nmap | cut -d: -f2- | awk '{print $1,$3}' | sort -u || true)
  # extract cpe information like the following:
  #	Service Info: OS: Linux; Device: WAP; CPE: cpe:/h:dlink:dir-300:2.14, cpe:/o:linux:linux_kernel, cpe:/h:d-link:dir-300
  mapfile -t NMAP_CPE_DETECTION < <(grep -ah "Service Info: " "$LOG_PATH_MODULE"/*.nmap | grep -a "CPE: .*" | sort -u)

  TYPE="Nmap scan (Scan info)"

  if [[ "${#NMAP_CPE_DETECTION[@]}" -gt 0 ]]; then
    for NMAP_CPES in "${NMAP_CPE_DETECTION[@]}"; do
      NMAP_CPES=$(echo "$NMAP_CPES" | grep -o "cpe:.*")
      # rewrite the string into an array:
      # NMAP_CPES_ARR=( $(echo "$NMAP_CPES" | tr "," "\n") )
      IFS=', ' read -r -a NMAP_CPES_ARR <<< "$NMAP_CPES"
      for NMAP_CPE in "${NMAP_CPES_ARR[@]}"; do
        #NMAP_CPE=${NMAP_CPE//\ cpe:\/}
        NMAP_CPE=${NMAP_CPE//cpe:\/}
        # just to ensure there is some kind of version information in our entry
        if [[ "$NMAP_CPE" =~ .*[0-9].* ]]; then
          print_output "[*] CPE details detected: $ORANGE$NMAP_CPE$NC"
          write_csv_log "---" "NA" "NA" "$NMAP_CPE" "NA" "$TYPE"
        fi
      done
    done
  fi

  TYPE="Nmap scan (Service info)"

  if [[ "${#NMAP_PORTS_SERVICES[@]}" -gt 0 ]]; then
    for SERVICE in "${NMAP_PORTS_SERVICES[@]}"; do
      print_output "[*] Service detected: $ORANGE$SERVICE$NC"
      SERVICE_NAME=$(echo "$SERVICE" | awk '{print $2}')
      if [[ "$SERVICE_NAME" == "unknown" ]] || [[ "$SERVICE_NAME" == "tcpwrapped" ]] || [[ -z "$SERVICE_NAME" ]]; then
        continue
      fi

      if [[ -f "$LOG_DIR"/s09_firmware_base_version_check.csv ]]; then
        # Let's check if we have already found details about this service in our other modules (S09, S115/S116)
        mapfile -t S09_L15_CHECK < <(grep "$SERVICE_NAME" "$LOG_DIR"/s09_firmware_base_version_check.csv || true)
        if [[ "${#S09_L15_CHECK[@]}" -gt 0 ]]; then
          for S09_L15_MATCH in "${S09_L15_CHECK[@]}"; do
            print_output "[+] Service also detected with static analysis (S09):\\n$(indent "$ORANGE$S09_L15_MATCH$NC")"
            echo "$S09_L15_MATCH" >> "$LOG_DIR"/l15_emulated_checks_nmap.csv
          done
        fi
      fi

      if [[ -f "$LOG_DIR"/s116_qemu_version_detection.csv ]]; then
        mapfile -t S116_L15_CHECK < <(grep "$SERVICE_NAME" "$LOG_DIR"/s116_qemu_version_detection.csv || true)
        if [[ "${#S116_L15_CHECK[@]}" -gt 0 ]]; then
          for S116_L15_MATCH in "${S116_L15_CHECK[@]}"; do
            print_output "[+] Service also detected with dynamic user-mode emulation (S115/S116):\\n $(indent "$ORANGE$S116_L15_MATCH$NC")"
            echo "$S116_L15_MATCH" >> "$LOG_DIR"/l15_emulated_checks_nmap.csv
          done
        fi
      fi
    done
  fi

  if [[ "${#NMAP_SERVICES[@]}" -gt 0 ]]; then
    print_ln
    for SERVICE in "${NMAP_SERVICES[@]}"; do
      if ! echo "$SERVICE" | grep -q "[0-9]"; then
        continue
      fi
      l15_version_detector "$SERVICE" "$TYPE"
    done
  fi

  print_ln
  print_output "[*] Nmap portscans for emulated system with IP $ORANGE$IP_ADDRESS_$NC finished"
}

l15_version_detector() {
  local SERVICE_="${1:-}"
  local TYPE_="${2:-}"

  local VERSION_LINE=""
  local STRICT=""
  local IDENTIFIER=""
  local LIC=""
  local CSV_REGEX=""
  local VERSION_IDENTIFIER=""
  local VERSION_FINDER=""

  print_output "[*] Testing detected service ${ORANGE}$SERVICE_$NC" "no_log"

  if ! [[ -f "$CONFIG_DIR"/bin_version_strings.cfg ]]; then
    print_output "[-] Missing configuration file - check your installation!"
    return
  fi

  while read -r VERSION_LINE; do
    if echo "$VERSION_LINE" | grep -v -q "^[^#*/;]"; then
      continue
    fi
    if echo "$VERSION_LINE" | grep -q "no_static"; then
      continue
    fi

    STRICT="$(echo "$VERSION_LINE" | cut -d\; -f2)"
    IDENTIFIER="$(echo "$VERSION_LINE" | cut -d\; -f1)"

    if [[ $STRICT == *"strict"* ]]; then
      continue
    elif [[ $STRICT == "zgrep" ]]; then
      continue
    fi

    LIC="$(echo "$VERSION_LINE" | cut -d\; -f3)"
    CSV_REGEX="$(echo "$VERSION_LINE" | cut -d\; -f5)"
    VERSION_IDENTIFIER="$(echo "$VERSION_LINE" | cut -d\; -f4 | sed s/^\"// | sed s/\"$//)"

    VERSION_FINDER=$(echo "$SERVICE_" | grep -o -a -E "$VERSION_IDENTIFIER" | head -1 2>/dev/null || true)
    if [[ -n $VERSION_FINDER ]]; then
      print_output "[+] Version information found ${RED}""$VERSION_FINDER""${NC}${GREEN} in $TYPE_ log."
      # use get_csv_rule from s09:
      get_csv_rule "$VERSION_FINDER" "$CSV_REGEX"
      write_csv_log "---" "$IDENTIFIER" "$VERSION_FINDER" "$CSV_RULE" "$LIC" "$TYPE_"
      continue
    fi
  done  < "$CONFIG_DIR"/bin_version_strings.cfg
}

