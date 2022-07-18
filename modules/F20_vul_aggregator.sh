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

# Description:  Aggregates all found version numbers together from S06, S08, S09, S25, S115/S116 and L15.
#               The versions are used for identification of known vulnerabilities cve-search,
#               finally it creates a list of exploits that are matching for the CVEs.

F20_vul_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final vulnerability aggregator"

  pre_module_reporter "${FUNCNAME[0]}"
  print_ln
  
  mkdir "$LOG_PATH_MODULE"/cve_sum
  mkdir "$LOG_PATH_MODULE"/exploit

  KERNELV=0
  HIGH_CVE_COUNTER=0
  MEDIUM_CVE_COUNTER=0
  LOW_CVE_COUNTER=0
  CVE_SEARCHSPLOIT=0
  RS_SEARCH=0
  MSF_SEARCH=0
  TRICKEST_SEARCH=0
  CVE_SEARCHSPLOIT=0
  local FOUND_CVE=0

  CVE_AGGREGATOR_LOG="f20_vul_aggregator.txt"

  local S06_LOG="$LOG_DIR"/s06_distribution_identification.csv
  local S08_LOG="$LOG_DIR"/s08_package_mgmt_extractor.csv
  local S09_LOG="$LOG_DIR"/s09_firmware_base_version_check.csv
  local S25_LOG="$LOG_DIR"/s25_kernel_check.txt
  local S116_LOG="$LOG_DIR"/s116_qemu_version_detection.csv
  local L15_LOG="$LOG_DIR"/l15_emulated_checks_nmap.csv
  local L25_LOG="$LOG_DIR"/l25_web_checks.csv

  local CVE_MINIMAL_LOG="$LOG_PATH_MODULE"/CVE_minimal.txt
  local EXPLOIT_OVERVIEW_LOG="$LOG_PATH_MODULE"/exploits-overview.txt

  if ! [[ -f "$KNOWN_EXP_CSV" ]]; then
    KNOWN_EXP_CSV="$EXT_DIR"/known_exploited_vulnerabilities.csv
  fi

  if [[ -f $PATH_CVE_SEARCH ]]; then
    print_output "[*] Aggregate vulnerability details"

    # get the kernel version from s25:
    get_kernel_check "$S25_LOG"
    # if we found a kernel in the kernel checker module we are going to use this kernel version (usually this version is better)
    # [+] Found Version details (base check): Linux kernel version 2.6.33
    # vs:
    # [+] Found Version details (kernel): Linux kernel version 2.6.33.2
    if [[ -v VERSIONS_KERNEL[@] ]]; then
      if [[ ${#VERSIONS_KERNEL[@]} -ne 0 ]]; then
        # then we have found a kernel in our s25 kernel module
        KERNELV=1
      fi
    fi

    get_firmware_details "$S06_LOG"
    get_package_details "$S08_LOG"
    get_firmware_base_version_check "$S09_LOG"
    get_usermode_emulator "$S116_LOG"
    get_systemmode_emulator "$L15_LOG"
    get_systemmode_webchecks "$L25_LOG"

    aggregate_versions
    
    check_cve_search

    if [[ "$CVE_SEARCH" -eq 0 ]]; then
      print_output "[*] Waiting for the cve-search environment ..."
      sleep 120
      check_cve_search

      if [[ "$CVE_SEARCH" -eq 0 ]]; then
        print_output "[*] Waiting for the cve-search environment ..."
        sleep 120
        check_cve_search
      fi
    fi

    if [[ "$CVE_SEARCH" -eq 1 ]]; then
      if command -v cve_searchsploit > /dev/null ; then
        CVE_SEARCHSPLOIT=1
      fi
      if [[ -f "$MSF_DB_PATH" ]]; then
        MSF_SEARCH=1
      fi
      if [[ -f "$TRICKEST_DB_PATH" ]]; then
        TRICKEST_SEARCH=1
      fi
      if [[ -f "$CONFIG_DIR"/routersploit_cve-db.txt || -f "$CONFIG_DIR"/routersploit_exploit-db.txt ]]; then
        RS_SEARCH=1
      fi

      write_csv_log "BINARY" "VERSION" "CVE identifier" "CVSS rating" "exploit db exploit available" "metasploit module" "trickest PoC" "Routersploit" "local exploit" "remote exploit" "DoS exploit" "known exploited vuln"
      generate_cve_details "${VERSIONS_AGGREGATED[@]}"
      generate_special_log "$CVE_MINIMAL_LOG" "$EXPLOIT_OVERVIEW_LOG"
    else
      print_cve_search_failure
      CVE_SEARCH=0
    fi
  else
    print_output "[-] CVE search binary search.py not found."
    print_output "[-] Run the installer or install it from here: https://github.com/cve-search/cve-search."
    print_output "[-] Installation instructions can be found on github.io: https://cve-search.github.io/cve-search/getting_started/installation.html#installation"
    CVE_SEARCH=0
  fi

  FOUND_CVE=$(sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "$LOG_FILE" | grep -c -E "\[\+\]\ Found\ " || true)

  write_log ""
  write_log "[*] Statistics:$CVE_SEARCH"

  module_end_log "${FUNCNAME[0]}" "$FOUND_CVE"
}

aggregate_versions() {
  sub_module_title "Software inventory generation."

  local VERSION=""
  export VERSIONS_AGGREGATED=()

  if [[ ${#VERSIONS_STAT_CHECK[@]} -gt 0 || ${#VERSIONS_EMULATOR[@]} -gt 0 || ${#VERSIONS_KERNEL[@]} -gt 0 || ${#VERSIONS_SYS_EMULATOR[@]} || ${#VERSIONS_S06_FW_DETAILS[@]} -gt 0 || ${#VERSIONS_SYS_EMULATOR_WEB[@]} -gt 0 ]]; then
    print_output "[*] Software inventory initial overview:"
    write_anchor "softwareinventoryinitialoverview"
    for VERSION in "${VERSIONS_S06_FW_DETAILS[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}firmware details check$GREEN): ""$ORANGE$VERSION$NC"
    done
    for VERSION in "${VERSIONS_S08_PACKAGE_DETAILS[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}package management system check$GREEN): ""$ORANGE$VERSION$NC"
    done
    for VERSION in "${VERSIONS_STAT_CHECK[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}statical check$GREEN): ""$ORANGE$VERSION$NC"
    done
    for VERSION in "${VERSIONS_EMULATOR[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}emulator$GREEN): ""$ORANGE$VERSION$NC"
    done
    for VERSION in "${VERSIONS_SYS_EMULATOR[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}system emulator$GREEN): ""$ORANGE$VERSION$NC"
    done
    for VERSION in "${VERSIONS_SYS_EMULATOR_WEB[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}system emulator - web$GREEN): ""$ORANGE$VERSION$NC"
    done

    for VERSION in "${VERSIONS_KERNEL[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}kernel$GREEN): ""$ORANGE$VERSION$NC"
      if [[ "$VERSION" =~ \.0$ ]]; then
        # shellcheck disable=SC2001
        VERSION=$(echo "$VERSION" | sed 's/\.0$/:/')
        VERSIONS_KERNEL+=( "$VERSION" )
        print_output "[+] Added modfied Kernel Version details (${ORANGE}kernel$GREEN): ""$ORANGE$VERSION$NC"
      fi
    done

    print_ln
    VERSIONS_AGGREGATED=("${VERSIONS_EMULATOR[@]}" "${VERSIONS_KERNEL[@]}" "${VERSIONS_STAT_CHECK[@]}" "${VERSIONS_SYS_EMULATOR[@]}" "${VERSIONS_S06_FW_DETAILS[@]}" "${VERSIONS_S08_PACKAGE_DETAILS[@]}" "${VERSIONS_SYS_EMULATOR_WEB[@]}")
  fi

  # sorting and unique our versions array:
  eval "VERSIONS_AGGREGATED=($(for i in "${VERSIONS_AGGREGATED[@]}" ; do echo "\"$i\"" ; done | sort -u))"
  if [[ -v VERSIONS_AGGREGATED[@] ]]; then
    for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      if [[ "$VERSION" == *" "* ]]; then
        print_output "[-] WARNING: Broken version identifier found: $ORANGE$VERSION$NC"
        continue
      fi
      if ! [[ "$VERSION" == *[0-9]* ]]; then
        print_output "[-] WARNING: Broken version identifier found: $ORANGE$VERSION$NC"
        continue
      fi
      if ! [[ "$VERSION" == *":"* ]]; then
        print_output "[-] WARNING: Broken version identifier found: $ORANGE$VERSION$NC"
        continue
      fi
      echo "$VERSION" >> "$LOG_PATH_MODULE"/versions.tmp
    done
  else
    print_output "[-] No Version details found."
  fi

  if [[ -f "$LOG_PATH_MODULE"/versions.tmp ]]; then
    # on old kernels it takes a huge amount of time to query all kernel CVE's. So, we move the kernel entry to the begin of our versions array
    mapfile -t KERNELS < <(grep kernel "$LOG_PATH_MODULE"/versions.tmp | sort -u || true)
    grep -v kernel "$LOG_PATH_MODULE"/versions.tmp | sort -u > "$LOG_PATH_MODULE"/versions1.tmp || true

    for KERNEL in "${KERNELS[@]}"; do
      if [[ -f "$LOG_PATH_MODULE"/versions1.tmp ]]; then
        if [[ $( wc -l "$LOG_PATH_MODULE"/versions1.tmp | awk '{print $1}') -eq 0 ]] ; then
          echo "$KERNEL" > "$LOG_PATH_MODULE"/versions1.tmp
        else
          sed -i "1s/^/$KERNEL\n/" "$LOG_PATH_MODULE"/versions1.tmp
        fi
      fi
    done

    if [[ -f "$LOG_PATH_MODULE"/versions1.tmp ]]; then
      mapfile -t VERSIONS_AGGREGATED < <(cat "$LOG_PATH_MODULE"/versions1.tmp)
    fi
    rm "$LOG_PATH_MODULE"/versions*.tmp 2>/dev/null

    # leave this here for debugging reasons
    if [[ ${#VERSIONS_AGGREGATED[@]} -ne 0 ]]; then
      print_bar ""
      print_output "[*] Software inventory aggregated:"
      for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
        print_output "[+] Found Version details (${ORANGE}aggregated$GREEN): ""$ORANGE$VERSION$NC"
      done
      print_bar ""
    else
      print_output "[-] No Version details found."
    fi
  else
    print_output "[-] No Version details found."
  fi
}

generate_special_log() {
  local CVE_MINIMAL_LOG="${1:-}"
  local EXPLOIT_OVERVIEW_LOG="${2:-}"

  if [[ $(grep -c "Found.*CVEs\ and" "$LOG_FILE" || true) -gt 0 ]]; then
    sub_module_title "Minimal report of exploits and CVE's."
    write_anchor "minimalreportofexploitsandcves"

    local EXPLOIT_HIGH=0
    local EXPLOIT_MEDIUM=0
    local EXPLOIT_LOW=0
    local KNOWN_EXPLOITED_VULNS=()
    local KNOWN_EXPLOITED_VULN=""
    local FILES=()
    local FILE=""
    local NAME=""
    local CVE_VALUES=""
    local EXPLOIT_=""
    local EXPLOITS_AVAIL=()

    readarray -t FILES < <(find "$LOG_PATH_MODULE"/ -maxdepth 1 -type f)
    print_ln
    print_output "[*] CVE log file generated."
    write_link "$CVE_MINIMAL_LOG"
    print_ln

    for FILE in "${FILES[@]}"; do
      NAME=$(basename "$FILE" | sed -e 's/\.txt//g' | sed -e 's/_/\ /g')
      CVE_VALUES=$(grep ^CVE "$FILE" | cut -d: -f2 | tr -d '\n' | sed -r 's/[[:space:]]+/, /g' | sed -e 's/^,\ //' || true)
      if [[ -n $CVE_VALUES ]]; then
        print_output "[*] CVE details for ${GREEN}$NAME${NC}:\\n"
        print_output "$CVE_VALUES"
        echo -e "\n[*] CVE details for ${GREEN}$NAME${NC}:" >> "$CVE_MINIMAL_LOG"
        echo "$CVE_VALUES" >> "$CVE_MINIMAL_LOG"
        print_ln
      fi
    done

    print_ln
    print_output "[*] Minimal exploit summary file generated."
    write_link "$EXPLOIT_OVERVIEW_LOG"
    print_ln

    echo -e "\n[*] Exploit summary:" >> "$EXPLOIT_OVERVIEW_LOG"
    grep -E "Exploit\ \(" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | sort -t : -k 4 -h -r | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" >> "$EXPLOIT_OVERVIEW_LOG" || true

    mapfile -t EXPLOITS_AVAIL < <(grep -E "Exploit\ \(" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | sort -t : -k 4 -h -r || true)

    for EXPLOIT_ in "${EXPLOITS_AVAIL[@]}"; do
      # remove color codes:
      EXPLOIT_=$(echo "$EXPLOIT_" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
      # extract CVSS value:
      CVSS_VALUE=$(echo "$EXPLOIT_" | sed -E 's/.*[[:blank:]]CVE-[0-9]{4}-[0-9]+[[:blank:]]//g' | cut -d: -f2 | sed -e 's/[[:blank:]]//g' | tr -dc '[:print:]')

      if (( $(echo "$CVSS_VALUE > 6.9" | bc -l) )); then
        print_output "$RED$EXPLOIT_$NC"
        ((EXPLOIT_HIGH+=1))
      elif (( $(echo "$CVSS_VALUE > 3.9" | bc -l) )); then
        print_output "$ORANGE$EXPLOIT_$NC"
        ((EXPLOIT_MEDIUM+=1))
      else
        print_output "$GREEN$EXPLOIT_$NC"
        ((EXPLOIT_LOW+=1))
      fi
    done

    if [[ -f "$LOG_PATH_MODULE"/exploit/known_exploited_vulns.log ]]; then
      mapfile -t KNOWN_EXPLOITED_VULNS < <(grep -E "known exploited" "$LOG_PATH_MODULE"/exploit/known_exploited_vulns.log || true 2>/dev/null)
      if [[ -v KNOWN_EXPLOITED_VULNS[@] ]]; then
        print_ln
        print_output "[*] Summary of known exploited vulnerabilities:"
        write_link "$LOG_PATH_MODULE/exploit/known_exploited_vulns.log"
        for KNOWN_EXPLOITED_VULN in "${KNOWN_EXPLOITED_VULNS[@]}"; do
          print_output "$KNOWN_EXPLOITED_VULN"
        done
        print_ln
      fi
    fi

    echo "$EXPLOIT_HIGH" > "$TMP_DIR"/EXPLOIT_HIGH_COUNTER.tmp
    echo "$EXPLOIT_MEDIUM" > "$TMP_DIR"/EXPLOIT_MEDIUM_COUNTER.tmp
    echo "$EXPLOIT_LOW" > "$TMP_DIR"/EXPLOIT_LOW_COUNTER.tmp
    echo "${#KNOWN_EXPLOITED_VULNS[@]}" > "$TMP_DIR"/KNOWN_EXPLOITED_COUNTER.tmp
  fi
}

generate_cve_details() {
  sub_module_title "Collect CVE and exploit details."
  write_anchor "collectcveandexploitdetails"

  CVE_COUNTER=0
  local VERSIONS_AGGREGATED=("$@")
  local BIN_VERSION=""

  for BIN_VERSION in "${VERSIONS_AGGREGATED[@]}"; do
    # BIN_VERSION is something like "binary:1.2.3"
    # we can use this format in cve-search
    if [[ "$THREADED" -eq 1 ]]; then
      # cve-search/mongodb calls called in parallel
      cve_db_lookup "$BIN_VERSION" &
      WAIT_PIDS_F19+=( "$!" )
      max_pids_protection "$MAX_MODS" "${WAIT_PIDS_F19[@]}"
    else
      cve_db_lookup "$BIN_VERSION"
    fi
  done

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_F19[@]}"
  fi
}

cve_db_lookup() {
  local BIN_VERSION_="${1:-}"

  # we create something like "binary_1.2.3" for log paths
  local VERSION_PATH="${BIN_VERSION_//:/_}"
  #local VERSION_BINARY
  #VERSION_BINARY=$(echo "$BIN_VERSION_" | cut -d: -f1)
  print_output "[*] CVE database lookup with version information: ${ORANGE}$BIN_VERSION_${NC}" "no_log"

  # CVE search:
  set +e
  "$PATH_CVE_SEARCH" -p "$BIN_VERSION_" -o json | jq -rc '"\(.id):\(.cvss):\(.cvss3)"' | sort -t ':' -k3 -r > "$LOG_PATH_MODULE"/"$VERSION_PATH".txt || true

  # shellcheck disable=SC2181
  if [[ "$?" -ne 0 ]]; then
    "$PATH_CVE_SEARCH" -p "$BIN_VERSION_" -o json | jq -rc '"\(.id):\(.cvss):\(.cvss3)"' | sort -t ':' -k3 -r > "$LOG_PATH_MODULE"/"$VERSION_PATH".txt || true
  fi
  set -e

  if [[ "$BIN_VERSION_" == *"dlink"* ]]; then
    # dlink extrawurst: dlink vs d-link
    # do a second cve-database check
    VERSION_SEARCHx="$(echo "$BIN_VERSION_" | sed 's/dlink/d-link/' | sed 's/_firmware//')"
    print_output "[*] CVE database lookup with version information: ${ORANGE}$VERSION_SEARCHx${NC}" "no_log"
    $PATH_CVE_SEARCH -p "$VERSION_SEARCHx" -o json | jq -rc '"\(.id):\(.cvss):\(.cvss3)"' | sort -t ':' -k3 -r >> "$LOG_PATH_MODULE"/"$VERSION_PATH".txt
  fi

  if [[ "$THREADED" -eq 1 ]]; then
    cve_extractor "$BIN_VERSION_" &
    WAIT_PIDS_F19_2+=( "$!" )
  else
    cve_extractor "$BIN_VERSION_"
  fi

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_F19_2[@]}"
  fi
}

cve_extractor() {
  local VERSION_orig="${1:-}"
  local VERSION=""
  local BINARY=""
  local CVE_VALUE=""
  local CVSS_VALUE=""
  local VSOURCE="unknown"
  local EXPLOIT_AVAIL=()
  local EXPLOIT_AVAIL_MSF=()
  local EXPLOIT_AVAIL_TRICKEST=()
  local EXPLOIT_AVAIL_ROUTERSPLOIT=()
  local EXPLOIT_AVAIL_ROUTERSPLOIT1=()
  local KNOWN_EXPLOITED_VULNS=()
  local KNOWN_EXPLOITED=0
  local LOCAL=0
  local REMOTE=0
  local DOS=0
  local CVEs_OUTPUT=()
  local CVE_OUTPUT=""

  if [[ "$(echo "$VERSION_orig" | sed 's/:$//' | grep -o ":" | wc -l || true)" -eq 1 ]]; then
    BINARY="$(echo "$VERSION_orig" | cut -d ":" -f1)"
    VERSION="$(echo "$VERSION_orig" | cut -d ":" -f2)"
  else
    # DETAILS="$(echo "$VERSION_orig" | cut -d ":" -f1)"
    BINARY="$(echo "$VERSION_orig" | cut -d ":" -f2)"
    VERSION="$(echo "$VERSION_orig" | cut -d ":" -f3-)"
  fi
  local VERSION_PATH="${VERSION_orig//:/_}"

  # VSOURCE is used to track the source of version details, this is relevant for the
  # final report. With this in place we know if it is from live testing via the network
  # or if it is found via static analysis or via user-mode emulation
  if grep -q "$VERSION_orig" "$S06_LOG" 2>/dev/null || grep -q "$VERSION_orig" "$S09_LOG" 2>/dev/null; then
    if [[ "$VSOURCE" == "unknown" ]]; then
      VSOURCE="STAT"
    else
      VSOURCE="$VSOURCE""/STAT"
    fi
  fi

  if [[ "$BINARY" == *"kernel"* ]]; then
    if grep -q "Statistics:$VERSION" "$S25_LOG" 2>/dev/null; then
      if [[ "$VSOURCE" == "unknown" ]]; then
        VSOURCE="STAT"
      elif ! [[ "$VSOURCE" =~ .*STAT.* ]]; then
        VSOURCE="$VSOURCE""/STAT"
      fi
    fi
  fi

  if grep -q "$VERSION_orig" "$S116_LOG" 2>/dev/null; then
    if [[ "$VSOURCE" == "unknown" ]]; then
      VSOURCE="UEMU"
    else
      VSOURCE="$VSOURCE""/UEMU"
    fi
  fi

  if grep -q "$BINARY;.*$VERSION" "$S08_LOG" 2>/dev/null; then
    if [[ "$VSOURCE" == "unknown" ]]; then
      VSOURCE="PACK"
    else
      VSOURCE="$VSOURCE""/PACK"
    fi
  fi


  if grep -q "$VERSION_orig" "$L15_LOG" 2>/dev/null || grep -q "$VERSION_orig" "$L25_LOG" 2>/dev/null; then
    if [[ "$VSOURCE" == "unknown" ]]; then
      VSOURCE="SEMU"
    else
      VSOURCE="$VSOURCE""/SEMU"
    fi
  fi

  AGG_LOG_FILE="$VERSION_PATH".txt

  EXPLOIT_COUNTER_VERSION=0
  CVE_COUNTER_VERSION=0
  # extract the CVE numbers and the CVSS values and sort it:
  if [[ -f "$LOG_PATH_MODULE"/"$AGG_LOG_FILE" ]]; then
    readarray -t CVEs_OUTPUT < "$LOG_PATH_MODULE"/"$AGG_LOG_FILE" || true

    for CVE_OUTPUT in "${CVEs_OUTPUT[@]}"; do
      local CVEv2_TMP=0
      ((CVE_COUNTER+=1))
      ((CVE_COUNTER_VERSION+=1))
      KNOWN_EXPLOITED=0
      CVE_VALUE=$(echo "$CVE_OUTPUT" | cut -d: -f1)
      CVSSv2_VALUE=$(echo "$CVE_OUTPUT" | cut -d: -f2)
      CVSS_VALUE=$(echo "$CVE_OUTPUT" | cut -d: -f3)

      # check if the CVE is known as a knwon exploited vulnerability:
      if [[ -f "$KNOWN_EXP_CSV" ]]; then
        if grep -q \""${CVE_VALUE}"\", "$KNOWN_EXP_CSV"; then
          print_output "[+] ${ORANGE}WARNING:$GREEN Vulnerability $ORANGE$CVE_VALUE$GREEN is a known exploited vulnerability."
          echo -e "[+] ${ORANGE}WARNING:$GREEN Vulnerability $ORANGE$CVE_VALUE$GREEN is a known exploited vulnerability." >> "$LOG_PATH_MODULE"/exploit/known_exploited_vulns.log
          KNOWN_EXPLOITED=1
        fi
      fi

      # default value
      EXPLOIT="No exploit available"

      EDB=0
      # as we already know about a bunch of kernel exploits - lets search them first
      if [[ "$BINARY" == *kernel* ]]; then
        for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
          if [[ "$KERNEL_CVE_EXPLOIT" == "$CVE_VALUE" ]]; then
            EXPLOIT="Exploit (linux-exploit-suggester"
            ((EXPLOIT_COUNTER_VERSION+=1))
            EDB=1
          fi
        done
      fi

      if [[ "$CVE_SEARCHSPLOIT" -eq 1 || "$MSF_SEARCH" -eq 1 || "$TRICKEST_SEARCH" -eq 1 ]] ; then
        if [[ $CVE_SEARCHSPLOIT -eq 1 ]]; then
          mapfile -t EXPLOIT_AVAIL < <(cve_searchsploit "$CVE_VALUE" 2>/dev/null || true)
        fi

        if [[ $MSF_SEARCH -eq 1 ]]; then
          mapfile -t EXPLOIT_AVAIL_MSF < <(grep -E "$CVE_VALUE"$ "$MSF_DB_PATH" 2>/dev/null || true)
        fi

        if [[ $TRICKEST_SEARCH -eq 1 ]]; then
          mapfile -t EXPLOIT_AVAIL_TRICKEST < <(grep -E "$CVE_VALUE\.md" "$TRICKEST_DB_PATH" 2>/dev/null || true)
        fi

        # routersploit db search
        if [[ $RS_SEARCH -eq 1 ]]; then
          mapfile -t EXPLOIT_AVAIL_ROUTERSPLOIT < <(grep -E "$CVE_VALUE"$ "$CONFIG_DIR/routersploit_cve-db.txt" 2>/dev/null || true)

          # now, we check the exploit-db results if we have a routersploit module:
          if [[ " ${EXPLOIT_AVAIL[*]} " =~ "Exploit DB Id:" ]]; then
            for EID_VALUE in "${EXPLOIT_AVAIL[@]}"; do
              if ! echo "$EID_VALUE" | grep -q "Exploit DB Id:"; then
                continue
              fi
              EID_VALUE=$(echo "$EID_VALUE" | grep "Exploit DB Id:" | cut -d: -f2)
              mapfile -t EXPLOIT_AVAIL_ROUTERSPLOIT1 < <(grep "$EID_VALUE" "$CONFIG_DIR/routersploit_exploit-db.txt" 2>/dev/null || true)
            done
          fi
        fi

        if [[ " ${EXPLOIT_AVAIL[*]} " =~ "Exploit DB Id:" ]]; then
          readarray -t EXPLOIT_IDS < <(echo "${EXPLOIT_AVAIL[@]}" | grep "Exploit DB Id:" | cut -d ":" -f 2 | sed 's/[^0-9]*//g' | sed 's/\ //' | sort -u)
          if [[ "$EXPLOIT" == "No exploit available" ]]; then
            EXPLOIT="Exploit (EDB ID:"
          else
            EXPLOIT="$EXPLOIT"" / EDB ID:"
          fi

          for EXPLOIT_ID in "${EXPLOIT_IDS[@]}" ; do
            LOCAL=0
            REMOTE=0
            DOS=0
            EXPLOIT="$EXPLOIT"" ""$EXPLOIT_ID"
            echo -e "[+] Exploit for $CVE_VALUE:\\n" >> "$LOG_PATH_MODULE""/exploit/""$EXPLOIT_ID"".txt"
            for LINE in "${EXPLOIT_AVAIL[@]}"; do
              echo "$LINE" >> "$LOG_PATH_MODULE""/exploit/""$EXPLOIT_ID"".txt"
              if [[ "$LINE" =~ "Platform: local" && "$LOCAL" -eq 0 ]]; then
                EXPLOIT="$EXPLOIT"" (L)"
                LOCAL=1
              fi
              if [[ "$LINE" =~ "Platform: remote" && "$REMOTE" -eq 0 ]]; then
                EXPLOIT="$EXPLOIT"" (R)"
                REMOTE=1
              fi
              if [[ "$LINE" =~ "Platform: dos" && "$DOS" -eq 0 ]]; then
                EXPLOIT="$EXPLOIT"" (D)"
                DOS=1
              fi
            done
            EDB=1
            ((EXPLOIT_COUNTER_VERSION+=1))
          done

          # copy the exploit-db exploits to the report
          for LINE in "${EXPLOIT_AVAIL[@]}"; do
            if [[ "$LINE" =~ "File:" ]]; then
              E_FILE=$(echo "$LINE" | awk '{print $2}')
              if [[ -f "$E_FILE" ]] ; then
                cp "$E_FILE" "$LOG_PATH_MODULE""/exploit/edb_""$(basename "$E_FILE")"
              fi
            fi
          done
        fi

        if [[ ${#EXPLOIT_AVAIL_MSF[@]} -gt 0 ]]; then
          if [[ "$EXPLOIT" == "No exploit available" ]]; then
            EXPLOIT="Exploit (MSF:"
          else
            EXPLOIT="$EXPLOIT"" ""/ MSF:"
          fi

          for EXPLOIT_MSF in "${EXPLOIT_AVAIL_MSF[@]}" ; do
            EXPLOIT_PATH=$(echo "$EXPLOIT_MSF" | cut -d: -f1)
            EXPLOIT_NAME=$(basename -s .rb "$EXPLOIT_PATH")
            EXPLOIT="$EXPLOIT"" ""$EXPLOIT_NAME"
            if [[ -f "$EXPLOIT_PATH" ]] ; then
              # for the web reporter we copy the original metasploit module into the EMBA log directory
              cp "$EXPLOIT_PATH" "$LOG_PATH_MODULE""/exploit/msf_""$EXPLOIT_NAME".rb
              if grep -q "< Msf::Exploit::Remote" "$EXPLOIT_PATH"; then
                EXPLOIT="$EXPLOIT"" (R)"
              fi
              if grep -q "< Msf::Exploit::Local" "$EXPLOIT_PATH"; then
                EXPLOIT="$EXPLOIT"" (L)"
              fi
              if grep -q "include Msf::Auxiliary::Dos" "$EXPLOIT_PATH"; then
                EXPLOIT="$EXPLOIT"" (D)"
              fi
            fi
          done

          if [[ $EDB -eq 0 ]]; then
            # only count the msf exploit if we have not already count an EDB exploit
            # otherwise we count an exploit for one CVE twice
            ((EXPLOIT_COUNTER_VERSION+=1))
            EDB=1
          fi
        fi

        if [[ ${#EXPLOIT_AVAIL_TRICKEST[@]} -gt 0 ]]; then
          if [[ "$EXPLOIT" == "No exploit available" ]]; then
            EXPLOIT="Exploit (Github:"
          else
            EXPLOIT="$EXPLOIT"" ""/ Github:"
          fi

          for EXPLOIT_TRICKEST in "${EXPLOIT_AVAIL_TRICKEST[@]}" ; do
            EXPLOIT_PATH=$(echo "$EXPLOIT_TRICKEST" | cut -d: -f1)
            EXPLOIT_NAME=$(echo "$EXPLOIT_TRICKEST" | cut -d: -f2- | sed -e 's/https\:\/\/github\.com\///g')
            EXPLOIT="$EXPLOIT"" ""$EXPLOIT_NAME"" (G)"
            # we remove slashes from the github url and use this as exploit name:
            EXPLOIT_NAME_=$(echo "$EXPLOIT_TRICKEST" | cut -d: -f2- | sed -e 's/https\:\/\/github\.com\///g' | tr '/' '_')
            if [[ -f "$EXPLOIT_PATH" ]] ; then
              # for the web reporter we copy the original metasploit module into the EMBA log directory
              if ! [[ -d "$LOG_PATH_MODULE""/exploit/" ]]; then
                mkdir "$LOG_PATH_MODULE""/exploit/"
              fi
              cp "$EXPLOIT_PATH" "$LOG_PATH_MODULE""/exploit/trickest_""$EXPLOIT_NAME_".md
            fi
          done

          if [[ $EDB -eq 0 ]]; then
            # only count the msf exploit if we have not already count an EDB exploit
            # otherwise we count an exploit for one CVE twice
            ((EXPLOIT_COUNTER_VERSION+=1))
            EDB=1
          fi
        fi

        if [[ -v EXPLOIT_AVAIL_ROUTERSPLOIT[@] || -v EXPLOIT_AVAIL_ROUTERSPLOIT1[@] ]]; then
          if [[ "$EXPLOIT" == "No exploit available" ]]; then
            EXPLOIT="Exploit (Routersploit:"
          else
            EXPLOIT="$EXPLOIT"" ""/ Routersploit:"
          fi
          EXPLOIT_ROUTERSPLOIT=("${EXPLOIT_AVAIL_ROUTERSPLOIT[@]}" "${EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}")
          for EXPLOIT_RS in "${EXPLOIT_ROUTERSPLOIT[@]}" ; do
            EXPLOIT_PATH=$(echo "$EXPLOIT_RS" | cut -d: -f1)
            EXPLOIT_NAME=$(basename -s .py "$EXPLOIT_PATH")
            EXPLOIT="$EXPLOIT"" ""$EXPLOIT_NAME"
            if [[ -f "$EXPLOIT_PATH" ]] ; then
              # for the web reporter we copy the original metasploit module into the EMBA log directory
              cp "$EXPLOIT_PATH" "$LOG_PATH_MODULE""/exploit/routersploit_""$EXPLOIT_NAME".py
              if grep -q Port "$EXPLOIT_PATH"; then
                EXPLOIT="$EXPLOIT"" (R)"
              fi
            fi
          done

          if [[ $EDB -eq 0 ]]; then
            # only count the msf exploit if we have not already count an EDB exploit
            # otherwise we count an exploit for one CVE twice
            ((EXPLOIT_COUNTER_VERSION+=1))
            EDB=1
          fi
        fi
      fi

      if [[ $KNOWN_EXPLOITED -eq 1 ]]; then
        EXPLOIT="$EXPLOIT"" (X)"
      fi

      if [[ $EDB -eq 1 ]]; then
        EXPLOIT="$EXPLOIT"")"
      fi

      #CVE_OUTPUT=$(echo "$CVE_OUTPUT" | sed -e "s/^CVE/""$BIN_VERSION_""/" | sed -e 's/\ \+/\t/g')
      #BINARY=$(echo "$CVE_OUTPUT" | cut -d: -f1 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
      #VERSION=$(echo "$CVE_OUTPUT" | cut -d: -f2- | sed -e 's/\t//g' | sed -e 's/\ \+//g' | sed -e 's/:CVE-[0-9].*//')
      # we do not deal with output formatting the usual way -> we use printf
      if [[ "$CVSS_VALUE" == "null" ]]; then
        print_output "[*] Missing CVSSv3 value for vulnerability $ORANGE$CVE_VALUE$NC - setting default CVSS to CVSSv2 $ORANGE$CVSSv2_VALUE$NC"
        CVSS_VALUE="$CVSSv2_VALUE"
        CVEv2_TMP=1
      fi
      if (( $(echo "$CVSS_VALUE > 6.9" | bc -l) )); then
        if [[ "$CVEv2_TMP" -eq 1 ]]; then CVSS_VALUE="$CVSS_VALUE""(v2)"; fi
        if [[ "$EXPLOIT" == *MSF* || "$EXPLOIT" == *EDB\ ID* || "$EXPLOIT" == *linux-exploit-suggester* || "$EXPLOIT" == *Routersploit* || "$EXPLOIT" == *Github* || "$KNOWN_EXPLOITED" -eq 1 ]]; then
          printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-17.17s:   %-9.9s:   %-15.15s:   %s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$VSOURCE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
        else
          printf "${RED}\t%-20.20s:   %-12.12s:   %-17.17s:   %-9.9s:   %-15.15s:   %s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$VSOURCE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
        fi
        ((HIGH_CVE_COUNTER+=1))
      elif (( $(echo "$CVSS_VALUE > 3.9" | bc -l) )); then
        if [[ "$CVEv2_TMP" -eq 1 ]]; then CVSS_VALUE="$CVSS_VALUE""(v2)"; fi
        if [[ "$EXPLOIT" == *MSF* || "$EXPLOIT" == *EDB\ ID* || "$EXPLOIT" == *linux-exploit-suggester* || "$EXPLOIT" == *Routersploit* || "$EXPLOIT" == *Github* || "$KNOWN_EXPLOITED" -eq 1 ]]; then
          printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-17.17s:   %-9.9s:   %-15.15s:   %s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$VSOURCE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
        else
          printf "${ORANGE}\t%-20.20s:   %-12.12s:   %-17.17s:   %-9.9s:   %-15.15s:   %s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$VSOURCE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
        fi
        ((MEDIUM_CVE_COUNTER+=1))
      else
        if [[ "$CVEv2_TMP" -eq 1 ]]; then CVSS_VALUE="$CVSS_VALUE""(v2)"; fi
        if [[ "$EXPLOIT" == *MSF* || "$EXPLOIT" == *EDB\ ID* || "$EXPLOIT" == *linux-exploit-suggester* || "$EXPLOIT" == *Routersploit* || "$EXPLOIT" == *Github* || "$KNOWN_EXPLOITED" -eq 1 ]]; then
          printf "${MAGENTA}\t%-20.20s:   %-12.12s:   %-17.17s:   %-9.9s:   %-15.15s:   %s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$VSOURCE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
        else
          printf "${GREEN}\t%-20.20s:   %-12.12s:   %-17.17s:   %-9.9s:   %-15.15s:   %s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$VSOURCE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
        fi
        ((LOW_CVE_COUNTER+=1))
      fi
      write_csv_log "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "${#EXPLOIT_AVAIL[@]}" "${#EXPLOIT_AVAIL_MSF[@]}" "${#EXPLOIT_AVAIL_TRICKEST[@]}" "${#EXPLOIT_AVAIL_ROUTERSPLOIT[@]}/${#EXPLOIT_AVAIL_ROUTERSPLOIT1[@]}" "$LOCAL" "$REMOTE" "$DOS" "${#KNOWN_EXPLOITED_VULNS[@]}"
    done
  fi
  
  { echo ""
    echo "[+] Statistics:$CVE_COUNTER_VERSION|$EXPLOIT_COUNTER_VERSION|$BIN_VERSION_"
  } >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"

  if [[ $LOW_CVE_COUNTER -gt 0 ]]; then
    echo "$LOW_CVE_COUNTER" >> "$TMP_DIR"/LOW_CVE_COUNTER.tmp
  fi
  if [[ $MEDIUM_CVE_COUNTER -gt 0 ]]; then
    echo "$MEDIUM_CVE_COUNTER" >> "$TMP_DIR"/MEDIUM_CVE_COUNTER.tmp
  fi
  if [[ $HIGH_CVE_COUNTER -gt 0 ]]; then
    echo "$HIGH_CVE_COUNTER" >> "$TMP_DIR"/HIGH_CVE_COUNTER.tmp
  fi

  print_output "[*] Vulnerability details for ${ORANGE}$BINARY$NC / version ${ORANGE}$VERSION$NC / source ${ORANGE}$VSOURCE$NC:"
  write_anchor "cve_$BINARY"
  if [[ "$EXPLOIT_COUNTER_VERSION" -gt 0 ]]; then
    print_ln
    grep -v "Statistics" "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE" | tee -a "$LOG_FILE"
    print_output "[+] Found $RED$BOLD$CVE_COUNTER_VERSION$NC$GREEN CVEs and $RED$BOLD$EXPLOIT_COUNTER_VERSION$NC$GREEN exploits (including POC's) in $ORANGE$BINARY$GREEN with version $ORANGE$VERSION$GREEN (source ${ORANGE}$VSOURCE$GREEN).${NC}"
    print_ln
  elif [[ "$CVE_COUNTER_VERSION" -gt 0 ]]; then
    print_ln
    grep -v "Statistics" "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE" | tee -a "$LOG_FILE"
    print_output "[+] Found $ORANGE$BOLD$CVE_COUNTER_VERSION$NC$GREEN CVEs and $ORANGE$BOLD$EXPLOIT_COUNTER_VERSION$NC$GREEN exploits (including POC's) in $ORANGE$BINARY$GREEN with version $ORANGE$VERSION$GREEN (source ${ORANGE}$VSOURCE$GREEN).${NC}"
    print_ln
  else
    print_ln
    print_output "[+] Found $ORANGE${BOLD}NO$NC$GREEN CVEs and $ORANGE${BOLD}NO$NC$GREEN exploits (including POC's) in $ORANGE$BINARY$GREEN with version $ORANGE$VERSION$GREEN (source ${ORANGE}$VSOURCE$GREEN).${NC}"
    print_ln
  fi

  CVEs="$CVE_COUNTER_VERSION"
  EXPLOITS="$EXPLOIT_COUNTER_VERSION"

  if [[ "$CVE_COUNTER_VERSION" -gt 0 || "$EXPLOIT_COUNTER_VERSION" -gt 0 ]]; then
    if ! [[ -f "$LOG_PATH_MODULE"/F20_summary.csv ]]; then
      echo "BINARY;VERSION;Number of CVEs;Number of EXPLOITS" >> "$LOG_PATH_MODULE"/F20_summary.csv
    fi
    if [[ "$EXPLOIT_COUNTER_VERSION" -gt 0 || "$KNOWN_EXPLOITED" -eq 1 ]]; then
      printf "[${MAGENTA}+${NC}]${MAGENTA} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-5.5s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "$BINARY" "$VERSION" "$CVEs" "$EXPLOITS" "$VSOURCE" >> "$LOG_PATH_MODULE"/F20_summary.txt
      echo "$BINARY;$VERSION;$CVEs;$EXPLOITS" >> "$LOG_PATH_MODULE"/F20_summary.csv
    else
      printf "[${ORANGE}+${NC}]${ORANGE} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-5.5s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "$BINARY" "$VERSION" "$CVEs" "$EXPLOITS" "$VSOURCE" >> "$LOG_PATH_MODULE"/F20_summary.txt
      echo "$BINARY;$VERSION;$CVEs;$EXPLOITS" >> "$LOG_PATH_MODULE"/F20_summary.csv
    fi
  elif [[ "$CVEs" -eq 0 && "$EXPLOITS" -eq 0 ]]; then
      printf "[${GREEN}+${NC}]${GREEN} Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-5.5s:   Exploits: %-5.5s:   Source: %-15.15s${NC}\n" "$BINARY" "$VERSION" "$CVEs" "$EXPLOITS" "$VSOURCE" >> "$LOG_PATH_MODULE"/F20_summary.txt
    echo "$BINARY;$VERSION;$CVEs;$EXPLOITS" >> "$LOG_PATH_MODULE"/F20_summary.csv
  else
    # this should never happen ...
    printf "[+] Found version details: \t%-20.20s:   %-15.15s:   CVEs: %-5.5s:   Exploits: %-5.5s:   Source: %-15.15s\n" "$BINARY" "$VERSION" "$CVEs" "$EXPLOITS" "$VSOURCE" >> "$LOG_PATH_MODULE"/F20_summary.txt
    echo "$BINARY;$VERSION;$CVEs;$EXPLOITS" >> "$LOG_PATH_MODULE"/F20_summary.csv
  fi

}

get_firmware_base_version_check() {
  local S09_LOG="${1:-}"
  VERSIONS_STAT_CHECK=()
  if [[ -f "$S09_LOG" ]]; then
    print_output "[*] Collect version details of module $(basename "$S09_LOG")."
    if [[ -f "$S09_LOG" ]]; then
      # if we have already kernel information:
      if [[ "$KERNELV" -eq 1 ]]; then
        readarray -t VERSIONS_STAT_CHECK < <(cut -d\; -f4 "$S09_LOG" | grep -v "csv_rule" | grep -v "kernel" | sort -u  || true)
      else
        readarray -t VERSIONS_STAT_CHECK < <(cut -d\; -f4 "$S09_LOG" | grep -v "csv_rule" | sort -u || true)
      fi
    fi
  fi
}

get_kernel_check() {
  local S25_LOG="${1:-}"
  VERSIONS_KERNEL=()
  KERNEL_CVE_EXPLOITS=()
  if [[ -f "$S25_LOG" ]]; then
    print_output "[*] Collect version details of module $(basename "$S25_LOG")."
    if [[ -f "$S25_LOG" ]]; then
      readarray -t KERNEL_CVE_EXPLOITS < <(grep "\[+\].*\[CVE-" "$S25_LOG" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | cut -d\[ -f3 | cut -d\] -f1 | sed -e 's/,/\r\n/g' || true)
      ## do a bit of sed modifications to have the same output as from the pre checker
      readarray -t VERSIONS_KERNEL < <(grep -a "Statistics:" "$S25_LOG" | sed -e 's/\[\*\]\ Statistics\:/kernel:/' | sort -u || true)
    fi
  fi
}

get_usermode_emulator() {
  local S116_LOG="${1:-}"
  VERSIONS_EMULATOR=()
  if [[ -f "$S116_LOG" ]]; then
    print_output "[*] Collect version details of module $(basename "$S116_LOG")."
    if [[ -f "$S116_LOG" ]]; then
      readarray -t VERSIONS_EMULATOR < <(cut -d\; -f4 "$S116_LOG" | grep -v "csv_rule" | sort -u || true)
    fi
  fi
}

get_systemmode_emulator() {
  local L15_LOG="${1:-}"
  VERSIONS_SYS_EMULATOR=()
  if [[ -f "$L15_LOG" ]]; then
    print_output "[*] Collect version details of module $(basename "$L15_LOG")."
    if [[ -f "$L15_LOG" ]]; then
      readarray -t VERSIONS_SYS_EMULATOR < <(cut -d\; -f4 "$L15_LOG" | grep -v "csv_rule" | sort -u || true)
    fi
  fi
}

get_systemmode_webchecks() {
  local L25_LOG="${1:-}"
  VERSIONS_SYS_EMULATOR_WEB=()
  if [[ -f "$L25_LOG" ]]; then
    print_output "[*] Collect version details of module $(basename "$L25_LOG")."
    if [[ -f "$L25_LOG" ]]; then
      readarray -t VERSIONS_SYS_EMULATOR_WEB < <(cut -d\; -f4 "$L25_LOG" | grep -v "csv_rule" | sort -u || true)
    fi
  fi
}


get_firmware_details() {
  local S06_LOG="${1:-}"
  VERSIONS_S06_FW_DETAILS=()
  if [[ -f "$S06_LOG" ]]; then
    print_output "[*] Collect version details of module $(basename "$S06_LOG")."
    if [[ -f "$S06_LOG" ]]; then
      readarray -t VERSIONS_S06_FW_DETAILS < <(cut -d\; -f4 "$S06_LOG" | grep -v "csv_rule" | sort -u || true)
    fi
  fi
}

get_package_details() {
  local S08_LOG="${1:-}"
  VERSIONS_S08_PACKAGE_DETAILS=()
  if [[ -f "$S08_LOG" ]]; then
    print_output "[*] Collect version details of module $(basename "$S08_LOG")."

    if [[ -f "$S08_LOG" ]]; then
      readarray -t VERSIONS_S08_PACKAGE_DETAILS < <(cut -d\; -f3,5 "$S08_LOG" | grep -v "package\;stripped version" | sort -u | tr ';' ':'|| true)
    fi
  fi
}
