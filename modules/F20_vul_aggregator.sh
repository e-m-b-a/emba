#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens Energy AG
# Copyright 2020 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Aggregates all found version numbers together from S06, S09, S25 and S115 and searches with cve-search for all CVEs, 
#               finally it creates a list of exploits that are matching for the CVEs.

F20_vul_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final vulnerability aggregator"
  
  mkdir "$LOG_PATH_MODULE"/cve_sum
  mkdir "$LOG_PATH_MODULE"/exploit

  KERNELV=0
  HIGH_CVE_COUNTER=0
  MEDIUM_CVE_COUNTER=0
  LOW_CVE_COUNTER=0
  CVE_SEARCHSPLOIT=0
  MSF_MODULE_CNT=0

  CVE_AGGREGATOR_LOG="f20_vul_aggregator.txt"

  S06_LOG="$LOG_DIR"/s06_distribution_identification.csv
  S09_LOG="$LOG_DIR"/s09_firmware_base_version_check.csv
  S25_LOG="$LOG_DIR"/s25_kernel_check.txt
  S116_LOG="$LOG_DIR"/s116_qemu_version_detection.csv
  L15_LOG="$LOG_DIR"/l15_emulated_checks_init.txt

  CVE_MINIMAL_LOG="$LOG_PATH_MODULE"/CVE_minimal.txt
  EXPLOIT_OVERVIEW_LOG="$LOG_PATH_MODULE"/exploits-overview.txt

  if [[ -f $PATH_CVE_SEARCH ]]; then
    print_output "[*] Aggregate vulnerability details"

    # get the kernel version from s25:
    get_kernel_check
    # if we found a kernel in the kernel checker module we are going to use this kernel version (usually this version is better)
    # [+] Found Version details (base check): Linux kernel version 2.6.33
    # vs:
    # [+] Found Version details (kernel): Linux kernel version 2.6.33.2
    if [[ ${#VERSIONS_KERNEL[@]} -ne 0 ]]; then
      # then we have found a kernel in our s25 kernel module
      KERNELV=1
    fi

    get_firmware_details
    get_firmware_base_version_check
    get_usermode_emulator
    get_systemmode_emulator

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

      generate_cve_details
      generate_special_log
    else
      print_output "[-] MongoDB not responding as expected."
      print_output "[-] CVE checks not possible!"
      print_output "[-] Have you installed all the needed dependencies?"
      print_output "[-] Installation instructions can be found on github.io: https://cve-search.github.io/cve-search/getting_started/installation.html#installation"
      CVE_SEARCH=0
    fi
  else
    print_output "[-] CVE search binary search.py not found."
    print_output "[-] Run the installer or install it from here: https://github.com/cve-search/cve-search."
    print_output "[-] Installation instructions can be found on github.io: https://cve-search.github.io/cve-search/getting_started/installation.html#installation"
    CVE_SEARCH=0
  fi

  FOUND_CVE=$(sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "$LOG_FILE" | grep -c -E "\[\+\]\ Found\ ")

  write_log ""
  write_log "[*] Statistics:$CVE_SEARCH"

  module_end_log "${FUNCNAME[0]}" "$FOUND_CVE"
}

aggregate_versions() {
  sub_module_title "Software inventory generation."

  if [[ ${#VERSIONS_BASE_CHECK[@]} -gt 0 || ${#VERSIONS_STAT_CHECK[@]} -gt 0 || ${#VERSIONS_EMULATOR[@]} -gt 0 || ${#VERSIONS_KERNEL[@]} -gt 0 || ${#VERSIONS_SYS_EMULATOR[@]} || ${#VERSIONS_S06_FW_DETAILS[@]} -gt 0 ]]; then
    print_output "[*] Software inventory initial overview:"
    write_anchor "softwareinventoryinitialoverview"
    for VERSION in "${VERSIONS_S06_FW_DETAILS[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}firmware details check$GREEN): ""$ORANGE$VERSION$NC"
    done
    for VERSION in "${VERSIONS_BASE_CHECK[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}base check$GREEN): ""$ORANGE$VERSION$NC"
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
    for VERSION in "${VERSIONS_KERNEL[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      print_output "[+] Found Version details (${ORANGE}kernel$GREEN): ""$ORANGE$VERSION$NC"
    done

    print_output ""
    VERSIONS_AGGREGATED=("${VERSIONS_BASE_CHECK[@]}" "${VERSIONS_EMULATOR[@]}" "${VERSIONS_KERNEL[@]}" "${VERSIONS_STAT_CHECK[@]}" "${VERSIONS_SYS_EMULATOR[@]}" "${VERSIONS_S06_FW_DETAILS[@]}")
  fi

  # sorting and unique our versions array:
  eval "VERSIONS_AGGREGATED=($(for i in "${VERSIONS_AGGREGATED[@]}" ; do echo "\"$i\"" ; done | sort -u))"
  if [[ ${#VERSIONS_AGGREGATED[@]} -ne 0 ]]; then
    for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
      if [ -z "$VERSION" ]; then
        continue
      fi
      if ! [[ "$VERSION" == *[0-9]* ]]; then
        continue
      fi
      echo "$VERSION" >> "$LOG_PATH_MODULE"/versions.tmp
    done
  else
    print_output "[-] No Version details found."
  fi

  if [[ -f "$LOG_PATH_MODULE"/versions.tmp ]]; then
    # on old kernels it takes a huge amount of time to query all kernel CVE's. So, we move the kernel entry to the begin of our versions array
    mapfile -t KERNELS < <(grep kernel "$LOG_PATH_MODULE"/versions.tmp | sort -u)
    grep -v kernel "$LOG_PATH_MODULE"/versions.tmp | sort -u > "$LOG_PATH_MODULE"/versions1.tmp
    for KERNEL in "${KERNELS[@]}"; do
      if [[ $( wc -l "$LOG_PATH_MODULE"/versions1.tmp | cut -d" " -f1 ) -eq 0 ]] ; then
        echo "$KERNEL" > "$LOG_PATH_MODULE"/versions1.tmp
      else
        sed -i "1s/^/$KERNEL\n/" "$LOG_PATH_MODULE"/versions1.tmp
      fi
    done
    mapfile -t VERSIONS_AGGREGATED < <(cat "$LOG_PATH_MODULE"/versions1.tmp)
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
  if [[ $(grep -c "Found.*CVEs\ and" "$LOG_FILE") -gt 0 ]]; then
    sub_module_title "Minimal report of exploits and CVE's."
    write_anchor "minimalreportofexploitsandcves"

    readarray -t FILES < <(find "$LOG_PATH_MODULE"/ -type f)
    print_output ""
    print_output "[*] CVE log file stored in $CVE_MINIMAL_LOG.\\n"
    for FILE in "${FILES[@]}"; do
      NAME=$(basename "$FILE" | sed -e 's/\.txt//g' | sed -e 's/_/\ /g')
      CVE_VALUES=$(grep ^CVE "$FILE" | cut -d: -f2 | tr -d '\n' | sed -r 's/[[:space:]]+/, /g' | sed -e 's/^,\ //') 
      if [[ -n $CVE_VALUES ]]; then
        print_output "[*] CVE details for ${GREEN}$NAME${NC}:\\n"
        print_output "$CVE_VALUES"
        echo -e "\n[*] CVE details for ${GREEN}$NAME${NC}:" >> "$CVE_MINIMAL_LOG"
        echo "$CVE_VALUES" >> "$CVE_MINIMAL_LOG"
        print_output ""
      fi
    done

    print_output ""
    print_output "[*] Minimal exploit summary file stored in $EXPLOIT_OVERVIEW_LOG.\\n"
    mapfile -t EXPLOITS_AVAIL < <(grep -E "Exploit\ \(" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | sort -t : -k 4 -h -r)
    for EXPLOIT_ in "${EXPLOITS_AVAIL[@]}"; do
      # remove color codes:
      EXPLOIT_=$(echo "$EXPLOIT_" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g")
      CVSS_VALUE=$(echo "$EXPLOIT_" | sed -e 's/.*CVE-[0-9]//g' | cut -d: -f2 | sed -e 's/[[:blank:]]//g')
      if (( $(echo "$CVSS_VALUE > 6.9" | bc -l) )); then
        print_output "$RED$EXPLOIT_$NC"
      elif (( $(echo "$CVSS_VALUE > 3.9" | bc -l) )); then
        print_output "$ORANGE$EXPLOIT_$NC"
      else
        print_output "$GREEN$EXPLOIT_$NC"
      fi
    done
    echo -e "\n[*] Exploit summary:" >> "$EXPLOIT_OVERVIEW_LOG"
    grep "Exploit\ available" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | sort -t : -k 4 -h -r >> "$EXPLOIT_OVERVIEW_LOG"
  fi
}

generate_cve_details() {
  sub_module_title "Collect CVE and exploit details."
  write_anchor "collectcveandexploitdetails"

  CVE_COUNTER=0
  EXPLOIT_COUNTER=0

  for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
    if [[ "$THREADED" -eq 1 ]]; then
      # cve-search/mongodb calls called in parallel
      cve_db_lookup &
      WAIT_PIDS_F19+=( "$!" )
      max_pids_protection "$MAX_MODS" "${WAIT_PIDS_F19[@]}"
    else
      cve_db_lookup
    fi
  done

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_F19[@]}"
  fi
}

cve_db_lookup() {
  # using $VERSION variable:
  VERSION_SEARCH="$VERSION"
  VERSION_PATH="${VERSION//:/_}"
  VERSION_BINARY=$(echo "$VERSION" | cut -d: -f1)
  print_output "[*] CVE database lookup with version information: ${ORANGE}$VERSION_SEARCH${NC}" "" "f19#cve_$VERSION_BINARY"

  # CVE search:
  "$PATH_CVE_SEARCH" -p "$VERSION" > "$LOG_PATH_MODULE"/"$VERSION_PATH".txt

  # shellcheck disable=SC2181
  if [[ "$?" -ne 0 ]]; then
    "$PATH_CVE_SEARCH" -p "$VERSION" > "$LOG_PATH_MODULE"/"$VERSION_PATH".txt
  fi

  if [[ "$VERSION" == *"dlink"* ]]; then
    # dlink extrawurst: dlink vs d-link
    # do a second cve-database check
    VERSION_SEARCHx="$(echo "$VERSION_SEARCH" | sed 's/dlink/d-link/' | sed 's/_firmware//')"
    print_output "[*] CVE database lookup with version information: ${ORANGE}$VERSION_SEARCHx${NC}" "" "f19#cve_$VERSION_BINARY"
    $PATH_CVE_SEARCH -p "$VERSION_SEARCHx" >> "$LOG_PATH_MODULE"/"$VERSION_PATH".txt
  fi

  if [[ "$THREADED" -eq 1 ]]; then
    cve_extractor "$VERSION" &
    WAIT_PIDS_F19_2+=( "$!" )
  else
    cve_extractor "$VERSION"
  fi

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_F19_2[@]}"
  fi
}

cve_extractor() {
  local VERSION_orig
  VERSION_orig="$1"
  local VERSION
  local BINARY

  if [[ "$(echo "$VERSION_orig" | grep -o ":" | wc -l)" -eq 1 ]]; then
    BINARY="$(echo "$VERSION_orig" | cut -d ":" -f1)"
    VERSION="$(echo "$VERSION_orig" | cut -d ":" -f2)"
  else
    # DETAILS="$(echo "$VERSION_orig" | cut -d ":" -f1)"
    BINARY="$(echo "$VERSION_orig" | cut -d ":" -f2)"
    VERSION="$(echo "$VERSION_orig" | cut -d ":" -f3)"
  fi

  AGG_LOG_FILE="$VERSION_PATH".txt

  EXPLOIT_COUNTER_VERSION=0
  CVE_COUNTER_VERSION=0
  # extract the CVE numbers and the CVSS values and sort it:
  readarray -t CVEs_OUTPUT < <(grep -A2 -e "[[:blank:]]:\ CVE-" "$LOG_PATH_MODULE"/"$AGG_LOG_FILE" | grep -v "DATE" | grep -v "\-\-" | sed -e 's/^\ //' | sed ':a;N;$!ba;s/\nCVSS//g' | sed -e 's/: /\ :\ /g' | sort -k4 -V -r)

  for CVE_OUTPUT in "${CVEs_OUTPUT[@]}"; do
    ((CVE_COUNTER++))
    ((CVE_COUNTER_VERSION++))
    #extract the CVSS and CVE value (remove all spaces and tabs)
    CVSS_VALUE=$(echo "$CVE_OUTPUT" | cut -d: -f3 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
    CVE_VALUE=$(echo "$CVE_OUTPUT" | cut -d: -f2 | sed -e 's/\t//g' | sed -e 's/\ \+//g')

    # default value
    EXPLOIT="No exploit available"

    EDB=0
    # as we already know about a bunch of kernel exploits - lets search them first
    if [[ "$VERSION_BINARY" == *kernel* ]]; then
      for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
        if [[ "$KERNEL_CVE_EXPLOIT" == "$CVE_VALUE" ]]; then
          EXPLOIT="Exploit (linux-exploit-suggester"
          ((EXPLOIT_COUNTER++))
          ((EXPLOIT_COUNTER_VERSION++))
          EDB=1
        fi
      done
    fi

    if [[ "$CVE_SEARCHSPLOIT" -eq 1 || "$MSF_SEARCH" -eq 1 ]] ; then
      if [[ $CVE_SEARCHSPLOIT -eq 1 ]]; then
        mapfile -t EXPLOIT_AVAIL < <(cve_searchsploit "$CVE_VALUE" 2>/dev/null)
      fi

      if [[ $MSF_SEARCH -eq 1 ]]; then
        mapfile -t EXPLOIT_AVAIL_MSF < <(grep "$CVE_VALUE" "$MSF_DB_PATH" 2>/dev/null)
      fi

      if [[ " ${EXPLOIT_AVAIL[*]} " =~ "Exploit DB Id:" ]]; then
        readarray -t EXPLOIT_IDS < <(echo "${EXPLOIT_AVAIL[@]}" | grep "Exploit DB Id:" | cut -d ":" -f 2 | sed 's/[^0-9]*//g' | sed 's/\ //')
        if [[ "$EXPLOIT" == "No exploit available" ]]; then
          EXPLOIT="Exploit (EDB ID:"
        else
          EXPLOIT="$EXPLOIT"" / EDB ID:"
        fi
        for EXPLOIT_ID in "${EXPLOIT_IDS[@]}" ; do
          EXPLOIT="$EXPLOIT"" ""$EXPLOIT_ID"
          echo -e "[+] Exploit for $CVE_VALUE:\\n" >> "$LOG_PATH_MODULE""/exploit/""$EXPLOIT_ID"".txt"
          for LINE in "${EXPLOIT_AVAIL[@]}"; do
            echo "$LINE" >> "$LOG_PATH_MODULE""/exploit/""$EXPLOIT_ID"".txt"
          done
          EDB=1
          ((EXPLOIT_COUNTER++))
          ((EXPLOIT_COUNTER_VERSION++))
        done
        readarray -t EXPLOIT_FILES < <(echo "${EXPLOIT_AVAIL[@]}" | grep "File:" | cut -d ":" -f 2 | sed 's/\ //')
        for E_FILE in "${EXPLOIT_FILES[@]}"; do
          if [[ -f "$E_FILE" ]] ; then
            cp "$E_FILE" "$LOG_PATH_MODULE""/exploit/edb_""$(basename "$E_FILE")"
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
          fi
          ((MSF_MODULE_CNT++))
        done
        if [[ $EDB -eq 0 ]]; then
          # only count the msf exploit if we have not already count an EDB exploit
          # otherwise we count an exploit for one CVE twice
          ((EXPLOIT_COUNTER++))
          ((EXPLOIT_COUNTER_VERSION++))
          EDB=1
        fi
      fi
    fi
    if [[ $EDB -eq 1 ]]; then
      EXPLOIT="$EXPLOIT"")"
    fi

    CVE_OUTPUT=$(echo "$CVE_OUTPUT" | sed -e "s/^CVE/""$VERSION_SEARCH""/" | sed -e 's/\ \+/\t/g')
    #BINARY=$(echo "$CVE_OUTPUT" | cut -d: -f1 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
    #VERSION=$(echo "$CVE_OUTPUT" | cut -d: -f2- | sed -e 's/\t//g' | sed -e 's/\ \+//g' | sed -e 's/:CVE-[0-9].*//')
    # we do not deal with output formatting the usual way -> we use printf
    if (( $(echo "$CVSS_VALUE > 6.9" | bc -l) )); then
      if [[ "$EXPLOIT" == *MSF* || "$EXPLOIT" == *EDB\ ID* || "$EXPLOIT" == *linux-exploit-suggester* ]]; then
        printf "${MAGENTA}\t%-20.20s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      else
        printf "${RED}\t%-20.20s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      fi
      ((HIGH_CVE_COUNTER++))
    elif (( $(echo "$CVSS_VALUE > 3.9" | bc -l) )); then
      if [[ "$EXPLOIT" == *MSF* || "$EXPLOIT" == *EDB\ ID* || "$EXPLOIT" == *linux-exploit-suggester* ]]; then
        printf "${MAGENTA}\t%-20.20s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      else
        printf "${ORANGE}\t%-20.20s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      fi
      ((MEDIUM_CVE_COUNTER++))
    else
      if [[ "$EXPLOIT" == *MSF* || "$EXPLOIT" == *EDB\ ID* || "$EXPLOIT" == *linux-exploit-suggester* ]]; then
        printf "${MAGENTA}\t%-20.20s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      else
        printf "${GREEN}\t%-20.20s\t:\t%-15.15s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_VALUE" "$CVSS_VALUE" "$EXPLOIT" >> "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE"
      fi
      ((LOW_CVE_COUNTER++))
    fi
  done


  { echo ""
    echo "[+] Statistics:$CVE_COUNTER_VERSION|$EXPLOIT_COUNTER_VERSION|$VERSION_SEARCH"
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
  if [[ $EXPLOIT_COUNTER -gt 0 ]]; then
    echo "$EXPLOIT_COUNTER" >> "$TMP_DIR"/EXPLOIT_COUNTER.tmp
  fi
  if [[ $MSF_MODULE_CNT -gt 0 ]]; then
    echo "$MSF_MODULE_CNT" >> "$TMP_DIR"/MSF_MODULE_CNT.tmp
  fi

  if [[ "$EXPLOIT_COUNTER_VERSION" -gt 0 ]]; then
    write_anchor "cve_$BINARY"
    print_output ""
    grep -v "Statistics" "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE" | tee -a "$LOG_FILE"
    print_output "[+] Found $RED$BOLD$CVE_COUNTER_VERSION$NC$GREEN CVEs and $RED$BOLD$EXPLOIT_COUNTER_VERSION$NC$GREEN exploits in $ORANGE$BINARY$GREEN with version $ORANGE$VERSION.${NC}"
    print_output ""
  elif [[ "$CVE_COUNTER_VERSION" -gt 0 ]]; then
    write_anchor "cve_$BINARY"
    print_output ""
    grep -v "Statistics" "$LOG_PATH_MODULE"/cve_sum/"$AGG_LOG_FILE" | tee -a "$LOG_FILE"
    print_output "[+] Found $ORANGE$BOLD$CVE_COUNTER_VERSION$NC$GREEN CVEs and $ORANGE$BOLD$EXPLOIT_COUNTER_VERSION$NC$GREEN exploits in $ORANGE$BINARY$GREEN with version $ORANGE$VERSION.${NC}"
    print_output ""
  fi

  CVEs="$CVE_COUNTER_VERSION"
  EXPLOITS="$EXPLOIT_COUNTER_VERSION"

  if [[ "$CVE_COUNTER_VERSION" -gt 0 || "$EXPLOIT_COUNTER_VERSION" -gt 0 ]]; then
    if [[ "$EXPLOIT_COUNTER_VERSION" -gt 0 ]]; then
      printf "[${MAGENTA}+${NC}]${MAGENTA} Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BINARY" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
    else
      printf "[${ORANGE}+${NC}]${ORANGE} Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BINARY" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
    fi
  elif [[ "$CVEs" -eq 0 && "$EXPLOITS" -eq 0 ]]; then
    printf "[${GREEN}+${NC}]${GREEN} Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BINARY" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
  else
    # this should never happen ...
    printf "[+] Found version details: \t%-20.20s\t:\t%-15.15s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s\n" "$BINARY" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/"$CVE_AGGREGATOR_LOG"
  fi

}

get_firmware_base_version_check() {
  print_output "[*] Collect version details of module $(basename "$S09_LOG")."
  if [[ -f "$S09_LOG" ]]; then
    # if we have already kernel information:
    if [[ "$KERNELV" -eq 1 ]]; then
      readarray -t VERSIONS_STAT_CHECK < <(cut -d\; -f4 "$S09_LOG" | grep -v "csv_rule" | grep -v "kernel" | sort -u )
    else
      readarray -t VERSIONS_STAT_CHECK < <(cut -d\; -f4 "$S09_LOG" | grep -v "csv_rule" | sort -u )
    fi
  fi
}

get_kernel_check() {
  print_output "[*] Collect version details of module $(basename "$S25_LOG")."
  if [[ -f "$S25_LOG" ]]; then
    readarray -t KERNEL_CVE_EXPLOITS < <(grep "\[+\].*\[CVE-" "$S25_LOG" | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | cut -d\[ -f3 | cut -d\] -f1 | sed -e 's/,/\r\n/g')
    ## do a bit of sed modifications to have the same output as from the pre checker
    readarray -t VERSIONS_KERNEL < <(grep -a "Statistics:" "$S25_LOG" | sed -e 's/\[\*\]\ Statistics\:/kernel:/' | sort -u)
  fi
}

get_usermode_emulator() {
  print_output "[*] Collect version details of module $(basename "$S116_LOG")."
  if [[ -f "$S116_LOG" ]]; then
    readarray -t VERSIONS_EMULATOR < <(cut -d\; -f4 "$S116_LOG" | grep -v "csv_rule" | sort -u)
  fi
}

get_systemmode_emulator() {
  print_output "[*] Collect version details of module $(basename "$L15_LOG")."
  if [[ -f "$L15_LOG" ]]; then
    #readarray -t VERSIONS_SYS_EMULATOR < <(cut -d\; -f4 "$S15_LOG" | grep -v "csv_rule" | sort -u)
    readarray -t VERSIONS_SYS_EMULATOR < <(grep -a "Version information found" "$L15_LOG" | cut -d\  -f5- | sed 's/ in .* scanning logs.//' | sort -u)
  fi
}

get_firmware_details() {
  print_output "[*] Collect version details of module $(basename "$S06_LOG")."
  if [[ -f "$S06_LOG" ]]; then
    readarray -t VERSIONS_S06_FW_DETAILS < <(cut -d\; -f4 "$S06_LOG" | grep -v "csv_rule" | sort -u)
  fi
}
