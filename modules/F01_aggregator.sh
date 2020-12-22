#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Module with all available functions and patterns to use
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}

F01_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final result aggregator"
  
  # we need:
  # apt-get install bc
  # sudo pip3 install cve-searchsploit
  # https://github.com/cve-search/cve-search

  # set it up
  PATH_CVE_SEARCH="../cve-search/bin/search.py"
  mkdir "$LOG_DIR"/aggregator
  KERNELV=0

  if [[ -f $PATH_CVE_SEARCH ]]; then
    print_output "[*] Aggregate vulnerability details"

    get_kernel_check
    # if we found a kernel in the kernel checker module we are going to use this kernel version (usually this version is better)
    # [+] Found Version details (base check): Linux kernel version 2.6.33
    # vs:
    # [+] Found Version details (kernel): Linux kernel version 2.6.33.2
    if [[ " ${VERSIONS_KERNEL[@]} " =~ "Linux kernel" ]]; then
      KERNELV=1
    fi
    get_firmware_base_version_check
    #get_version_vulnerability_check
    get_usermode_emulator
    generate_cve_details
  else
    print_output "[-] CVE search binary search.py not found."
    print_output "[-] Install it from here: https://github.com/cve-search/cve-search."
  fi
}

generate_cve_details() {
  sub_module_title "Collect CVE details."

  for VERSION in "${VERSIONS_BASE_CHECK[@]}"; do
    echo -e "[+] Found Version details (base check): ""$VERSION"""
  done
  for VERSION in "${VERSIONS_EMULATOR[@]}"; do
    echo -e "[+] Found Version details (emulator): ""$VERSION"""
  done
  for VERSION in "${VERSIONS_KERNEL[@]}"; do
    echo -e "[+] Found Version details (kernel): ""$VERSION"""
  done
  echo
  for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
    echo -e "[+] Found Kernel exploit: ""$KERNEL_CVE_EXPLOIT"""
  done

  VERSIONS_AGGREGATED=("${VERSIONS_BASE_CHECK[@]}" "${VERSIONS_EMULATOR[@]}" "${VERSIONS_KERNEL[@]}")
  # sorting and unique our versions array:
  for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
    # we try to handle as many version strings as possible through these generic rules
    VERSION_lower="$(echo "$VERSION" | tr '[:upper:]' '[:lower:]')"
    #echo "$VERSION_lower"
    # if we have a version string like "binary version v1.2.3" we have to remove the version and the v:
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\ version\://')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/version\ //')"
    # remove the v in something like this: "space v[number]"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\ v([0-9]+)/\ \1/g')"
    # "mkfs\.jffs2\ revision\ [0-9]\.[0-9]\.[0-9]\.[0-9]"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/revision//')"
    #"Dropbear\ sshd\ v20[0-9][0-9]\.[0-9][0-9]"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/sshd//')"
    # iwconfig\ \ Wireless-Tools\ version\ [0-9][0-9]"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/wireless\-tools//')"
    #"ndisc6\:\ IPv6\ Neighbor\/Router\ Discovery\ userland\ tool\ [0-9]\.[0-9]\.[0-9]\ "
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\:\ ipv6\ neighbor\/router\ discovery\ userland\ tool//')"
    # "ucloud_v2\ ver\.[0-9][0-9][0-9]"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/ver\.//')"
    # rdnssd\:\ IPv6\ Recursive\ DNS\ Server\ discovery\ Daemon\
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\:\ ipv6\ recursive\ dns\ server\ discovery\ daemon//')"
    #NETIO\ -\ Network\ Throughput\ Benchmark,\ Version
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\-\ network\ throughput\ benchmark\,\ //')"
    #ntpq\ -\ standard\ NTP\ query\ program\ -\ Ver\.
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\-\ standard\ ntp\ query\ program\ \-//')"
    #ntpd\ -\ NTP\ daemon\ program\ -\ Ver\.
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\-\ ntp\ daemon\ program\ \-//')"
    #igmpproxy, Version 0.1
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/,//')"
    #"ez-ipupdate:\ -\ [0-9]\.[0-9]\.[0-9][0-9]"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/://')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/-\ //')"
    #mini_httpd/1.19
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\//\ /')"
    #remove multiple spaces
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\ \+/\ /')"
    #echo "$VERSION_lower"

    # sometimes we get "Linux kernel x.yz.ab -> remove the first part of it
    if [[ $VERSION_lower == *linux\ kernel* ]]; then
      VERSION_lower="$(echo "$VERSION_lower" | cut -d\  -f2-3)"
    fi

    # now we should have the name an the version in the first two coloumns:
    VERSION_lower="$(echo "$VERSION_lower" | cut -d\  -f1-2)"
    VERSIONS_CLEANED+=( "$VERSION_lower" )
  done

  eval VERSIONS_CLEANED=($(for i in  "${VERSIONS_CLEANED[@]}" ; do  echo "\"$i\"" ; done | sort -u))

  echo
  for VERSION in "${VERSIONS_CLEANED[@]}"; do
    echo -e "[+] Found Version details (aggregated): ""$VERSION"""
  done

  echo
  CVE_COUNTER=0
  EXPLOIT_COUNTER=0

  for VERSION in "${VERSIONS_CLEANED[@]}"; do
    CVE_COUNTER_VERSION=0
    EXPLOIT_COUNTER_VERSION=0
    VERSION_search="$(echo "$VERSION" | sed 's/\ /:/')"
    VERSION_path="$(echo "$VERSION" | sed 's/\ /_/')"
    echo -e "[*] CVE database lookup with version information: ${GREEN}$VERSION_search${NC}"

    $PATH_CVE_SEARCH -p "$VERSION_search" > "$LOG_DIR"/aggregator/"$VERSION_path".txt

    # extract the CVE numbers and the CVSS values and sort it:
    readarray -t CVEs_OUTPUT < <(grep -A2 -e ":\ CVE-" "$LOG_DIR"/aggregator/"$VERSION_path".txt | grep -v "DATE" | grep -v "\-\-" | sed -e 's/^\ //' | sed ':a;N;$!ba;s/\nCVSS//g' | sed -e 's/: /\ :\ /g' | sort -k4 -V -r)

    for CVE_OUTPUT in "${CVEs_OUTPUT[@]}"; do
      ((CVE_COUNTER++))
      ((CVE_COUNTER_VERSION++))
      #extract the CVSS and CVE value (remove all spaces and tabs)
      CVSS_value=$(echo "$CVE_OUTPUT" | cut -d: -f3 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
      CVE_value=$(echo "$CVE_OUTPUT" | cut -d: -f2 | sed -e 's/\t//g' | sed -e 's/\ \+//g')

      EXPLOIT="No exploit available"

      # as we already know about a buch of kernel exploits - lets search them
      if [[ "$VERSION" == *kernel* ]]; then
        for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
          if [[ "$KERNEL_CVE_EXPLOIT" == "$CVE_value" ]]; then
            EXPLOIT="Exploit available (Source: linux-exploit-suggester)"
            ((EXPLOIT_COUNTER++))
            ((EXPLOIT_COUNTER_VERSION++))
          fi
        done
      fi

      if command -v cve_searchsploit > /dev/null ; then
        # if no exploit was found lets talk to exploitdb:
        if [[ "$EXPLOIT" == "No exploit available" ]]; then
          if cve_searchsploit "$CVE_value" | grep -q "Exploit DB Id:" 2>/dev/null ; then
            EXPLOIT="Exploit available (Source: Exploit database)"
            ((EXPLOIT_COUNTER++))
            ((EXPLOIT_COUNTER_VERSION++))
          fi
        fi
      fi

      CVE_OUTPUT=$(echo "$CVE_OUTPUT" | sed -e "s/^CVE/""$VERSION_search""/" | sed -e 's/\ \+/\t/g')
      BINARY=$(echo "$CVE_OUTPUT" | cut -d: -f1 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
      VERSION=$(echo "$CVE_OUTPUT" | cut -d: -f2 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
      if [[ "$EXPLOIT" == *Source* ]]; then
        printf "${MAGENTA}\t%-8.8s\t:\t%-8.8s\t:\t%-15.15s\t:\t%-8.8s:\t%s\n" "$BINARY" "$VERSION" "$CVE_value" "$CVSS_value" "$EXPLOIT"
      elif (( $(echo "$CVSS_value > 6.9" | bc -l) )); then
        printf "${RED}\t%-8.8s\t:\t%-8.8s\t:\t%-15.15s\t:\t%-8.8s:\t%s\n" "$BINARY" "$VERSION" "$CVE_value" "$CVSS_value" "$EXPLOIT"
      elif (( $(echo "$CVSS_value > 3.9" | bc -l) )); then
        printf "${ORANGE}\t%-8.8s\t:\t%-8.8s\t:\t%-15.15s\t:\t%-8.8s:\t%s\n" "$BINARY" "$VERSION" "$CVE_value" "$CVSS_value" "$EXPLOIT"
      else
        printf "${GREEN}\t%-8.8s\t:\t%-8.8s\t:\t%-15.15s\t:\t%-8.8s:\t%s\n" "$BINARY" "$VERSION" "$CVE_value" "$CVSS_value" "$EXPLOIT"
      fi
    done
    echo
    echo "" >> "$LOG_DIR"/aggregator/"$VERSION_path".txt
    echo "[*] Statistics:CVE_COUNTER|EXPLOIT_COUNTER|BINARY VERSION" >> "$LOG_DIR"/aggregator/"$VERSION_path".txt
    echo "[+] Statistics:$CVE_COUNTER_VERSION|$EXPLOIT_COUNTER_VERSION|$VERSION_search" >> "$LOG_DIR"/aggregator/"$VERSION_path".txt

    if [[ "$EXPLOIT_COUNTER_VERSION" -gt 0 ]]; then
      echo -e "${RED}Found $CVE_COUNTER_VERSION CVEs and $EXPLOIT_COUNTER_VERSION exploits in $VERSION_search.${NC}"
    elif [[ "$CVE_COUNTER_VERSION" -gt 0 ]];then
      echo -e "${ORANGE}Found $CVE_COUNTER_VERSION CVEs and $EXPLOIT_COUNTER_VERSION exploits in $VERSION_search.${NC}"
    else
      echo -e "Found $CVE_COUNTER_VERSION CVEs and $EXPLOIT_COUNTER_VERSION exploits in $VERSION_search."
    fi
    echo
  done

  echo
  echo -e "[*] Identified the following version details, vulnerabilities and exploits:"
  for FILE_AGGR in "$LOG_DIR"/aggregator/*; do
    STATS=$(grep "\[+\]\ Statistics\:" $FILE_AGGR | cut -d\: -f2-)
    #echo "$STATS"

    VERSION=$(echo $STATS | cut -d\| -f3-)
    BIN=$(echo $VERSION | cut -d\: -f1)
    #echo "binary: $BIN"
    VERSION=$(echo $VERSION | cut -d\: -f2)
    #echo "version: $VERSION"

    EXPLOITS=$(echo $STATS | cut -d\| -f2 | sed -e 's/\ //g')
    CVEs=$(echo $STATS | cut -d\| -f1 | sed -e 's/\ //g')

    if [[ "$CVEs" -gt 0 || "$EXPLOITS" -gt 0 ]]; then
      if [[ "$EXPLOITS" -gt 0 ]]; then
        printf "${MAGENTA}[+] Found version details: \t%-15.15s\t:\t%-8.8s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS"
      else
        #echo -e "${ORANGE}[*] Found version details: $BIN\t:\t$VERSION\t:\tCVEs: $CVEs\t:\tExploits: $EXPLOITS${NC}"
        printf "${ORANGE}[+] Found version details: \t%-15.15s\t:\t%-8.8s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS"
      fi
    else
      #echo -e "${GREEN}[*] Found version details: $BIN\t:\t$VERSION\t:\tCVEs: $CVEs\t:\tExploits: $EXPLOITS${NC}"
      printf "${GREEN}[+] Found version details: \t%-15.15s\t:\t%-8.8s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS"
    fi
  done
  echo
  echo -e "[+] Found $CVE_COUNTER CVE entries."
  echo -e "[+] Found $EXPLOIT_COUNTER exploits."
  echo
}

get_firmware_base_version_check() {
  sub_module_title "Collect version details of module p09_firmware_base_version_check."
  if [[ -f "$LOG_DIR"/p09_firmware_base_version_check.txt ]]; then
    # if we have already kernel information:
    if [[ "$KERNELV" -eq 1 ]]; then
      readarray -t VERSIONS_BASE_CHECK < <(grep "Version information found" "$LOG_DIR"/p09_firmware_base_version_check.txt | cut -d\  -f5- | sed -e 's/ in firmware blob.//' | sort -u | grep -v "Linux kernel")
    else
      readarray -t VERSIONS_BASE_CHECK < <(grep "Version information found" "$LOG_DIR"/p09_firmware_base_version_check.txt | cut -d\  -f5- | sed -e 's/ in firmware blob.//' | sort -u)
    fi
  fi
}

get_version_vulnerability_check() {
  sub_module_title "Collect version details of module s30_version_vulnerability_check."
  echo -e "[*] Currently nothing todo here ..."
}

get_kernel_check() {
  sub_module_title "Collect version details of module s25_kernel_check."
  if [[ -f "$LOG_DIR"/s25_kernel_check.txt ]]; then
    readarray -t KERNEL_CVE_EXPLOITS < <(grep "\[+\].*\[CVE-" "$LOG_DIR"/s25_kernel_check.txt | cut -d\[ -f3 | cut -d\] -f1 | sed -e 's/,/\r\n/g')
    ## do a bit of sed modifications to have the same output as from the pre checker
    readarray -t VERSIONS_KERNEL < <(grep "Kernel version:\ " "$LOG_DIR"/s25_kernel_check.txt | sed -e 's/Kernel\ version\:/Linux\ kernel\ version/' | sort -u)
  fi
}

get_usermode_emulator() {
  sub_module_title "Collect version details of module s115_usermode_emulator."
  if [[ -f "$LOG_DIR"/s115_usermode_emulator.txt ]]; then
    #VERSIONS_AGGREGATED+=("$(grep "Version information found" "$LOG_DIR"/s115_usermode_emulator.txt | cut -d\  -f5- | sed -e 's/\ found\ in.*$//' | sed -e 's/vers..n\ //' | sed -e 's/\ (.*$//')")
    readarray -t VERSIONS_EMULATOR < <(grep "Version information found" "$LOG_DIR"/s115_usermode_emulator.txt | cut -d\  -f5- | sed -e 's/\ found\ in.*$//' | sed -e 's/vers..n\ //' | sed -e 's/\ (.*$//' | sort -u)
  fi
}
