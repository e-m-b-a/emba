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

F19_cve_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final CVE aggregator"
  
  # we need:
  # apt-get install bc
  # sudo pip3 install cve-searchsploit
  # https://github.com/cve-search/cve-search

  # set it up
  PATH_CVE_SEARCH="/home/m1k3/git-repos/cve-search/bin/search.py"
  mkdir "$LOG_DIR"/aggregator
  KERNELV=0

  if [[ -f $PATH_CVE_SEARCH ]]; then
    print_output "[*] Aggregate vulnerability details"

    get_kernel_check
    # if we found a kernel in the kernel checker module we are going to use this kernel version (usually this version is better)
    # [+] Found Version details (base check): Linux kernel version 2.6.33
    # vs:
    # [+] Found Version details (kernel): Linux kernel version 2.6.33.2
    if [[ "${VERSIONS_KERNEL[*]}" =~ "Linux kernel" ]]; then
      KERNELV=1
    fi

    get_firmware_base_version_check
    get_usermode_emulator
    aggregate_versions
    generate_cve_details
  else
    print_output "[-] CVE search binary search.py not found."
    print_output "[-] Install it from here: https://github.com/cve-search/cve-search."
  fi
}

prepare_version_data() {
    # we try to handle as many version strings as possible through these generic rules
    VERSION_lower="$(echo "$VERSION" | tr '[:upper:]' '[:lower:]')"
    #This is perl 5, version 20, subversion 0 (v5.20.0) built
    VERSION_lower="${VERSION_lower//this\ is\ perl\ .*\ \(v/}"
    VERSION_lower="${VERSION_lower//\)\ built/}"
    #D-Bus Message Bus Daemon 1.6.8
    VERSION_lower="${VERSION_lower//d-bus\ message\ bus\ daemon/:dbus\ }"
    #jQuery JavaScript Library v1.4.3
    VERSION_lower="${VERSION_lower//jquery\ javascript\ library\ v/jquery\ }"
    #xl2tpd version:  xl2tpd-1.3.6
    VERSION_lower="${VERSION_lower//xl2tpd\ version\:\ \ xl2tpd-/xl2tpd\ }"
    VERSION_lower="${VERSION_lower//xl2tpd-/}"
    #ntpd\ -\ standard\ NTP\ query\ program\ -\ Ver\.
    VERSION_lower="${VERSION_lower//ntpd\ -\ ntp\ daemon\ program\ -\ ver\.\ /ntpd\ }"
    VERSION_lower="${VERSION_lower//ntpq\ -\ standard\ ntp\ query\ program\ -\ ver\.\ /ntpq\ }"
    #This is SMTPclient Version
    VERSION_lower="${VERSION_lower//this\ is\ smtpclient\ version/smtpclient}"
    # iputils-sss
    VERSION_lower="${VERSION_lower//iputils-sss/iputils\ }"
    VERSION_lower="${VERSION_lower//iproute2-ss/iproute2\ }"
    # Ralink\ DOT1X\ daemon,\ version\ = '
    VERSION_lower="${VERSION_lower//Ralink\ DOT1X\ daemon,\ version\ = \'/ralink-dot1x}"
    # if we have a version string like "binary version v1.2.3" we have to remove the version and the v:
    VERSION_lower="${VERSION_lower//\ version\:/}"
    VERSION_lower="${VERSION_lower//version\ /}"
    #Wireless-Tools version 29
    VERSION_lower="${VERSION_lower//wireless-tools\ /wireless_tools\ }"
    # apt-Version 1.2.3
    VERSION_lower="${VERSION_lower//apt-/apt\ }"
    # remove the v in something like this: "space v[number]"
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/\ v([0-9]+)/\ \1/g')"
    # "mkfs\.jffs2\ revision\ [0-9]\.[0-9]\.[0-9]\.[0-9]"
    VERSION_lower="${VERSION_lower//revision/}"
    #"Dropbear\ sshd\ v20[0-9][0-9]\.[0-9][0-9]"
    VERSION_lower="${VERSION_lower//sshd/}"
    # GNU grep 2.6.3
    VERSION_lower="${VERSION_lower//^gnu\ /}"
    #3.0.10 - $Id: ez-ipupdate.c,v 1.44 (from binary 3322ip) found in qemu_3322ip.txt.
    VERSION_lower="$(echo "$VERSION_lower" | sed -r 's/([0-9]\.[0-9]\.[0-9]+)\ -\ .*ez\-ipupdate\.c,v\ [0-9]\.[0-9][0-9]/ez-ipupdate \1/')"
    # iwconfig\ \ Wireless-Tools\ version\ [0-9][0-9]"
    VERSION_lower="${VERSION_lower//wireless\-tools/}"
    #"ndisc6\:\ IPv6\ Neighbor\/Router\ Discovery\ userland\ tool\ [0-9]\.[0-9]\.[0-9]\ "
    VERSION_lower="${VERSION_lower//\:\ ipv6\ neighbor\/router\ discovery\ userland\ tool/}"
    #"ucloud_v2\ ver\.[0-9][0-9][0-9]"
    VERSION_lower="${VERSION_lower//ver\./}"
    # rdnssd\:\ IPv6\ Recursive\ DNS\ Server\ discovery\ Daemon\
    VERSION_lower="${VERSION_lower//\:\ ipv6\ recursive\ dns\ server\ discovery\ daemon/}"
    #NETIO\ -\ Network\ Throughput\ Benchmark,\ Version
    VERSION_lower="${VERSION_lower//-\ network\ throughput\ benchmark\,\ /}"
    #ntpd\ -\ NTP\ daemon\ program\ -\ Ver\.
    VERSION_lower="${VERSION_lower//-\ ntp\ daemon\ program\ -/}"
    # GNU bash, 4.3.39
    VERSION_lower="${VERSION_lower//gnu\ bash,\ /bash\ }"
    # FUSE library version: 2.9.4
    VERSION_lower="${VERSION_lower//fuse\ library/fuse}"
    # NET-SNMP\ version:\ \ 
    VERSION_lower="${VERSION_lower//net-snmp\ /net-snmp}"
    #igmpproxy, Version 0.1
    VERSION_lower="${VERSION_lower//,/}"
    # BoosterMainFunction:305
    VERSION_lower="${VERSION_lower//boostermainfunction:305/booster}"
    VERSION_lower="${VERSION_lower//:/}"
    VERSION_lower="${VERSION_lower//--\ /}"
    VERSION_lower="${VERSION_lower//-\ /}"
    #mini_httpd/1.19
    VERSION_lower="${VERSION_lower/\//\ }"
    #Beceem\ CM\ Server\
    VERSION_lower="${VERSION_lower//beceem\ cm\ server/beceem}"
    VERSION_lower="${VERSION_lower//beceem\ cscm\ command\ line\ client/beceem}"
    # loadkeys von kbd
    VERSION_lower="${VERSION_lower//loadkeys\ von\ kbd/loadkeys}"
    # CLIENT\ libcurl\
    VERSION_lower="${VERSION_lower//client\ libcurl/libcurl }"
    # GNU C Library (AuDis-V04.56) stable release version 2.23
    #VERSION_lower="${VERSION_lower//gnu\ c\ library.*stable\ release/gnu:libc}"
    # shellcheck disable=SC2001
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/gnu\ c\ library.*stable\ release/gnu:libc/')"
    #remove multiple spaces
    VERSION_lower="${VERSION_lower//\ \+/\ }"
    #remove '
    VERSION_lower="${VERSION_lower//\'/}"
    #our current version detection on strict version includes backslashes:
    #VERSION_lower="${VERSION_lower//\\/}"

    # sometimes we get "Linux kernel x.yz.ab -> remove the first part of it
    if [[ $VERSION_lower == *linux\ kernel* ]]; then
      VERSION_lower="$(echo "$VERSION_lower" | cut -d\  -f2-3)"
    fi
}

aggregate_versions() {
  sub_module_title "Aggregate versions."

  # initial output - probably we will remove it in the future
  # currently it is very helpful
  print_output ""
  for VERSION in "${VERSIONS_BASE_CHECK[@]}"; do
    print_output "[+] Found Version details (base check): ""$VERSION"""
  done
  for VERSION in "${VERSIONS_EMULATOR[@]}"; do
    print_output "[+] Found Version details (emulator): ""$VERSION"""
  done
  for VERSION in "${VERSIONS_KERNEL[@]}"; do
    print_output "[+] Found Version details (kernel): ""$VERSION"""
  done

  #print_output ""
  #for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
  #  print_output "[+] Found Kernel exploit: ""$KERNEL_CVE_EXPLOIT"""
  #done

  print_output ""
  VERSIONS_AGGREGATED=("${VERSIONS_BASE_CHECK[@]}" "${VERSIONS_EMULATOR[@]}" "${VERSIONS_KERNEL[@]}")
  for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
    prepare_version_data
    # now we should have the name and the version in the first two coloumns:
    echo "$VERSION_lower"
    VERSION_lower="$(echo "$VERSION_lower" | cut -d\  -f1-2)"
    echo "$VERSION_lower"
    # check if we have some number in it ... without a number we have no version info and we can drop this entry ...
    if [[ $VERSION_lower =~ [0-9] ]]; then
      VERSIONS_CLEANED+=( "$VERSION_lower" )
    fi
  done

  # sorting and unique our versions array:
  eval "VERSIONS_CLEANED=($(for i in  "${VERSIONS_CLEANED[@]}" ; do  echo "\"$i\"" ; done | sort -u))"

  if [[ ${#VERSIONS_CLEANED[@]} -ne 0 ]]; then
    for VERSION in "${VERSIONS_CLEANED[@]}"; do
      print_output "[+] Found Version details (aggregated): ""$VERSION"""
    done
  else
      print_output "[-] No Version details found."
  fi
  print_output ""

}

generate_cve_details() {
  sub_module_title "Collect CVE details."

  CVE_COUNTER=0
  EXPLOIT_COUNTER=0

  for VERSION in "${VERSIONS_CLEANED[@]}"; do
    CVE_COUNTER_VERSION=0
    EXPLOIT_COUNTER_VERSION=0
    VERSION_search="${VERSION//\ /:}"
    VERSION_path="${VERSION//\ /_}"
    print_output ""
    print_output "[*] CVE database lookup with version information: ${GREEN}$VERSION_search${NC}"

    # CVE search:
    $PATH_CVE_SEARCH -p "$VERSION_search" > "$LOG_DIR"/aggregator/"$VERSION_path".txt

    # extract the CVE numbers and the CVSS values and sort it:
    readarray -t CVEs_OUTPUT < <(grep -A2 -e "[[:blank:]]:\ CVE-" "$LOG_DIR"/aggregator/"$VERSION_path".txt | grep -v "DATE" | grep -v "\-\-" | sed -e 's/^\ //' | sed ':a;N;$!ba;s/\nCVSS//g' | sed -e 's/: /\ :\ /g' | sort -k4 -V -r)

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
        printf "${MAGENTA}\t%-10.10s\t:\t%-10.10s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_value" "$CVSS_value" "$EXPLOIT" | tee -a "$LOG_DIR"/f19_cve_aggregator.txt
      elif (( $(echo "$CVSS_value > 6.9" | bc -l) )); then
        printf "${RED}\t%-10.10s\t:\t%-10.10s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_value" "$CVSS_value" "$EXPLOIT" | tee -a "$LOG_DIR"/f19_cve_aggregator.txt
      elif (( $(echo "$CVSS_value > 3.9" | bc -l) )); then
        printf "${ORANGE}\t%-10.10s\t:\t%-10.10s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_value" "$CVSS_value" "$EXPLOIT" | tee -a "$LOG_DIR"/f19_cve_aggregator.txt
      else
        printf "${GREEN}\t%-10.10s\t:\t%-10.10s\t:\t%-15.15s\t:\t%-8.8s:\t%s${NC}\n" "$BINARY" "$VERSION" "$CVE_value" "$CVSS_value" "$EXPLOIT" | tee -a "$LOG_DIR"/f19_cve_aggregator.txt
      fi
    done

    { echo ""
      echo "[*] Statistics:CVE_COUNTER|EXPLOIT_COUNTER|BINARY VERSION"
      echo "[+] Statistics:$CVE_COUNTER_VERSION|$EXPLOIT_COUNTER_VERSION|$VERSION_search"
    } >> "$LOG_DIR"/aggregator/"$VERSION_path".txt

    print_output ""
    if [[ "$EXPLOIT_COUNTER_VERSION" -gt 0 ]]; then
      print_output "${RED}Found $CVE_COUNTER_VERSION CVEs and $EXPLOIT_COUNTER_VERSION exploits in $VERSION_search.${NC}"
    elif [[ "$CVE_COUNTER_VERSION" -gt 0 ]];then
      print_output "${ORANGE}Found $CVE_COUNTER_VERSION CVEs and $EXPLOIT_COUNTER_VERSION exploits in $VERSION_search.${NC}"
    else
      print_output "Found $CVE_COUNTER_VERSION CVEs and $EXPLOIT_COUNTER_VERSION exploits in $VERSION_search."
    fi
  done

  print_output ""
  print_output "[*] Identified the following version details, vulnerabilities and exploits:"
  for FILE_AGGR in "$LOG_DIR"/aggregator/*; do
    if [[ -f $FILE_AGGR ]]; then
      STATS=$(grep "\[+\]\ Statistics\:" "$FILE_AGGR" | cut -d: -f2- 2>/dev/null)
  
      VERSION=$(echo "$STATS" | cut -d\| -f3-)
      BIN=$(echo "$VERSION" | cut -d: -f1)
      VERSION=$(echo "$VERSION" | cut -d: -f2)
  
      EXPLOITS=$(echo "$STATS" | cut -d\| -f2 | sed -e 's/\ //g')
      CVEs=$(echo "$STATS" | cut -d\| -f1 | sed -e 's/\ //g')
  
      if [[ "$CVEs" -gt 0 || "$EXPLOITS" -gt 0 ]]; then
        if [[ "$EXPLOITS" -gt 0 ]]; then
          printf "${MAGENTA}[+] Found version details: \t%-15.15s\t:\t%-8.8s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/f19_cve_aggregator.txt
        else
          printf "${ORANGE}[+] Found version details: \t%-15.15s\t:\t%-8.8s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/f19_cve_aggregator.txt
        fi
      else
        printf "${GREEN}[+] Found version details: \t%-15.15s\t:\t%-8.8s\t:\tCVEs: %-8.8s\t:\tExploits: %-8.8s${NC}\n" "$BIN" "$VERSION" "$CVEs" "$EXPLOITS" | tee -a "$LOG_DIR"/f19_cve_aggregator.txt
      fi
    fi
  done

  print_output "${NC}"
  if [[ "$S30_VUL_COUNTER" -gt 0 ]]; then
    print_output "[+] Found $S30_VUL_COUNTER CVE entries for all binaries from S30_version_vulnerability_check.sh."
  fi
  print_output "[+] Confirmed $CVE_COUNTER CVE entries."
  print_output "[+] $EXPLOIT_COUNTER possible exploits available.\\n"
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
  print_output "[*] Currently nothing todo here ..."
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
    readarray -t VERSIONS_EMULATOR < <(grep "Version information found" "$LOG_DIR"/s115_usermode_emulator.txt | cut -d\  -f5- | sed -e 's/\ found\ in.*$//' | sed -e 's/vers..n\ //' | sed -e 's/\ (.*$//' | sort -u)
  fi
}
