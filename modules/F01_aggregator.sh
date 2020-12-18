#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens Energy AG
# Copyright 2020 Siemens AG
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

  # set it up
  PATH_CVE_SEARCH="../cve-search/bin/search.py"
  mkdir "$LOG_DIR"/aggregator

  if [[ -f $PATH_CVE_SEARCH ]]; then
    print_output "[*] Aggregate all vulnerability output"

    get_firmware_base_version_check
    #get_version_vulnerability_check
    get_kernel_check
    get_usermode_emulator
    generate_cve_details
  else
    print_output "[-] CVE search binary search.py not found."
    print_output "[-] Install it from here: https://github.com/cve-search/cve-search."
  fi
}

generate_cve_details() {
  sub_module_title "Collect CVE details."

  for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
    print_output "[+] Found Version details: ""$VERSION"""
  done
  for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
    print_output "[+] Found Kernel exploit: ""$KERNEL_CVE_EXPLOIT"""
  done

  CVE_COUNTER=0
  EXPLOIT_COUNTER=0
  KERNEL=0

  for VERSION in "${VERSIONS_AGGREGATED[@]}"; do

    # we try to handle as many version strings as possible through these generic rules
    VERSION_lower="$(echo "$VERSION" | tr '[:upper:]' '[:lower:]')"
    echo "$VERSION_lower"
    # if we have a version string like "binary version v1.2.3" we have to remove the version and the v:
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/version\ //' | sed 's/\ v[0-9]//')"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\ version\://')"
    #"Dropbear\ sshd\ v20[0-9][0-9]\.[0-9][0-9]"
    VERSION_lower="$(echo "$VERSION_lower" | sed -e 's/\sshd//')"
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
      # if we have already analysed a kernel version string we break here
      if [[ "$KERNEL" -eq 1 ]]; then 
        break
      fi
      VERSION_lower="$(echo "$VERSION_lower" | cut -d\  -f2,3)"
      KERNEL=1
    elif [[ $VERSION_lower == *kernel* ]]; then
      # if we have already analysed a kernel version string we break here
      if [[ "$KERNEL" -eq 1 ]]; then
        break
      fi
      KERNEL=1
    fi

    # now we should have the name an the version in the first two coloumns:
    VERSION_lower="$(echo "$VERSION_lower" | cut -d\  -f1-2)"

    VERSION_search="$(echo "$VERSION_lower" | sed 's/\ /:/')"
    VERSION_path="$(echo "$VERSION_lower" | sed 's/\ /_/')"
    print_output "[*] CVE database lookup with version information: ${GREEN}$VERSION_search${NC}"

    $PATH_CVE_SEARCH -p "$VERSION_search" > "$LOG_DIR"/aggregator/"$VERSION_path".txt
    
    # extract the CVE numbers and the CVSS values and sort it:
    readarray -t CVEs_OUTPUT < <(grep -A2 -e ":\ CVE-" "$LOG_DIR"/aggregator/"$VERSION_path".txt | grep -v "DATE" | grep -v "\-\-" | sed -e 's/^\ //' | sed ':a;N;$!ba;s/\nCVSS//g' | sed -e 's/: /\ :\ /g' | sort -k4 -V -r)

    for CVE_OUTPUT in "${CVEs_OUTPUT[@]}"; do
      ((CVE_COUNTER++))
      #extract the CVSS and CVE value (remove all spaces and tabs)
      CVSS_value=$(echo "$CVE_OUTPUT" | cut -d: -f3 | sed -e 's/\t//g' | sed -e 's/\ \+//g')
      CVE_value=$(echo "$CVE_OUTPUT" | cut -d: -f2 | sed -e 's/\t//g' | sed -e 's/\ \+//g')

      EXPLOIT="No exploit available"

      # as we already know about a buch of kernel exploits - letz search them
      if [[ "$VERSION_lower" == *kernel* ]]; then
        for KERNEL_CVE_EXPLOIT in "${KERNEL_CVE_EXPLOITS[@]}"; do
          if [[ "$KERNEL_CVE_EXPLOIT" == "$CVE_value" ]]; then
            EXPLOIT="${MAGENTA}Exploit available (Source: linux-exploit-suggester)"
            ((EXPLOIT_COUNTER++))
          fi
        done
      fi

      if command -v cve_searchsploit > /dev/null ; then
        # if no exploit was found lets talk to exploitdb:
        if [[ "$EXPLOIT" == "No exploit available" ]]; then
          if cve_searchsploit "$CVE_value" | grep -q "Exploit DB Id:" 2>/dev/null ; then
            EXPLOIT="${CYAN}Exploit available (Source: Exploit database)"
            ((EXPLOIT_COUNTER++))
          fi
        fi
      fi

      CVE_OUTPUT=$(echo "$CVE_OUTPUT" | sed -e "s/^CVE/""$VERSION_search""/" | sed -e 's/\ \+/\t/g')
      if (( $(echo "$CVSS_value > 6.9" | bc -l) )); then
        print_output "$(indent ${RED}$CVE_OUTPUT\t:\t$EXPLOIT${NC})"
      elif (( $(echo "$CVSS_value > 3.9" | bc -l) )); then
        print_output "$(indent ${ORANGE}$CVE_OUTPUT\t:\t$EXPLOIT${NC})"
      else
        print_output "$(indent ${GREEN}$CVE_OUTPUT\t:\t$EXPLOIT${NC})"
      fi
    done
  done

  echo
  print_output "[*] Identified the following version details, vulnerabilities and exploits:"
  for VERSION in "${VERSIONS_AGGREGATED[@]}"; do
    print_output "[*] Found version details: $VERSION"
  done
  echo
  print_output "[+] Found $CVE_COUNTER CVE entries for these versions."
  print_output "[+] Found $EXPLOIT_COUNTER exploits for these vulnerabilities."
  echo
}

get_firmware_base_version_check() {
  sub_module_title "Collect version details of module p09_firmware_base_version_check."
  if [[ -f "$LOG_DIR"/p09_firmware_base_version_check.txt ]]; then
    readarray -t VERSIONS_AGGREGATED < <(grep "Version information found" "$LOG_DIR"/p09_firmware_base_version_check.txt | cut -d\  -f5- | sed -e 's/ in firmware blob.//')
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
    VERSIONS_AGGREGATED+=("$(grep "Kernel version:\ " "$LOG_DIR"/s25_kernel_check.txt)")
  fi
}

get_usermode_emulator() {
  sub_module_title "Collect version details of module s115_usermode_emulator."
  if [[ -f "$LOG_DIR"/s115_usermode_emulator.txt ]]; then
    VERSIONS_AGGREGATED+=("$(grep "Version information found" "$LOG_DIR"/s115_usermode_emulator.txt | cut -d\  -f5- | sed -e 's/\ found\ in.*$//' | sed -e 's/vers..n\ //' | sed -e 's/\ (from\ binary.*)$//')")
  fi
}
