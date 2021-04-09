#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2021 Siemens Energy AG
# Copyright 2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Generates an overview over all modules.

F50_base_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final aggregator"

  CVE_AGGREGATOR_LOG="f19_cve_aggregator.txt"
  S25_LOG="s25_kernel_check.txt"
  P02_LOG="p02_firmware_bin_file_check.txt"
  P07_LOG="p07_firmware_bin_base_analyzer.txt"
  S05_LOG="s05_firmware_details.txt"
  S10_LOG="s10_binaries_check.txt"
  S20_LOG="s20_shell_check.txt"
  S21_LOG="s21_python_check.txt"
  S22_LOG="s22_php_check.txt"
  S30_LOG="s30_version_vulnerability_check.txt"
  S40_LOG="s40_weak_perm_check.txt"
  S45_LOG="s45_pass_file_check.txt"
  S50_LOG="s50_authentication_check.txt"
  S55_LOG="s55_history_file_check.txt"
  S60_LOG="s60_cert_file_check.txt"
  S85_LOG="s85_ssh_check.txt"
  S95_LOG="s95_interesting_binaries_check.txt"
  S108_LOG="s108_linux_common_file_checker.txt"
  S110_LOG="s110_yara_check.txt"
  S120_LOG="s120_cwe_checker.txt"

  LOG_FILE="$( get_log_file )"

  get_data
  output_overview
  output_details
  output_config_issues
  output_binaries
  output_cve_exploits

  module_end_log "${FUNCNAME[0]}" 1 
}

output_overview() {

  if [[ -n "$FW_VENDOR" ]]; then
    print_output "[+] Tested Firmware vendor: ""$ORANGE""$FW_VENDOR"
  fi  
  if [[ -n "$FW_VERSION" ]]; then
    print_output "[+] Tested Firmware version: ""$ORANGE""$FW_VERSION"
  fi  
  if [[ -n "$FW_DEVICE" ]]; then
    print_output "[+] Tested Firmware from device: ""$ORANGE""$FW_DEVICE"
  fi  
  if [[ -n "$FW_NOTES" ]]; then
    print_output "[+] Additional notes: ""$ORANGE""$FW_NOTES"
  fi  

  print_output "[+] Tested firmware:""$ORANGE"" ""$FIRMWARE_PATH"
  print_output "[+] Emba start command:""$ORANGE"" ""$EMBA_COMMAND"

  if [[ -n "$ARCH" ]]; then
    print_output "[+] Detected architecture (""$ORANGE""verified$GREEN):""$ORANGE"" ""$ARCH"
  elif [[ -f "$LOG_DIR"/"$P07_LOG" ]]; then
    if [[ -n "$PRE_ARCH" ]]; then
      print_output "[+] Detected architecture:""$ORANGE"" ""$PRE_ARCH"
    fi
  fi
  os_detector
  print_bar
}

output_details() {

  if [[ "$FILE_ARR_COUNT" -gt 0 ]]; then
    print_output "[+] ""$ORANGE""$FILE_ARR_COUNT""$GREEN"" files and ""$ORANGE""$DETECTED_DIR"" ""$GREEN""directories detected."
  fi
  ENTROPY_PIC=$(find "$LOG_DIR" -xdev -type f -iname "*_entropy.png" 2> /dev/null)
  if [[ -n "$ENTROPY" ]]; then
    print_output "[+] Entropy analysis of binary firmware is:""$ORANGE""$ENTROPY"
  fi
  if [[ -n "$ENTROPY_PIC" ]]; then
    print_output "[+] Entropy analysis of binary firmware is available:""$ORANGE"" ""$ENTROPY_PIC"
  fi

  if [[ "$S20_SHELL_VULNS" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$S20_SHELL_VULNS"" issues""$GREEN"" in ""$ORANGE""$S20_SCRIPTS""$GREEN"" shell scripts.""$NC"
  fi
  if [[ "$S21_PY_VULNS" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$S21_PY_VULNS"" issues""$GREEN"" in ""$ORANGE""$S21_PY_SCRIPTS""$GREEN"" python files.""$NC"
  fi
  if [[ "$S22_PHP_VULNS" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$S22_PHP_VULNS"" issues""$GREEN"" in ""$ORANGE""$S22_PHP_SCRIPTS""$GREEN"" php files.""$NC"
  fi
  if [[ "$YARA_CNT" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$YARA_CNT""$GREEN"" yara rule matches in $ORANGE${#FILE_ARR[@]}$GREEN files.""$NC"
  fi
  EMUL=$(find "$LOG_DIR"/qemu_emulator -xdev -type f -iname "qemu_*" 2>/dev/null | wc -l) 
  if [[ "$EMUL" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$EMUL""$GREEN"" successful emulated processes.""$NC"
  fi

  print_bar
}

output_config_issues() {

  if [[ "$S85_SSH_VUL_CNT" -gt 0 || "$FILE_COUNTER" -gt 0 || "$INT_COUNT" -gt 0 || "$POST_COUNT" -gt 0 || "$MOD_DATA_COUNTER" -gt 0 || "$S40_WEAK_PERM_COUNTER" -gt 0 || "$S55_HISTORY_COUNTER" -gt 0 || "$S50_AUTH_ISSUES" -gt 0 || "$PASS_FILES_FOUND" -gt 0 || "$CERT_CNT" -gt 0 ]]; then
    print_output "[+] Found the following configuration issues:"
    if [[ "$S40_WEAK_PERM_COUNTER" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$S40_WEAK_PERM_COUNTER$GREEN areas with weak permissions.")")"
    fi
    if [[ "$S55_HISTORY_COUNTER" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$S55_HISTORY_COUNTER$GREEN history files.")")"
    fi
    if [[ "$S50_AUTH_ISSUES" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$S50_AUTH_ISSUES$GREEN authentication issues.")")"
    fi
    if [[ "$S85_SSH_VUL_CNT" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$S85_SSH_VUL_CNT$GREEN SSHd issues.")")"
    fi
    if [[ "$PASS_FILES_FOUND" -ne 0 ]]; then
      print_output "$(indent "$(green "Found passwords or weak credential configuration - check log file for details.")")"
    fi
    if [[ "$CERT_CNT" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$CERT_OUT_CNT$GREEN outdated certificates in $ORANGE$CERT_CNT$GREEN certificates.")")"
    fi
    if [[ "$MOD_DATA_COUNTER" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$MOD_DATA_COUNTER$GREEN kernel modules with $ORANGE$KMOD_BAD$GREEN licensing issues.")")"
    fi
    if [[ "$FILE_COUNTER" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$FILE_COUNTER$GREEN not common Linux files with $ORANGE$FILE_COUNTER_ALL$GREEN files at all.")")"
    fi
    if [[ "$INT_COUNT" -gt 0 || "$POST_COUNT" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$INT_COUNT$GREEN interesting files and $ORANGE$POST_COUNT$GREEN files that could be useful for post-exploitation.")")"
    fi
    print_bar
  fi
}

output_binaries() {

  if [[ "${#BINARIES[@]}" -gt 0 ]]; then
    if [[ -f "$LOG_DIR"/"$S10_LOG" ]]; then
      CANARY=$(grep -c "No canary" "$LOG_DIR"/"$S10_LOG")
      RELRO=$(grep -c "No RELRO" "$LOG_DIR"/"$S10_LOG")
      NX=$(grep -c "NX disabled" "$LOG_DIR"/"$S10_LOG")
      PIE=$(grep -c "No PIE" "$LOG_DIR"/"$S10_LOG")
      STRIPPED=$(grep -c "No Symbols" "$LOG_DIR"/"$S10_LOG")
      BINS_CHECKED=$(grep -c "RELRO.*NX.*RPATH" "$LOG_DIR"/"$S10_LOG")
      # we have to remove the first line of the original output:
      (( BINS_CHECKED-- ))
    fi
  
    if [[ -n "$CANARY" ]]; then
      CAN_PER=$(bc -l <<< "$CANARY/($BINS_CHECKED/100)" 2>/dev/null)
      CAN_PER=$(printf "%.0f" "$CAN_PER" 2>/dev/null)
      print_output "[+] Found ""$ORANGE""$CANARY"" (""$CAN_PER""%)""$GREEN"" binaries without enabled stack canaries in $ORANGE""$BINS_CHECKED""$GREEN binaries."
    fi
    if [[ -n "$RELRO" ]]; then
      RELRO_PER=$(bc -l <<< "$RELRO/($BINS_CHECKED/100)" 2>/dev/null)
      RELRO_PER=$(printf "%.0f" "$RELRO_PER" 2>/dev/null)
      print_output "[+] Found ""$ORANGE""$RELRO"" (""$RELRO_PER""%)""$GREEN"" binaries without enabled RELRO in $ORANGE""$BINS_CHECKED""$GREEN binaries."
    fi
    if [[ -n "$NX" ]]; then
      NX_PER=$(bc -l <<< "$NX/($BINS_CHECKED/100)" 2>/dev/null)
      NX_PER=$(printf "%.0f" "$NX_PER" 2>/dev/null)
      print_output "[+] Found ""$ORANGE""$NX"" (""$NX_PER""%)""$GREEN"" binaries without enabled NX in $ORANGE""$BINS_CHECKED""$GREEN binaries."
    fi
    if [[ -n "$PIE" ]]; then
      PIE_PER=$(bc -l <<< "$PIE/($BINS_CHECKED/100)" 2>/dev/null)
      PIE_PER=$(printf "%.0f" "$PIE_PER" 2>/dev/null)
      print_output "[+] Found ""$ORANGE""$PIE"" (""$PIE_PER""%)""$GREEN"" binaries without enabled PIE in $ORANGE""$BINS_CHECKED""$GREEN binaries."
    fi
    if [[ -n "$STRIPPED" ]]; then
      STRIPPED_PER=$(bc -l <<< "$STRIPPED/($BINS_CHECKED/100)" 2>/dev/null)
      STRIPPED_PER=$(printf "%.0f" "$STRIPPED_PER" 2>/dev/null)
      print_output "[+] Found ""$ORANGE""$STRIPPED"" (""$STRIPPED_PER""%)""$GREEN"" stripped binaries without symbols in $ORANGE""$BINS_CHECKED""$GREEN binaries."
    fi
    print_bar
  fi

  # we use the logger from the s120 cwe checker module again:
  final_cwe_log "$TOTAL_CWE_CNT"

  if [[ "$STRCPY_CNT" -gt 0 ]]; then

    print_output "[+] Found ""$ORANGE""$STRCPY_CNT""$GREEN"" usages of strcpy in ""$ORANGE""${#BINARIES[@]}""$GREEN"" binaries.""$NC"
  fi

  FUNCTION="strcpy"
  FUNCTION1="system"
  
  if [[ "$(find "$LOG_DIR""/vul_func_checker/" -xdev -iname "vul_func_*_""$FUNCTION""-*.txt" | wc -l)" -gt 0 ]]; then
    readarray -t RESULTS < <( find "$LOG_DIR""/vul_func_checker/" -xdev -iname "vul_func_*_""$FUNCTION""-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_""$FUNCTION""-/  /" | sed "s/\.txt//" 2> /dev/null)
    readarray -t RESULTS1 < <( find "$LOG_DIR""/vul_func_checker/" -xdev -iname "vul_func_*_""$FUNCTION1""-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_""$FUNCTION1""-/  /" | sed "s/\.txt//" 2> /dev/null)

    if [[ "${#RESULTS[@]}" -gt 0 ]]; then
      print_output ""
      print_output "[+] ""$FUNCTION""/""$FUNCTION1"" - top 10 results:"
      i=0 
      for LINE in "${RESULTS[@]}" ; do
        SEARCH_TERM="$(echo "$LINE" | cut -d\  -f3)"
        F_COUNTER="$(echo "$LINE" | cut -d\  -f1)"
        SEARCH_TERM1="$(echo "${RESULTS1[$i]}" | cut -d\  -f3)"
        F_COUNTER1="$(echo "${RESULTS1[$i]}" | cut -d\  -f1)"
        if [[ -f "$BASE_LINUX_FILES" ]]; then
          # if we have the base linux config file we are checking it:
          if grep -q "^$SEARCH_TERM\$" "$BASE_LINUX_FILES" 2>/dev/null; then
            if grep -q "^$SEARCH_TERM1\$" "$BASE_LINUX_FILES" 2>/dev/null; then
              printf "${GREEN}\t%-5.5s : %-15.15s : common linux file: yes${NC}\t||\t${GREEN}%-5.5s : %-15.15s : common linux file: yes${NC}\n" "$F_COUNTER" "$SEARCH_TERM" "$F_COUNTER1" "$SEARCH_TERM1" | tee -a "$LOG_FILE"
            else
              printf "${GREEN}\t%-5.5s : %-15.15s : common linux file: yes${NC}\t||\t${ORANGE}%-5.5s : %-15.15s : common linux file: no${NC}\n" "$F_COUNTER" "$SEARCH_TERM" "$F_COUNTER1" "$SEARCH_TERM1" | tee -a "$LOG_FILE"
            fi  
          else
            if grep -q "^$SEARCH_TERM1\$" "$BASE_LINUX_FILES" 2>/dev/null; then
              printf "${ORANGE}\t%-5.5s : %-15.15s : common linux file: no${NC}\t\t||\t${GREEN}%-5.5s : %-15.15s : common linux file: yes${NC}\n" "$F_COUNTER" "$SEARCH_TERM" "$F_COUNTER1" "$SEARCH_TERM1" | tee -a "$LOG_FILE"
            else
              printf "${ORANGE}\t%-5.5s : %-15.15s : common linux file: no${NC}\t\t||\t${ORANGE}%-5.5s : %-15.15s : common linux file: no${NC}\n" "$F_COUNTER" "$SEARCH_TERM" "$F_COUNTER1" "$SEARCH_TERM1" | tee -a "$LOG_FILE"
            fi  
          fi  
        else
          printf "${ORANGE}\t%-5.5s : %-15.15s${NC}\t\t||\t${ORANGE}%-5.5s : %-15.15s${NC}\n" "$F_COUNTER" "$SEARCH_TERM" "$F_COUNTER1" "$SEARCH_TERM1" | tee -a "$LOG_FILE"
        fi  
        (( i++ ))
      done
    fi  
    print_bar
  fi 

}

output_cve_exploits() {

  if [[ "$S30_VUL_COUNTER" -gt 0 || "$CVE_COUNTER" -gt 0 || "$EXPLOIT_COUNTER" -gt 0 ]]; then

    print_output "[*] Identified the following software inventory, vulnerabilities and exploits:"
    print_output "$(grep " Found version details:" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" 2>/dev/null)"

    print_output ""
    if [[ "${#VERSIONS_CLEANED[@]}" -gt 0 ]]; then
      print_output "[+] Identified ""$ORANGE""${#VERSIONS_CLEANED[@]}""$GREEN"" software components with version details.\\n"
    fi
    if [[ "$S30_VUL_COUNTER" -gt 0 ]]; then
      print_output "[+] Found ""$ORANGE""$S30_VUL_COUNTER""$GREEN"" CVE vulnerabilities in ""$ORANGE""${#BINARIES[@]}""$GREEN"" executables (without version checking).""$NC"
    fi
    if [[ "$CVE_COUNTER" -gt 0 ]]; then
      print_output "[+] Confirmed ""$ORANGE""$CVE_COUNTER""$GREEN"" CVE entries."
      print_output "$(indent "$(green "Confirmed $RED$BOLD$HIGH_CVE_COUNTER$NC$GREEN High rated CVE entries.")")"
      print_output "$(indent "$(green "Confirmed $ORANGE$BOLD$MEDIUM_CVE_COUNTER$NC$GREEN Medium rated CVE entries.")")"
      print_output "$(indent "$(green "Confirmed $GREEN$BOLD$LOW_CVE_COUNTER$NC$GREEN Low rated CVE entries.")")"
    fi
    if [[ "$EXPLOIT_COUNTER" -gt 0 ]]; then
      print_output "$(indent "$(green "$MAGENTA$BOLD$EXPLOIT_COUNTER$NC$GREEN possible exploits available.")")"
    fi
    print_bar
  fi
}

get_data() {
  if [[ -f "$LOG_DIR"/"$P02_LOG" ]]; then
    ENTROPY=$(grep -a "Entropy" "$LOG_DIR"/"$P02_LOG" | cut -d= -f2)
  fi
  if [[ -f "$LOG_DIR"/"$P07_LOG" ]]; then
    PRE_ARCH=$(grep -a "Possible architecture details found" "$LOG_DIR"/"$P07_LOG" | cut -d: -f2)
  fi
  if [[ -f "$LOG_DIR"/"$S05_LOG" ]]; then
    FILE_ARR_COUNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S05_LOG" | cut -d: -f2)
    DETECTED_DIR=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S05_LOG" | cut -d: -f3)
  fi
  if [[ -f "$LOG_DIR"/"$S10_LOG" ]]; then
    STRCPY_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S10_LOG" | cut -d: -f2)
    ARCH=$(grep -a "\[\*\]\ Statistics1:" "$LOG_DIR"/"$S10_LOG" | cut -d: -f2)
  fi
  if [[ -f "$LOG_DIR"/"$S20_LOG" ]]; then
    S20_SHELL_VULNS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S20_LOG" | cut -d: -f2)
    S20_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S20_LOG" | cut -d: -f3)
  fi
  if [[ -f "$LOG_DIR"/"$S21_LOG" ]]; then
    S21_PY_VULNS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S21_LOG" | cut -d: -f2)
    S21_PY_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S21_LOG" | cut -d: -f3)
  fi
  if [[ -f "$LOG_DIR"/"$S22_LOG" ]]; then
    S22_PHP_VULNS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S22_LOG" | cut -d: -f2)
    S22_PHP_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S22_LOG" | cut -d: -f3)
  fi
  if [[ -f "$LOG_DIR"/"$S25_LOG" ]]; then
    MOD_DATA_COUNTER=$(grep -a "\[\*\]\ Statistics1:" "$LOG_DIR"/"$S25_LOG" | cut -d: -f2)
    KMOD_BAD=$(grep -a "\[\*\]\ Statistics1:" "$LOG_DIR"/"$S25_LOG" | cut -d: -f3)
  fi
  if [[ -f "$LOG_DIR"/"$S30_LOG" ]]; then
    S30_VUL_COUNTER=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S30_LOG" | cut -d: -f2)
  fi
  if [[ -f "$LOG_DIR"/"$S40_LOG" ]]; then
    S40_WEAK_PERM_COUNTER=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S40_LOG" | cut -d: -f2)
  fi
  if [[ -f "$LOG_DIR"/"$S45_LOG" ]]; then
    PASS_FILES_FOUND=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S45_LOG" | cut -d: -f2)
  fi
  if [[ -f "$LOG_DIR"/"$S50_LOG" ]]; then
    S50_AUTH_ISSUES=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S50_LOG" | cut -d: -f2)
  fi
  if [[ -f "$LOG_DIR"/"$S55_LOG" ]]; then
    S55_HISTORY_COUNTER=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S55_LOG" | cut -d: -f2)
  fi
  if [[ -f "$LOG_DIR"/"$S60_LOG" ]]; then
    CERT_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S60_LOG" | cut -d: -f2)
    CERT_OUT_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S60_LOG" | cut -d: -f3)
  fi
  if [[ -f "$LOG_DIR"/"$S85_LOG" ]]; then
    S85_SSH_VUL_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S85_LOG" | cut -d: -f2)
  fi
  if [[ -f "$LOG_DIR"/"$S95_LOG" ]]; then
    INT_COUNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S95_LOG" | cut -d: -f2)
    POST_COUNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S95_LOG" | cut -d: -f3)
  fi
  if [[ -f "$LOG_DIR"/"$S108_LOG" ]]; then
    FILE_COUNTER=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S108_LOG" | cut -d: -f2)
    FILE_COUNTER_ALL=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S108_LOG" | cut -d: -f3)
  fi
  if [[ -f "$LOG_DIR"/"$S110_LOG" ]]; then
    YARA_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S110_LOG" | cut -d: -f2)
  fi
  if [[ -f "$LOG_DIR"/"$S120_LOG" ]]; then
    export TOTAL_CWE_CNT
    TOTAL_CWE_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S120_LOG" | cut -d: -f2)
  fi
}

os_detector() {

  VERIFIED=0
  OSES=("kernel" "vxworks" "siprotec" "freebsd")

  #### The following check is based on the results of the aggregator:
  if [[ -f "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" ]]; then
    for OS_TO_CHECK in "${OSES[@]}"; do
      mapfile -t SYSTEM_VERSION < <(grep -i "Found version details:" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | grep -w "$OS_TO_CHECK" | cut -d: -f3 | sed -e 's/[[:blank:]]//g')
      if [[ "${#SYSTEM_VERSION[@]}" -gt 0 ]]; then
        if [[ "$OS_TO_CHECK" == "kernel" ]]; then
          SYSTEM="Linux"
        elif [[ "$OS_TO_CHECK" == "siprotec" ]]; then
          SYSTEM="SIPROTEC"
        elif [[ "$OS_TO_CHECK" == "vxworks" ]]; then
          SYSTEM="VxWorks"
        elif [[ "$OS_TO_CHECK" == "freebsd" ]]; then
          SYSTEM="FreeBSD"
        else
          SYSTEM="$OS_TO_CHECK"
        fi
        # version detected -> verified linux
        for SYSTEM_VER in "${SYSTEM_VERSION[@]}"; do
          SYSTEM="$SYSTEM"" / v$SYSTEM_VER"
          VERIFIED=1
        done
        if [[ $VERIFIED -eq 1 ]]; then
          print_os
        fi
      fi
    done
  fi

  #### The following check is needed if the aggreagator has failed till now
  if [[ $VERIFIED -eq 0 ]]; then
    # the OS was not verified in the first step (but we can try to verify it now with more data of other modules)
    mapfile -t OS_DETECT < <(grep "\ verified.*operating\ system\ detected" "$LOG_DIR"/"$P07_LOG" 2>/dev/null | awk '{print $1 " - #" $3}' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" )
    if [[ "${#OS_DETECT[@]}" -gt 0 ]]; then
      for SYSTEM in "${OS_DETECT[@]}"; do
        VERIFIED=1
        print_os
      done
    fi

    mapfile -t OS_DETECT < <(grep "\ detected" "$LOG_DIR"/"$P07_LOG" 2>/dev/null | awk '{print $1 " - #" $3}' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" )

    if [[ "${#OS_DETECT[@]}" -gt 0 && "$VERIFIED" -eq 0 ]]; then
      for SYSTEM in "${OS_DETECT[@]}"; do
        VERIFIED=0
        print_os
      done
    fi
  fi

  #### The following check is just in place if something went wrong
  if [[ $VERIFIED -eq 0 ]]; then
    # usually the results of the kernel module checker are already used in f19 (first os check)
    # but just in case something went wrong we use it now
    os_kernel_module_detect
    if [[ $VERIFIED -eq 1 ]]; then
      print_os
    fi
  fi

}

os_kernel_module_detect() {

  if [[ -f "$LOG_DIR"/"$S25_LOG" ]]; then
    mapfile -t KERNELV < <(grep "Statistics:" "$LOG_DIR"/"$S25_LOG" | cut -d: -f2 | sort -u)
    if [[ "${#KERNELV[@]}" -ne 0 ]]; then
      # if we have found a kernel it is a Linux system:
      LINUX_VERSIONS="Linux"
      for KV in "${KERNELV[@]}"; do
        LINUX_VERSIONS="$LINUX_VERSIONS"" / v$KV"
        VERIFIED=1
      done
      SYSTEM="$LINUX_VERSIONS"
    fi
  fi
}

print_os() {
  if [[ $VERIFIED -eq 1 ]]; then
    print_output "[+] Operating system detected (""$ORANGE""verified$GREEN): $ORANGE$SYSTEM"
  else
    print_output "[+] Possible operating system detected (""$ORANGE""unverified$GREEN): $ORANGE$SYSTEM"
  fi
}

