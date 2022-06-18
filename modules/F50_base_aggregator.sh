#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2021-2022 Siemens Energy AG
# Copyright 2021-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Generates an overview over all modules.
#shellcheck disable=SC2153

F50_base_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final aggregator"

  CVE_AGGREGATOR_LOG="f20_vul_aggregator.txt"
  F20_EXPLOITS_LOG="$LOG_DIR"/f20_vul_aggregator/exploits-overview.txt
  P02_LOG="p02_firmware_bin_file_check.txt"
  S03_LOG="s03_firmware_bin_base_analyzer.txt"
  S05_LOG="s05_firmware_details.txt"
  S06_LOG="s06_distribution_identification.txt"
  S12_LOG="s12_binary_protection.txt"
  S13_LOG="s13_weak_func_check.txt"
  S14_LOG="s14_weak_func_radare_check.txt"
  S20_LOG="s20_shell_check.txt"
  S21_LOG="s21_python_check.txt"
  S22_LOG="s22_php_check.txt"
  S25_LOG="s25_kernel_check.txt"
  S30_LOG="s30_version_vulnerability_check.txt"
  S40_LOG="s40_weak_perm_check.txt"
  S45_LOG="s45_pass_file_check.txt"
  S50_LOG="s50_authentication_check.txt"
  S55_LOG="s55_history_file_check.txt"
  S60_LOG="s60_cert_file_check.txt"
  S85_LOG="s85_ssh_check.txt"
  S95_LOG="s95_interesting_binaries_check.txt"
  S107_LOG="s107_deep_password_search.txt"
  S108_LOG="s108_stacs_password_search.txt"
  S110_LOG="s110_yara_check.txt"
  S120_LOG="s120_cwe_checker.txt"
  #L10_LOG="l10_system_emulator.txt"
  L15_LOG="l15_emulated_checks_init.txt"
  L20_LOG="l20_snmp_checks.txt"
  L25_LOG="l25_web_checks.txt"
  L30_LOG="l30_routersploit.txt"
  SYS_EMU_RESULTS="$LOG_DIR"/emulator_online_results.log

  CSV_LOG_FILE="$LOG_DIR""/""$(basename -s .txt "$LOG_FILE")".csv

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
    print_output "[+] Tested Firmware vendor: ""$ORANGE""$FW_VENDOR""$NC"
    echo "Firmware_vendor;\"$FW_VENDOR\"" >> "$CSV_LOG_FILE"
  fi  
  if [[ -n "$FW_VERSION" ]]; then
    print_output "[+] Tested Firmware version: ""$ORANGE""$FW_VERSION""$NC"
    echo "Firmware_version;\"$FW_VERSION\"" >> "$CSV_LOG_FILE"
  fi  
  if [[ -n "$FW_DEVICE" ]]; then
    print_output "[+] Tested Firmware from device: ""$ORANGE""$FW_DEVICE""$NC"
    echo "Device;\"$FW_DEVICE\"" >> "$CSV_LOG_FILE"
  fi  
  if [[ -n "$FW_NOTES" ]]; then
    print_output "[+] Additional notes: ""$ORANGE""$FW_NOTES""$NC"
    echo "FW_notes;\"$FW_NOTES\"" >> "$CSV_LOG_FILE"
  fi  

  if [[ "$IN_DOCKER" -eq 1 ]] && [[ -f "$TMP_DIR"/fw_name.log ]] && [[ -f "$TMP_DIR"/emba_command.log ]]; then
    # we need to rewrite this firmware path to the original path
    FW_PATH_ORIG="$(cat "$TMP_DIR"/fw_name.log)"
    EMBA_COMMAND_ORIG="$(cat "$TMP_DIR"/emba_command.log)"
    print_output "[+] Tested firmware:""$ORANGE"" ""$FW_PATH_ORIG""$NC"
    echo "FW_path;\"$FW_PATH_ORIG\"" >> "$CSV_LOG_FILE"
    print_output "[+] Emba start command:""$ORANGE"" ""$EMBA_COMMAND_ORIG""$NC"
    echo "emba_command;\"$EMBA_COMMAND_ORIG\"" >> "$CSV_LOG_FILE"
  else
    print_output "[+] Tested firmware:""$ORANGE"" ""$FIRMWARE_PATH""$NC"
    echo "FW_path;\"$FIRMWARE_PATH\"" >> "$CSV_LOG_FILE"
    print_output "[+] Emba start command:""$ORANGE"" ""$EMBA_COMMAND""$NC"
    echo "emba_command;\"$EMBA_COMMAND\"" >> "$CSV_LOG_FILE"
  fi

  if [[ -n "$ARCH" ]]; then
    if [[ -n "$D_END" ]]; then
      print_output "[+] Detected architecture and endianness (""$ORANGE""verified$GREEN):""$ORANGE"" ""$ARCH"" / ""$D_END""$NC"
    else
      print_output "[+] Detected architecture (""$ORANGE""verified$GREEN):""$ORANGE"" ""$ARCH""$NC"
    fi
    write_link "p99"
    echo "architecture_verified;\"$ARCH\"" >> "$CSV_LOG_FILE"
  elif [[ -f "$LOG_DIR"/"$S03_LOG" ]]; then
    if [[ -n "$PRE_ARCH" ]]; then
      print_output "[+] Detected architecture:""$ORANGE"" ""$PRE_ARCH""$NC"
      write_link "p99"
      echo "architecture_verified;\"unknown\"" >> "$CSV_LOG_FILE"
      echo "architecture_unverified;\"$PRE_ARCH\"" >> "$CSV_LOG_FILE"
    fi
  else
    echo "architecture_verified;\"unknown\"" >> "$CSV_LOG_FILE"
  fi
  os_detector
  distribution_detector
  print_bar
}

output_details() {

  local DATA=0
  if [[ "${FILE_ARR_COUNT:-0}" -gt 0 ]]; then
    print_output "[+] ""$ORANGE""$FILE_ARR_COUNT""$GREEN"" files and ""$ORANGE""$DETECTED_DIR"" ""$GREEN""directories detected."
    if [[ -f "$LOG_DIR"/"$S05_LOG" ]]; then
      write_link "s05"
    else
      write_link "p20"
    fi
    echo "files;\"$FILE_ARR_COUNT\"" >> "$CSV_LOG_FILE"
    echo "directories;\"$DETECTED_DIR\"" >> "$CSV_LOG_FILE"
    DATA=1
  fi
  ENTROPY_PIC=$(find "$LOG_DIR" -xdev -type f -iname "*_entropy.png" 2> /dev/null)
  if [[ -n "$ENTROPY" ]]; then
    print_output "[+] Entropy analysis of binary firmware is: ""$ORANGE""$ENTROPY"
    write_link "p02"
    echo "entropy_value;\"$ENTROPY\"" >> "$CSV_LOG_FILE"
    DATA=1
  fi
  if [[ -n "$ENTROPY_PIC" ]]; then
    print_output "[+] Entropy analysis of binary firmware is available:""$ORANGE"" ""$ENTROPY_PIC"
    write_link "$ENTROPY_PIC"
    DATA=1
  fi

  if [[ "${S20_SHELL_VULNS:-0}" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$S20_SHELL_VULNS"" issues""$GREEN"" in ""$ORANGE""$S20_SCRIPTS""$GREEN"" shell scripts.""$NC"
    write_link "s20"
    echo "shell_scripts;\"$S20_SCRIPTS\"" >> "$CSV_LOG_FILE"
    echo "shell_script_vulns;\"$S20_SHELL_VULNS\"" >> "$CSV_LOG_FILE"
    DATA=1
  fi
  if [[ "${S21_PY_VULNS:-0}" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$S21_PY_VULNS"" vulnerabilities""$GREEN"" in ""$ORANGE""$S21_PY_SCRIPTS""$GREEN"" python files.""$NC"
    write_link "s21"
    echo "python_scripts;\"$S21_PY_SCRIPTS\"" >> "$CSV_LOG_FILE"
    echo "python_vulns;\"$S21_PY_VULNS\"" >> "$CSV_LOG_FILE"
    DATA=1
  fi
  if [[ "${S22_PHP_VULNS:-0}" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$S22_PHP_VULNS"" vulnerabilities""$GREEN"" in ""$ORANGE""$S22_PHP_SCRIPTS""$GREEN"" php files.""$NC"
    write_link "s22"
    echo "php_scripts;\"$S22_PHP_SCRIPTS\"" >> "$CSV_LOG_FILE"
    echo "php_vulns;\"$S22_PHP_VULNS\"" >> "$CSV_LOG_FILE"
  fi
  if [[ "${S22_PHP_INI_ISSUES:-0}" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$S22_PHP_INI_ISSUES"" issues""$GREEN"" in ""$ORANGE""$S22_PHP_INI_CONFIGS""$GREEN"" php configuration file.""$NC"
    write_link "s22"
    echo "php_ini_issues;\"$S22_PHP_INI_ISSUES\"" >> "$CSV_LOG_FILE"
    echo "php_ini_configs;\"$S22_PHP_INI_CONFIGS\"" >> "$CSV_LOG_FILE"
    DATA=1
  fi
  if [[ "${YARA_CNT:-0}" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$YARA_CNT""$GREEN"" yara rule matches in $ORANGE${#FILE_ARR[@]}$GREEN files.""$NC"
    write_link "s110"
    echo "yara_rules_match;\"$YARA_CNT\"" >> "$CSV_LOG_FILE"
    DATA=1
  fi
  EMUL=$(grep -c "Version information found" "$LOG_DIR"/s116_qemu_version_detection.txt 2>/dev/null || true)
  if [[ "${EMUL:-0}" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$EMUL""$GREEN"" successful emulated processes $ORANGE(${GREEN}user mode emulation$ORANGE)$GREEN.""$NC"
    write_link "s116"
    echo "user_emulation_state;\"$EMUL\"" >> "$CSV_LOG_FILE"
    DATA=1
  fi

  if [[ "${BOOTED:-0}" -gt 0 ]] || [[ "${IP_ADDR:-0}" -gt 0 ]] || [[ "${ICMP:-0}" -gt 0 ]] || [[ "${TCP_0:-0}" -gt 0 ]] || [[ "${TCP:-0}" -gt 0 ]]; then

    STATE="$ORANGE(""$GREEN""booted"
    EMU_STATE="booted"
    if [[ "$IP_ADDR" -gt 0 ]]; then
      STATE="$STATE""$ORANGE / ""$GREEN""IP address detected (mode: $ORANGE$MODE$NC)"
      EMU_STATE="$EMU_STATE"";IP_DET"
    fi
    if [[ "${ICMP:-0}" -gt 0 || "${TCP_0:-0}" -gt 0 ]]; then
      STATE="$STATE""$ORANGE / ""$GREEN""ICMP"
      EMU_STATE="$EMU_STATE"";ICMP"
    fi
    if [[ "${TCP:-0}" -gt 0 ]]; then
      STATE="$STATE""$ORANGE / ""$GREEN""NMAP"
      EMU_STATE="$EMU_STATE"";NMAP"
    fi
    if [[ "${SNMP_UP:-0}" -gt 0 ]]; then
      STATE="$STATE""$ORANGE / ""$GREEN""SNMP"
      EMU_STATE="$EMU_STATE"";SNMP"
    fi
    if [[ "${WEB_UP:-0}" -gt 0 ]]; then
      STATE="$STATE""$ORANGE / ""$GREEN""WEB"
      EMU_STATE="$EMU_STATE"";WEB"
    fi
    if [[ "${ROUTERSPLOIT_VULN:-0}" -gt 0 ]]; then
      STATE="$STATE""$ORANGE / ""$GREEN""Routersploit"
      EMU_STATE="$EMU_STATE"";Routersploit"
    fi
    STATE="$STATE$ORANGE"")$NC"

    print_output "[+] System emulation was successful $STATE" "" "l10"
    echo "system_emulation_state;\"$EMU_STATE\"" >> "$CSV_LOG_FILE"
    DATA=1
  fi

  if [[ $DATA -eq 1 ]]; then
    print_bar
  fi
}

output_config_issues() {

  local DATA=0
  if [[ "${PW_COUNTER:-0}" -gt 0 || "${S85_SSH_VUL_CNT:-0}" -gt 0 || "${STACS_HASHES:-0}" -gt 0 || "${INT_COUNT:-0}" -gt 0 || "${POST_COUNT:-0}" -gt 0 || "${MOD_DATA_COUNTER:-0}" -gt 0 || "${S40_WEAK_PERM_COUNTER:-0}" -gt 0 || "${S55_HISTORY_COUNTER:-0}" -gt 0 || "${S50_AUTH_ISSUES:-0}" -gt 0 || "${PASS_FILES_FOUND:-0}" -gt 0 || "${CERT_CNT:-0}" -gt 0 ]]; then
    print_output "[+] Found the following configuration issues:"
    if [[ "${S40_WEAK_PERM_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$S40_WEAK_PERM_COUNTER$GREEN areas with weak permissions.")")"
      write_link "s40"
      echo "weak_perm_count;\"$S40_WEAK_PERM_COUNTER\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${S55_HISTORY_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$S55_HISTORY_COUNTER$GREEN history files.")")"
      write_link "s55"
      echo "history_file_count;\"$S55_HISTORY_COUNTER\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${S50_AUTH_ISSUES:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$S50_AUTH_ISSUES$GREEN authentication issues.")")"
      write_link "s50"
      echo "auth_issues;\"$S50_AUTH_ISSUES\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${S85_SSH_VUL_CNT:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$S85_SSH_VUL_CNT$GREEN SSHd issues.")")"
      write_link "s85"
      echo "ssh_issues;\"$S85_SSH_VUL_CNT\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${PW_COUNTER:-0}" -gt 0 || "${STACS_HASHES:-0}" -gt 0 ]]; then
      if [[ "${PW_COUNTER:-0}" -gt 0 ]]; then
        print_output "$(indent "$(green "Found $ORANGE$PW_COUNTER$GREEN password related details.")")"
        write_link "s107"
        echo "password_hashes;\"$PW_COUNTER\"" >> "$CSV_LOG_FILE"
      fi
      if [[ "${STACS_HASHES:-0}" -gt 0 ]]; then
        print_output "$(indent "$(green "Found $ORANGE$STACS_HASHES$GREEN password related details via STACS.")")"
        write_link "s108"
        echo "password_hashes_stacs;\"$STACS_HASHES\"" >> "$CSV_LOG_FILE"
      fi
      DATA=1
    fi
    if [[ "${CERT_CNT:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$CERT_OUT_CNT$GREEN outdated certificates in $ORANGE$CERT_CNT$GREEN certificates.")")"
      write_link "s60"
      echo "certificates;\"$CERT_CNT\"" >> "$CSV_LOG_FILE"
      echo "certificates_outdated;\"$CERT_OUT_CNT\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${MOD_DATA_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE$MOD_DATA_COUNTER$GREEN kernel modules with $ORANGE$KMOD_BAD$GREEN licensing issues.")")"
      write_link "s25#kernel_modules"
      echo "kernel_modules;\"$MOD_DATA_COUNTER\"" >> "$CSV_LOG_FILE"
      echo "kernel_modules_lic;\"$KMOD_BAD\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${INT_COUNT:-0}" -gt 0 || "${POST_COUNT:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found $ORANGE${INT_COUNT}$GREEN interesting files and $ORANGE${POST_COUNT:-0}$GREEN files that could be useful for post-exploitation.")")"
      write_link "s95"
      echo "interesting_files;\"${INT_COUNT:-0}\"" >> "$CSV_LOG_FILE"
      echo "post_files;\"${POST_COUNT:-0}\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
  fi
  if [[ $DATA -eq 1 ]]; then
    print_bar
  fi
}

output_binaries() {

  local DATA=0
  if [[ -v BINARIES[@] ]]; then
    if [[ -f "$LOG_DIR"/"$S12_LOG" ]]; then
      CANARY=$(grep -c "No canary" "$LOG_DIR"/"$S12_LOG" || true)
      RELRO=$(grep -c "No RELRO" "$LOG_DIR"/"$S12_LOG" || true)
      NX=$(grep -c "NX disabled" "$LOG_DIR"/"$S12_LOG" || true)
      PIE=$(grep -c "No PIE" "$LOG_DIR"/"$S12_LOG" || true)
      STRIPPED=$(grep -c "No Symbols" "$LOG_DIR"/"$S12_LOG" || true)
      BINS_CHECKED=$(grep -c "RELRO.*NX.*RPATH" "$LOG_DIR"/"$S12_LOG" || true)
      # we have to remove the first line of the original output:
      (( BINS_CHECKED-- ))
    fi
  
    if [[ "${CANARY:-0}" -gt 0 ]]; then
      CAN_PER=$(bc -l <<< "$CANARY/($BINS_CHECKED/100)" 2>/dev/null)
      CAN_PER=$(printf "%.0f" "$CAN_PER" 2>/dev/null || true)
      print_output "[+] Found ""$ORANGE""$CANARY"" (""$CAN_PER""%)""$GREEN"" binaries without enabled stack canaries in $ORANGE""$BINS_CHECKED""$GREEN binaries."
      write_link "s12"
      echo "canary;\"$CANARY\"" >> "$CSV_LOG_FILE"
      echo "canary_per;\"$CAN_PER\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${RELRO:-0}" -gt 0 ]]; then
      RELRO_PER=$(bc -l <<< "$RELRO/($BINS_CHECKED/100)" 2>/dev/null)
      RELRO_PER=$(printf "%.0f" "$RELRO_PER" 2>/dev/null || true)
      print_output "[+] Found ""$ORANGE""$RELRO"" (""$RELRO_PER""%)""$GREEN"" binaries without enabled RELRO in $ORANGE""$BINS_CHECKED""$GREEN binaries."
      write_link "s12"
      echo "relro;\"$RELRO\"" >> "$CSV_LOG_FILE"
      echo "relro_per;\"$RELRO_PER\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${NX:-0}" -gt 0 ]]; then
      NX_PER=$(bc -l <<< "$NX/($BINS_CHECKED/100)" 2>/dev/null)
      NX_PER=$(printf "%.0f" "$NX_PER" 2>/dev/null || true)
      print_output "[+] Found ""$ORANGE""$NX"" (""$NX_PER""%)""$GREEN"" binaries without enabled NX in $ORANGE""$BINS_CHECKED""$GREEN binaries."
      write_link "s12"
      echo "nx;\"$NX\"" >> "$CSV_LOG_FILE"
      echo "nx_per;\"$NX_PER\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${PIE:-0}" -gt 0 ]]; then
      PIE_PER=$(bc -l <<< "$PIE/($BINS_CHECKED/100)" 2>/dev/null)
      PIE_PER=$(printf "%.0f" "$PIE_PER" 2>/dev/null || true)
      print_output "[+] Found ""$ORANGE""$PIE"" (""$PIE_PER""%)""$GREEN"" binaries without enabled PIE in $ORANGE""$BINS_CHECKED""$GREEN binaries."
      write_link "s12"
      echo "pie;\"$PIE\"" >> "$CSV_LOG_FILE"
      echo "pie_per;\"$PIE_PER\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${STRIPPED:-0}" -gt 0 ]]; then
      STRIPPED_PER=$(bc -l <<< "$STRIPPED/($BINS_CHECKED/100)" 2>/dev/null)
      STRIPPED_PER=$(printf "%.0f" "$STRIPPED_PER" 2>/dev/null || true)
      print_output "[+] Found ""$ORANGE""$STRIPPED"" (""$STRIPPED_PER""%)""$GREEN"" stripped binaries without symbols in $ORANGE""$BINS_CHECKED""$GREEN binaries."
      write_link "s12"
      echo "stripped;\"$STRIPPED\"" >> "$CSV_LOG_FILE"
      echo "stripped_per;\"$STRIPPED_PER\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${BINS_CHECKED:-0}" -gt 0 ]]; then
      echo "bins_checked;\"$BINS_CHECKED\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
  fi
  if [[ $DATA -eq 1 ]]; then
    print_bar
  fi

  cwe_logging

  if [[ "${STRCPY_CNT:-0}" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""$STRCPY_CNT""$GREEN"" usages of strcpy in ""$ORANGE""${#BINARIES[@]}""$GREEN"" binaries.""$NC"
    if [[ $(find "$LOG_DIR""/s13_weak_func_check/" -type f 2>/dev/null | wc -l) -gt $(find "$LOG_DIR""/s14_weak_func_radare_check/" -type f 2>/dev/null | wc -l) ]]; then
      write_link "s13"
    else
      write_link "s14"
    fi
    print_output ""
    echo "strcpy;\"$STRCPY_CNT\"" >> "$CSV_LOG_FILE"
  fi

  local DATA=0

  if [[ "${STRCPY_CNT:-0}" -gt 0 ]] && [[ -d "$LOG_DIR""/s13_weak_func_check/" || -d "$LOG_DIR""/s14_weak_func_radare_check/" ]] ; then

    # color codes for printf
    RED_="$(tput setaf 1)"
    GREEN_="$(tput setaf 2)"
    ORANGE_="$(tput setaf 3)"
    NC_="$(tput sgr0)"

    readarray -t RESULTS_STRCPY < <( find "$LOG_DIR"/s1[34]*/ -xdev -iname "vul_func_*_strcpy-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_strcpy-/ strcpy /" | sed "s/\.txt//" 2> /dev/null)
    readarray -t RESULTS_SYSTEM < <( find "$LOG_DIR"/s1[34]*/ -xdev -iname "vul_func_*_system-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_system-/ system /" | sed "s/\.txt//" 2> /dev/null)

    #strcpy:
    if [[ "${#RESULTS_STRCPY[@]}" -gt 0 ]]; then
      print_output ""
      print_output "[+] STRCPY - top 10 results:"
      if [[ -d "$LOG_DIR""/s13_weak_func_check/" ]]; then
        write_link "s13#strcpysummary"
      else
        write_link "s14#strcpysummary"
      fi
      DATA=1
      for LINE in "${RESULTS_STRCPY[@]}" ; do
        binary_fct_output "$LINE"
        echo "strcpy_bin;\"$BINARY\";\"$F_COUNTER\"" >> "$CSV_LOG_FILE"
      done
      print_output "$NC"
    fi

    #system:
    if [[ "${#RESULTS_SYSTEM[@]}" -gt 0 ]]; then
      print_output ""
      print_output "[+] SYSTEM - top 10 results:"
      if [[ -d "$LOG_DIR""/s13_weak_func_check/" ]]; then
        write_link "s13#systemsummary"
      else
        write_link "s14#systemsummary"
      fi
      DATA=1
      for LINE in "${RESULTS_SYSTEM[@]}" ; do
        binary_fct_output "$LINE"
        echo "system_bin;\"$BINARY\";\"$F_COUNTER\"" >> "$CSV_LOG_FILE"
      done
      print_output "$NC"
    fi
  fi
  if [[ $DATA -eq 1 ]]; then
    print_bar
  fi
}

binary_fct_output() {
  BINARY_DETAILS="$1"
  F_COUNTER="$(echo "$BINARY_DETAILS" | cut -d\  -f1)"
  FCT="$(echo "$BINARY_DETAILS" | cut -d\  -f2)"
  BINARY="$(echo "$BINARY_DETAILS" | cut -d\  -f3)"

  if grep -q "$BINARY" "$LOG_DIR"/"$S12_LOG" 2>/dev/null; then
    if grep "$BINARY" "$LOG_DIR"/"$S12_LOG" | grep -o -q "No RELRO"; then
      RELRO="$RED_""No RELRO$NC_"
    else
      RELRO="$GREEN_""RELRO   $NC_"
    fi
    if grep "$BINARY" "$LOG_DIR"/"$S12_LOG" | grep -o -q "No canary found"; then
      CANARY="$RED_""No Canary$NC_"
    else
      CANARY="$GREEN_""Canary   $NC_"
    fi
    if grep "$BINARY" "$LOG_DIR"/"$S12_LOG" | grep -o -q "NX disabled"; then
      NX="$RED_""NX disabled$NC_"
    else
      NX="$GREEN_""NX enabled $NC_"
    fi
    if grep "$BINARY" "$LOG_DIR"/"$S12_LOG" | grep -o -q "No Symbols"; then
      SYMBOLS="$GREEN_""No Symbols$NC_"
    else
      SYMBOLS="$RED_""Symbols   $NC_"
    fi
  else
    RELRO="$ORANGE_""RELRO unknown$NC_"
    NX="$ORANGE_""NX unknown$NC_"
    CANARY="$ORANGE_""CANARY unknown$NC_"
    SYMBOLS="$ORANGE_""Symbols unknown$NC_"
  fi

  # networking
  if grep -q "/${BINARY} " "$LOG_DIR"/s1[34]_*.csv 2>/dev/null; then
    if grep "/${BINARY} " "$LOG_DIR"/s1[34]_*.csv | cut -d\; -f5 | sort -u | grep -o -q "no"; then
      NETWORKING="$GREEN_""No Networking     $NC_"
    else
      NETWORKING="$RED_""Networking        $NC_"
    fi
  else
    NETWORKING="$ORANGE_""Networking unknown$NC_"
  fi


  if [[ -f "$BASE_LINUX_FILES" ]]; then
    local FCT_LINK=""
    # if we have the base linux config file we are checking it:
    if grep -q "^$BINARY" "$BASE_LINUX_FILES" 2>/dev/null; then
      FCT_LINK=$(find "$LOG_DIR"/s1[34]_weak_func_*check/ -name "vul_func_*$FCT-$BINARY*.txt" | sort -u | head -1 || true)
      printf "$GREEN_\t%-5.5s : %-15.15s : common linux file: yes  |  %-14.14s  |  %-15.15s  |  %-16.16s  |  %-15.15s  |  %-20.20s  |$NC\n" "$F_COUNTER" "$BINARY" "$RELRO" "$CANARY" "$NX" "$SYMBOLS" "$NETWORKING" | tee -a "$LOG_FILE"
      write_link "$FCT_LINK"
    else
      FCT_LINK=$(find "$LOG_DIR"/s1[34]_weak_func_*check/ -name "vul_func_*$FCT-$BINARY*.txt" | sort -u | head -1 || true)
      printf "$ORANGE_\t%-5.5s : %-15.15s : common linux file: no   |  %-14.14s  |  %-15.15s  |  %-16.16s  |  %-15.15s  |  %-20.20s  |$NC\n" "$F_COUNTER" "$BINARY" "$RELRO" "$CANARY" "$NX" "$SYMBOLS" "$NETWORKING"| tee -a "$LOG_FILE"
      write_link "$FCT_LINK"
    fi
  else
    FCT_LINK=$(find "$LOG_DIR"/s1[34]_weak_func_check/ -name "vul_func_*$FCT-$BINARY*.txt" | sort -u | head -1 || true)
    printf "$ORANGE_\t%-5.5s : %-15.15s : common linux file: unknown |  %-14.14s  |  %-15.15s  |  %-16.16s  |  %-15.15s  |  %-20.20s  |$NC\n" "$F_COUNTER" "$BINARY" "$RELRO" "$CANARY" "$NX" "$SYMBOLS" "$NETWORKING" | tee -a "$LOG_FILE"
    write_link "$FCT_LINK"
  fi
}

output_cve_exploits() {

  local DATA=0
  if [[ "${S30_VUL_COUNTER:-0}" -gt 0 || "${CVE_COUNTER:-0}" -gt 0 || "${EXPLOIT_COUNTER:-0}" -gt 0 || -v VERSIONS_AGGREGATED[@] ]]; then
    if [[ "${CVE_COUNTER:-0}" -gt 0 || "${EXPLOIT_COUNTER:-0}" -gt 0 || -v VERSIONS_AGGREGATED[@] ]]; then
      print_output "[*] Identified the following software inventory, vulnerabilities and exploits:"
      write_link "f20#collectcveandexploitdetails"

      # run over F20_summary.txt and add links - need to do this here and not in f20 as there bites us the threading mode
      while read -r OVERVIEW_LINE; do
        BINARY_="$(echo "$OVERVIEW_LINE" | cut -d: -f2 | tr -d '[:blank:]')"
        print_output "$OVERVIEW_LINE"
        write_link "f20#cve_$BINARY_"
      done < "$LOG_DIR/f20_vul_aggregator/F20_summary.txt"
      print_output ""
    fi

    if [[ -v VERSIONS_AGGREGATED[@] ]]; then
      print_output "[+] Identified ""$ORANGE""${#VERSIONS_AGGREGATED[@]}""$GREEN"" software components with version details.\\n"
      write_link "f20#softwareinventoryinitialoverview"
      echo "versions_identified;\"${#VERSIONS_AGGREGATED[@]}\"" >> "$CSV_LOG_FILE"
      DATA=1
    fi
    if [[ "${S30_VUL_COUNTER:-0}" -gt 0 ]]; then
      print_output "[+] Found ""$ORANGE""$S30_VUL_COUNTER""$GREEN"" CVE vulnerabilities in ""$ORANGE""${#BINARIES[@]}""$GREEN"" executables (without version checking).""$NC"
      write_link "s30"
      DATA=1
    fi
    if [[ "${CVE_COUNTER:-0}" -gt 0 ]]; then
      echo -e "\n" >> "$LOG_FILE"
      print_output "[+] Identified ""$ORANGE""$CVE_COUNTER""$GREEN"" CVE entries."
      write_link "f20#collectcveandexploitdetails"
      print_output "$(indent "$(green "Identified $RED$BOLD$HIGH_CVE_COUNTER$NC$GREEN High rated CVE entries / Exploits: $ORANGE${EXPLOIT_HIGH_COUNT:0}$NC")")"
      print_output "$(indent "$(green "Identified $ORANGE$BOLD$MEDIUM_CVE_COUNTER$NC$GREEN Medium rated CVE entries / Exploits: $ORANGE${EXPLOIT_MEDIUM_COUNT:0}$NC")")"
      print_output "$(indent "$(green "Identified $GREEN$BOLD$LOW_CVE_COUNTER$NC$GREEN Low rated CVE entries /Exploits: $ORANGE${EXPLOIT_LOW_COUNT:0}$NC")")"
      # shellcheck disable=SC2129
      echo "cve_high;\"$HIGH_CVE_COUNTER\"" >> "$CSV_LOG_FILE"
      echo "cve_medium;\"$MEDIUM_CVE_COUNTER\"" >> "$CSV_LOG_FILE"
      echo "cve_low;\"$LOW_CVE_COUNTER\"" >> "$CSV_LOG_FILE"
      DATA=1
    elif [[ "$CVE_SEARCH" -ne 1 ]]; then
      print_output ""
      print_output "[!] WARNING: CVE-Search was not performed. The vulnerability results should be taken with caution!"
      print_output ""
    fi
    if [[ "${EXPLOIT_COUNTER:-0}" -gt 0 ]]; then
      echo "exploits;\"$EXPLOIT_COUNTER\"" >> "$CSV_LOG_FILE"
      if [[ $MSF_MODULE_CNT -gt 0 ]]; then
        print_output "$(indent "$(green "$MAGENTA$BOLD$EXPLOIT_COUNTER$NC$GREEN possible exploits available ($MAGENTA$MSF_MODULE_CNT$GREEN Metasploit modules).")")"
        write_link "f20#minimalreportofexploitsandcves"
        echo "metasploit_modules;\"$MSF_MODULE_CNT\"" >> "$CSV_LOG_FILE"
      else
        print_output "$(indent "$(green "$MAGENTA$BOLD$EXPLOIT_COUNTER$NC$GREEN possible exploits available.")")"
        write_link "f20#minimalreportofexploitsandcves"
      fi
      if [[ "$REMOTE_EXPLOIT_CNT" -gt 0 || "$LOCAL_EXPLOIT_CNT" -gt 0 || "$DOS_EXPLOIT_CNT" -gt 0 || "$GITHUB_EXPLOIT_CNT" -gt 0 || "$KNOWN_EXPLOITED_COUNTER" -gt 0 ]]; then
        print_output "$(indent "$(green "Remote exploits: $MAGENTA$BOLD$REMOTE_EXPLOIT_CNT$NC$GREEN / Local exploits: $MAGENTA$BOLD$LOCAL_EXPLOIT_CNT$NC$GREEN / DoS exploits: $MAGENTA$BOLD$DOS_EXPLOIT_CNT$NC$GREEN / Github PoCs: $MAGENTA$BOLD$GITHUB_EXPLOIT_CNT$NC$GREEN / Known exploited vulnerabilities: $MAGENTA$BOLD$KNOWN_EXPLOITED_COUNTER$NC")")"
        write_csv_log "remote_exploits" "$REMOTE_EXPLOIT_CNT"
        write_csv_log "local_exploits" "$LOCAL_EXPLOIT_CNT"
        write_csv_log "dos_exploits" "$DOS_EXPLOIT_CNT"
        write_csv_log "github_exploits" "$GITHUB_EXPLOIT_CNT"
        write_csv_log "known_exploited" "$KNOWN_EXPLOITED_COUNTER"
      fi
      # we report only software components with exploits to csv:
      grep "Found version details" "$LOG_DIR/f20_vul_aggregator/F20_summary.txt" 2>/dev/null | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | tr -d "\[\+\]" | grep -v "CVEs: 0" | sed -e 's/Found version details:/version_details:/' |sed -e 's/[[:blank:]]//g' | sed -e 's/:/;/g' >> "$CSV_LOG_FILE" || true
      DATA=1
    fi
  fi
  if [[ $DATA -eq 1 ]]; then
    print_bar
  fi
}

get_data() {
  REMOTE_EXPLOIT_CNT=0
  LOCAL_EXPLOIT_CNT=0
  DOS_EXPLOIT_CNT=0
  GITHUB_EXPLOIT_CNT=0
  HIGH_CVE_COUNTER=0
  MEDIUM_CVE_COUNTER=0
  LOW_CVE_COUNTER=0
  EXPLOIT_COUNTER=0
  MSF_MODULE_CNT=0
  INT_COUNT=0
  POST_COUNT=0
  KNOWN_EXPLOITED_COUNTER=0

  if [[ -f "$LOG_DIR"/"$P02_LOG" ]]; then
    ENTROPY=$(grep -a "Entropy" "$LOG_DIR"/"$P02_LOG" | cut -d= -f2 | sed 's/^\ //' || true)
  fi
  if [[ -f "$LOG_DIR"/"$S03_LOG" ]]; then
    PRE_ARCH=$(grep -a "Possible architecture details found" "$LOG_DIR"/"$S03_LOG" | cut -d: -f2 | tr -d '[:space:]' || true)
    PRE_ARCH=$(strip_color_codes "$PRE_ARCH")
  fi
  if [[ -f "$LOG_DIR"/"$S05_LOG" ]]; then
    FILE_ARR_COUNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S05_LOG" | cut -d: -f2 || true)
    DETECTED_DIR=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S05_LOG" | cut -d: -f3 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S06_LOG" ]]; then
    mapfile -t LINUX_DISTRIS < <(grep "Version information found" "$LOG_DIR"/"$S06_LOG" | cut -d\  -f5- | sed 's/ in file .*//' | sort -u || true)
  fi
  if ! [[ "${FILE_ARR_COUNT-0}" -gt 0 ]]; then
    FILE_ARR_COUNT=$(find "$FIRMWARE_PATH_CP" -type f 2>/dev/null| wc -l || true)
    DETECTED_DIR=$(find "$FIRMWARE_PATH_CP" -type d 2>/dev/null | wc -l || true)
  fi
  if [[ -f "$LOG_DIR"/"$S13_LOG" ]]; then
    STRCPY_CNT_13=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S13_LOG" | cut -d: -f2 || true)
    ARCH=$(grep -a "\[\*\]\ Statistics1:" "$LOG_DIR"/"$S13_LOG" | cut -d: -f2 || true)
  else
    STRCPY_CNT_13=0
  fi
  if [[ -f "$LOG_DIR"/"$S14_LOG" ]]; then
    STRCPY_CNT_14=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S14_LOG" | cut -d: -f2 || true)
    ARCH=$(grep -a "\[\*\]\ Statistics1:" "$LOG_DIR"/"$S14_LOG" | cut -d: -f2 || true)
    STRCPY_CNT=$((STRCPY_CNT_14+STRCPY_CNT_13))
  else
    STRCPY_CNT="$STRCPY_CNT_13"
  fi
  if [[ -f "$LOG_DIR"/"$S20_LOG" ]]; then
    S20_SHELL_VULNS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S20_LOG" | cut -d: -f2 || true)
    S20_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S20_LOG" | cut -d: -f3 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S21_LOG" ]]; then
    S21_PY_VULNS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S21_LOG" | cut -d: -f2 || true)
    S21_PY_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S21_LOG" | cut -d: -f3 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S22_LOG" ]]; then
    S22_PHP_VULNS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S22_LOG" | cut -d: -f2 || true)
    S22_PHP_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S22_LOG" | cut -d: -f3 || true)
    S22_PHP_INI_ISSUES=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S22_LOG" | cut -d: -f4 || true)
    S22_PHP_INI_CONFIGS=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S22_LOG" | cut -d: -f5 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S25_LOG" ]]; then
    MOD_DATA_COUNTER=$(grep -a "\[\*\]\ Statistics1:" "$LOG_DIR"/"$S25_LOG" | cut -d: -f2 || true)
    KMOD_BAD=$(grep -a "\[\*\]\ Statistics1:" "$LOG_DIR"/"$S25_LOG" | cut -d: -f3 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S30_LOG" ]]; then
    S30_VUL_COUNTER=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S30_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S40_LOG" ]]; then
    S40_WEAK_PERM_COUNTER=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S40_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S45_LOG" ]]; then
    PASS_FILES_FOUND=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S45_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S50_LOG" ]]; then
    S50_AUTH_ISSUES=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S50_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S55_LOG" ]]; then
    S55_HISTORY_COUNTER=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S55_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S60_LOG" ]]; then
    CERT_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S60_LOG" | cut -d: -f2 || true)
    CERT_OUT_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S60_LOG" | cut -d: -f3 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S85_LOG" ]]; then
    S85_SSH_VUL_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S85_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S95_LOG" ]]; then
    INT_COUNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S95_LOG" | cut -d: -f2 || true)
    POST_COUNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S95_LOG" | cut -d: -f3 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S107_LOG" ]]; then
    PW_COUNTER=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S107_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S108_LOG" ]]; then
    STACS_HASHES=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S108_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S110_LOG" ]]; then
    YARA_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S110_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$LOG_DIR"/"$S120_LOG" ]]; then
    export TOTAL_CWE_CNT
    TOTAL_CWE_CNT=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$S120_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$SYS_EMU_RESULTS" ]]; then
    BOOTED=$(grep -c "Booted yes;" "$SYS_EMU_RESULTS" || true)
    ICMP=$(grep -c "ICMP ok;" "$SYS_EMU_RESULTS" || true)
    TCP_0=$(grep -c "TCP-0 ok;" "$SYS_EMU_RESULTS" || true)
    TCP=$(grep -c "TCP ok;" "$SYS_EMU_RESULTS" || true)
    IP_ADDR=$(grep -E -c "IP\ address:\ [0-9]+" "$SYS_EMU_RESULTS" || true)
    # we make something like this: "bridge-default-normal"
    MODE=$(grep -e "ICMP ok;\|TCP-0 ok;\|TCP ok" "$SYS_EMU_RESULTS" | cut -d\; -f8 | sort -u | sed 's/Network mode: //g' | tr -d '[:blank:]' | tr '\n' '-' | sed 's/-$//g' || true)
  fi
  if [[ -f "$LOG_DIR"/"$L15_LOG" ]]; then
    #NMAP_UP=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$L15_LOG" | cut -d: -f2 || true)
    SNMP_UP=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$L20_LOG" | cut -d: -f2 || true)
    WEB_UP=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$L25_LOG" | cut -d: -f2 || true)
    ROUTERSPLOIT_VULN=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$L30_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" ]]; then
    CVE_SEARCH=$(grep -a "\[\*\]\ Statistics:" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | cut -d: -f2 || true)
  fi
  if [[ -f "$TMP_DIR"/HIGH_CVE_COUNTER.tmp ]]; then
    while read -r COUNTING; do
      (( HIGH_CVE_COUNTER="$HIGH_CVE_COUNTER"+"$COUNTING" ))
    done < "$TMP_DIR"/HIGH_CVE_COUNTER.tmp
    (( CVE_COUNTER="$CVE_COUNTER"+"$HIGH_CVE_COUNTER" ))
  fi
  if [[ -f "$TMP_DIR"/MEDIUM_CVE_COUNTER.tmp ]]; then
    while read -r COUNTING; do
      (( MEDIUM_CVE_COUNTER="$MEDIUM_CVE_COUNTER"+"$COUNTING" ))
    done < "$TMP_DIR"/MEDIUM_CVE_COUNTER.tmp
    (( CVE_COUNTER="$CVE_COUNTER"+"$MEDIUM_CVE_COUNTER" ))
  fi
  if [[ -f "$TMP_DIR"/LOW_CVE_COUNTER.tmp ]]; then
    while read -r COUNTING; do
      (( LOW_CVE_COUNTER="$LOW_CVE_COUNTER"+"$COUNTING" ))
    done < "$TMP_DIR"/LOW_CVE_COUNTER.tmp
    (( CVE_COUNTER="$CVE_COUNTER"+"$LOW_CVE_COUNTER" ))
  fi
  if [[ -f "$TMP_DIR"/KNOWN_EXPLOITED_COUNTER.tmp ]]; then
    KNOWN_EXPLOITED_COUNTER=$(cat "$TMP_DIR"/KNOWN_EXPLOITED_COUNTER.tmp)
  fi
  if [[ -f "$F20_EXPLOITS_LOG" ]]; then
    #EXPLOIT_COUNTER="$(grep -c -E "Exploit\ .*" "$F20_EXPLOITS_LOG" || true)"
    # shellcheck disable=SC2126
    EXPLOIT_COUNTER="$(grep -E "Exploit\ .*" "$F20_EXPLOITS_LOG" | grep -v "Exploit summary" | wc -l || true)"
    MSF_MODULE_CNT="$(grep -c -E "Exploit\ .*MSF" "$F20_EXPLOITS_LOG" || true)"
    REMOTE_EXPLOIT_CNT="$(grep -c -E "Exploit\ .*\ \(R\)" "$F20_EXPLOITS_LOG" || true)"
    LOCAL_EXPLOIT_CNT="$(grep -c -E "Exploit\ .*\ \(L\)" "$F20_EXPLOITS_LOG" || true)"
    DOS_EXPLOIT_CNT="$(grep -c -E "Exploit\ .*\ \(D\)" "$F20_EXPLOITS_LOG" || true)"
    GITHUB_EXPLOIT_CNT="$(grep -c -E "Exploit\ .*\ \(G\)" "$F20_EXPLOITS_LOG" || true)"
    EXPLOIT_HIGH_COUNT="$(cat "$TMP_DIR"/EXPLOIT_HIGH_COUNTER.tmp || true)"
    EXPLOIT_MEDIUM_COUNT="$(cat "$TMP_DIR"/EXPLOIT_MEDIUM_COUNTER.tmp || true)"
    EXPLOIT_LOW_COUNT="$(cat "$TMP_DIR"/EXPLOIT_LOW_COUNTER.tmp || true)"
  fi
}

distribution_detector() {
  for DISTRI in "${LINUX_DISTRIS[@]}"; do
    print_output "[+] Linux distribution detected: $ORANGE$DISTRI$NC"
    write_link "s06"
  done
}

os_detector() {

  VERIFIED=0
  VERIFIED_S03=0
  OSES=("kernel" "vxworks" "siprotec" "freebsd" "qnx\ neutrino\ rtos" "simatic\ cp443-1")

  #### The following check is based on the results of the aggregator:
  if [[ -f "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" ]]; then
    for OS_TO_CHECK in "${OSES[@]}"; do
      mapfile -t SYSTEM_VERSION < <(grep -i "Found Version details" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" | grep aggregated | grep "$OS_TO_CHECK" | cut -d: -f3 | sed -e 's/[[:blank:]]//g' || true)
      if [[ "${#SYSTEM_VERSION[@]}" -gt 0 ]]; then
        if [[ "$OS_TO_CHECK" == "kernel" ]]; then
          SYSTEM="Linux"
        elif [[ "$OS_TO_CHECK" == "siprotec" ]]; then
          SYSTEM="SIPROTEC"
        elif [[ "$OS_TO_CHECK" == "vxworks" ]]; then
          SYSTEM="VxWorks"
        elif [[ "$OS_TO_CHECK" == "freebsd" ]]; then
          SYSTEM="FreeBSD"
        elif [[ "$OS_TO_CHECK" == "qnx\ neutrino\ rtos" ]]; then
          SYSTEM="QNX Neutrino"
        elif [[ "$OS_TO_CHECK" == "simatic\ cp443-1" ]]; then
          SYSTEM="Siemens CP443-1"
        else
          SYSTEM="$OS_TO_CHECK"
        fi
        # version detected -> verified linux
        for SYSTEM_VER in "${SYSTEM_VERSION[@]}"; do
          SYSTEM_VER=$(strip_color_codes "$SYSTEM_VER")
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
  if [[ $VERIFIED -eq 0 && -f "$LOG_DIR"/"$S03_LOG" ]]; then
    # the OS was not verified in the first step (but we can try to verify it now with more data of other modules)
    mapfile -t OS_DETECT < <(grep "verified.*operating\ system\ detected" "$LOG_DIR"/"$S03_LOG" 2>/dev/null | cut -d: -f1,2 | awk '{print $2 " - #" $5}' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" || true)
    if [[ "${#OS_DETECT[@]}" -gt 0 ]]; then
      for SYSTEM in "${OS_DETECT[@]}"; do
        VERIFIED_S03=1
        VERIFIED=1
        print_os
      done
    fi

    # we print the unverified OS only if we have no verified results:
    mapfile -t OS_DETECT < <(grep "\ detected" "$LOG_DIR"/"$S03_LOG" 2>/dev/null | cut -d: -f1,2 | awk '{print $2 " - #" $5}' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | sort -r -n -t '#' -k2 || true)

    if [[ "${#OS_DETECT[@]}" -gt 0 && "$VERIFIED" -eq 0 ]]; then
      for SYSTEM in "${OS_DETECT[@]}"; do
        VERIFIED=0
        print_os
      done
    fi
  fi

  #### The following check is just in place if something went wrong
  if [[ $VERIFIED -eq 0 ]]; then
    # usually the results of the kernel module checker are already used in f20 (first os check)
    # but just in case something went wrong we use it now
    os_kernel_module_detect
    if [[ $VERIFIED -eq 1 ]]; then
      print_os
    fi
  fi
}

os_kernel_module_detect() {

  if [[ -f "$LOG_DIR"/"$S25_LOG" ]]; then
    mapfile -t KERNELV < <(grep "Statistics:" "$LOG_DIR"/"$S25_LOG" | cut -d: -f2 | sort -u || true)
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
    if [[ "$VERIFIED_S03" -eq 1 ]]; then
      SYSTEM=$(echo "$SYSTEM" | awk '{print $1}')
      print_output "[+] Operating system detected (""$ORANGE""verified$GREEN): $ORANGE$SYSTEM$NC"
      write_link "s03"
    else
      print_output "[+] Operating system detected (""$ORANGE""verified$GREEN): $ORANGE$SYSTEM$NC"
      write_link "s25"
    fi
    echo "os_verified;\"$SYSTEM\"" >> "$CSV_LOG_FILE"
  else
    print_output "[+] Possible operating system detected (""$ORANGE""unverified$GREEN): $ORANGE$SYSTEM$NC"
    write_link "s03"
    if [[ "$(grep -c os_verified "$CSV_LOG_FILE")" -lt 1 ]]; then
      echo "os_verified;\"unknown\"" >> "$CSV_LOG_FILE"
    fi
    echo "os_unverified;\"$SYSTEM\"" >> "$CSV_LOG_FILE"
  fi
}

cwe_logging() {
  LOG_DIR_MOD="s120_cwe_checker"
  if [[ -d "$LOG_DIR"/"$LOG_DIR_MOD" ]]; then
    mapfile -t CWE_OUT < <( cat "$LOG_DIR"/"$LOG_DIR_MOD"/cwe_*.log 2>/dev/null | grep -v "ERROR\|DEBUG\|INFO" | grep "CWE[0-9]" | sed -z 's/[0-9]\.[0-9]//g' | cut -d\( -f1,3 | cut -d\) -f1 | sort -u | tr -d '(' | tr -d "[" | tr -d "]" || true)
    if [[ ${#CWE_OUT[@]} -gt 0 ]] ; then
      print_output "[+] cwe-checker found a total of ""$ORANGE""$TOTAL_CWE_CNT""$GREEN"" of the following security issues:"
      write_link "s120"
      for CWE_LINE in "${CWE_OUT[@]}"; do
        CWE="$(echo "$CWE_LINE" | cut -d\  -f1)"
        CWE_DESC="$(echo "$CWE_LINE" | cut -d\  -f2-)"
        CWE_CNT="$(cat "$LOG_DIR"/"$LOG_DIR_MOD"/cwe_*.log 2>/dev/null | grep -c "$CWE" || true)"
        print_output "$(indent "$(orange "$CWE""$GREEN"" - ""$CWE_DESC"" - ""$ORANGE""$CWE_CNT"" times.")")"
      done
      print_output ""
      echo "cwe_issues;\"$TOTAL_CWE_CNT\"" >> "$CSV_LOG_FILE"
    fi
  fi
}

