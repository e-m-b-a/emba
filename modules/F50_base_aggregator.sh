#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2021-2024 Siemens Energy AG
# Copyright 2021-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Generates an overview over all modules.
# shellcheck disable=SC2153

F50_base_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final aggregator"
  pre_module_reporter "${FUNCNAME[0]}"

  # Todo: move all the log vars to a dedicated variable loader from EMBA
  # Todo: Change all log usages to these vars in EMBA
  export CVE_AGGREGATOR_LOG="f20_vul_aggregator.txt"
  export F20_EXPLOITS_LOG="${LOG_DIR}"/f20_vul_aggregator/exploits-overview.txt
  export P02_CSV_LOG="${CSV_DIR}""/p02_firmware_bin_file_check.csv"
  export P99_CSV_LOG="${CSV_DIR}""/p99_prepare_analyzer.csv"
  export P99_LOG="${LOG_DIR}""/p99_prepare_analyzer.txt"
  export P35_LOG="p35_uefi_extractor.txt"
  export S02_LOG="s02_uefi_fwhunt.txt"
  export S03_LOG="s03_firmware_bin_base_analyzer.txt"
  export S05_LOG="s05_firmware_details.txt"
  export S06_LOG="s06_distribution_identification.txt"
  export S12_LOG="s12_binary_protection.txt"
  export S12_CSV_LOG="${CSV_DIR}""/s12_binary_protection.csv"
  export S13_LOG="s13_weak_func_check.txt"
  export S14_LOG="s14_weak_func_radare_check.txt"
  export S16_LOG="s16_ghidra_decompile_checks.txt"
  export S17_CSV_LOG="${CSV_DIR}""/s17_apk_check.csv"
  export S24_CSV_LOG="${CSV_DIR}""/s24_kernel_bin_identifier.csv"
  export S20_LOG="s20_shell_check.txt"
  export S21_LOG="s21_python_check.txt"
  export S22_LOG="s22_php_check.txt"
  export S24_LOG="s24_kernel_bin_identifier.txt"
  export S25_LOG="s25_kernel_check.txt"
  export S26_LOG="s26_kernel_vuln_verifier.txt"
  export S30_LOG="s30_version_vulnerability_check.txt"
  export S40_LOG="s40_weak_perm_check.txt"
  export S45_LOG="s45_pass_file_check.txt"
  export S50_LOG="s50_authentication_check.txt"
  export S55_LOG="s55_history_file_check.txt"
  export S60_LOG="s60_cert_file_check.txt"
  export S85_LOG="s85_ssh_check.txt"
  export S95_LOG="s95_interesting_files_check.txt"
  export S107_LOG="s107_deep_password_search.txt"
  export S108_LOG="s108_stacs_password_search.txt"
  export S109_LOG="s109_jtr_local_pw_cracking.txt"
  export S110_LOG="s110_yara_check.txt"
  export S17_LOG="s17_cwe_checker.txt"
  # L10_LOG="l10_system_emulator.txt"
  export L15_LOG="l15_emulated_checks_init.txt"
  export L20_LOG="l20_snmp_checks.txt"
  export L25_LOG="l25_web_checks.txt"
  export L30_LOG="l30_routersploit.txt"
  export Q02_LOG="q02_openai_question.txt"
  export L35_CSV_LOG="${CSV_DIR}""/l35_metasploit_check.csv"
  export SYS_EMU_RESULTS="${LOG_DIR}"/emulator_online_results.log

  if [[ "${RESTART}" -eq 1 ]] && [[ -f "${LOG_FILE}" ]]; then
    rm "${LOG_FILE}"
  fi

  get_data
  output_overview
  output_details
  output_config_issues
  output_binaries
  output_cve_exploits

  # dedicated firmware diff output function
  if [[ "${DIFF_MODE}" -gt 0 ]]; then
    output_diff
  fi

  module_end_log "${FUNCNAME[0]}" 1
}

output_diff() {
  print_output "[!] Aggregator integration of firmware diffing mode not available" "no_log"
}

output_overview() {
  local EMBA_COMMAND_ORIG=""

  if [[ -n "${FW_VENDOR}" ]]; then
    print_output "[+] Tested Firmware vendor: ""${ORANGE}""${FW_VENDOR}""${NC}"
    write_csv_log "Firmware_vendor" "${FW_VENDOR}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi
  if [[ -n "${FW_VERSION}" ]]; then
    print_output "[+] Tested Firmware version: ""${ORANGE}""${FW_VERSION}""${NC}"
    write_csv_log "Firmware_version" "${FW_VERSION}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi
  if [[ -n "${FW_DEVICE}" ]]; then
    print_output "[+] Tested Firmware from device: ""${ORANGE}""${FW_DEVICE}""${NC}"
    write_csv_log "Device" "${FW_DEVICE}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi
  if [[ -n "${FW_NOTES}" ]]; then
    print_output "[+] Additional notes: ""${ORANGE}""${FW_NOTES}""${NC}"
    write_csv_log "FW_notes" "${FW_NOTES}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi

  if [[ "${IN_DOCKER}" -eq 1 ]] && [[ -f "${TMP_DIR}"/fw_name.log ]] && [[ -f "${TMP_DIR}"/emba_command.log ]]; then
    local FW_PATH_ORIG_ARR=()
    local FW_PATH_ORIG=""
    # we need to rewrite this firmware path to the original path
    mapfile -t FW_PATH_ORIG_ARR < <(sort -u "${TMP_DIR}"/fw_name.log)
    EMBA_COMMAND_ORIG="$(sort -u "${TMP_DIR}"/emba_command.log)"
    for FW_PATH_ORIG in "${FW_PATH_ORIG_ARR[@]}"; do
      print_output "[+] Tested firmware:""${ORANGE}"" ""${FW_PATH_ORIG}""${NC}"
      write_csv_log "FW_path" "${FW_PATH_ORIG}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    done
    print_output "[+] EMBA start command:""${ORANGE}"" ""${EMBA_COMMAND_ORIG}""${NC}"
    write_csv_log "emba_command" "${EMBA_COMMAND_ORIG}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  else
    print_output "[+] Tested firmware:""${ORANGE}"" ""${FIRMWARE_PATH}""${NC}"
    write_csv_log "FW_path" "${FIRMWARE_PATH}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    print_output "[+] EMBA start command:""${ORANGE}"" ""${EMBA_COMMAND}""${NC}"
    write_csv_log "emba_command" "${EMBA_COMMAND}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi

  if [[ -f "${LOG_DIR}"/"${Q02_LOG}" ]] && [[ "${GPT_OPTION}" -gt 0 ]]; then
    GPT_RESULTS=$(grep -c "AI analysis for" "${LOG_DIR}"/"${Q02_LOG}" || true)
    if [[ "${GPT_RESULTS}" -gt 0 ]]; then
      print_output "[+] EMBA AI analysis discovered ${ORANGE}${GPT_RESULTS}${GREEN} results."
      write_link "q02"
    fi
  fi

  if [[ -n "${ARCH}" ]]; then
    if [[ -n "${D_END:-"NA"}" ]]; then
      write_csv_log "architecture_verified" "${ARCH}" "${D_END}" "NA" "NA" "NA" "NA" "NA" "NA"
      print_output "[+] Detected architecture and endianness (""${ORANGE}""verified${GREEN}):""${ORANGE}"" ""${ARCH}"" / ""${D_END}""${NC}"
    else
      write_csv_log "architecture_verified" "${ARCH}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      print_output "[+] Detected architecture (""${ORANGE}""verified${GREEN}):""${ORANGE}"" ""${ARCH}""${NC}"
    fi
    write_link "p99"
  elif [[ -f "${P99_CSV_LOG}" ]] && [[ -n "${P99_ARCH}" ]]; then
    if [[ -n "${D_END:-"NA"}" ]]; then
      write_csv_log "architecture_verified" "${P99_ARCH}" "${P99_ARCH_END}" "NA" "NA" "NA" "NA" "NA" "NA"
      print_output "[+] Detected architecture and endianness (""${ORANGE}""verified${GREEN}):""${ORANGE}"" ""${P99_ARCH}"" / ""${P99_ARCH_END}""${NC}"
    else
      write_csv_log "architecture_verified" "${P99_ARCH}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      print_output "[+] Detected architecture (""${ORANGE}""verified${GREEN}):""${ORANGE}"" ""${P99_ARCH}""${NC}"
    fi
    write_link "p99"
  # architecture detection from vmlinux-to-elf:
  elif [[ -f "${S24_CSV_LOG}" ]] && [[ -n "${K_ARCH}" ]]; then
    if [[ -n "${K_ARCH_END}" ]]; then
      write_csv_log "architecture_verified" "${K_ARCH}" "${K_ARCH_END}" "NA" "NA" "NA" "NA" "NA" "NA"
      print_output "[+] Detected architecture and endianness (""${ORANGE}""verified${GREEN}):""${ORANGE}"" ""${K_ARCH}"" / ""${K_ARCH_END}""${NC}"
    else
      write_csv_log "architecture_verified" "${K_ARCH}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      print_output "[+] Detected architecture (""${ORANGE}""verified${GREEN}):""${ORANGE}"" ""${K_ARCH}""${NC}"
    fi
    write_link "s24"
  elif [[ -f "${LOG_DIR}"/"${S03_LOG}" ]]; then
    if [[ -n "${PRE_ARCH}" ]]; then
      print_output "[+] Detected architecture:""${ORANGE}"" ""${PRE_ARCH}""${NC}"
      write_link "s03"
      write_csv_log "architecture_verified" "unknown" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "architecture_unverified" "${PRE_ARCH}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    fi
    if [[ -n "${EFI_ARCH}" ]]; then
      print_output "[+] Detected architecture:""${ORANGE}"" ""${EFI_ARCH}""${NC}"
      write_link "p35"
      write_csv_log "architecture_verified" "${EFI_ARCH}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    fi
  else
    write_csv_log "architecture_verified" "unknown" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi
  os_detector
  distribution_detector
  print_bar
}

output_details() {
  local DATA=0
  local STATE=""
  local EMU_STATE=""
  local EMUL=0
  local ENTROPY_PIC=""

  if [[ "${FILE_ARR_COUNT:-0}" -gt 0 ]]; then
    print_output "[+] ""${ORANGE}""${FILE_ARR_COUNT}""${GREEN}"" files and ""${ORANGE}""${DETECTED_DIR}"" ""${GREEN}""directories detected."
    if [[ -f "${LOG_DIR}"/"${S05_LOG}" ]]; then
      write_link "s05"
    else
      write_link "p99"
    fi
    write_csv_log "files" "${FILE_ARR_COUNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "directories" "${DETECTED_DIR}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    DATA=1
  fi
  ENTROPY_PIC=$(find "${LOG_DIR}" -xdev -maxdepth 1 -type f -iname "*_entropy.png" 2> /dev/null)
  if [[ -n "${ENTROPY}" ]]; then
    print_output "[+] Entropy analysis of binary firmware is: ""${ORANGE}""${ENTROPY}"
    write_link "p02"
    write_csv_log "entropy_value" "${ENTROPY}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    DATA=1
  fi
  if [[ -n "${ENTROPY_PIC}" ]]; then
    print_output "[+] Entropy analysis of binary firmware is available:""${ORANGE}"" ""${ENTROPY_PIC}"
    write_link "${ENTROPY_PIC}"
    DATA=1
  fi

  if [[ "${S20_SHELL_VULNS:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${S20_SHELL_VULNS}"" issues""${GREEN}"" in ""${ORANGE}""${S20_SCRIPTS}""${GREEN}"" shell scripts.""${NC}"
    write_link "s20"
    write_csv_log "shell_scripts" "${S20_SCRIPTS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "shell_script_vulns" "${S20_SHELL_VULNS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    DATA=1
  fi
  if [[ "${S21_PY_VULNS:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${S21_PY_VULNS}"" vulnerabilities""${GREEN}"" in ""${ORANGE}""${S21_PY_SCRIPTS}""${GREEN}"" python files.""${NC}"
    write_link "s21"
    write_csv_log "python_scripts" "${S21_PY_SCRIPTS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "python_vulns" "${S21_PY_VULNS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    DATA=1
  fi
  if [[ "${S22_PHP_VULNS:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${S22_PHP_VULNS}"" vulnerabilities""${GREEN}"" via progpilot in ""${ORANGE}""${S22_PHP_SCRIPTS}""${GREEN}"" php files.""${NC}"
    write_link "s22"
    write_csv_log "php_scripts" "${S22_PHP_SCRIPTS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "php_vulns_progpilot" "${S22_PHP_VULNS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi
  if [[ "${S22_PHP_VULNS_SEMGREP:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${S22_PHP_VULNS_SEMGREP}"" vulnerabilities""${GREEN}"" via semgrep in ""${ORANGE}""${S22_PHP_SCRIPTS}""${GREEN}"" php files.""${NC}"
    write_link "s22"
    write_csv_log "php_scripts" "${S22_PHP_SCRIPTS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "php_vulns_semgrep" "${S22_PHP_VULNS_SEMGREP}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi

  if [[ "${S22_PHP_INI_ISSUES:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${S22_PHP_INI_ISSUES}"" issues""${GREEN}"" in ""${ORANGE}""${S22_PHP_INI_CONFIGS}""${GREEN}"" php configuration file.""${NC}"
    write_link "s22"
    write_csv_log "php_ini_issues" "${S22_PHP_INI_ISSUES}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "php_ini_configs" "${S22_PHP_INI_CONFIGS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    DATA=1
  fi
  if [[ "${YARA_CNT:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${YARA_CNT}""${GREEN}"" yara rule matches in ${ORANGE}${#FILE_ARR[@]}${GREEN} files.""${NC}"
    write_link "s110"
    write_csv_log "yara_rules_match" "${YARA_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    DATA=1
  fi
  if [[ "${FWHUNTER_CNT:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${FWHUNTER_CNT}""${GREEN}"" UEFI vulnerabilities.""${NC}"
    write_link "s02"
    write_csv_log "uefi_vulns" "${FWHUNTER_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    DATA=1
  fi

  EMUL=$(cut -d\; -f1 "${CSV_DIR}"/s116_qemu_version_detection.csv 2>/dev/null | grep -v "binary/file" | sort -u | wc -l || true)
  if [[ "${EMUL:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${EMUL}""${GREEN}"" successful emulated processes ${ORANGE}(${GREEN}user mode emulation${ORANGE})${GREEN}.""${NC}"
    write_link "s116"
    write_csv_log "user_emulation_state" "${EMUL}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    DATA=1
  fi

  if [[ "${GPT_RESULTS}" -gt 0 ]]; then
    print_output "[+] EMBA AI tests identified ${ORANGE}${GPT_RESULTS}${GREEN} results via ChatGPT."
    write_link "q02"
    write_csv_log "AI results" "${GPT_RESULTS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi

  if [[ "${BOOTED:-0}" -gt 0 ]] || [[ "${IP_ADDR:-0}" -gt 0 ]]; then
    STATE="${ORANGE}(""${GREEN}""booted"
    EMU_STATE="booted"
    if [[ "${IP_ADDR}" -gt 0 ]]; then
      STATE="${STATE}""${ORANGE} / ""${GREEN}""IP address detected (mode: ${ORANGE}${MODE}${GREEN})"
      EMU_STATE="${EMU_STATE}"";IP_DET"
    fi
    if [[ "${ICMP:-0}" -gt 0 || "${TCP_0:-0}" -gt 0 ]]; then
      STATE="${STATE}""${ORANGE} / ""${GREEN}""ICMP"
      EMU_STATE="${EMU_STATE}"";ICMP"
    fi
    if [[ "${TCP:-0}" -gt 0 ]]; then
      STATE="${STATE}""${ORANGE} / ""${GREEN}""NMAP"
      EMU_STATE="${EMU_STATE}"";NMAP"
    fi
    if [[ "${SNMP_UP:-0}" -gt 0 ]]; then
      STATE="${STATE}""${ORANGE} / ""${GREEN}""SNMP"
      EMU_STATE="${EMU_STATE}"";SNMP"
    fi
    if [[ "${WEB_UP:-0}" -gt 0 ]]; then
      STATE="${STATE}""${ORANGE} / ""${GREEN}""WEB"
      EMU_STATE="${EMU_STATE}"";WEB"
    fi
    if [[ "${ROUTERSPLOIT_VULN:-0}" -gt 0 ]]; then
      STATE="${STATE}""${ORANGE} / ""${GREEN}""Routersploit"
      EMU_STATE="${EMU_STATE}"";Routersploit"
    fi
    if [[ "${MSF_VERIFIED}" -gt 0 ]]; then
      STATE="${STATE}""${ORANGE} / ""${GREEN}""Exploited"
      EMU_STATE="${EMU_STATE}"";Exploited"
    fi
    STATE="${STATE}${ORANGE}"")${NC}"

    print_output "[+] System emulation was successful ${STATE}" "" "l10"
    write_csv_log "system_emulation_state" "${EMU_STATE}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    DATA=1
  fi

  if [[ "${K_CVE_VERIFIED_SYMBOLS:-0}" -gt 0 ]] || [[ "${K_CVE_VERIFIED_COMPILED:-0}" -gt 0 ]]; then
    if [[ "${K_CVE_VERIFIED_SYMBOLS:-0}" -gt 0 ]]; then
      print_output "[+] Verified ${ORANGE}${K_CVE_VERIFIED_SYMBOLS:-0}${GREEN} kernel vulnerabilities (${ORANGE}kernel symbols${GREEN})."
      write_link "s26"
    fi
    if [[ "${K_CVE_VERIFIED_COMPILED:-0}" -gt 0 ]]; then
      print_output "[+] Verified ${ORANGE}${K_CVE_VERIFIED_COMPILED:-0}${GREEN} kernel vulnerabilities (${ORANGE}kernel compilation${GREEN})."
      write_link "s26"
    fi
    DATA=1
    write_csv_log "kernel_verified" "${K_CVE_VERIFIED_SYMBOLS:-0}" "${K_CVE_VERIFIED_COMPILED:-0}" "NA" "NA" "NA" "NA" "NA" "NA"
  fi

  if [[ ${DATA} -eq 1 ]]; then
    print_bar
  fi
}

output_config_issues() {
  local DATA=0

  if [[ "${PW_COUNTER:-0}" -gt 0 || "${S85_SSH_VUL_CNT:-0}" -gt 0 || "${STACS_HASHES:-0}" -gt 0 || "${INT_COUNT:-0}" -gt 0 || "${POST_COUNT:-0}" -gt 0 || "${MOD_DATA_COUNTER:-0}" -gt 0 || "${S40_WEAK_PERM_COUNTER:-0}" -gt 0 || "${S55_HISTORY_COUNTER:-0}" -gt 0 || "${S50_AUTH_ISSUES:-0}" -gt 0 || "${PASS_FILES_FOUND:-0}" -gt 0 || "${TOTAL_CERT_CNT:-0}" -gt 0 || "${S24_FAILED_KSETTINGS:-0}" -gt 0 ]]; then
    print_output "[+] Found the following configuration issues:"
    if [[ "${S40_WEAK_PERM_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${S40_WEAK_PERM_COUNTER}${GREEN} areas with weak permissions.")")"
      write_link "s40"
      write_csv_log "weak_perm_count" "${S40_WEAK_PERM_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${S55_HISTORY_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${S55_HISTORY_COUNTER}${GREEN} history files.")")"
      write_link "s55"
      write_csv_log "history_file_count" "${S55_HISTORY_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${S50_AUTH_ISSUES:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${S50_AUTH_ISSUES}${GREEN} authentication issues.")")"
      write_link "s50"
      write_csv_log "auth_issues" "${S50_AUTH_ISSUES}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${S85_SSH_VUL_CNT:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${S85_SSH_VUL_CNT}${GREEN} SSHd issues.")")"
      write_link "s85"
      write_csv_log "ssh_issues" "${S85_SSH_VUL_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${PW_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${PW_COUNTER}${GREEN} password related details.")")"
      write_link "s107"
      write_csv_log "password_hashes" "${PW_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${STACS_HASHES:-0}" -gt 0 ]]; then
      write_csv_log "password_hashes_stacs" "${STACS_HASHES}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      if [[ "${HASHES_CRACKED:-0}" -gt 0 ]]; then
        print_output "$(indent "$(green "Found ${ORANGE}${STACS_HASHES}${GREEN} password related details via STACS (${ORANGE}${HASHES_CRACKED}${GREEN} passwords cracked.)")")"
        write_link "s109"
        write_csv_log "password_hashes_cracked" "${HASHES_CRACKED}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      else
        print_output "$(indent "$(green "Found ${ORANGE}${STACS_HASHES}${GREEN} password related details via STACS.")")"
        write_link "s108"
      fi
      DATA=1
    fi
    if [[ "${TOTAL_CERT_CNT:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${CERT_OUT_CNT}${GREEN} outdated certificates and ${ORANGE}${CERT_WARNING_CNT} expiring certificates in ${ORANGE}${CERT_CNT}${GREEN} certificate files and in a total of ${ORANGE}${TOTAL_CERT_CNT}${GREEN} certificates.")")"
      write_link "s60"
      write_csv_log "total_certificates" "${TOTAL_CERT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "certificate_files" "${CERT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "certificates_outdated" "${CERT_OUT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "certificates_expiring" "${CERT_WARNING_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${MOD_DATA_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${MOD_DATA_COUNTER}${GREEN} kernel modules with ${ORANGE}${KMOD_BAD}${GREEN} licensing issues.")")"
      write_link "s25#kernel_modules"
      write_csv_log "kernel_modules" "${MOD_DATA_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "kernel_modules_lic" "${KMOD_BAD}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${S24_FAILED_KSETTINGS:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${S24_FAILED_KSETTINGS}${GREEN} security related kernel settings for review.")")"
      write_link "s24"
      write_csv_log "kernel_settings" "${S24_FAILED_KSETTINGS:-0}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${INT_COUNT:-0}" -gt 0 || "${POST_COUNT:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${INT_COUNT}${GREEN} interesting files and ${ORANGE}${POST_COUNT:-0}${GREEN} files that could be useful for post-exploitation.")")"
      write_link "s95"
      write_csv_log "interesting_files" "${INT_COUNT:-0}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "post_files" "${POST_COUNT:-0}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${APK_ISSUES:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${APK_ISSUES}${GREEN} issues in Android APK packages.")")"
      write_link "s17"
      write_csv_log "apk_issues" "${APK_ISSUES}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    fi
  fi
  if [[ ${DATA} -eq 1 ]]; then
    print_bar
  fi
}

output_binaries() {
  local DATA=0
  local CANARY=0
  local RELRO=0
  local NX=0
  local PIE=0
  local STRIPPED=0
  local BINS_CHECKED=0
  local CAN_PER=0
  local RELRO_PER=0
  local NX_PER=0
  local PIE_PER=0
  local STRIPPED_PER=0
  local RESULTS_STRCPY=()
  local RESULTS_SYSTEM=()
  local DETAIL_STRCPY=0
  local DETAIL_SYSTEM=0

  if [[ -v BINARIES[@] ]]; then
    if [[ -f "${S12_CSV_LOG}" ]]; then
      CANARY=$(grep -c "No Canary" "${S12_CSV_LOG}" || true)
      RELRO=$(grep -c "No RELRO" "${S12_CSV_LOG}" || true)
      NX=$(grep -c "NX disabled" "${S12_CSV_LOG}" || true)
      PIE=$(grep -c "No PIE" "${S12_CSV_LOG}" || true)
      STRIPPED=$(grep -c "No Symbols" "${S12_CSV_LOG}" || true)
      BINS_CHECKED=$(grep -c "RELRO.*NX.*RPATH" "${S12_CSV_LOG}" || true)
      if [[ "${BINS_CHECKED}" -gt 0 ]]; then
        # we have to remove the first line of the original output:
        (( BINS_CHECKED-- ))
      fi
    elif [[ -f "${LOG_DIR}"/"${S13_LOG}" ]]; then
      BINS_CHECKED=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S13_LOG}" | cut -d: -f3 || true)
    fi

    if [[ "${CANARY:-0}" -gt 0 ]]; then
      CAN_PER=$(bc -l <<< "${CANARY}/(${BINS_CHECKED}/100)" 2>/dev/null)
      CAN_PER=$(/bin/printf "%.0f" "${CAN_PER}" 2>/dev/null || true)
      print_output "[+] Found ""${ORANGE}""${CANARY}"" (""${CAN_PER}""%)""${GREEN}"" binaries without enabled stack canaries in ${ORANGE}""${BINS_CHECKED}""${GREEN} binaries."
      write_link "s12"
      write_csv_log "canary" "${CANARY}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "canary_per" "${CAN_PER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${RELRO:-0}" -gt 0 ]]; then
      RELRO_PER=$(bc -l <<< "${RELRO}/(${BINS_CHECKED}/100)" 2>/dev/null)
      RELRO_PER=$(/bin/printf "%.0f" "${RELRO_PER}" 2>/dev/null || true)
      print_output "[+] Found ""${ORANGE}""${RELRO}"" (""${RELRO_PER}""%)""${GREEN}"" binaries without enabled RELRO in ${ORANGE}""${BINS_CHECKED}""${GREEN} binaries."
      write_link "s12"
      write_csv_log "relro" "${RELRO}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "relro_per" "${RELRO_PER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${NX:-0}" -gt 0 ]]; then
      NX_PER=$(bc -l <<< "${NX}/(${BINS_CHECKED}/100)" 2>/dev/null)
      NX_PER=$(/bin/printf "%.0f" "${NX_PER}" 2>/dev/null || true)
      print_output "[+] Found ""${ORANGE}""${NX}"" (""${NX_PER}""%)""${GREEN}"" binaries without enabled NX in ${ORANGE}""${BINS_CHECKED}""${GREEN} binaries."
      write_link "s12"
      write_csv_log "nx" "${NX}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "nx_per" "${NX_PER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${PIE:-0}" -gt 0 ]]; then
      PIE_PER=$(bc -l <<< "${PIE}/(${BINS_CHECKED}/100)" 2>/dev/null)
      PIE_PER=$(/bin/printf "%.0f" "${PIE_PER}" 2>/dev/null || true)
      print_output "[+] Found ""${ORANGE}""${PIE}"" (""${PIE_PER}""%)""${GREEN}"" binaries without enabled PIE in ${ORANGE}""${BINS_CHECKED}""${GREEN} binaries."
      write_link "s12"
      write_csv_log "pie" "${PIE}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "pie_per" "${PIE_PER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${STRIPPED:-0}" -gt 0 ]]; then
      STRIPPED_PER=$(bc -l <<< "${STRIPPED}/(${BINS_CHECKED}/100)" 2>/dev/null)
      STRIPPED_PER=$(/bin/printf "%.0f" "${STRIPPED_PER}" 2>/dev/null || true)
      print_output "[+] Found ""${ORANGE}""${STRIPPED}"" (""${STRIPPED_PER}""%)""${GREEN}"" stripped binaries without symbols in ${ORANGE}""${BINS_CHECKED}""${GREEN} binaries."
      write_link "s12"
      write_csv_log "stripped" "${STRIPPED}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "stripped_per" "${STRIPPED_PER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${BINS_CHECKED:-0}" -gt 0 ]]; then
      write_csv_log "bins_checked" "${BINS_CHECKED}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    fi
  fi
  if [[ ${DATA} -eq 1 ]]; then
    print_bar
  fi

  cwe_logging

  if [[ "${S16_GHIDRA_SEMGREP:-0}" -gt 0 ]]; then
    write_csv_log "ghidra_semgrep_issues" "${S16_GHIDRA_SEMGREP}" "${S16_BINS_CHECKED}" "NA" "NA" "NA" "NA" "NA" "NA"
    print_output "[+] Found ""${ORANGE}""${S16_GHIDRA_SEMGREP}""${GREEN}"" possible vulnerabilities (${ORANGE}via semgrep in Ghidra decompiled code${GREEN}) in ""${ORANGE}""${S16_BINS_CHECKED}""${GREEN}"" tested binaries.""${NC}"
    write_link "s16"
  fi

  if [[ "${STRCPY_CNT:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${STRCPY_CNT}""${GREEN}"" usages of strcpy in ""${ORANGE}""${BINS_CHECKED}""${GREEN}"" binaries.""${NC}"
    if [[ $(find "${LOG_DIR}""/s13_weak_func_check/" -type f 2>/dev/null | wc -l) -gt $(find "${LOG_DIR}""/s14_weak_func_radare_check/" -type f 2>/dev/null | wc -l) ]]; then
      write_link "s13"
    else
      write_link "s14"
    fi
    write_csv_log "strcpy" "${STRCPY_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi

  local DATA=0

  if [[ "${STRCPY_CNT:-0}" -gt 0 ]] && [[ -d "${LOG_DIR}""/s13_weak_func_check/" || -d "${LOG_DIR}""/s14_weak_func_radare_check/" ]] ; then

    # color codes for printf
    local RED_=""
    local GREEN_=""
    local ORANGE_=""
    local NC_=""

    # this is needed for EMBArk:
    if [[ -z "${TERM}" ]] || [[ "${TERM}" == "dumb" ]]; then
      RED_="$(tput -T xterm setaf 1)"
      GREEN_="$(tput -T xterm setaf 2)"
      ORANGE_="$(tput -T xterm setaf 3)"
      NC_="$(tput -T xterm sgr0)"
    else
      RED_="$(tput setaf 1)"
      GREEN_="$(tput setaf 2)"
      ORANGE_="$(tput setaf 3)"
      NC_="$(tput sgr0)"
    fi

    readarray -t RESULTS_STRCPY < <( find "${LOG_DIR}"/s1[34]*/ -xdev -iname "vul_func_*_strcpy-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_strcpy-/ strcpy /" | sed "s/\.txt//" 2> /dev/null || true)
    readarray -t RESULTS_SYSTEM < <( find "${LOG_DIR}"/s1[34]*/ -xdev -iname "vul_func_*_system-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_system-/ system /" | sed "s/\.txt//" 2> /dev/null || true)

    # strcpy:
    if [[ "${#RESULTS_STRCPY[@]}" -gt 0 ]] && [[ $(echo "${RESULTS_STRCPY[0]}" | awk '{print $1}') -gt 0 ]]; then
      print_ln
      print_output "[+] STRCPY - top 10 results:"
      if [[ -d "${LOG_DIR}""/s13_weak_func_check/" ]]; then
        write_link "s13#strcpysummary"
      else
        write_link "s14#strcpysummary"
      fi
      DATA=1
      printf "${GREEN_}\t%-5.5s| %-15.15s | common linux file: y/n | %-8.8s / %-8.8s| %-8.8s | %-9.9s | %-11.11s | %-10.10s | %-13.13s |${NC}\n" "COUNT" "BINARY NAME" "CWE CNT" "SEMGREP" "RELRO" "CANARY" "NX state" "SYMBOLS" "NETWORKING" | tee -a "${LOG_FILE}"
      for DETAIL_STRCPY in "${RESULTS_STRCPY[@]}" ; do
        binary_fct_output "${DETAIL_STRCPY}"
        write_csv_log "strcpy_bin" "${BINARY}" "${F_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA"
      done
      print_output "${NC}"
    fi

    # system:
    if [[ "${#RESULTS_SYSTEM[@]}" -gt 0 ]] && [[ $(echo "${RESULTS_SYSTEM[0]}" | awk '{print $1}') -gt 0 ]]; then
      print_ln
      print_output "[+] SYSTEM - top 10 results:"
      if [[ -d "${LOG_DIR}""/s13_weak_func_check/" ]]; then
        write_link "s13#systemsummary"
      else
        write_link "s14#systemsummary"
      fi
      DATA=1
      printf "${GREEN_}\t%-5.5s| %-15.15s | common linux file: y/n | %-8.8s / %-8.8s| %-8.8s | %-9.9s | %-11.11s | %-10.10s | %-13.13s |${NC}\n" "COUNT" "BINARY NAME" "CWE CNT" "SEMGREP" "RELRO" "CANARY" "NX state" "SYMBOLS" "NETWORKING" | tee -a "${LOG_FILE}"
      for DETAIL_SYSTEM in "${RESULTS_SYSTEM[@]}" ; do
        binary_fct_output "${DETAIL_SYSTEM}"
        write_csv_log "system_bin" "${BINARY}" "${F_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA"
      done
      print_output "${NC}"
    fi
  fi
  if [[ ${DATA} -eq 1 ]]; then
    print_bar
  fi
}

binary_fct_output() {
  local BINARY_DETAILS="${1:-}"
  export F_COUNTER=""
  F_COUNTER="$(echo "${BINARY_DETAILS}" | cut -d\  -f1)"
  export BINARY=""
  BINARY="$(echo "${BINARY_DETAILS}" | cut -d\  -f3)"
  local FCT=""
  FCT="$(echo "${BINARY_DETAILS}" | cut -d\  -f2)"
  local RELRO=""
  local CANARY=""
  local NX=""
  local SYMBOLS=""
  local NETWORKING=""
  local CWE_CNT=0
  local SEMGREP_CNT=0

  if grep -q "${BINARY}" "${LOG_DIR}"/"${S12_LOG}" 2>/dev/null; then
    if grep "${BINARY}" "${LOG_DIR}"/"${S12_LOG}" | grep -o -q "No RELRO"; then
      RELRO="${RED_}""No RELRO${NC_}"
    else
      RELRO="${GREEN_}""RELRO   ${NC_}"
    fi
    if grep "${BINARY}" "${LOG_DIR}"/"${S12_LOG}" | grep -o -q "No canary found"; then
      CANARY="${RED_}""No Canary${NC_}"
    else
      CANARY="${GREEN_}""Canary   ${NC_}"
    fi
    if grep "${BINARY}" "${LOG_DIR}"/"${S12_LOG}" | grep -o -q "NX disabled"; then
      NX="${RED_}""NX disabled${NC_}"
    else
      NX="${GREEN_}""NX enabled ${NC_}"
    fi
    if grep "${BINARY}" "${LOG_DIR}"/"${S12_LOG}" | grep -o -q "No Symbols"; then
      SYMBOLS="${GREEN_}""No Symbols${NC_}"
    else
      SYMBOLS="${RED_}""Symbols   ${NC_}"
    fi
  else
    RELRO="${ORANGE_}""RELRO unknown${NC_}"
    NX="${ORANGE_}""NX unknown${NC_}"
    CANARY="${ORANGE_}""CANARY unknown${NC_}"
    SYMBOLS="${ORANGE_}""Symbols unknown${NC_}"
  fi

  # networking
  if grep -q "/${BINARY} " "${CSV_DIR}"/s1[34]_*.csv 2>/dev/null; then
    if grep "/${BINARY} " "${CSV_DIR}"/s1[34]_*.csv | cut -d\; -f5 | sort -u | grep -o -q "no"; then
      NETWORKING="${GREEN_}""No Networking     ${NC_}"
    else
      NETWORKING="${RED_}""Networking        ${NC_}"
    fi
  else
    NETWORKING="${ORANGE_}""Networking unknown${NC_}"
  fi

  # cwe-checker and semgrep results per binary
  if [[ -f "${LOG_DIR}"/s17_cwe_checker/cwe_"${BINARY}".log ]]; then
    CWE_CNT=$(grep -Ec "CWE[0-9]+" "${LOG_DIR}""/s17_cwe_checker/cwe_""${BINARY}"".log" || true)
  fi
  if [[ -f "${LOG_DIR}"/s16_ghidra_decompile_checks/semgrep_"${BINARY}".csv ]]; then
    SEMGREP_CNT=$(wc -l "${LOG_DIR}/s16_ghidra_decompile_checks/semgrep_${BINARY}.csv" | awk '{print $1}' || true)
  fi
  if [[ -f "${BASE_LINUX_FILES}" ]]; then
    local FCT_LINK=""
    if [[ "${SEMGREP_CNT}" -gt 0 ]] && [[ -f "${LOG_DIR}"/s16_ghidra_decompile_checks/semgrep_"${BINARY}".log ]]; then
      # FCT_LINK="${LOG_DIR}"/s16_ghidra_decompile_checks/semgrep_"${BINARY}".log
      FCT_LINK="s16"
    else
      FCT_LINK=$(find "${LOG_DIR}"/s1[34]_weak_func_*check/ -name "vul_func_*${FCT}-${BINARY}*.txt" | sort -u | head -1 || true)
    fi
    [[ "${SEMGREP_CNT}" -eq 0 ]] && SEMGREP_CNT="NA"
    [[ "${CWE_CNT}" -eq 0 ]] && CWE_CNT="NA"

    # if we have the base linux config file we are checking it:
    if grep -E -q "^${BINARY}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
      printf "${GREEN_}\t%-5.5s| %-15.15s | common linux file: yes | Vulns: %-4.4s / %-4.4s | %-14.14s | %-15.15s | %-16.16s | %-15.15s | %-18.18s |${NC}\n" "${F_COUNTER}" "${BINARY}" "${CWE_CNT}" "${SEMGREP_CNT}" "${RELRO}" "${CANARY}" "${NX}" "${SYMBOLS}" "${NETWORKING}" | tee -a "${LOG_FILE}"
    else
      printf "${ORANGE_}\t%-5.5s| %-15.15s | common linux file: no  | Vulns: %-4.4s / %-4.4s | %-14.14s | %-15.15s | %-16.16s | %-15.15s | %-18.18s |${NC}\n" "${F_COUNTER}" "${BINARY}" "${CWE_CNT}" "${SEMGREP_CNT}" "${RELRO}" "${CANARY}" "${NX}" "${SYMBOLS}" "${NETWORKING}"| tee -a "${LOG_FILE}"
    fi
    write_link "${FCT_LINK}"
  else
    printf "${ORANGE_}\t%-5.5s| %-15.15s | common linux file: NA  | Vulns: %-4.4s / %-4.4s | %-14.14s | %-15.15s | %-16.16s | %-15.15s | %-18.18s |${NC}\n" "${F_COUNTER}" "${BINARY}" "${CWE_CNT}" "${SEMGREP_CNT}" "${RELRO}" "${CANARY}" "${NX}" "${SYMBOLS}" "${NETWORKING}" | tee -a "${LOG_FILE}"
    write_link "${FCT_LINK}"
  fi
}

output_cve_exploits() {
  local DATA=0
  local BINARY_=""

  if [[ "${S30_VUL_COUNTER:-0}" -gt 0 || "${CVE_COUNTER:-0}" -gt 0 || "${EXPLOIT_COUNTER:-0}" -gt 0 || -v VERSIONS_AGGREGATED[@] ]]; then
    if [[ "${CVE_COUNTER:-0}" -gt 0 || "${EXPLOIT_COUNTER:-0}" -gt 0 || -v VERSIONS_AGGREGATED[@] ]] && [[ -f "${LOG_DIR}/f20_vul_aggregator/F20_summary.txt" ]]; then
      print_output "[*] Identified the following software inventory, vulnerabilities and exploits:"
      write_link "f20#softwareinventoryinitialoverview"

      # run over F20_summary.txt and add links - need to do this here and not in f20 as there bites us the threading mode
      while read -r OVERVIEW_LINE; do
        BINARY_="$(echo "${OVERVIEW_LINE}" | cut -d: -f2 | tr -d '[:blank:]')"
        print_output "${OVERVIEW_LINE}"
        write_link "f20#cve_${BINARY_}"
      done < "${LOG_DIR}/f20_vul_aggregator/F20_summary.txt"
      print_ln
    fi

    if [[ -v VERSIONS_AGGREGATED[@] ]]; then
      if [[ -f "${LOG_DIR}"/f21_cyclonedx_sbom.txt ]]; then
        print_output "[+] Identified a SBOM including ""${ORANGE}""${#VERSIONS_AGGREGATED[@]}""${GREEN}"" software components with version details."
        write_link "f21"
      else
        print_output "[+] Identified ""${ORANGE}""${#VERSIONS_AGGREGATED[@]}""${GREEN}"" software components with version details.\\n"
        write_link "f20#softwareinventoryinitialoverview"
      fi
      write_csv_log "versions_identified" "${#VERSIONS_AGGREGATED[@]}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    fi
    if [[ "${S30_VUL_COUNTER:-0}" -gt 0 ]]; then
      print_output "[+] Found ""${ORANGE}""${S30_VUL_COUNTER}""${GREEN}"" CVE vulnerabilities in ""${ORANGE}""${#BINARIES[@]}""${GREEN}"" executables (without version checking).""${NC}"
      write_link "s30"
      DATA=1
    fi
    if [[ "${CVE_COUNTER:-0}" -gt 0 ]]; then
      echo -e "\n" >> "${LOG_FILE}"
      print_output "[+] Identified ""${ORANGE}""${CVE_COUNTER}""${GREEN}"" CVE entries."
      write_link "f20#collectcveandexploitdetails"
      print_output "$(indent "$(green "Identified ${RED}${BOLD}${HIGH_CVE_COUNTER}${NC}${GREEN} High rated CVE entries / Exploits: ${ORANGE}${EXPLOIT_HIGH_COUNT:-0}${NC}")")"
      print_output "$(indent "$(green "Identified ${ORANGE}${BOLD}${MEDIUM_CVE_COUNTER}${NC}${GREEN} Medium rated CVE entries / Exploits: ${ORANGE}${EXPLOIT_MEDIUM_COUNT:-0}${NC}")")"
      print_output "$(indent "$(green "Identified ${GREEN}${BOLD}${LOW_CVE_COUNTER}${NC}${GREEN} Low rated CVE entries /Exploits: ${ORANGE}${EXPLOIT_LOW_COUNT:-0}${NC}")")"
      write_csv_log "cve_high" "${HIGH_CVE_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "cve_medium" "${MEDIUM_CVE_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "cve_low" "${LOW_CVE_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      DATA=1
    elif [[ "${CVE_SEARCH}" -ne 1 ]]; then
      print_ln
      print_output "[!] WARNING: CVE-Search was not performed. The vulnerability results should be taken with caution!"
      print_ln
    fi
    if [[ "${EXPLOIT_COUNTER:-0}" -gt 0 ]] || [[ "${MSF_VERIFIED}" -gt 0 ]]; then
      write_csv_log "exploits" "${EXPLOIT_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      if [[ "${MSF_MODULE_CNT}" -gt 0 ]]; then
        print_output "$(indent "$(green "${MAGENTA}${BOLD}${EXPLOIT_COUNTER}${NC}${GREEN} possible exploits available (${MAGENTA}${MSF_MODULE_CNT}${GREEN} Metasploit modules).")")"
        write_link "f20#minimalreportofexploitsandcves"
        write_csv_log "metasploit_modules" "${MSF_MODULE_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      else
        print_output "$(indent "$(green "${MAGENTA}${BOLD}${EXPLOIT_COUNTER}${NC}${GREEN} possible exploits available.")")"
        write_link "f20#minimalreportofexploitsandcves"
      fi
      if [[ "${MSF_VERIFIED}" -gt 0 ]]; then
        print_output "$(indent "$(green "${MAGENTA}${BOLD}${MSF_VERIFIED}${NC}${GREEN} exploits in system mode emulation verified.")")"
        write_link "l35"
      fi
      if [[ "${REMOTE_EXPLOIT_CNT}" -gt 0 || "${LOCAL_EXPLOIT_CNT}" -gt 0 || "${DOS_EXPLOIT_CNT}" -gt 0 || "${GITHUB_EXPLOIT_CNT}" -gt 0 || "${KNOWN_EXPLOITED_COUNTER}" -gt 0 || "${MSF_VERIFIED}" -gt 0 ]]; then
        print_output "$(indent "$(green "Remote exploits: ${MAGENTA}${BOLD}${REMOTE_EXPLOIT_CNT}${NC}${GREEN} / Local exploits: ${MAGENTA}${BOLD}${LOCAL_EXPLOIT_CNT}${NC}${GREEN} / DoS exploits: ${MAGENTA}${BOLD}${DOS_EXPLOIT_CNT}${NC}${GREEN} / Github PoCs: ${MAGENTA}${BOLD}${GITHUB_EXPLOIT_CNT}${NC}${GREEN} / Known exploited vulnerabilities: ${MAGENTA}${BOLD}${KNOWN_EXPLOITED_COUNTER}${GREEN} / Verified Exploits: ${MAGENTA}${BOLD}${MSF_VERIFIED}${NC}")")"
        write_csv_log "remote_exploits" "${REMOTE_EXPLOIT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
        write_csv_log "local_exploits" "${LOCAL_EXPLOIT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
        write_csv_log "dos_exploits" "${DOS_EXPLOIT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
        write_csv_log "github_exploits" "${GITHUB_EXPLOIT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
        write_csv_log "known_exploited" "${KNOWN_EXPLOITED_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
        write_csv_log "verified_exploited" "${MSF_VERIFIED}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      fi
      # we report only software components with exploits to csv:
      grep "Found version details" "${LOG_DIR}/f20_vul_aggregator/F20_summary.txt" 2>/dev/null | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | tr -d "\[\+\]" | grep -v "CVEs: 0" | sed -e 's/Found version details:/version_details:/' |sed -e 's/[[:blank:]]//g' | sed -e 's/:/;/g' >> "${CSV_LOG}" || true
      DATA=1
    fi
  fi
  if [[ ${DATA} -eq 1 ]]; then
    print_bar
  fi
}

get_data() {
  export REMOTE_EXPLOIT_CNT=0
  export LOCAL_EXPLOIT_CNT=0
  export DOS_EXPLOIT_CNT=0
  export GITHUB_EXPLOIT_CNT=0
  export HIGH_CVE_COUNTER=0
  export MEDIUM_CVE_COUNTER=0
  export LOW_CVE_COUNTER=0
  export EXPLOIT_COUNTER=0
  export EXPLOIT_HIGH_COUNT=0
  export EXPLOIT_MEDIUM_COUNT=0
  export EXPLOIT_LOW_COUNT=0
  export MSF_MODULE_CNT=0
  export INT_COUNT=0
  export POST_COUNT=0
  export KNOWN_EXPLOITED_COUNTER=0
  export S30_VUL_COUNTER=0
  export ENTROPY=""
  export PRE_ARCH=""
  export EFI_ARCH=""
  export K_ARCH_END=""
  export P99_ARCH=""
  export P99_ARCH_END=""
  export FILE_ARR_COUNT=0
  export DETECTED_DIR=0
  export LINUX_DISTRIS=()
  export STRCPY_CNT_13=0
  export ARCH=""
  export K_ARCH=""
  export STRCPY_CNT_14=0
  export STRCPY_CNT=0
  export S20_SHELL_VULNS=0
  export S20_SCRIPTS=0
  export S21_PY_VULNS=0
  export S21_PY_SCRIPTS=0
  export S22_PHP_VULNS=0
  export S22_PHP_VULNS_SEMGREP=0
  export S22_PHP_SCRIPTS=0
  export S22_PHP_INI_ISSUES=0
  export S22_PHP_INI_CONFIGS=0
  export S24_FAILED_KSETTINGS=0
  export S16_GHIDRA_SEMGREP=0
  export S16_BINS_CHECKED=0
  export MOD_DATA_COUNTER=0
  export KMOD_BAD=0
  export S40_WEAK_PERM_COUNTER=0
  export PASS_FILES_FOUND=0
  export S50_AUTH_ISSUES=0
  export S55_HISTORY_COUNTER=0
  export TOTAL_CERT_CNT=0
  export CERT_CNT=0
  export CERT_OUT_CNT=0
  export CERT_WARNING_CNT=0
  export S85_SSH_VUL_CNT=0
  export INT_COUNT=0
  export POST_COUNT=0
  export PW_COUNTER=0
  export STACS_HASHES=0
  export HASHES_CRACKED=0
  export YARA_CNT=0
  export BOOTED=0
  export ICMP=0
  export TCP_0=0
  export IP_ADDR=0
  export MODE=""
  export SNMP_UP=0
  export WEB_UP=0
  export ROUTERSPLOIT_VULN=0
  export CVE_COUNTER=0
  export CVE_SEARCH=1
  export FWHUNTER_CNT=0
  # export FWHUNTER_CNT_CVE=0
  export MSF_VERIFIED=0
  export K_CVE_VERIFIED_SYMBOLS=0
  export K_CVE_VERIFIED_COMPILED=0
  export APK_ISSUES=0
  export GPT_RESULTS=0
  export TOTAL_CWE_CNT=0
  export TOTAL_CWE_BINS=0

  if [[ -f "${P02_CSV_LOG}" ]]; then
    ENTROPY=$(grep -a "Entropy" "${P02_CSV_LOG}" | cut -d\; -f2 | cut -d= -f2 | sed 's/^\ //' || true)
  fi
  if [[ -f "${LOG_DIR}"/"${P35_LOG}" ]]; then
    EFI_ARCH=$(grep -a "Possible architecture details found" "${LOG_DIR}"/"${P35_LOG}" | cut -d: -f2 | sed 's/\ //g' | tr '\r\n' '/' || true)
    EFI_ARCH="${EFI_ARCH%\/}"
    EFI_ARCH=$(strip_color_codes "${EFI_ARCH}")
  fi
  if [[ -f "${P99_LOG}" ]]; then
    P99_ARCH="$(grep -a "\[\*\]\ Statistics:" "${P99_LOG}" | cut -d: -f 2)"
    P99_ARCH_END="$(grep -a "\[\*\]\ Statistics:" "${P99_LOG}" | cut -d: -f 3)"
  fi
  if [[ -f "${S24_CSV_LOG}" ]]; then
    K_ARCH="$(tail -n +2 "${S24_CSV_LOG}" | cut -d\; -f 8 | sort -u | grep "\S" | head -1 || true)"
    K_ARCH_END="$(tail -n +2 "${S24_CSV_LOG}" | cut -d\; -f 9 | sort -u | grep "\S" | head -1 || true)"
  fi

  if [[ -f "${LOG_DIR}"/"${S02_LOG}" ]]; then
    # FWHUNTER_CNT_CVE=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S02_LOG}" | cut -d: -f2 || true)
    FWHUNTER_CNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S02_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S03_LOG}" ]]; then
    PRE_ARCH="$(strip_color_codes "$(grep -a "Possible architecture details found" "${LOG_DIR}"/"${S03_LOG}" | cut -d: -f2 | sed 's/\ //g' | tr '\r\n' ' ' | sed 's/\ /\ \//' || true)")"
    PRE_ARCH="${PRE_ARCH%\/}"
  fi
  if [[ -f "${LOG_DIR}"/"${S05_LOG}" ]]; then
    FILE_ARR_COUNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S05_LOG}" | cut -d: -f2 || true)
    DETECTED_DIR=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S05_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S06_LOG}" ]]; then
    mapfile -t LINUX_DISTRIS < <(grep "Version information found" "${LOG_DIR}"/"${S06_LOG}" | cut -d\  -f5- | sed 's/ in file .*//' | sort -u || true)
  fi
  if ! [[ "${FILE_ARR_COUNT-0}" -gt 0 ]]; then
    FILE_ARR_COUNT=$(find "${FIRMWARE_PATH_CP}" -type f 2>/dev/null| wc -l || true)
    DETECTED_DIR=$(find "${FIRMWARE_PATH_CP}" -type d 2>/dev/null | wc -l || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S13_LOG}" ]]; then
    STRCPY_CNT_13=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S13_LOG}" | cut -d: -f2 || true)
    ARCH=$(grep -a "\[\*\]\ Statistics1:" "${LOG_DIR}"/"${S13_LOG}" | cut -d: -f2 || true)
  else
    STRCPY_CNT_13=0
  fi
  if [[ -f "${LOG_DIR}"/"${S14_LOG}" ]]; then
    STRCPY_CNT_14=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S14_LOG}" | cut -d: -f2 || true)
    ARCH=$(grep -a "\[\*\]\ Statistics1:" "${LOG_DIR}"/"${S14_LOG}" | cut -d: -f2 || true)
    STRCPY_CNT=$((STRCPY_CNT_14+STRCPY_CNT_13))
  else
    STRCPY_CNT="${STRCPY_CNT_13}"
  fi
  if [[ -f "${LOG_DIR}"/"${S16_LOG}" ]]; then
    S16_GHIDRA_SEMGREP=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S16_LOG}" | cut -d: -f2 || true)
    S16_BINS_CHECKED=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S16_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S20_LOG}" ]]; then
    S20_SHELL_VULNS=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S20_LOG}" | cut -d: -f2 || true)
    S20_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S20_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S21_LOG}" ]]; then
    S21_PY_VULNS=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S21_LOG}" | cut -d: -f2 || true)
    S21_PY_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S21_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S22_LOG}" ]]; then
    S22_PHP_VULNS=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S22_LOG}" | cut -d: -f2 || true)
    S22_PHP_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S22_LOG}" | cut -d: -f3 || true)
    S22_PHP_INI_ISSUES=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S22_LOG}" | cut -d: -f4 || true)
    S22_PHP_INI_CONFIGS=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S22_LOG}" | cut -d: -f5 || true)
    S22_PHP_VULNS_SEMGREP=$(grep -a "\[\*\]\ Statistics1:" "${LOG_DIR}"/"${S22_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S24_LOG}" ]]; then
    # we currently only respect one kernel settings analysis in our final aggregator.
    S24_FAILED_KSETTINGS=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S24_LOG}" | cut -d: -f2 | head -1 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S25_LOG}" ]]; then
    MOD_DATA_COUNTER=$(grep -a "\[\*\]\ Statistics1:" "${LOG_DIR}"/"${S25_LOG}" | cut -d: -f2 || true)
    KMOD_BAD=$(grep -a "\[\*\]\ Statistics1:" "${LOG_DIR}"/"${S25_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S26_LOG}" ]]; then
    K_CVE_VERIFIED_SYMBOLS=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S26_LOG}" | cut -d: -f4 || true)
    K_CVE_VERIFIED_COMPILED=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S26_LOG}" | cut -d: -f5 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S30_LOG}" ]]; then
    S30_VUL_COUNTER=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S30_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S40_LOG}" ]]; then
    S40_WEAK_PERM_COUNTER=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S40_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S45_LOG}" ]]; then
    PASS_FILES_FOUND=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S45_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S50_LOG}" ]]; then
    S50_AUTH_ISSUES=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S50_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S55_LOG}" ]]; then
    S55_HISTORY_COUNTER=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S55_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S60_LOG}" ]]; then
    TOTAL_CERT_CNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S60_LOG}" | cut -d: -f2 || true)
    CERT_CNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S60_LOG}" | cut -d: -f3 || true)
    CERT_OUT_CNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S60_LOG}" | cut -d: -f4 || true)
    CERT_WARNING_CNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S60_LOG}" | cut -d: -f5 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S85_LOG}" ]]; then
    S85_SSH_VUL_CNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S85_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S95_LOG}" ]]; then
    INT_COUNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S95_LOG}" | cut -d: -f2 || true)
    POST_COUNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S95_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S107_LOG}" ]]; then
    PW_COUNTER=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S107_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S108_LOG}" ]]; then
    STACS_HASHES=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S108_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S109_LOG}" ]]; then
    HASHES_CRACKED=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S109_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S110_LOG}" ]]; then
    YARA_CNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S110_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${LOG_DIR}"/"${S17_LOG}" ]]; then
    TOTAL_CWE_CNT=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S17_LOG}" | cut -d: -f2 || true)
    TOTAL_CWE_BINS=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${S17_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${SYS_EMU_RESULTS}" ]]; then
    BOOTED=$(grep -c "Booted yes;" "${SYS_EMU_RESULTS}" || true)
    ICMP=$(grep -c "ICMP ok;" "${SYS_EMU_RESULTS}" || true)
    TCP_0=$(grep -c "TCP-0 ok;" "${SYS_EMU_RESULTS}" || true)
    TCP=$(grep -c "TCP ok;" "${SYS_EMU_RESULTS}" || true)
    IP_ADDR=$(grep -e "Booted yes;\|ICMP ok;\|TCP-0 ok;\|TCP ok" "${SYS_EMU_RESULTS}" | grep -E -c "IP\ address:\ [0-9]+" || true)
    # we make something like this: "bridge-default-normal"
    MODE=$(grep -e "Booted yes;\|ICMP ok;\|TCP-0 ok;\|TCP ok" "${SYS_EMU_RESULTS}" | cut -d\; -f9 | sed 's/Network mode: //g'| tr -d '[:blank:]' | cut -d\( -f1 | sort -u | tr '\n' '-' | sed 's/-$//g' || true)
  fi
  if [[ -f "${LOG_DIR}"/"${L15_LOG}" ]]; then
    # NMAP_UP=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${L15_LOG}" | cut -d: -f2 || true)
    SNMP_UP=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${L20_LOG}" | cut -d: -f2 || true)
    WEB_UP=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${L25_LOG}" | cut -d: -f2 || true)
    ROUTERSPLOIT_VULN=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${L30_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${L35_CSV_LOG}" ]]; then
    MSF_VERIFIED=$(grep -v -c "Source" "${L35_CSV_LOG}" || true)
  fi
  if [[ -f "${LOG_DIR}"/"${CVE_AGGREGATOR_LOG}" ]]; then
    CVE_SEARCH=$(grep -a "\[\*\]\ Statistics:" "${LOG_DIR}"/"${CVE_AGGREGATOR_LOG}" | sort -u | cut -d: -f2 || true)
  fi
  if [[ -f "${TMP_DIR}"/HIGH_CVE_COUNTER.tmp ]]; then
    HIGH_CVE_COUNTER=$(awk '{ sum += $1 } END { print sum }' "${TMP_DIR}"/HIGH_CVE_COUNTER.tmp)
    (( CVE_COUNTER="${CVE_COUNTER}"+"${HIGH_CVE_COUNTER}" ))
  fi
  if [[ -f "${TMP_DIR}"/MEDIUM_CVE_COUNTER.tmp ]]; then
    MEDIUM_CVE_COUNTER=$(awk '{ sum += $1 } END { print sum }' "${TMP_DIR}"/MEDIUM_CVE_COUNTER.tmp)
    (( CVE_COUNTER="${CVE_COUNTER}"+"${MEDIUM_CVE_COUNTER}" ))
  fi
  if [[ -f "${TMP_DIR}"/LOW_CVE_COUNTER.tmp ]]; then
    LOW_CVE_COUNTER=$(awk '{ sum += $1 } END { print sum }' "${TMP_DIR}"/LOW_CVE_COUNTER.tmp)
    (( CVE_COUNTER="${CVE_COUNTER}"+"${LOW_CVE_COUNTER}" ))
  fi
  if [[ -f "${TMP_DIR}"/KNOWN_EXPLOITED_COUNTER.tmp ]]; then
    KNOWN_EXPLOITED_COUNTER=$(cat "${TMP_DIR}"/KNOWN_EXPLOITED_COUNTER.tmp)
  fi
  if [[ -f "${F20_EXPLOITS_LOG}" ]]; then
    # EXPLOIT_COUNTER="$(grep -c -E "Exploit\ .*" "${F20_EXPLOITS_LOG}" || true)"
    EXPLOIT_COUNTER="$(grep -E "Exploit\ .*" "${F20_EXPLOITS_LOG}" | grep -cv "Exploit summary" || true)"
    MSF_MODULE_CNT="$(grep -c -E "Exploit\ .*MSF" "${F20_EXPLOITS_LOG}" || true)"
    REMOTE_EXPLOIT_CNT="$(grep -c -E "Exploit\ .*\ \(R\)" "${F20_EXPLOITS_LOG}" || true)"
    LOCAL_EXPLOIT_CNT="$(grep -c -E "Exploit\ .*\ \(L\)" "${F20_EXPLOITS_LOG}" || true)"
    DOS_EXPLOIT_CNT="$(grep -c -E "Exploit\ .*\ \(D\)" "${F20_EXPLOITS_LOG}" || true)"
    GITHUB_EXPLOIT_CNT="$(grep -c -E "Exploit\ .*\ \(G\)" "${F20_EXPLOITS_LOG}" || true)"
    if [[ -f "${TMP_DIR}"/EXPLOIT_HIGH_COUNTER.tmp ]]; then
      EXPLOIT_HIGH_COUNT="$(cat "${TMP_DIR}"/EXPLOIT_HIGH_COUNTER.tmp || true)"
    fi
    if [[ -f "${TMP_DIR}"/EXPLOIT_MEDIUM_COUNTER.tmp ]]; then
      EXPLOIT_MEDIUM_COUNT="$(cat "${TMP_DIR}"/EXPLOIT_MEDIUM_COUNTER.tmp || true)"
    fi
    if [[ -f "${TMP_DIR}"/EXPLOIT_LOW_COUNTER.tmp ]]; then
      EXPLOIT_LOW_COUNT="$(cat "${TMP_DIR}"/EXPLOIT_LOW_COUNTER.tmp || true)"
    fi
  fi
  if [[ -f "${S17_CSV_LOG}" ]]; then
    APK_ISSUES="$(cut -d\; -f 2 "${S17_CSV_LOG}" | awk '{ sum += $1 } END { print sum }' || true)"
  fi
}

distribution_detector() {
  local DISTRI=""

  for DISTRI in "${LINUX_DISTRIS[@]}"; do
    print_output "[+] Linux distribution detected: ${ORANGE}${DISTRI}${NC}"
    write_link "s06"
  done
}

os_detector() {
  export VERIFIED=0
  export VERIFIED_S03=0
  export SYSTEM=""
  local OSES=("kernel" "vxworks" "siprotec" "freebsd" "qnx\ neutrino\ rtos" "simatic\ cp443-1")
  local OS_TO_CHECK=""
  local OS_DETECT=()
  local SYSTEM_VER=""
  local SYSTEM_VERSION=()

  #### The following check is based on the results of the aggregator:
  if [[ -f "${LOG_DIR}"/"${CVE_AGGREGATOR_LOG}" ]]; then
    for OS_TO_CHECK in "${OSES[@]}"; do
      mapfile -t SYSTEM_VERSION < <(grep -i "Found Version details" "${LOG_DIR}"/"${CVE_AGGREGATOR_LOG}" | grep aggregated | grep "${OS_TO_CHECK}" | cut -d: -f3 | sed -e 's/[[:blank:]]//g' | sort -u || true)
      if [[ "${#SYSTEM_VERSION[@]}" -gt 0 ]]; then
        if [[ "${OS_TO_CHECK}" == "kernel" ]]; then
          SYSTEM="Linux"
        elif [[ "${OS_TO_CHECK}" == "siprotec" ]]; then
          SYSTEM="SIPROTEC"
        elif [[ "${OS_TO_CHECK}" == "vxworks" ]]; then
          SYSTEM="VxWorks"
        elif [[ "${OS_TO_CHECK}" == "freebsd" ]]; then
          SYSTEM="FreeBSD"
        elif [[ "${OS_TO_CHECK}" == "qnx\ neutrino\ rtos" ]]; then
          SYSTEM="QNX Neutrino"
        elif [[ "${OS_TO_CHECK}" == "simatic\ cp443-1" ]]; then
          SYSTEM="Siemens CP443-1"
        else
          SYSTEM="${OS_TO_CHECK}"
        fi
        # version detected -> verified linux
        for SYSTEM_VER in "${SYSTEM_VERSION[@]}"; do
          SYSTEM_VER=$(strip_color_codes "${SYSTEM_VER}")
          SYSTEM="${SYSTEM}"" / v${SYSTEM_VER}"
          VERIFIED=1
        done
        if [[ ${VERIFIED} -eq 1 ]]; then
          print_os "${SYSTEM}"
        fi
      fi
    done
  fi

  #### The following check is needed if the aggreagator has failed till now
  if [[ ${VERIFIED} -eq 0 && -f "${LOG_DIR}"/"${S03_LOG}" ]]; then
    # the OS was not verified in the first step (but we can try to verify it now with more data of other modules)
    mapfile -t OS_DETECT < <(grep "verified.*operating\ system\ detected" "${LOG_DIR}"/"${S03_LOG}" 2>/dev/null | cut -d: -f1,2 | awk '{print $2 " - #" $5}' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" || true)
    if [[ "${#OS_DETECT[@]}" -gt 0 ]]; then
      for SYSTEM in "${OS_DETECT[@]}"; do
        VERIFIED_S03=1
        VERIFIED=1
        print_os "${SYSTEM}"
      done
    fi

    # we print the unverified OS only if we have no verified results:
    mapfile -t OS_DETECT < <(grep "\ detected" "${LOG_DIR}"/"${S03_LOG}" 2>/dev/null | cut -d: -f1,2 | awk '{print $2 " - #" $5}' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | sort -r -n -t '#' -k2 || true)

    if [[ "${#OS_DETECT[@]}" -gt 0 && "${VERIFIED}" -eq 0 ]]; then
      for SYSTEM in "${OS_DETECT[@]}"; do
        VERIFIED=0
        print_os "${SYSTEM}"
      done
    fi
  fi

  #### The following check is just in place if something went wrong
  if [[ ${VERIFIED} -eq 0 ]]; then
    # usually the results of the kernel module checker are already used in f20 (first os check)
    # but just in case something went wrong we use it now
    os_kernel_module_detect
    if [[ ${VERIFIED} -eq 1 ]]; then
      print_os "${SYSTEM}"
    fi
  fi
}

os_kernel_module_detect() {
  local LINUX_VERSIONS=""
  local KV=""
  local KERNELV=()

  if [[ -f "${LOG_DIR}"/"${S25_LOG}" ]]; then
    mapfile -t KERNELV < <(grep "Statistics:" "${LOG_DIR}"/"${S25_LOG}" | cut -d: -f2 | sort -u || true)
    if [[ "${#KERNELV[@]}" -ne 0 ]]; then
      # if we have found a kernel it is a Linux system:
      LINUX_VERSIONS="Linux"
      for KV in "${KERNELV[@]}"; do
        LINUX_VERSIONS="${LINUX_VERSIONS}"" / v${KV}"
        VERIFIED=1
      done
      SYSTEM="${LINUX_VERSIONS}"
    fi
  fi
}

print_os() {
  local SYSTEM="${1:-}"

  if [[ ${VERIFIED} -eq 1 ]]; then
    if [[ "${VERIFIED_S03}" -eq 1 ]]; then
      SYSTEM=$(echo "${SYSTEM}" | awk '{print $1}')
      print_output "[+] Operating system detected (""${ORANGE}""verified${GREEN}): ${ORANGE}${SYSTEM}${NC}"
      write_link "s03"
    else
      print_output "[+] Operating system detected (""${ORANGE}""verified${GREEN}): ${ORANGE}${SYSTEM}${NC}"
      write_link "s25"
    fi
    write_csv_log "os_verified" "${SYSTEM}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  else
    print_output "[+] Possible operating system detected (""${ORANGE}""unverified${GREEN}): ${ORANGE}${SYSTEM}${NC}"
    write_link "s03"
    if [[ "$(grep -c os_verified "${CSV_LOG}")" -lt 1 ]]; then
      write_csv_log "os_verified" "unknown" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    fi
    write_csv_log "os_unverified" "${SYSTEM}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi
}

cwe_logging() {
  local LOG_DIR_MOD="s17_cwe_checker"
  local CWE_OUT=()
  local CWE_ENTRY=""
  local CWE=""
  local CWE_DESC=""
  local CWE_CNT=""

  if [[ -d "${LOG_DIR}"/"${LOG_DIR_MOD}" ]]; then
    # mapfile -t CWE_OUT < <( cat "${LOG_DIR}"/"${LOG_DIR_MOD}"/cwe_*.log 2>/dev/null | grep -v "ERROR\|DEBUG\|INFO" | grep "CWE[0-9]" | sed -z 's/[0-9]\.[0-9]//g' | cut -d\( -f1,3 | cut -d\) -f1 | sort -u | tr -d '(' | tr -d "[" | tr -d "]" || true)
    mapfile -t CWE_OUT < <( jq -r '.[] | "\(.name) \(.description)"' "${LOG_DIR}"/"${LOG_DIR_MOD}"/cwe_*.log | cut -d\) -f1 | tr -d '('  | sort -u|| true)

    if [[ ${#CWE_OUT[@]} -gt 0 ]] ; then
      print_output "[+] cwe-checker found a total of ""${ORANGE}""${TOTAL_CWE_CNT}""${GREEN}"" security issues in ${ORANGE}${TOTAL_CWE_BINS}${GREEN} tested binaries:"
      write_link "s17"
      for CWE_ENTRY in "${CWE_OUT[@]}"; do
        CWE="$(echo "${CWE_ENTRY}" | awk '{print $1}')"
        CWE_DESC="$(echo "${CWE_ENTRY}" | cut -d\  -f2-)"
        # do not change this to grep -c!
        # shellcheck disable=SC2126
        CWE_CNT="$(grep "${CWE}" "${LOG_DIR}"/"${LOG_DIR_MOD}"/cwe_*.log 2>/dev/null | wc -l || true)"
        print_output "$(indent "$(orange "${CWE}""${GREEN}"" - ""${CWE_DESC}"" - ""${ORANGE}""${CWE_CNT}"" times.")")"
      done
      print_ln
      write_csv_log "cwe_issues" "${TOTAL_CWE_CNT}" "${TOTAL_CWE_BINS}" "NA" "NA" "NA" "NA" "NA" "NA"
    fi
  fi
}
