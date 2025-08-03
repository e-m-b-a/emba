#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2021-2025 Siemens Energy AG
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
  local lEMBA_COMMAND_ORIG=""

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
    local lFW_PATH_ORIG_ARR=()
    local lFW_PATH_ORIG=""
    # we need to rewrite this firmware path to the original path
    mapfile -t lFW_PATH_ORIG_ARR < <(sort -u "${TMP_DIR}"/fw_name.log)
    lEMBA_COMMAND_ORIG="$(sort -u "${TMP_DIR}"/emba_command.log)"
    for lFW_PATH_ORIG in "${lFW_PATH_ORIG_ARR[@]}"; do
      print_output "[+] Tested firmware:""${ORANGE}"" ""${lFW_PATH_ORIG}""${NC}"
      write_csv_log "FW_path" "${lFW_PATH_ORIG}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    done
    print_output "[+] EMBA start command:""${ORANGE}"" ""${lEMBA_COMMAND_ORIG}""${NC}"
    write_csv_log "emba_command" "${lEMBA_COMMAND_ORIG}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  else
    print_output "[+] Tested firmware:""${ORANGE}"" ""${FIRMWARE_PATH}""${NC}"
    write_csv_log "FW_path" "${FIRMWARE_PATH}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    print_output "[+] EMBA start command:""${ORANGE}"" ""${EMBA_COMMAND}""${NC}"
    write_csv_log "emba_command" "${EMBA_COMMAND}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi

  # EMBA details
  local lSBOM_TOOL_VERS=""
  lSBOM_TOOL_VERS="$(cat "${CONFIG_DIR}"/VERSION.txt)"
  if [[ -d "${INVOCATION_PATH}/.git" ]]; then
    git config --global --add safe.directory "${INVOCATION_PATH}"
    lCURRENT_GIT_BRANCH=$(git branch --show-current 2>/dev/null || echo "NA")
    if [[ -f "${INVOCATION_PATH}/.git/refs/heads/${lCURRENT_GIT_BRANCH}" ]]; then
      lSBOM_TOOL_VERS+=" / branch ${lCURRENT_GIT_BRANCH} / commit $(cat "${INVOCATION_PATH}/.git/refs/heads/${lCURRENT_GIT_BRANCH}")"
    fi
  fi
  print_output "[+] EMBA version: ""${ORANGE}""${lSBOM_TOOL_VERS}""${NC}"
  write_csv_log "EMBA_version" "${lSBOM_TOOL_VERS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"

  if [[ -f "${Q02_LOG}" ]] && [[ "${GPT_OPTION}" -gt 0 ]]; then
    lGPT_RESULTS_CNT=$(grep -c "AI analysis for" "${Q02_LOG}" || true)
    if [[ "${lGPT_RESULTS_CNT}" -gt 0 ]]; then
      print_output "[+] EMBA AI analysis discovered ${ORANGE}${lGPT_RESULTS_CNT}${GREEN} results."
      write_link "q02"
    fi
  fi

  if [[ -n "${ARCH}" ]] && [[ "${ARCH}" != "NA" ]]; then
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
  elif [[ -f "${S03_LOG}" ]]; then
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
  local lDATA_GENERATED=0
  local lSTATE_FOR_OUTPUT=""
  local lEMU_STATE_FOR_CSV=""
  local lUSER_EMUL_CNT=0
  local lENTROPY_PIC_PATH=""

  if [[ "${FILE_ARR_COUNT:-0}" -gt 0 ]]; then
    print_output "[+] ""${ORANGE}""${FILE_ARR_COUNT}""${GREEN}"" files and ""${ORANGE}""${DETECTED_DIR}"" ""${GREEN}""directories detected."
    if [[ -f "${S05_LOG}" ]]; then
      write_link "s05"
    else
      write_link "p99"
    fi
    write_csv_log "files" "${FILE_ARR_COUNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "directories" "${DETECTED_DIR}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi
  lENTROPY_PIC_PATH=$(find "${LOG_DIR}" -xdev -maxdepth 1 -type f -iname "*_entropy.png" 2> /dev/null)
  if [[ -n "${ENTROPY}" ]]; then
    print_output "[+] Entropy analysis of binary firmware is: ""${ORANGE}""${ENTROPY}"
    write_link "p02"
    write_csv_log "entropy_value" "${ENTROPY}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi
  if [[ -n "${lENTROPY_PIC_PATH}" ]]; then
    print_output "[+] Entropy analysis of binary firmware is available:""${ORANGE}"" ""${lENTROPY_PIC_PATH}"
    write_link "${lENTROPY_PIC_PATH}"
    lDATA_GENERATED=1
  fi

  if [[ "${S20_SHELL_VULNS:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${S20_SHELL_VULNS}"" issues""${GREEN}"" in ""${ORANGE}""${S20_SCRIPTS}""${GREEN}"" shell scripts.""${NC}"
    write_link "s20"
    write_csv_log "shell_scripts" "${S20_SCRIPTS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "shell_script_vulns" "${S20_SHELL_VULNS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi
  if [[ "${S21_PY_VULNS:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${S21_PY_VULNS}"" vulnerabilities""${GREEN}"" in ""${ORANGE}""${S21_PY_SCRIPTS}""${GREEN}"" python files.""${NC}"
    write_link "s21"
    write_csv_log "python_scripts" "${S21_PY_SCRIPTS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "python_vulns" "${S21_PY_VULNS}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
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
    lDATA_GENERATED=1
  fi
  if [[ "${YARA_CNT:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${YARA_CNT}""${GREEN}"" yara rule matches in ${ORANGE}${#FILE_ARR[@]}${GREEN} files.""${NC}"
    write_link "s110"
    write_csv_log "yara_rules_match" "${YARA_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi
  if [[ "${FWHUNTER_CNT:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${FWHUNTER_CNT}""${GREEN}"" UEFI vulnerabilities.""${NC}"
    write_link "s02"
    write_csv_log "uefi_vulns" "${FWHUNTER_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi

  lUSER_EMUL_CNT=$(cut -d\; -f1 "${CSV_DIR}"/s116_qemu_version_detection.csv 2>/dev/null | grep -v "binary/file" | sort -u | wc -l || true)
  if [[ "${lUSER_EMUL_CNT:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${lUSER_EMUL_CNT}""${GREEN}"" successful emulated processes ${ORANGE}(${GREEN}user mode emulation${ORANGE})${GREEN}.""${NC}"
    write_link "s116"
    write_csv_log "user_emulation_state" "${lUSER_EMUL_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi

  if [[ "${lGPT_RESULTS_CNT:-0}" -gt 0 ]]; then
    print_output "[+] EMBA AI tests identified ${ORANGE}${lGPT_RESULTS_CNT}${GREEN} results via ChatGPT."
    write_link "q02"
    write_csv_log "AI results" "${lGPT_RESULTS_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi

  if [[ "${BOOTED:-0}" -gt 0 ]] || [[ "${IP_ADDR:-0}" -gt 0 ]]; then
    lSTATE_FOR_OUTPUT="${ORANGE}(""${GREEN}""booted"
    lEMU_STATE_FOR_CSV="booted"
    if [[ "${IP_ADDR}" -gt 0 ]]; then
      lSTATE_FOR_OUTPUT="${lSTATE_FOR_OUTPUT}""${ORANGE} / ""${GREEN}""IP address detected (mode: ${ORANGE}${MODE}${GREEN})"
      lEMU_STATE_FOR_CSV="${lEMU_STATE_FOR_CSV}"";IP_DET"
    fi
    if [[ "${ICMP:-0}" -gt 0 || "${TCP_0:-0}" -gt 0 ]]; then
      lSTATE_FOR_OUTPUT="${lSTATE_FOR_OUTPUT}""${ORANGE} / ""${GREEN}""ICMP"
      lEMU_STATE_FOR_CSV="${lEMU_STATE_FOR_CSV}"";ICMP"
    fi
    if [[ "${TCP:-0}" -gt 0 ]]; then
      lSTATE_FOR_OUTPUT="${lSTATE_FOR_OUTPUT}""${ORANGE} / ""${GREEN}""NMAP"
      lEMU_STATE_FOR_CSV="${lEMU_STATE_FOR_CSV}"";NMAP"
    fi
    if [[ "${SNMP_UP:-0}" -gt 0 ]]; then
      lSTATE_FOR_OUTPUT="${lSTATE_FOR_OUTPUT}""${ORANGE} / ""${GREEN}""SNMP"
      lEMU_STATE_FOR_CSV="${lEMU_STATE_FOR_CSV}"";SNMP"
    fi
    if [[ "${WEB_UP:-0}" -gt 0 ]]; then
      lSTATE_FOR_OUTPUT="${lSTATE_FOR_OUTPUT}""${ORANGE} / ""${GREEN}""WEB"
      lEMU_STATE_FOR_CSV="${lEMU_STATE_FOR_CSV}"";WEB"
    fi
    if [[ "${ROUTERSPLOIT_VULN:-0}" -gt 0 ]]; then
      lSTATE_FOR_OUTPUT="${lSTATE_FOR_OUTPUT}""${ORANGE} / ""${GREEN}""Routersploit"
      lEMU_STATE_FOR_CSV="${lEMU_STATE_FOR_CSV}"";Routersploit"
    fi
    if [[ "${MSF_VERIFIED}" -gt 0 ]]; then
      lSTATE_FOR_OUTPUT="${lSTATE_FOR_OUTPUT}""${ORANGE} / ""${GREEN}""Exploited"
      lEMU_STATE_FOR_CSV="${lEMU_STATE_FOR_CSV}"";Exploited"
    fi
    lSTATE_FOR_OUTPUT="${lSTATE_FOR_OUTPUT}${ORANGE}"")${NC}"

    print_output "[+] System emulation was successful ${lSTATE_FOR_OUTPUT}" "" "l10"
    write_csv_log "system_emulation_state" "${lEMU_STATE_FOR_CSV}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
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
    lDATA_GENERATED=1
    write_csv_log "kernel_verified" "${K_CVE_VERIFIED_SYMBOLS:-0}" "${K_CVE_VERIFIED_COMPILED:-0}" "NA" "NA" "NA" "NA" "NA" "NA"
  fi

  if [[ ${lDATA_GENERATED} -eq 1 ]]; then
    print_bar
  fi
}

output_config_issues() {
  local lDATA_GENERATED=0

  if [[ "${PW_COUNTER:-0}" -gt 0 || "${S85_SSH_VUL_CNT:-0}" -gt 0 || "${STACS_HASHES:-0}" -gt 0 || "${INT_COUNT:-0}" -gt 0 || "${POST_COUNT:-0}" -gt 0 || "${MOD_DATA_COUNTER:-0}" -gt 0 || "${S40_WEAK_PERM_COUNTER:-0}" -gt 0 || "${S55_HISTORY_COUNTER:-0}" -gt 0 || "${S50_AUTH_ISSUES:-0}" -gt 0 || "${PASS_FILES_FOUND:-0}" -gt 0 || "${TOTAL_CERT_CNT:-0}" -gt 0 || "${S24_FAILED_KSETTINGS:-0}" -gt 0 ]]; then
    print_output "[+] Found the following configuration issues:"
    if [[ "${S40_WEAK_PERM_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${S40_WEAK_PERM_COUNTER}${GREEN} areas with weak permissions.")")"
      write_link "s40"
      write_csv_log "weak_perm_count" "${S40_WEAK_PERM_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
    fi
    if [[ "${S55_HISTORY_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${S55_HISTORY_COUNTER}${GREEN} history files.")")"
      write_link "s55"
      write_csv_log "history_file_count" "${S55_HISTORY_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
    fi
    if [[ "${S50_AUTH_ISSUES:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${S50_AUTH_ISSUES}${GREEN} authentication issues.")")"
      write_link "s50"
      write_csv_log "auth_issues" "${S50_AUTH_ISSUES}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
    fi
    if [[ "${S85_SSH_VUL_CNT:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${S85_SSH_VUL_CNT}${GREEN} SSHd issues.")")"
      write_link "s85"
      write_csv_log "ssh_issues" "${S85_SSH_VUL_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
    fi
    if [[ "${PW_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${PW_COUNTER}${GREEN} password related details.")")"
      write_link "s107"
      write_csv_log "password_hashes" "${PW_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
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
      lDATA_GENERATED=1
    fi
    if [[ "${TOTAL_CERT_CNT:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${CERT_OUT_CNT}${GREEN} outdated certificates and ${ORANGE}${CERT_WARNING_CNT} expiring certificates in ${ORANGE}${CERT_CNT}${GREEN} certificate files and in a total of ${ORANGE}${TOTAL_CERT_CNT}${GREEN} certificates.")")"
      write_link "s60"
      write_csv_log "total_certificates" "${TOTAL_CERT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "certificate_files" "${CERT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "certificates_outdated" "${CERT_OUT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "certificates_expiring" "${CERT_WARNING_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
    fi
    if [[ "${MOD_DATA_COUNTER:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${MOD_DATA_COUNTER}${GREEN} kernel modules with ${ORANGE}${KMOD_BAD}${GREEN} licensing issues.")")"
      write_link "s25#kernel_modules"
      write_csv_log "kernel_modules" "${MOD_DATA_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "kernel_modules_lic" "${KMOD_BAD}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
    fi
    if [[ "${S24_FAILED_KSETTINGS:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${S24_FAILED_KSETTINGS}${GREEN} security related kernel settings for review.")")"
      write_link "s24"
      write_csv_log "kernel_settings" "${S24_FAILED_KSETTINGS:-0}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
    fi
    if [[ "${INT_COUNT:-0}" -gt 0 || "${POST_COUNT:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${INT_COUNT}${GREEN} interesting files and ${ORANGE}${POST_COUNT:-0}${GREEN} files that could be useful for post-exploitation.")")"
      write_link "s95"
      write_csv_log "interesting_files" "${INT_COUNT:-0}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "post_files" "${POST_COUNT:-0}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
    fi
    if [[ "${APK_ISSUES:-0}" -gt 0 ]]; then
      print_output "$(indent "$(green "Found ${ORANGE}${APK_ISSUES}${GREEN} issues in Android APK packages.")")"
      write_link "s17"
      write_csv_log "apk_issues" "${APK_ISSUES}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    fi
  fi
  if [[ ${lDATA_GENERATED} -eq 1 ]]; then
    print_bar
  fi
}

output_binaries() {
  local lDATA_GENERATED=0
  local lBIN_CANARY_CNT=0
  local lBINS_RELRO_CNT=0
  local lBIN_NX_CNT=0
  local lBINS_PIE_CNT=0
  local lBIN_STRIPPED_CNT=0
  local lBINS_CHECKED_CNT=0
  local lCANARY_PER=0
  local lRELRO_PER=0
  local lNX_PER=0
  local lPIE_PER=0
  local lSTRIPPED_PER=0
  local lRESULTS_STRCPY_ARR=()
  local lRESULTS_SYSTEM_ARR=()
  local lDETAIL_STRCPY=0
  local lDETAIL_SYSTEM=0

  if [[ -f "${S12_CSV_LOG}" ]]; then
    lBIN_CANARY_CNT=$(grep -c "No Canary" "${S12_CSV_LOG}" || true)
    lBINS_RELRO_CNT=$(grep -c "No RELRO" "${S12_CSV_LOG}" || true)
    lBIN_NX_CNT=$(grep -c "NX disabled" "${S12_CSV_LOG}" || true)
    lBINS_PIE_CNT=$(grep -c "No PIE" "${S12_CSV_LOG}" || true)
    lBIN_STRIPPED_CNT=$(grep -c "No Symbols" "${S12_CSV_LOG}" || true)
    lBINS_CHECKED_CNT=$(grep -c "RELRO.*NX.*RPATH" "${S12_CSV_LOG}" || true)
    if [[ "${lBINS_CHECKED_CNT}" -gt 0 ]]; then
      # we have to remove the first line of the original output:
      (( lBINS_CHECKED_CNT-- ))
    fi
  elif [[ -f "${S13_LOG}" ]]; then
      lBINS_CHECKED_CNT=$(grep -a "\[\*\]\ Statistics:" "${S13_LOG}" | cut -d: -f3 || true)
  fi

  if [[ "${lBIN_CANARY_CNT:-0}" -gt 0 || "${lBINS_RELRO_CNT:-0}" -gt 0 || "${lBIN_NX_CNT:-0}" -gt 0 || "${lBINS_PIE_CNT:-0}" -gt 0 || "${lBIN_STRIPPED_CNT:-0}" -gt 0 ]]; then
    print_output "[*] Identified the following binary details:"
  fi

  if [[ "${lBIN_CANARY_CNT:-0}" -gt 0 ]]; then
    lCANARY_PER=$(bc -l <<< "${lBIN_CANARY_CNT}/(${lBINS_CHECKED_CNT}/100)" 2>/dev/null)
    lCANARY_PER=$(/bin/printf "%.0f" "${lCANARY_PER}" 2>/dev/null || true)
    print_output "[+] Found ""${ORANGE}""${lBIN_CANARY_CNT}"" (""${lCANARY_PER}""%)""${GREEN}"" binaries without enabled stack canaries in ${ORANGE}""${lBINS_CHECKED_CNT}""${GREEN} binaries."
    write_link "s12"
    write_csv_log "canary" "${lBIN_CANARY_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "canary_per" "${lCANARY_PER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi
  if [[ "${lBINS_RELRO_CNT:-0}" -gt 0 ]]; then
    lRELRO_PER=$(bc -l <<< "${lBINS_RELRO_CNT}/(${lBINS_CHECKED_CNT}/100)" 2>/dev/null)
    lRELRO_PER=$(/bin/printf "%.0f" "${lRELRO_PER}" 2>/dev/null || true)
    print_output "[+] Found ""${ORANGE}""${lBINS_RELRO_CNT}"" (""${lRELRO_PER}""%)""${GREEN}"" binaries without enabled RELRO in ${ORANGE}""${lBINS_CHECKED_CNT}""${GREEN} binaries."
    write_link "s12"
    write_csv_log "relro" "${lBINS_RELRO_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "relro_per" "${lRELRO_PER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi
  if [[ "${lBIN_NX_CNT:-0}" -gt 0 ]]; then
    lNX_PER=$(bc -l <<< "${lBIN_NX_CNT}/(${lBINS_CHECKED_CNT}/100)" 2>/dev/null)
    lNX_PER=$(/bin/printf "%.0f" "${lNX_PER}" 2>/dev/null || true)
    print_output "[+] Found ""${ORANGE}""${lBIN_NX_CNT}"" (""${lNX_PER}""%)""${GREEN}"" binaries without enabled NX in ${ORANGE}""${lBINS_CHECKED_CNT}""${GREEN} binaries."
    write_link "s12"
    write_csv_log "nx" "${lBIN_NX_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "nx_per" "${lNX_PER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi
  if [[ "${lBINS_PIE_CNT:-0}" -gt 0 ]]; then
    lPIE_PER=$(bc -l <<< "${lBINS_PIE_CNT}/(${lBINS_CHECKED_CNT}/100)" 2>/dev/null)
    lPIE_PER=$(/bin/printf "%.0f" "${lPIE_PER}" 2>/dev/null || true)
    print_output "[+] Found ""${ORANGE}""${lBINS_PIE_CNT}"" (""${lPIE_PER}""%)""${GREEN}"" binaries without enabled PIE in ${ORANGE}""${lBINS_CHECKED_CNT}""${GREEN} binaries."
    write_link "s12"
    write_csv_log "pie" "${lBINS_PIE_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "pie_per" "${lPIE_PER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi
  if [[ "${lBIN_STRIPPED_CNT:-0}" -gt 0 ]]; then
    lSTRIPPED_PER=$(bc -l <<< "${lBIN_STRIPPED_CNT}/(${lBINS_CHECKED_CNT}/100)" 2>/dev/null)
    lSTRIPPED_PER=$(/bin/printf "%.0f" "${lSTRIPPED_PER}" 2>/dev/null || true)
    print_output "[+] Found ""${ORANGE}""${lBIN_STRIPPED_CNT}"" (""${lSTRIPPED_PER}""%)""${GREEN}"" stripped binaries without symbols in ${ORANGE}""${lBINS_CHECKED_CNT}""${GREEN} binaries."
    write_link "s12"
    write_csv_log "stripped" "${lBIN_STRIPPED_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    write_csv_log "stripped_per" "${lSTRIPPED_PER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    lDATA_GENERATED=1
  fi
  if [[ "${lBINS_CHECKED_CNT:-0}" -gt 0 ]]; then
    write_csv_log "bins_checked" "${lBINS_CHECKED_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi
  if [[ ${lDATA_GENERATED} -eq 1 ]]; then
    print_bar
  fi

  cwe_logging

  if [[ "${S16_GHIDRA_SEMGREP:-0}" -gt 0 ]]; then
    write_csv_log "ghidra_semgrep_issues" "${S16_GHIDRA_SEMGREP}" "${S16_BINS_CHECKED}" "NA" "NA" "NA" "NA" "NA" "NA"
    print_output "[+] Found ""${ORANGE}""${S16_GHIDRA_SEMGREP}""${GREEN}"" possible vulnerabilities (${ORANGE}via semgrep in Ghidra decompiled code${GREEN}) in ""${ORANGE}""${S16_BINS_CHECKED}""${GREEN}"" tested binaries.""${NC}"
    write_link "s16"
  fi

  if [[ "${STRCPY_CNT:-0}" -gt 0 ]]; then
    print_output "[+] Found ""${ORANGE}""${STRCPY_CNT}""${GREEN}"" usages of strcpy in ""${ORANGE}""${lBINS_CHECKED_CNT}""${GREEN}"" binaries.""${NC}"
    if [[ $(find "${LOG_DIR}""/s13_weak_func_check/" -type f 2>/dev/null | wc -l) -gt $(find "${LOG_DIR}""/s14_weak_func_radare_check/" -type f 2>/dev/null | wc -l) ]]; then
      write_link "s13"
    else
      write_link "s14"
    fi
    write_csv_log "strcpy" "${STRCPY_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi

  local lDATA_GENERATED=0

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

    readarray -t lRESULTS_STRCPY_ARR < <( find "${LOG_DIR}"/s1[34]*/ -xdev -iname "vul_func_*_strcpy-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_strcpy-/ strcpy /" | sed "s/\.txt//" 2> /dev/null || true)
    readarray -t lRESULTS_SYSTEM_ARR < <( find "${LOG_DIR}"/s1[34]*/ -xdev -iname "vul_func_*_system-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_system-/ system /" | sed "s/\.txt//" 2> /dev/null || true)

    # strcpy:
    if [[ "${#lRESULTS_STRCPY_ARR[@]}" -gt 0 ]] && [[ $(echo "${lRESULTS_STRCPY_ARR[0]}" | awk '{print $1}') -gt 0 ]]; then
      print_ln
      print_output "[+] STRCPY - top 10 results:"
      if [[ -d "${LOG_DIR}""/s13_weak_func_check/" ]]; then
        write_link "s13#strcpysummary"
      else
        write_link "s14#strcpysummary"
      fi
      lDATA_GENERATED=1
      printf "${GREEN_}\t%-5.5s| %-15.15s | common linux file: y/n | %-8.8s / %-8.8s| %-8.8s | %-9.9s | %-11.11s | %-10.10s | %-13.13s |${NC}\n" "COUNT" "BINARY NAME" "CWE CNT" "SEMGREP" "RELRO" "lBIN_CANARY_CNT" "NX state" "SYMBOLS" "NETWORKING" | tee -a "${LOG_FILE}"
      for lDETAIL_STRCPY in "${lRESULTS_STRCPY_ARR[@]}" ; do
        binary_fct_output "${lDETAIL_STRCPY}"
        write_csv_log "strcpy_bin" "${BINARY}" "${F_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA"
      done
      print_output "${NC}"
    fi

    # system:
    if [[ "${#lRESULTS_SYSTEM_ARR[@]}" -gt 0 ]] && [[ $(echo "${lRESULTS_SYSTEM_ARR[0]}" | awk '{print $1}') -gt 0 ]]; then
      print_ln
      print_output "[+] SYSTEM - top 10 results:"
      if [[ -d "${LOG_DIR}""/s13_weak_func_check/" ]]; then
        write_link "s13#systemsummary"
      else
        write_link "s14#systemsummary"
      fi
      lDATA_GENERATED=1
      printf "${GREEN_}\t%-5.5s| %-15.15s | common linux file: y/n | %-8.8s / %-8.8s| %-8.8s | %-9.9s | %-11.11s | %-10.10s | %-13.13s |${NC}\n" "COUNT" "BINARY NAME" "CWE CNT" "SEMGREP" "RELRO" "lBIN_CANARY_CNT" "NX state" "SYMBOLS" "NETWORKING" | tee -a "${LOG_FILE}"
      for lDETAIL_SYSTEM in "${lRESULTS_SYSTEM_ARR[@]}" ; do
        binary_fct_output "${lDETAIL_SYSTEM}"
        write_csv_log "system_bin" "${BINARY}" "${F_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA"
      done
      print_output "${NC}"
    fi
  fi
  if [[ ${lDATA_GENERATED} -eq 1 ]]; then
    print_bar
  fi
}

binary_fct_output() {
  local lBINARY_DETAILS="${1:-}"
  export F_COUNTER=""
  F_COUNTER="$(echo "${lBINARY_DETAILS}" | cut -d\  -f1)"
  export BINARY=""
  BINARY="$(echo "${lBINARY_DETAILS}" | cut -d\  -f3)"
  local lBINS_FCT=""
  lBINS_FCT="$(echo "${lBINARY_DETAILS}" | cut -d\  -f2)"
  local lBIN_RELRO_STRING=""
  local lBIN_CANARY_STRING=""
  local lBIN_NX_STRING=""
  local lBIN_SYMBOLS_STRING=""
  local lBINS_NETWORKING_CNT=""
  local lBINS_CWE_CHCK_CNT=0
  local lBINS_SEMGREP_CNT=0

  if grep -q "${BINARY}" "${S12_LOG}" 2>/dev/null; then
    if grep "${BINARY}" "${S12_LOG}" | grep -o -q "No RELRO"; then
      lBIN_RELRO_STRING="${RED_}""No RELRO${NC_}"
    else
      lBIN_RELRO_STRING="${GREEN_}""RELRO   ${NC_}"
    fi
    if grep "${BINARY}" "${S12_LOG}" | grep -o -q "No Canary found"; then
      lBIN_CANARY_STRING="${RED_}""No Canary${NC_}"
    else
      lBIN_CANARY_STRING="${GREEN_}""Canary   ${NC_}"
    fi
    if grep "${BINARY}" "${S12_LOG}" | grep -o -q "NX disabled"; then
      lBIN_NX_STRING="${RED_}""NX disabled${NC_}"
    else
      lBIN_NX_STRING="${GREEN_}""NX enabled ${NC_}"
    fi
    if grep "${BINARY}" "${S12_LOG}" | grep -o -q "No Symbols"; then
      lBIN_SYMBOLS_STRING="${GREEN_}""No Symbols${NC_}"
    else
      lBIN_SYMBOLS_STRING="${RED_}""Symbols   ${NC_}"
    fi
  else
    lBIN_RELRO_STRING="${ORANGE_}""RELRO unknown${NC_}"
    lBIN_NX_STRING="${ORANGE_}""NX unknown${NC_}"
    lBIN_CANARY_STRING="${ORANGE_}""CANARY unknown${NC_}"
    lBIN_SYMBOLS_STRING="${ORANGE_}""Symbols unknown${NC_}"
  fi

  # networking
  if grep -q "/${BINARY} " "${CSV_DIR}"/s1[34]_*.csv 2>/dev/null; then
    if grep "/${BINARY} " "${CSV_DIR}"/s1[34]_*.csv | cut -d\; -f5 | sort -u | grep -o -q "no"; then
      lBINS_NETWORKING_CNT="${GREEN_}""No Networking     ${NC_}"
    else
      lBINS_NETWORKING_CNT="${RED_}""Networking        ${NC_}"
    fi
  else
    lBINS_NETWORKING_CNT="${ORANGE_}""Networking unknown${NC_}"
  fi

  # cwe-checker and semgrep results per binary
  if [[ -f "${LOG_DIR}"/s17_cwe_checker/cwe_"${BINARY}".log ]]; then
    lBINS_CWE_CHCK_CNT=$(grep -Ec "CWE[0-9]+" "${LOG_DIR}/s17_cwe_checker/cwe_${BINARY}.log" || true)
  fi
  lBINS_SEMGREP_CNT=$(wc -l < "${LOG_DIR}/s16_ghidra_decompile_checks/semgrep_${BINARY}_"[0-9]*".csv" || true)
  if [[ -f "${BASE_LINUX_FILES}" ]]; then
    local lFCT_LINK=""
    if [[ "${lBINS_SEMGREP_CNT}" -gt 0 ]]; then
      lFCT_LINK="s16"
    else
      lFCT_LINK=$(find "${LOG_DIR}"/s1[34]_weak_func_*check/ -name "vul_func_*${lBINS_FCT}-${BINARY}*.txt" | sort -u | head -1 || true)
    fi
    [[ "${lBINS_SEMGREP_CNT:-0}" -eq 0 ]] && lBINS_SEMGREP_CNT="NA"
    [[ "${lBINS_CWE_CHCK_CNT:-0}" -eq 0 ]] && lBINS_CWE_CHCK_CNT="NA"

    # if we have the base linux config file we are checking it:
    if grep -E -q "^${BINARY}$" "${BASE_LINUX_FILES}" 2>/dev/null; then
      printf "${GREEN_}\t%-5.5s| %-15.15s | common linux file: yes | Vulns: %-4.4s / %-4.4s | %-14.14s | %-15.15s | %-16.16s | %-15.15s | %-18.18s |${NC}\n" "${F_COUNTER}" "${BINARY}" "${lBINS_CWE_CHCK_CNT}" "${lBINS_SEMGREP_CNT}" "${lBIN_RELRO_STRING}" "${lBIN_CANARY_STRING}" "${lBIN_NX_STRING}" "${lBIN_SYMBOLS_STRING}" "${lBINS_NETWORKING_CNT}" | tee -a "${LOG_FILE}"
    else
      printf "${ORANGE_}\t%-5.5s| %-15.15s | common linux file: no  | Vulns: %-4.4s / %-4.4s | %-14.14s | %-15.15s | %-16.16s | %-15.15s | %-18.18s |${NC}\n" "${F_COUNTER}" "${BINARY}" "${lBINS_CWE_CHCK_CNT}" "${lBINS_SEMGREP_CNT}" "${lBIN_RELRO_STRING}" "${lBIN_CANARY_STRING}" "${lBIN_NX_STRING}" "${lBIN_SYMBOLS_STRING}" "${lBINS_NETWORKING_CNT}"| tee -a "${LOG_FILE}"
    fi
    write_link "${lFCT_LINK}"
  else
    printf "${ORANGE_}\t%-5.5s| %-15.15s | common linux file: NA  | Vulns: %-4.4s / %-4.4s | %-14.14s | %-15.15s | %-16.16s | %-15.15s | %-18.18s |${NC}\n" "${F_COUNTER}" "${BINARY}" "${lBINS_CWE_CHCK_CNT}" "${lBINS_SEMGREP_CNT}" "${lBIN_RELRO_STRING}" "${lBIN_CANARY_STRING}" "${lBIN_NX_STRING}" "${lBIN_SYMBOLS_STRING}" "${lBINS_NETWORKING_CNT}" | tee -a "${LOG_FILE}"
    write_link "${lFCT_LINK}"
  fi
}

output_cve_exploits() {
  local lDATA_GENERATED=0
  local lBINARY=""
  local lBIN_VERS=""

  if [[ "${S30_VUL_COUNTER:-0}" -gt 0 || "${CVE_COUNTER:-0}" -gt 0 || "${EXPLOIT_COUNTER:-0}" -gt 0 ]]; then
    if [[ "${CVE_COUNTER:-0}" -gt 0 || "${EXPLOIT_COUNTER:-0}" -gt 0 ]] && [[ -f "${F17_LOG_DIR}/vuln_summary.txt" ]]; then
      print_output "[*] Identified the following software inventory, vulnerabilities and exploits:"
      write_link "f17#softwareinventoryinitialoverview"

      # run over F17/vuln_summary.txt and add links - need to do this here and not in f17 as there the threading mode kicks us
      while read -r OVERVIEW_LINE; do
        lBINARY="$(echo "${OVERVIEW_LINE}" | cut -d: -f2 | tr -d '[:blank:]')"
        lBIN_VERS="$(echo "${OVERVIEW_LINE}" | cut -d: -f3 | tr -d '[:blank:]')"
        print_output "${OVERVIEW_LINE}"
        write_link "f17#cve_${lBINARY}_${lBIN_VERS}"
      done < "${F17_LOG_DIR}/vuln_summary.txt"
      print_ln
    fi

    if [[ "${F17_VERSIONS_IDENTIFIED}" -gt 0 ]]; then
      if [[ -f "${F15_LOG}" ]]; then
        print_output "[+] Identified a SBOM including ""${ORANGE}${F17_VERSIONS_IDENTIFIED}${GREEN}"" software components with version details."
        write_link "f15"
      else
        print_output "[+] Identified ""${ORANGE}${F17_VERSIONS_IDENTIFIED}${GREEN}"" software components with version details.\\n"
        write_link "f17#softwareinventoryinitialoverview"
      fi
      write_csv_log "versions_identified" "${F17_VERSIONS_IDENTIFIED}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
    fi
    if [[ "${S30_VUL_COUNTER:-0}" -gt 0 ]]; then
      local lBINARIES_CNT=0
      lBINARIES_CNT=$(grep ";ELF" "${P99_CSV_LOG}" | cut -d ';' -f1 | sort -u | wc -l)
      print_output "[+] Found ""${ORANGE}""${S30_VUL_COUNTER}""${GREEN}"" CVE vulnerabilities in ""${ORANGE}""${lBINARIES_CNT}""${GREEN}"" executables (without version checking).""${NC}"
      write_link "s30"
      lDATA_GENERATED=1
    fi
    if [[ "${CVE_COUNTER:-0}" -gt 0 ]]; then
      echo -e "\n" >> "${LOG_FILE}"
      print_output "[+] Identified ""${ORANGE}""${CVE_COUNTER}""${GREEN}"" CVE entries."
      write_link "f17#collectcveandexploitdetails"
      print_output "$(indent "$(green "Identified ${RED}${BOLD}${CRITICAL_CVE_COUNTER}${NC}${GREEN} Critical rated CVE entries / Exploits: ${ORANGE}${EXPLOIT_CRITICAL_COUNT:-NA}${NC}")")"
      print_output "$(indent "$(green "Identified ${RED}${BOLD}${HIGH_CVE_COUNTER}${NC}${GREEN} High rated CVE entries / Exploits: ${ORANGE}${EXPLOIT_HIGH_COUNT:-NA}${NC}")")"
      print_output "$(indent "$(green "Identified ${ORANGE}${BOLD}${MEDIUM_CVE_COUNTER}${NC}${GREEN} Medium rated CVE entries / Exploits: ${ORANGE}${EXPLOIT_MEDIUM_COUNT:-NA}${NC}")")"
      print_output "$(indent "$(green "Identified ${GREEN}${BOLD}${LOW_CVE_COUNTER}${NC}${GREEN} Low rated CVE entries /Exploits: ${ORANGE}${EXPLOIT_LOW_COUNT:-NA}${NC}")")"
      write_csv_log "cve_critical" "${CRITICAL_CVE_COUNTER}" "${EXPLOIT_CRITICAL_COUNT}" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "cve_high" "${HIGH_CVE_COUNTER}" "${EXPLOIT_HIGH_COUNT}" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "cve_medium" "${MEDIUM_CVE_COUNTER}" "${EXPLOIT_MEDIUM_COUNT}" "NA" "NA" "NA" "NA" "NA" "NA"
      write_csv_log "cve_low" "${LOW_CVE_COUNTER}" "${EXPLOIT_LOW_COUNT}" "NA" "NA" "NA" "NA" "NA" "NA"
      lDATA_GENERATED=1
    fi
    if [[ "${EXPLOIT_COUNTER:-0}" -gt 0 ]] || [[ "${MSF_VERIFIED}" -gt 0 ]]; then
      write_csv_log "exploits" "${EXPLOIT_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      if [[ "${MSF_MODULE_CNT}" -gt 0 ]]; then
        print_output "$(indent "$(green "${MAGENTA}${BOLD}${EXPLOIT_COUNTER}${NC}${GREEN} possible exploits available (${MAGENTA}${MSF_MODULE_CNT}${GREEN} Metasploit modules).")")"
        write_link "f17#minimalreportofexploitsandcves"
        write_csv_log "metasploit_modules" "${MSF_MODULE_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      else
        print_output "$(indent "$(green "${MAGENTA}${BOLD}${EXPLOIT_COUNTER}${NC}${GREEN} possible exploits available.")")"
        write_link "f17#minimalreportofexploitsandcves"
      fi
      if [[ "${MSF_VERIFIED}" -gt 0 ]]; then
        print_output "$(indent "$(green "${MAGENTA}${BOLD}${MSF_VERIFIED}${NC}${GREEN} exploits in system mode emulation verified.")")"
        write_link "l35"
      fi
      if [[ "${REMOTE_EXPLOIT_CNT}" -gt 0 || "${LOCAL_EXPLOIT_CNT}" -gt 0 || "${DOS_EXPLOIT_CNT}" -gt 0 || "${KNOWN_EXPLOITED_COUNTER}" -gt 0 || "${MSF_VERIFIED}" -gt 0 ]]; then
        print_output "$(indent "$(green "Remote exploits: ${MAGENTA}${BOLD}${REMOTE_EXPLOIT_CNT}${NC}${GREEN} / Local exploits: ${MAGENTA}${BOLD}${LOCAL_EXPLOIT_CNT}${NC}${GREEN} / DoS exploits: ${MAGENTA}${BOLD}${DOS_EXPLOIT_CNT}${NC}${GREEN} / Known exploited vulnerabilities: ${MAGENTA}${BOLD}${KNOWN_EXPLOITED_COUNTER}${GREEN} / Verified Exploits: ${MAGENTA}${BOLD}${MSF_VERIFIED}${NC}")")"
        write_csv_log "remote_exploits" "${REMOTE_EXPLOIT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
        write_csv_log "local_exploits" "${LOCAL_EXPLOIT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
        write_csv_log "dos_exploits" "${DOS_EXPLOIT_CNT}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
        write_csv_log "known_exploited" "${KNOWN_EXPLOITED_COUNTER}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
        write_csv_log "verified_exploited" "${MSF_VERIFIED}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
      fi
      # we report only software components with exploits to csv:
      grep "Found version details" "${F17_LOG_DIR}/vuln_summary.txt" 2>/dev/null | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | tr -d "\[\+\]" | grep -v "CVEs: 0" | sed -e 's/Found version details:/version_details:/' |sed -e 's/[[:blank:]]//g' | sed -e 's/:/;/g' >> "${F50_CSV_LOG}" || true
      lDATA_GENERATED=1
    fi
  fi
  if [[ ${lDATA_GENERATED} -eq 1 ]]; then
    print_bar
  fi
}

get_data() {
  export REMOTE_EXPLOIT_CNT=0
  export LOCAL_EXPLOIT_CNT=0
  export DOS_EXPLOIT_CNT=0
  export CRITICAL_CVE_COUNTER=0
  export HIGH_CVE_COUNTER=0
  export MEDIUM_CVE_COUNTER=0
  export LOW_CVE_COUNTER=0
  export EXPLOIT_COUNTER=0
  export EXPLOIT_CRITICAL_COUNT=0
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
  export LINUX_DISTRIS_ARR=()
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
  export FWHUNTER_CNT=0
  # export FWHUNTER_CNT_CVE=0
  export MSF_VERIFIED=0
  export K_CVE_VERIFIED_SYMBOLS=0
  export K_CVE_VERIFIED_COMPILED=0
  export APK_ISSUES=0
  export TOTAL_CWE_CNT=0
  export TOTAL_CWE_BINS=0
  export F17_VERSIONS_IDENTIFIED=0

  if [[ -f "${P02_CSV_LOG}" ]]; then
    ENTROPY=$(grep -a "Entropy" "${P02_CSV_LOG}" | cut -d\; -f2 | cut -d= -f2 | sed 's/^\ //' || true)
  fi
  if [[ -f "${P35_LOG}" ]]; then
    EFI_ARCH=$(grep -a "Possible architecture details found" "${P35_LOG}" | cut -d: -f2 | sed 's/\ //g' | tr '\r\n' '/' || true)
    EFI_ARCH="${EFI_ARCH%\/}"
    EFI_ARCH=$(strip_color_codes "${EFI_ARCH}")
  fi
  if [[ -f "${P99_LOG}" ]]; then
    P99_ARCH="$(grep -a "\[\*\]\ Statistics:" "${P99_LOG}" | cut -d: -f 2 | grep -v "NA" || true)"
    P99_ARCH_END="$(grep -a "\[\*\]\ Statistics:" "${P99_LOG}" | cut -d: -f 3 | grep -v "NA" || true)"
  fi
  if [[ -f "${S24_CSV_LOG}" ]]; then
    K_ARCH="$(tail -n +2 "${S24_CSV_LOG}" | cut -d\; -f 8 | sort -u | grep "\S" | head -1 || true)"
    K_ARCH_END="$(tail -n +2 "${S24_CSV_LOG}" | cut -d\; -f 9 | sort -u | grep "\S" | head -1 || true)"
  fi

  if [[ -f "${S02_LOG}" ]]; then
    # FWHUNTER_CNT_CVE=$(grep -a "\[\*\]\ Statistics:" "${S02_LOG}" | cut -d: -f2 || true)
    FWHUNTER_CNT=$(grep -a "\[\*\]\ Statistics:" "${S02_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${S03_LOG}" ]]; then
    PRE_ARCH="$(strip_color_codes "$(grep -a "Possible architecture details found" "${S03_LOG}" | cut -d: -f2 | sed 's/\ //g' | tr '\r\n' ' ' | sed 's/\ /\ \//' || true)")"
    PRE_ARCH="${PRE_ARCH%\/}"
  fi
  if [[ -f "${S05_LOG}" ]]; then
    FILE_ARR_COUNT=$(grep -a "\[\*\]\ Statistics:" "${S05_LOG}" | cut -d: -f2 || true)
    DETECTED_DIR=$(grep -a "\[\*\]\ Statistics:" "${S05_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${S06_LOG}" ]]; then
    mapfile -t LINUX_DISTRIS_ARR < <(grep "Version information found" "${S06_LOG}" | cut -d\  -f5- | sed 's/ in file .*//' | sort -u || true)
  fi
  if ! [[ "${FILE_ARR_COUNT-0}" -gt 0 ]]; then
    FILE_ARR_COUNT=$(wc -l < "${P99_CSV_LOG}"|| true)
    DETECTED_DIR=$(find "${FIRMWARE_PATH_CP}" -type d 2>/dev/null | wc -l || true)
  fi
  if [[ -f "${S13_LOG}" ]]; then
    STRCPY_CNT_13=$(grep -a "\[\*\]\ Statistics:" "${S13_LOG}" | cut -d: -f2 || true)
    ARCH=$(grep -a "\[\*\]\ Statistics1:" "${S13_LOG}" | cut -d: -f2 || true)
  else
    STRCPY_CNT_13=0
  fi
  if [[ -f "${S14_LOG}" ]]; then
    STRCPY_CNT_14=$(grep -a "\[\*\]\ Statistics:" "${S14_LOG}" | cut -d: -f2 || true)
    ARCH=$(grep -a "\[\*\]\ Statistics1:" "${S14_LOG}" | cut -d: -f2 || true)
    STRCPY_CNT=$((STRCPY_CNT_14+STRCPY_CNT_13))
  else
    STRCPY_CNT="${STRCPY_CNT_13}"
  fi
  if [[ -f "${S16_LOG}" ]]; then
    S16_GHIDRA_SEMGREP=$(grep -a "\[\*\]\ Statistics:" "${S16_LOG}" | cut -d: -f2 || true)
    S16_BINS_CHECKED=$(grep -a "\[\*\]\ Statistics:" "${S16_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${S20_LOG}" ]]; then
    S20_SHELL_VULNS=$(grep -a "\[\*\]\ Statistics:" "${S20_LOG}" | cut -d: -f2 || true)
    S20_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "${S20_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${S21_LOG}" ]]; then
    S21_PY_VULNS=$(grep -a "\[\*\]\ Statistics:" "${S21_LOG}" | cut -d: -f2 || true)
    S21_PY_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "${S21_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${S22_LOG}" ]]; then
    S22_PHP_VULNS=$(grep -a "\[\*\]\ Statistics:" "${S22_LOG}" | cut -d: -f2 || true)
    S22_PHP_SCRIPTS=$(grep -a "\[\*\]\ Statistics:" "${S22_LOG}" | cut -d: -f3 || true)
    S22_PHP_INI_ISSUES=$(grep -a "\[\*\]\ Statistics:" "${S22_LOG}" | cut -d: -f4 || true)
    S22_PHP_INI_CONFIGS=$(grep -a "\[\*\]\ Statistics:" "${S22_LOG}" | cut -d: -f5 || true)
    S22_PHP_VULNS_SEMGREP=$(grep -a "\[\*\]\ Statistics1:" "${S22_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S24_LOG}" ]]; then
    # we currently only respect one kernel settings analysis in our final aggregator.
    S24_FAILED_KSETTINGS=$(grep -a "\[\*\]\ Statistics:" "${S24_LOG}" | cut -d: -f2 | head -1 || true)
  fi
  if [[ -f "${S25_LOG}" ]]; then
    MOD_DATA_COUNTER=$(grep -a "\[\*\]\ Statistics1:" "${S25_LOG}" | cut -d: -f2 || true)
    KMOD_BAD=$(grep -a "\[\*\]\ Statistics1:" "${S25_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${S26_LOG}" ]]; then
    K_CVE_VERIFIED_SYMBOLS=$(grep -a "\[\*\]\ Statistics:" "${S26_LOG}" | cut -d: -f4 || true)
    K_CVE_VERIFIED_COMPILED=$(grep -a "\[\*\]\ Statistics:" "${S26_LOG}" | cut -d: -f5 || true)
  fi
  if [[ -f "${S30_LOG}" ]]; then
    S30_VUL_COUNTER=$(grep -a "\[\*\]\ Statistics:" "${S30_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S40_LOG}" ]]; then
    S40_WEAK_PERM_COUNTER=$(grep -a "\[\*\]\ Statistics:" "${S40_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S45_LOG}" ]]; then
    PASS_FILES_FOUND=$(grep -a "\[\*\]\ Statistics:" "${S45_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S50_LOG}" ]]; then
    S50_AUTH_ISSUES=$(grep -a "\[\*\]\ Statistics:" "${S50_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S55_LOG}" ]]; then
    S55_HISTORY_COUNTER=$(grep -a "\[\*\]\ Statistics:" "${S55_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S60_LOG}" ]]; then
    TOTAL_CERT_CNT=$(grep -a "\[\*\]\ Statistics:" "${S60_LOG}" | cut -d: -f2 || true)
    CERT_CNT=$(grep -a "\[\*\]\ Statistics:" "${S60_LOG}" | cut -d: -f3 || true)
    CERT_OUT_CNT=$(grep -a "\[\*\]\ Statistics:" "${S60_LOG}" | cut -d: -f4 || true)
    CERT_WARNING_CNT=$(grep -a "\[\*\]\ Statistics:" "${S60_LOG}" | cut -d: -f5 || true)
  fi
  if [[ -f "${S85_LOG}" ]]; then
    S85_SSH_VUL_CNT=$(grep -a "\[\*\]\ Statistics:" "${S85_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S95_LOG}" ]]; then
    INT_COUNT=$(grep -a "\[\*\]\ Statistics:" "${S95_LOG}" | cut -d: -f2 || true)
    POST_COUNT=$(grep -a "\[\*\]\ Statistics:" "${S95_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${S107_LOG}" ]]; then
    PW_COUNTER=$(grep -a "\[\*\]\ Statistics:" "${S107_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S108_LOG}" ]]; then
    STACS_HASHES=$(grep -a "\[\*\]\ Statistics:" "${S108_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S109_LOG}" ]]; then
    HASHES_CRACKED=$(grep -a "\[\*\]\ Statistics:" "${S109_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S110_LOG}" ]]; then
    YARA_CNT=$(grep -a "\[\*\]\ Statistics:" "${S110_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${S17_LOG}" ]]; then
    TOTAL_CWE_CNT=$(grep -a "\[\*\]\ Statistics:" "${S17_LOG}" | cut -d: -f2 || true)
    TOTAL_CWE_BINS=$(grep -a "\[\*\]\ Statistics:" "${S17_LOG}" | cut -d: -f3 || true)
  fi
  if [[ -f "${L10_SYS_EMU_RESULTS}" ]]; then
    BOOTED=$(grep -c "Booted yes;" "${L10_SYS_EMU_RESULTS}" || true)
    ICMP=$(grep -c "ICMP ok;" "${L10_SYS_EMU_RESULTS}" || true)
    TCP_0=$(grep -c "TCP-0 ok;" "${L10_SYS_EMU_RESULTS}" || true)
    TCP=$(grep -c "TCP ok;" "${L10_SYS_EMU_RESULTS}" || true)
    IP_ADDR=$(grep -e "Booted yes;\|ICMP ok;\|TCP-0 ok;\|TCP ok" "${L10_SYS_EMU_RESULTS}" | grep -E -c "IP\ address:\ [0-9]+" || true)
    # we make something like this: "bridge-default-normal"
    MODE=$(grep -e "Booted yes;\|ICMP ok;\|TCP-0 ok;\|TCP ok" "${L10_SYS_EMU_RESULTS}" | cut -d\; -f9 | sed 's/Network mode: //g'| tr -d '[:blank:]' | cut -d\( -f1 | sort -u | tr '\n' '-' | sed 's/-$//g' || true)
  fi
  if [[ -f "${L20_LOG}" ]]; then
    # NMAP_UP=$(grep -a "\[\*\]\ Statistics:" "${L15_LOG}" | cut -d: -f2 || true)
    SNMP_UP=$(grep -a "\[\*\]\ Statistics:" "${L20_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${L25_LOG}" ]]; then
    WEB_UP=$(grep -a "\[\*\]\ Statistics:" "${L25_LOG}" | cut -d: -f2 || true)
  fi
  if [[ -f "${L35_CSV_LOG}" ]]; then
    MSF_VERIFIED=$(grep -v -c "Source" "${L35_CSV_LOG}" || true)
  fi
  if [[ -d "${F17_LOG_DIR}" ]]; then
    F17_VERSIONS_IDENTIFIED=$(wc -l < "${F17_LOG_DIR}/vuln_summary.txt")
    CRITICAL_CVE_COUNTER=$(cut -d ',' -f4,5 "${F17_LOG_DIR}"/*.csv 2>/dev/null | sort -u | grep -c "CVE-.*,CRITICAL" || true)
    CVE_COUNTER=$((CVE_COUNTER+CRITICAL_CVE_COUNTER))
    HIGH_CVE_COUNTER=$(cut -d ',' -f4,5 "${F17_LOG_DIR}"/*.csv 2>/dev/null | sort -u | grep -c "CVE-.*,HIGH" || true)
    CVE_COUNTER=$((CVE_COUNTER+HIGH_CVE_COUNTER))
    MEDIUM_CVE_COUNTER=$(cut -d ',' -f4,5 "${F17_LOG_DIR}"/*.csv 2>/dev/null | sort -u | grep -c "CVE-.*,MEDIUM" || true)
    CVE_COUNTER=$((CVE_COUNTER+MEDIUM_CVE_COUNTER))
    LOW_CVE_COUNTER=$(cut -d ',' -f4,5 "${F17_LOG_DIR}"/*.csv 2>/dev/null | sort -u | grep -c "CVE-.*,LOW" || true)
    CVE_COUNTER=$((CVE_COUNTER+LOW_CVE_COUNTER))
  fi
  if [[ -f "${F17_LOG_DIR}"/KEV.txt ]]; then
    KNOWN_EXPLOITED_COUNTER=$(wc -l < "${F17_LOG_DIR}"/KEV.txt)
  fi
  if [[ -d "${F17_LOG_DIR}/cve_sum" ]]; then
    # nosemgrep
    EXPLOIT_COUNTER="$(cat "${F17_LOG_DIR}"/cve_sum/*finished.txt | grep -c "Exploit (" || true)"
    # nosemgrep
    MSF_MODULE_CNT="$(cat "${F17_LOG_DIR}"/cve_sum/*finished.txt | grep -c -E "Exploit\ .*MSF" || true)"
    # nosemgrep
    REMOTE_EXPLOIT_CNT="$(cat "${F17_LOG_DIR}"/cve_sum/*finished.txt | grep -c -E "Exploit\ .*\ \(R\)" || true)"
    # nosemgrep
    LOCAL_EXPLOIT_CNT="$(cat "${F17_LOG_DIR}"/cve_sum/*finished.txt | grep -c -E "Exploit\ .*\ \(L\)" || true)"
    # nosemgrep
    DOS_EXPLOIT_CNT="$(cat "${F17_LOG_DIR}"/cve_sum/*finished.txt | grep -c -E "Exploit\ .*\ \(D\)" || true)"
    if [[ -f "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp ]]; then
      EXPLOIT_CRITICAL_COUNT="$(grep -c "CRITICAL" "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp || true)"
      EXPLOIT_HIGH_COUNT="$(grep -c "HIGH" "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp || true)"
      EXPLOIT_MEDIUM_COUNT="$(grep -c "MEDIUM" "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp || true)"
      EXPLOIT_LOW_COUNT="$(grep -c "LOW" "${TMP_DIR}"/SEVERITY_EXPLOITS.tmp || true)"
    fi
  fi
  if [[ -f "${S17_CSV_LOG}" ]]; then
    APK_ISSUES="$(cut -d\; -f 2 "${S17_CSV_LOG}" | awk '{ sum += $1 } END { print sum }' || true)"
  fi
}

distribution_detector() {
  local lLINUX_DISTRI_IDENTIFID=""

  for lLINUX_DISTRI_IDENTIFID in "${LINUX_DISTRIS_ARR[@]}"; do
    print_output "[+] Linux distribution detected: ${ORANGE}${lLINUX_DISTRI_IDENTIFID}${NC}"
    write_link "s06"
  done
}

os_detector() {
  export VERIFIED=0
  export VERIFIED_S03=0
  export SYSTEM=""
  local lOS_TO_CHECK_ARR=("kernel" "vxworks" "siprotec" "freebsd" "qnx\ neutrino\ rtos" "simatic\ cp443-1")
  local lOS_TO_CHECK=""
  local lOS_DETECTED_ARR=()
  local lSYSTEM_VERSION_ARR=()
  local lSYSTEM_VERSION=""

  #### The following check is based on the results of the aggregator:
  if [[ -f "${F17_LOG_DIR}"/vuln_summary.txt ]]; then
    for lOS_TO_CHECK in "${lOS_TO_CHECK_ARR[@]}"; do
      mapfile -t lSYSTEM_VERSION_ARR < <(grep -E "Component details:( )+.*${lOS_TO_CHECK}.*:" "${F17_LOG_DIR}"/vuln_summary.txt | cut -d ':' -f3 | sed -e 's/[[:blank:]]//g' | sort -u || true)
      if [[ "${#lSYSTEM_VERSION_ARR[@]}" -gt 0 ]]; then
        if [[ "${lOS_TO_CHECK}" == "kernel" ]]; then
          SYSTEM="Linux"
        elif [[ "${lOS_TO_CHECK}" == "siprotec" ]]; then
          SYSTEM="SIPROTEC"
        elif [[ "${lOS_TO_CHECK}" == "vxworks" ]]; then
          SYSTEM="VxWorks"
        elif [[ "${lOS_TO_CHECK}" == "freebsd" ]]; then
          SYSTEM="FreeBSD"
        elif [[ "${lOS_TO_CHECK}" == "qnx\ neutrino\ rtos" ]]; then
          SYSTEM="QNX Neutrino"
        elif [[ "${lOS_TO_CHECK}" == "simatic\ cp443-1" ]]; then
          SYSTEM="Siemens CP443-1"
        else
          SYSTEM="${lOS_TO_CHECK}"
        fi
        # version detected -> verified linux
        for lSYSTEM_VERSION in "${lSYSTEM_VERSION_ARR[@]}"; do
          lSYSTEM_VERSION=$(strip_color_codes "${lSYSTEM_VERSION}")
          SYSTEM+=" / v${lSYSTEM_VERSION}"
          VERIFIED=1
        done
        if [[ ${VERIFIED} -eq 1 ]]; then
          print_os "${SYSTEM}"
        fi
      fi
    done
  fi

  #### The following check is needed if the aggreagator has failed till now
  if [[ ${VERIFIED} -eq 0 && -f "${S03_LOG}" ]]; then
    # the OS was not verified in the first step (but we can try to verify it now with more data of other modules)
    mapfile -t lOS_DETECTED_ARR < <(grep "verified.*operating\ system\ detected" "${S03_LOG}" 2>/dev/null | cut -d: -f1,2 | awk '{print $2 " - #" $5}' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" || true)
    if [[ "${#lOS_DETECTED_ARR[@]}" -gt 0 ]]; then
      for SYSTEM in "${lOS_DETECTED_ARR[@]}"; do
        VERIFIED_S03=1
        VERIFIED=1
        print_os "${SYSTEM}"
      done
    fi

    # we print the unverified OS only if we have no verified results:
    mapfile -t lOS_DETECTED_ARR < <(grep "\ detected" "${S03_LOG}" 2>/dev/null | cut -d: -f1,2 | awk '{print $2 " - #" $5}' | sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | sort -r -n -t '#' -k2 || true)

    if [[ "${#lOS_DETECTED_ARR[@]}" -gt 0 && "${VERIFIED}" -eq 0 ]]; then
      for SYSTEM in "${lOS_DETECTED_ARR[@]}"; do
        VERIFIED=0
        print_os "${SYSTEM}"
      done
    fi
  fi

  #### The following check is just in place if something went wrong
  if [[ ${VERIFIED} -eq 0 ]]; then
    # usually the results of the kernel module checker are already used in f17 (first os check)
    # but just in case something went wrong we use it now
    os_kernel_module_detect
    if [[ ${VERIFIED} -eq 1 ]]; then
      print_os "${SYSTEM}"
    fi
  fi
}

os_kernel_module_detect() {
  local lLINUX_VERSIONS_STRING=""
  local lKV_STRING=""
  local lKERNELV_ARR=()

  if [[ -f "${S25_LOG}" ]]; then
    mapfile -t lKERNELV_ARR < <(grep "Statistics:" "${S25_LOG}" | cut -d: -f2 | sort -u || true)
    if [[ "${#lKERNELV_ARR[@]}" -ne 0 ]]; then
      # if we have found a kernel it is a Linux system:
      lLINUX_VERSIONS_STRING="Linux"
      for lKV_STRING in "${lKERNELV_ARR[@]}"; do
        lLINUX_VERSIONS_STRING="${lLINUX_VERSIONS_STRING}"" / v${lKV_STRING}"
        VERIFIED=1
      done
      SYSTEM="${lLINUX_VERSIONS_STRING}"
    fi
  fi
}

print_os() {
  local lSYSTEM="${1:-}"
  lSYSTEM="${lSYSTEM//[![:print:]]/}"

  if [[ ${VERIFIED} -eq 1 ]]; then
    print_output "[+] Operating system detected (""${ORANGE}""verified${GREEN}): ${ORANGE}${lSYSTEM}${NC}"
    if [[ "${VERIFIED_S03}" -eq 1 ]]; then
      write_link "s03"
    elif [[ -s "${S24_LOG}" ]] && ! (grep -q "nothing reported" "${S24_LOG}"); then
      write_link "s24"
    else
      write_link "s25"
    fi
    write_csv_log "os_verified" "${lSYSTEM}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  else
    print_output "[+] Possible operating system detected (""${ORANGE}""unverified${GREEN}): ${ORANGE}${lSYSTEM}${NC}"
    write_link "s03"
    if [[ "$(grep -c os_verified "${F50_CSV_LOG}")" -lt 1 ]]; then
      write_csv_log "os_verified" "unknown" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
    fi
    write_csv_log "os_unverified" "${lSYSTEM}" "NA" "NA" "NA" "NA" "NA" "NA" "NA"
  fi
}

cwe_logging() {
  local lLOG_DIR_MOD="s17_cwe_checker"
  local lCWE_OUT_ARR=()
  local lCWE_ENTRY=""
  local lCWE=""
  local lCWE_DESC=""
  local lBINS_CWE_CHCK_CNT=""

  if [[ -d "${LOG_DIR}"/"${lLOG_DIR_MOD}" ]]; then
    # mapfile -t lCWE_OUT_ARR < <( cat "${LOG_DIR}"/"${lLOG_DIR_MOD}"/cwe_*.log 2>/dev/null | grep -v "ERROR\|DEBUG\|INFO" | grep "lCWE[0-9]" | sed -z 's/[0-9]\.[0-9]//g' | cut -d\( -f1,3 | cut -d\) -f1 | sort -u | tr -d '(' | tr -d "[" | tr -d "]" || true)
    mapfile -t lCWE_OUT_ARR < <( jq -r '.[] | "\(.name) \(.description)"' "${LOG_DIR}"/"${lLOG_DIR_MOD}"/cwe_*.log | cut -d\) -f1 | tr -d '('  | sort -u|| true)

    if [[ ${#lCWE_OUT_ARR[@]} -gt 0 ]] ; then
      print_output "[+] cwe-checker found a total of ""${ORANGE}""${TOTAL_CWE_CNT}""${GREEN}"" security issues in ${ORANGE}${TOTAL_CWE_BINS}${GREEN} tested binaries:"
      write_link "s17"
      for lCWE_ENTRY in "${lCWE_OUT_ARR[@]}"; do
        lCWE="$(echo "${lCWE_ENTRY}" | awk '{print $1}')"
        lCWE_DESC="$(echo "${lCWE_ENTRY}" | cut -d\  -f2-)"
        # do not change this to grep -c!
        # shellcheck disable=SC2126
        lBINS_CWE_CHCK_CNT="$(grep "${lCWE}" "${LOG_DIR}"/"${lLOG_DIR_MOD}"/cwe_*.log 2>/dev/null | wc -l || true)"
        print_output "$(indent "$(orange "${lCWE}""${GREEN}"" - ""${lCWE_DESC}"" - ""${ORANGE}""${lBINS_CWE_CHCK_CNT}"" times.")")"
      done
      print_ln
      write_csv_log "cwe_issues" "${TOTAL_CWE_CNT}" "${TOTAL_CWE_BINS}" "NA" "NA" "NA" "NA" "NA" "NA"
    fi
  fi
}
