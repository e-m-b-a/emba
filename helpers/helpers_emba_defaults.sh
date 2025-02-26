#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Benedikt Kuehne

# Description: Sets default values for EMBA


set_defaults() {
  # read and export all vars in .env
  if [[ -f "${INVOCATION_PATH}/config/.env" ]]; then
    # readin .env
    set -a # automatically export all variables
    source "${INVOCATION_PATH}/config/.env"
    set +a
  else
    echo -e "${RED}""    Missing ""${INVOCATION_PATH}/config/.env"" - check your installation""${NC}"
  fi
}

set_log_paths() {
  export SBOM_LOG_PATH="${LOG_DIR}/SBOM"
  export P02_CSV_LOG="${CSV_DIR}/p02_firmware_bin_file_check.csv"
  export P99_CSV_LOG="${CSV_DIR}/p99_prepare_analyzer.csv"
  export P55_LOG="${LOG_DIR}/p55_unblob_extractor.txt"
  export P60_LOG="${LOG_DIR}/p60_deep_extractor.txt"
  export P99_LOG="${LOG_DIR}/p99_prepare_analyzer.txt"
  export P35_LOG="${LOG_DIR}/p35_uefi_extractor.txt"
  export S02_LOG="${LOG_DIR}/s02_uefi_fwhunt.txt"
  export S02_CSV_LOG="${CSV_DIR}/s02_uefi_fwhunt.csv"
  export S03_LOG="${LOG_DIR}/s03_firmware_bin_base_analyzer.txt"
  export S05_LOG="${LOG_DIR}/s05_firmware_details.txt"
  export S06_LOG="${LOG_DIR}/s06_distribution_identification.txt"
  export S06_CSV_LOG="${CSV_DIR}/s06_distribution_identification.csv"
  export S08_CSV_LOG="${CSV_DIR}/s08_package_mgmt_extractor.csv"
  export S09_CSV_LOG="${CSV_DIR}/s09_firmware_base_version_check.csv"
  export S12_LOG="${LOG_DIR}/s12_binary_protection.txt"
  export S12_CSV_LOG="${CSV_DIR}/s12_binary_protection.csv"
  export S13_LOG="${LOG_DIR}/s13_weak_func_check.txt"
  export S13_CSV_LOG="${CSV_DIR}/s13_weak_func_check.csv"
  export S14_LOG="${LOG_DIR}/s14_weak_func_radare_check.txt"
  export S14_CSV_LOG="${CSV_DIR}/s14_weak_func_radare_check.csv"
  export S16_LOG="${LOG_DIR}/s16_ghidra_decompile_checks.txt"
  export S17_LOG="${LOG_DIR}/s17_cwe_checker.txt"
  export S17_CSV_LOG="${CSV_DIR}/s17_apk_check.csv"
  export S25_CSV_LOG="${CSV_DIR}/s25_kernel_check.csv"
  export S20_LOG="${LOG_DIR}/s20_shell_check.txt"
  export S21_LOG="${LOG_DIR}/s21_python_check.txt"
  export S22_LOG="${LOG_DIR}/s22_php_check.txt"
  export S22_CSV_LOG="${CSV_DIR}/s22_php_check.csv"
  export S23_LOG="${LOG_DIR}/s23_lua_check.txt"
  export S23_CSV_LOG="${CSV_DIR}/s23_lua_check.csv"
  export S24_LOG="${LOG_DIR}/s24_kernel_bin_identifier.txt"
  export S24_CSV_LOG="${CSV_DIR}/s24_kernel_bin_identifier.csv"
  export S25_LOG="${LOG_DIR}/s25_kernel_check.txt"
  export S26_LOG="${LOG_DIR}/s26_kernel_vuln_verifier.txt"
  export S26_LOG_DIR="${S26_LOG/\.txt/\/}"
  export S30_LOG="${LOG_DIR}/s30_version_vulnerability_check.txt"
  export S36_LOG="${LOG_DIR}/s36_lighttpd.txt"
  export S36_LOG_DIR="${S36_LOG/\.txt/\/}"
  export S36_CSV_LOG="${CSV_DIR}/s36_lighttpd.csv"
  export S40_LOG="${LOG_DIR}/s40_weak_perm_check.txt"
  export S45_LOG="${LOG_DIR}/s45_pass_file_check.txt"
  export S50_LOG="${LOG_DIR}/s50_authentication_check.txt"
  export S55_LOG="${LOG_DIR}/s55_history_file_check.txt"
  export S60_LOG="${LOG_DIR}/s60_cert_file_check.txt"
  export S85_LOG="${LOG_DIR}/s85_ssh_check.txt"
  export S95_LOG="${LOG_DIR}/s95_interesting_files_check.txt"
  export S107_LOG="${LOG_DIR}/s107_deep_password_search.txt"
  export S108_LOG="${LOG_DIR}/s108_stacs_password_search.txt"
  export S108_CSV_LOG="${CSV_DIR}/s108_stacs_password_search.csv"
  export S109_LOG="${LOG_DIR}/s109_jtr_local_pw_cracking.txt"
  export S110_LOG="${LOG_DIR}/s110_yara_check.txt"
  export S116_CSV_LOG="${CSV_DIR}/s116_qemu_version_detection.csv"
  export S118_CSV_LOG="${CSV_DIR}/s118_busybox_verifier.csv"
  export S118_LOG="${LOG_DIR}/s118_busybox_verifier.txt"
  export S118_LOG_DIR="${S118_LOG/\.txt/\/}"
  export Q02_LOG="${LOG_DIR}/q02_openai_question.txt"
  export L10_LOG="${LOG_DIR}/l10_system_emulator.txt"
  export L10_SYS_EMU_RESULTS="${LOG_DIR}/emulator_online_results.log"
  export L15_LOG="${LOG_DIR}/l15_emulated_checks_init.txt"
  export L15_CSV_LOG="${CSV_DIR}/l15_emulated_checks_nmap.csv"
  export L20_LOG="${LOG_DIR}/l20_snmp_checks.txt"
  export L25_LOG="${LOG_DIR}/l25_web_checks.txt"
  export L25_CSV_LOG="${CSV_DIR}/l25_web_checks.csv"
  export L35_CSV_LOG="${CSV_DIR}/l35_metasploit_check.csv"
  export F15_LOG="${LOG_DIR}/f15_cyclonedx_sbom.txt"
  export F15_CSV_LOG="${CSV_DIR}/f15_cyclonedx_sbom.csv"
  export F17_LOG_DIR="${LOG_DIR}/f17_cve_bin_tool"
  export F50_CSV_LOG="${CSV_DIR}/f50_base_aggregator.csv"
}
