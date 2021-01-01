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

F10_base_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final aggregator"

  print_output "[+] Tested firmware:""$NC"" ""$FIRMWARE_PATH"""
  print_output "[+] Found architecture:""$NC"" ""$D_ARCH"""
  print_output "[+] Emba start command:""$NC"" ""$EMBACOMMAND"""
  print_output ""

  if [[ -n "$S20_SHELL_VULNS" ]]; then
    print_output "[+] Found ""$ORANGE""""$S20_SHELL_VULNS"" issues""$GREEN"" in ""$S20_SCRIPTS"" scripts.""$NC"""
  fi
  if [[ -n "$S30_VUL_COUNTER" ]]; then
    print_output "[+] Found ""$ORANGE""""$S30_VUL_COUNTER""""$GREEN"" CVE vulnerabilities in ${#BINARIES[@]} binaries (without version checking).""$NC"""
  fi
  if [[ -n "$STRCPY_CNT" ]]; then
    print_output "[+] Found ""$ORANGE""""$STRCPY_CNT""""$GREEN"" usages of strcpy in ${#BINARIES[@]} binaries.""$NC"""
  fi
  if [[ -n "$CERT_OUT_CNT" ]]; then
    print_output "[+] Found ""$ORANGE""""$CERT_OUT_CNT""""$GREEN"" outdated certificates in ""$CERT_CNT"" certificates.""$NC"""
  fi
  if [[ -n "$YARA_CNT" ]]; then
    print_output "[+] Found ""$ORANGE""""$YARA_CNT""""$GREEN"" yara rule matches.""$NC"""
  fi

  if [[ -f "$LOG_DIR"/s10_binaries_check.txt ]]; then
    CANARY=$(grep -c "No canary" "$LOG_DIR"/s10_binaries_check.txt)
    RELRO=$(grep -c "No RELRO" "$LOG_DIR"/s10_binaries_check.txt)
    NX=$(grep -c "NX disabled" "$LOG_DIR"/s10_binaries_check.txt)
    PIE=$(grep -c "No PIE" "$LOG_DIR"/s10_binaries_check.txt)
  fi

  if [[ -n "$CANARY" ]]; then
    CAN_PER=$(( CANARY/(${#BINARIES[@]}/100) ))
    print_output "[+] Found ""$ORANGE""""$CANARY""""$GREEN"" binaries without enabled stack canaries in ${#BINARIES[@]} binaries - ""$ORANGE""""$CAN_PER""% ""$GREEN""without stack canaries enabled""$NC"""
  fi
  if [[ -n "$RELRO" ]]; then
    RELRO_PER=$(( RELRO/(${#BINARIES[@]}/100) ))
    print_output "[+] Found ""$ORANGE""""$RELRO""""$GREEN"" binaries without enabled RELRO in ${#BINARIES[@]} binaries - ""$ORANGE""""$RELRO_PER""% ""$GREEN""without RELRO enabled""$NC"""
  fi
  if [[ -n "$NX" ]]; then
    NX_PER=$(( NX/(${#BINARIES[@]}/100) ))
    print_output "[+] Found ""$ORANGE""""$NX""""$GREEN"" binaries without enabled NX in ${#BINARIES[@]} binaries - ""$ORANGE""""$NX_PER""% ""$GREEN""without NX enabled""$NC"""
  fi
  if [[ -n "$PIE" ]]; then
    PIE_PER=$(( PIE/(${#BINARIES[@]}/100) ))
    print_output "[+] Found ""$ORANGE""""$PIE""""$GREEN"" binaries without enabled PIE in ${#BINARIES[@]} binaries - ""$ORANGE""""$PIE_PER""% ""$GREEN""without PIE enabled""$NC"""
  fi
}
