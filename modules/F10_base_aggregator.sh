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
  print_output ""

  if [[ -n "$S20_SHELL_VULNS" ]]; then
    print_output "[+] Found ""$ORANGE""""$S20_SHELL_VULNS"" issues""$GREEN"" in ""$S20_SCRIPTS"" scripts.""$NC"""
  fi
  if [[ -n "$S30_VUL_COUNTER" ]]; then
    print_output "[+] Found ""$ORANGE""""$S30_VUL_COUNTER""""$GREEN"" CVE vulnerabilities in all binaries (without version checking).""$NC"""
  fi
  if [[ -n "$STRCPY_CNT" ]]; then
    print_output "[+] Found ""$ORANGE""""$STRCPY_CNT""""$GREEN"" usages of strcpy in all binaries.""$NC"""
  fi
  if [[ -n "$CERT_OUT_CNT" ]]; then
    print_output "[+] Found ""$ORANGE""""$CERT_OUT_CNT""""$GREEN"" outdated certificates in ""$CERT_CNT"" certificates.""$NC"""
  fi

  CANARY=$(grep -c "No canary" "$LOG_DIR"/s10_binaries_check.txt)
  RELRO=$(grep -c "No RELRO" "$LOG_DIR"/s10_binaries_check.txt)
  NX=$(grep -c "NX disabled" "$LOG_DIR"/s10_binaries_check.txt)
  PIE=$(grep -c "No PIE" "$LOG_DIR"/s10_binaries_check.txt)

  if [[ -n "$CANARY" ]]; then
    print_output "[+] Found ""$ORANGE""""$CANARY""""$GREEN"" binaries without enabled stack canaries""$NC"""
  fi
  if [[ -n "$RELRO" ]]; then
    print_output "[+] Found ""$ORANGE""""$RELRO""""$GREEN"" binaries without enabled RELRO""$NC"""
  fi
  if [[ -n "$NX" ]]; then
    print_output "[+] Found ""$ORANGE""""$NX""""$GREEN"" binaries without enabled NX""$NC"""
  fi
  if [[ -n "$PIE" ]]; then
    print_output "[+] Found ""$ORANGE""""$PIE""""$GREEN"" binaries without enabled PIE""$NC"""
  fi

}
