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

F50_base_aggregator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Final aggregator"

  print_output "[+] Tested firmware:""$NC"" ""$FIRMWARE_PATH"""
  if [[ -n "$D_ARCH" ]]; then
    print_output "[+] Found architecture:""$NC"" ""$D_ARCH"""
  fi
  KERNELV=$(grep "Kernel version:\ " "$LOG_DIR"/s25_kernel_check.txt 2>/dev/null | sed -e 's/Kernel\ version\:/Linux\ kernel\ version/' | sort -u | head -1)
  if [[ -n "$KERNELV" ]]; then
    print_output "[+] Detected kernel version:""$ORANGE"" ""$KERNELV"""
  fi
  if [[ "${#MOD_DATA[@]}" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""""${#MOD_DATA[@]}""""$GREEN"" kernel modules with ""$ORANGE""""$KMOD_BAD""""$GREEN"" licensing issues."
  fi
  print_output "[+] Emba start command:""$NC"" ""$EMBACOMMAND"""
  print_output "[+] ""$ORANGE""""$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f | wc -l )""""$GREEN"" files and ""$ORANGE""""$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type d | wc -l)"" ""$GREEN""directories detected."
  if [[ -f "$LOG_DIR/*_entropy.png" ]]; then
    print_output "[+] Entropy analysis of binary firmware is available in log directory:""$NC"" ""$LOG_DIR"""
  fi
  print_output ""

  if [[ "$S20_SHELL_VULNS" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""""$S20_SHELL_VULNS"" issues""$GREEN"" in ""$ORANGE""""$S20_SCRIPTS""""$GREEN"" shell scripts.""$NC"""
  fi
  if [[ "$S30_VUL_COUNTER" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""""$S30_VUL_COUNTER""""$GREEN"" CVE vulnerabilities in ""$ORANGE""""${#BINARIES[@]}""""$GREEN"" binaries (without version checking).""$NC"""
  fi
  if [[ "$STRCPY_CNT" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""""$STRCPY_CNT""""$GREEN"" usages of strcpy in ""$ORANGE""""${#BINARIES[@]}""""$GREEN"" binaries.""$NC"""
  fi
  if [[ "$CERT_CNT" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""""$CERT_OUT_CNT""""$GREEN"" outdated certificates in ""$ORANGE""""$CERT_CNT""""$GREEN"" certificates.""$NC"""
  fi
  if [[ "$YARA_CNT" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""""$YARA_CNT""""$GREEN"" yara rule matches.""$NC"""
  fi
  if [[ -n "$FILE_COUNTER" ]]; then
    print_output "[+] Found ""$ORANGE""""$FILE_COUNTER""""$GREEN"" not common Linux files with ""$ORANGE""""$FILE_COUNTER_ALL""""$GREEN"" files at all.""$NC"""
  fi
  EMUL=$(find "$LOG_DIR"/qemu_emulator -type f -iname "qemu_*" 2>/dev/null | wc -l)
  if [[ "$EMUL" -gt 0 ]]; then
    print_output "[+] Found ""$EMUL"" successful emulated processes."
  fi

  if [[ "${#BINARIES[@]}" -gt 0 ]]; then
    print_output ""
    if [[ -f "$LOG_DIR"/s10_binaries_check.txt ]]; then
      CANARY=$(grep -c "No canary" "$LOG_DIR"/s10_binaries_check.txt)
      RELRO=$(grep -c "No RELRO" "$LOG_DIR"/s10_binaries_check.txt)
      NX=$(grep -c "NX disabled" "$LOG_DIR"/s10_binaries_check.txt)
      PIE=$(grep -c "No PIE" "$LOG_DIR"/s10_binaries_check.txt)
    fi
  
    if [[ -n "$CANARY" ]]; then
      CAN_PER=$(bc -l <<< "scale=0;$CANARY/(${#BINARIES[@]}/100)" 2>/dev/null)
      print_output "[+] Found ""$ORANGE""""$CANARY""""$GREEN"" binaries without enabled stack canaries in ${#BINARIES[@]} binaries - ""$ORANGE""""$CAN_PER""% ""$GREEN""without stack canaries enabled""$NC"""
    fi
    if [[ -n "$RELRO" ]]; then
      RELRO_PER=$(bc -l <<< "scale=0;$RELRO/(${#BINARIES[@]}/100)" 2>/dev/null)
      print_output "[+] Found ""$ORANGE""""$RELRO""""$GREEN"" binaries without enabled RELRO in ${#BINARIES[@]} binaries - ""$ORANGE""""$RELRO_PER""% ""$GREEN""without RELRO enabled""$NC"""
    fi
    if [[ -n "$NX" ]]; then
      #NX_PER=$(( NX/(${#BINARIES[@]}/100) ))
      NX_PER=$(bc -l <<< "scale=0;$NX/(${#BINARIES[@]}/100)" 2>/dev/null)
      print_output "[+] Found ""$ORANGE""""$NX""""$GREEN"" binaries without enabled NX in ${#BINARIES[@]} binaries - ""$ORANGE""""$NX_PER""% ""$GREEN""without NX enabled""$NC"""
    fi
    if [[ -n "$PIE" ]]; then
      #PIE_PER=$(( PIE/(${#BINARIES[@]}/100) ))
      PIE_PER=$(bc -l <<< "scale=0;$PIE/(${#BINARIES[@]}/100)" 2>/dev/null)
      print_output "[+] Found ""$ORANGE""""$PIE""""$GREEN"" binaries without enabled PIE in ${#BINARIES[@]} binaries - ""$ORANGE""""$PIE_PER""% ""$GREEN""without PIE enabled""$NC"""
    fi
  fi

  print_output ""
  if [[ -f "$LOG_DIR"/f19_cve_aggregator.txt ]]; then
    print_output "[*] Identified the following version details, vulnerabilities and exploits:"
    print_output "$(cat "$LOG_DIR"/f19_cve_aggregator.txt | grep "\[+\] Found version details" 2>/dev/null)"

    print_output "${NC}"
    if [[ "$S30_VUL_COUNTER" -gt 0 ]]; then
      print_output "[+] Found $S30_VUL_COUNTER CVE entries for all binaries from S30_version_vulnerability_check.sh."
    fi
    print_output "[+] Confirmed $CVE_COUNTER CVE entries."
    print_output "[+] $EXPLOIT_COUNTER possible exploits available.\\n"

  fi
}
