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

  CVE_AGGREGATOR_LOG="f19_cve_aggregator.txt"
  BIN_CHECK_LOG="s10_binaries_check.txt"
  KERNEL_CHECK_LOG="s25_kernel_check.txt"

  print_output "[+] Tested firmware:""$ORANGE"" ""$FIRMWARE_PATH"""
  print_output "[+] Emba start command:""$ORANGE"" ""$EMBACOMMAND"""
  if [[ -n "$D_ARCH" ]]; then
    print_output "[+] Detected architecture:""$ORANGE"" ""$D_ARCH"""
  fi
  print_output "[+] ""$ORANGE""""$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f 2>/dev/null | wc -l )""""$GREEN"" files and ""$ORANGE""""$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type d 2>/dev/null | wc -l)"" ""$GREEN""directories detected."
  KERNELV=$(grep "Kernel version:\ " "$LOG_DIR"/"$KERNEL_CHECK_LOG" 2>/dev/null | sed -e 's/Kernel\ version\:/Linux\ kernel\ version/' | sort -u | head -1)
  if [[ -n "$KERNELV" ]]; then
    print_output "[+] Detected kernel version:""$ORANGE"" ""$KERNELV"""
  fi
  if [[ "${#MOD_DATA[@]}" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""""${#MOD_DATA[@]}""""$GREEN"" kernel modules with ""$ORANGE""""$KMOD_BAD""""$GREEN"" licensing issues."
  fi
  ENTROPY=$(find "$LOG_DIR" -type f -iname "*_entropy.png" 2> /dev/null)
  if [[ -n "$ENTROPY" ]]; then
    print_output "[+] Entropy analysis of binary firmware is available:""$ORANGE"" ""$ENTROPY"""
  fi
  print_output ""

  if [[ "$S20_SHELL_VULNS" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""""$S20_SHELL_VULNS"" issues""$GREEN"" in ""$ORANGE""""$S20_SCRIPTS""""$GREEN"" shell scripts.""$NC"""
  fi
  if [[ "$S30_VUL_COUNTER" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""""$S30_VUL_COUNTER""""$GREEN"" CVE vulnerabilities in ""$ORANGE""""${#BINARIES[@]}""""$GREEN"" binaries (without version checking).""$NC"""
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
    print_output "[+] Found ""$ORANGE""""$EMUL""""$GREEN"" successful emulated processes.""$NC"""
  fi

  if [[ "${#BINARIES[@]}" -gt 0 ]]; then
    print_output ""
    if [[ -f "$LOG_DIR"/"$BIN_CHECK_LOG" ]]; then
      CANARY=$(grep -c "No canary" "$LOG_DIR"/"$BIN_CHECK_LOG")
      RELRO=$(grep -c "No RELRO" "$LOG_DIR"/"$BIN_CHECK_LOG")
      NX=$(grep -c "NX disabled" "$LOG_DIR"/"$BIN_CHECK_LOG")
      PIE=$(grep -c "No PIE" "$LOG_DIR"/"$BIN_CHECK_LOG")
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

  if [[ "$STRCPY_CNT" -gt 0 ]]; then
    print_output "[+] Found ""$ORANGE""""$STRCPY_CNT""""$GREEN"" usages of strcpy in ""$ORANGE""""${#BINARIES[@]}""""$GREEN"" binaries.""$NC"""
  fi

  FUNCTION="strcpy"
  if [[ "$(find "$LOG_DIR""/vul_func_checker/" -iname "vul_func_*_""$FUNCTION""-*.txt" | wc -l)" -gt 0 ]]; then
    local SEARCH_TERM
    local RESULTS
    readarray -t RESULTS < <( find "$LOG_DIR""/vul_func_checker/" -iname "vul_func_*_""$FUNCTION""-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_""$FUNCTION""-/  /" | sed "s/\.txt//" 2> /dev/null)

    if [[ "${#RESULTS[@]}" -gt 0 ]]; then
      print_output ""
      print_output "[+] ""$FUNCTION"" - top 10 results:"
      for LINE in "${RESULTS[@]}" ; do
        SEARCH_TERM=$(echo "$LINE" | cut -d\  -f3)
        if [[ -f "$BASE_LINUX_FILES" ]]; then
          if grep -q "^$SEARCH_TERM\$" "$BASE_LINUX_FILES" 2>/dev/null; then
            #LINE=$(echo "$LINE" | sed -e 's/\ \+/\t/g')
            print_output "$(indent "$(green "$LINE"" - common linux file: yes")")"
          else
            #LINE=$(echo "$LINE" | sed -e 's/\ \+/\t/g')
            print_output "$(indent "$(orange "$LINE"" - common linux file: no")")"
          fi
        else
          print_output "$(indent "$(orange "$LINE")")"
        fi
      done
    fi
  fi

  print_output ""
  if [[ -f "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" ]]; then
    print_output "[*] Identified the following version details, vulnerabilities and exploits:"
    print_output "$(grep "\[+\] Found version details" "$LOG_DIR"/"$CVE_AGGREGATOR_LOG" 2>/dev/null)"

    print_output ""
    if [[ "$S30_VUL_COUNTER" -gt 0 ]]; then
      print_output "[+] Found ""$ORANGE""$S30_VUL_COUNTER""$GREEN"" CVE entries for all binaries from S30_version_vulnerability_check.sh."
    fi
    print_output "[+] Confirmed ""$ORANGE""$CVE_COUNTER""$GREEN"" CVE entries."
    print_output "[+] ""$ORANGE""$EXPLOIT_COUNTER""$GREEN"" possible exploits available.\\n"
  fi
}
