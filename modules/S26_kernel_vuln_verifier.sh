#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  After the s24 module was able to identify the kernel, the downloader
#               helper function "kernel_downloader" has downloaded the kernel sources
#               This module checks if we have symbols and/or the kernel config extracted,
#               identifies vulnerabilities via the version number and tries to verify the 
#               CVEs

S26_kernel_vuln_verifier()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Kernel vulnerability identification and verification"
  pre_module_reporter "${FUNCNAME[0]}"

  KERNEL_CONFIG="NA"
  HOME_DIR="$(pwd)"
  # KERNEL_ARCH_PATH is the directory where we store all the kernels
  KERNEL_ARCH_PATH="$EXT_DIR""/linux_kernel_sources"
  S24_CSV_LOG="$CSV_DIR""/s24_kernel_bin_identifier.csv"
  WAIT_PIDS_S26=()
  NEG_LOG=0

  # we wait until the s24 module is finished and hopefully shows us a kernel version
  while ! [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; do
    sleep 1
  done
  if [[ -f "$LOG_DIR"/"$MAIN_LOG_FILE" ]]; then
    while [[ $(grep -c S24_kernel_bin_identifier "$LOG_DIR"/"$MAIN_LOG_FILE") -lt 2 ]]; do
      sleep 1
    done
  fi
  # now we should have a csv log with a kernel version:
  if ! [[ -f "$S24_CSV_LOG" ]] || [[ "$(wc -l "$S24_CSV_LOG" | awk '{print $1}')" -lt 2 ]]; then
    print_output "[-] No Kernel version file identified ..."
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
    return
  fi

  # extract kernel version
  get_csv_data_s24 "$S24_CSV_LOG"

  if ! [[ -f "$KERNEL_ELF_PATH" ]]; then
    print_output "[-] Warning: Kernel ELF file not found"
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
    return
  fi
  if ! [[ -v K_VERSION ]]; then
    print_output "[-] Missing kernel version .. exit now"
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
    return
  fi

  CVE_DETAILS_PATH="$LOG_PATH_MODULE""/kernel-$K_VERSION-vulns.json"

  if ! [[ -f $PATH_CVE_SEARCH ]]; then
    print_output "[-] CVE search binary search.py not found."
    print_output "[-] Run the installer or install it from here: https://github.com/cve-search/cve-search."
    print_output "[-] Installation instructions can be found on github.io: https://cve-search.github.io/cve-search/getting_started/installation.html#installation"
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
    return
  fi

  check_cve_search

  if [[ "$CVE_SEARCH" -eq 0 ]]; then
    print_output "[*] Waiting for the cve-search environment ..."
    sleep 120
    check_cve_search

    if [[ "$CVE_SEARCH" -eq 0 ]]; then
      print_output "[*] Waiting for the cve-search environment ..."
      sleep 120
      check_cve_search
    fi
  fi
  if [[ "$CVE_SEARCH" -ne 1 ]]; then
    print_cve_search_failure
    return
  fi

  if [[ -f "$KERNEL_ELF_PATH" ]]; then
    extract_kernel_arch "$KERNEL_ELF_PATH"
  fi

  WAIT_CNT=0
  while ! [[ -f "$KERNEL_ARCH_PATH/linux-$K_VERSION.tar.gz" ]]; do
    print_output "[*] Waiting for kernel sources ..." "no_log"
    ((WAIT_CNT+=1))
    if [[ "$WAIT_CNT" -gt 60 ]]; then
      print_output "[-] No kernel source file available ... exit module now"
      module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
      return
    fi
    sleep 5
  done

  print_output "[*] Kernel archive for version $ORANGE$K_VERSION$NC available"

  KERNEL_DIR="$LOG_PATH_MODULE/linux-$K_VERSION"
  if [[ -d "$KERNEL_DIR" ]]; then
    rm -rf "$KERNEL_DIR"
  fi
  if ! [[ -d "$KERNEL_DIR" ]] && [[ "$(file "$KERNEL_ARCH_PATH/linux-$K_VERSION.tar.gz")" == *"gzip compressed data"* ]]; then
    print_output "[*] Kernel extract for version $ORANGE$K_VERSION$NC"
    tar -xzf "$KERNEL_ARCH_PATH/linux-$K_VERSION.tar.gz" -C "$LOG_PATH_MODULE"
  fi

  get_cve_kernel_data

  if ! [[ -f "$CVE_DETAILS_PATH" ]]; then
    print_output "[-] No CVE details generated ... return"
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
    return
  fi

  print_output "[*] Create CVE vulnerabilities array for kernel version $ORANGE$K_VERSION$NC ..."
  mapfile -t ALL_KVULNS < <(jq -rc '"\(.id):\(.cvss):\(.cvss3):\(.summary)"' "$CVE_DETAILS_PATH")
  print_output "[+] Extracted $ORANGE${#ALL_KVULNS[@]}$GREEN vulnerabilities based on kernel version only"
  print_output "[*] Starting in depth testing of these vulnerabilities ..."

  if [[ -f "$KERNEL_CONFIG" ]] && [[ -d "$KERNEL_DIR" ]]; then
    compile_kernel "$KERNEL_CONFIG" "$KERNEL_DIR" "$ORIG_K_ARCH"
  fi

  print_ln
  print_output "[*] Identify kernel symbols ..."
  readelf -s "$KERNEL_ELF_PATH" | grep "FUNC\|OBJECT" | sed 's/.*FUNC//' | sed 's/.*OBJECT//' | awk '{print $4}' | \
    sed 's/\[\.\.\.\]//' > "$LOG_PATH_MODULE"/symbols.txt
  SYMBOLS_CNT=$(wc -l "$LOG_PATH_MODULE"/symbols.txt | awk '{print $1}')
  print_output "[*] Extracted $SYMBOLS_CNT symbols from kernel"

  if [[ -d "$LOG_DIR""/firmware" ]]; then
    print_output "[*] Identify kernel modules symbols ..."
    find "$LOG_DIR/firmware" -name "*.ko" -exec readelf -a {} \; | grep FUNC | sed 's/.*FUNC//' | \
      awk '{print $4}' | sed 's/\[\.\.\.\]//' >> "$LOG_PATH_MODULE"/symbols.txt
  fi

  uniq "$LOG_PATH_MODULE"/symbols.txt > "$LOG_PATH_MODULE"/symbols_uniq.txt
  SYMBOLS_CNT=$(wc -l "$LOG_PATH_MODULE"/symbols_uniq.txt | awk '{print $1}')
  print_output "[*] Extracted $ORANGE$SYMBOLS_CNT$NC unique symbols"

  if [[ "$SYMBOLS_CNT" -eq 0 ]]; then
    print_output "[-] No symbols found ... exit"
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
    return
  fi

  print_output "[*] Splitting symbols file for processing"
  split -l 100 "$LOG_PATH_MODULE"/symbols_uniq.txt "$LOG_PATH_MODULE"/symbols_uniq.split.
  sed -i 's/^/EXPORT_SYMBOL\(/' "$LOG_PATH_MODULE"/symbols_uniq.split.*
  sed -i 's/$/\)/' "$LOG_PATH_MODULE"/symbols_uniq.split.*

  split -l 100 "$LOG_PATH_MODULE"/symbols_uniq.txt "$LOG_PATH_MODULE"/symbols_uniq.split_gpl.
  sed -i 's/^/EXPORT_SYMBOL_GPL\(/' "$LOG_PATH_MODULE"/symbols_uniq.split_gpl.*
  sed -i 's/$/\)/' "$LOG_PATH_MODULE"/symbols_uniq.split_gpl.*

  export CNT_PATHS_UNK=0
  export CNT_PATHS_FOUND=0
  export CNT_PATHS_NOT_FOUND=0
  export VULN_CNT=1
  export CNT_PATHS_FOUND_WRONG_ARCH=0
  local NEG_LOG=1

  print_ln
  print_output "[*] Checking vulnerabilities for kernel version $ORANGE$K_VERSION$NC"
  print_ln

  for VULN in "${ALL_KVULNS[@]}"; do
    K_PATHS=()
    K_PATHS_FILES_TMP=()
    K_PATH="undocumented source path"

    CVE=$(echo "$VULN" | cut -d: -f1)
    print_output "[*] Testing vulnerability $ORANGE$VULN_CNT$NC / $ORANGE${#ALL_KVULNS[@]}$NC / $ORANGE$CVE$NC"

    CVSS2="$(echo "$VULN" | cut -d: -f2)"
    CVSS3="$(echo "$VULN" | cut -d: -f3)"
    SUMMARY="$(echo "$VULN" | cut -d: -f4-)"

    # extract kernel source paths from summary -> we use these paths to check if they are used by our
    # symbols or during kernel compilation
    mapfile -t K_PATHS < <(echo "$SUMMARY" | tr ' ' '\n' | grep ".*\.[chS]$" | sed -r 's/CVE-[0-9]+-[0-9]+:[0-9].*://' \
      | sed -r 's/CVE-[0-9]+-[0-9]+:null.*://' | sed 's/^(//' | sed 's/)$//' | sed 's/,$//' | sed 's/\.$//' | cut -d: -f1 || true)

    for K_PATH in "${K_PATHS[@]}"; do
      # we have only a filename without path -> we search for possible candidate files in the kernel sources
      if ! [[ "$K_PATH" == *"/"* ]]; then
        print_output "[*] Found file name $ORANGE$K_PATH$NC for $ORANGE$CVE$NC without path details ... looking for candidates now"
        mapfile -t K_PATHS_FILES_TMP < <(find "$KERNEL_DIR" -name "$K_PATH" | sed "s&$KERNEL_DIR\/&&")
      fi
      K_PATHS+=("${K_PATHS_FILES_TMP[@]}")
    done

    if [[ "${#K_PATHS[@]}" -gt 0 ]]; then
      for K_PATH in "${K_PATHS[@]}"; do
        if [[ -f "$KERNEL_DIR/$K_PATH" ]]; then
          # check if arch is in path -> if so we check if our architecture is also in the path
          # if we find our architecture then we can proceed with symbol_verifier
          if [[ "$K_PATH" == "arch/"* ]]; then
            if [[ "$K_PATH" == "arch/$ORIG_K_ARCH/"* ]]; then
              ((CNT_PATHS_FOUND+=1))
              symbol_verifier "$CVE" "$K_VERSION" "$K_PATH" "$CVSS2/$CVSS3" &
              WAIT_PIDS_S26+=( "$!" )
              compile_verifier "$CVE" "$K_VERSION" "$K_PATH" "$CVSS2/$CVSS3" &
              WAIT_PIDS_S26+=( "$!" )
            else
              # this vulnerability is for a different architecture -> we can skip it for our kernel
              print_output "[-] Vulnerable path for different architecture found for $ORANGE$K_PATH$NC - not further processing $ORANGE$CVE$NC"
              ((CNT_PATHS_FOUND_WRONG_ARCH+=1))
            fi
          else
            ((CNT_PATHS_FOUND+=1))
            symbol_verifier "$CVE" "$K_VERSION" "$K_PATH" "$CVSS2/$CVSS3" &
            WAIT_PIDS_S26+=( "$!" )
            compile_verifier "$CVE" "$K_VERSION" "$K_PATH" "$CVSS2/$CVSS3" &
            WAIT_PIDS_S26+=( "$!" )
          fi
        else
          # no source file in our kernel sources -> no vulns
          print_output "[-] $ORANGE$CVE$NC - $ORANGE$K_PATH$NC - source file not found"
          ((CNT_PATHS_NOT_FOUND+=1))
        fi
        max_pids_protection 20 "${WAIT_PIDS_S26[@]}"
      done
    else
      print_output "[-] $CVE - $K_PATH"
      ((CNT_PATHS_UNK+=1))
    fi
    ((VULN_CNT+=1))
  done

  wait_for_pid "${WAIT_PIDS_S26[@]}"

  final_log_kernel_vulns

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

get_cve_kernel_data() {
  print_output "[*] Extract CVE data for kernel version $ORANGE$K_VERSION$NC"
  "$PATH_CVE_SEARCH" -p linux_kernel:"$K_VERSION" -o json > "$CVE_DETAILS_PATH"
}

extract_kernel_arch() {
  KERNEL_ELF_PATH="${1:-}"
  ORIG_K_ARCH=$(file "$KERNEL_ELF_PATH" | cut -d, -f2)

  # for ARM -> ARM aarch64 to ARM64
  ORIG_K_ARCH=${ORIG_K_ARCH/ARM\ aarch64/arm64}
  # for MIPS64 -> MIPS64 to MIPS
  ORIG_K_ARCH=${ORIG_K_ARCH/MIPS64/MIPS}

  ORIG_K_ARCH=$(echo "$ORIG_K_ARCH" | tr -d ' ' | tr "[:upper:]" "[:lower:]")
  print_output "[+] Found kernel architecture $ORANGE$ORIG_K_ARCH$NC"
}

symbol_verifier() {
  local CVE="${1:-}"
  local K_VERSION="${2:-}"
  local K_PATH="${3:-}"
  local CVSS="${4:-}"
  local VULN_FOUND=0

  for CHUNK_FILE in "$LOG_PATH_MODULE"/symbols_uniq.split.* ; do
    # echo "testing chunk file $CHUNK_FILE"
    if grep -q -f "$CHUNK_FILE" "$KERNEL_DIR/$K_PATH" ; then
      # echo "verified chunk file $CHUNK_FILE"
      print_output "[+] $CVE ($CVSS) - $K_PATH verified - exported symbol$NC"
      echo "$CVE ($CVSS) - $K_VERSION - exported symbol verified - $K_PATH" >> "$LOG_PATH_MODULE""/${CVE}_symbol_verified.txt"
      VULN_FOUND=1
      break
    fi
  done

  if [[ "$VULN_FOUND" -eq 1 ]]; then
    # if we have already a match for this path we can skip the 2nd check
    # this is only for speed up the process a bit
    return
  fi

  for CHUNK_FILE in "$LOG_PATH_MODULE"/symbols_uniq.split_gpl.* ; do
    # echo "testing chunk file $CHUNK_FILE"
    if grep -q -f "$CHUNK_FILE" "$KERNEL_DIR/$K_PATH" ; then
      # print_output "[*] verified chunk file $CHUNK_FILE (GPL)"
      print_output "[+] $CVE ($CVSS) - $K_PATH verified - exported symbol (gpl)$NC"
      echo "$CVE ($CVSS) - $K_VERSION - exported symbol verified (gpl) - $K_PATH" >> "$LOG_PATH_MODULE""/${CVE}_symbol_verified.txt"
      VULN_FOUND=1
      break
    fi
  done
}

compile_verifier() {
  local CVE_="${1:-}"
  local K_VERSION="${2:-}"
  local K_PATH="${3:-}"
  local CVSS="${4:-}"
  local VULN_FOUND=0
  if ! [[ -f "$LOG_PATH_MODULE"/kernel-compile.files ]]; then
    return
  fi

  if grep -q "$K_PATH" "$LOG_PATH_MODULE"/kernel-compile.files ; then
    print_output "[+] $CVE_ ($CVSS) - $K_PATH verified - compiled path"
    echo "$CVE_ ($CVSS) - $K_VERSION - compiled path verified - $K_PATH" >> "$LOG_PATH_MODULE""/${CVE_}_compiled_verified.txt"
  fi
} 

compile_kernel() {
  # this is based on the great work shown here https://arxiv.org/pdf/2209.05217.pdf
  local KERNEL_CONFIG_FILE="${1:-}"
  local KERNEL_DIR="${2:-}"
  local KARCH="${3:-}"
  export COMPILE_SOURCE_FILES=0

  if ! [[ -f "$KERNEL_CONFIG_FILE" ]]; then
    return
  fi
  if ! [[ -d "$KERNEL_DIR" ]]; then
    return
  fi

  KARCH=$(echo "$KARCH" | tr '[:upper:]' '[:lower:]')
  # todo handle further architecture values

  print_bar
  cd "$KERNEL_DIR" || exit
  print_output "[*] Create default kernel config for $ORANGE$KARCH$NC architecture"
  LANG=en make ARCH="$KARCH" defconfig
  cp "$KERNEL_CONFIG_FILE" .config
  print_ln
  print_output "[*] Update kernel config with the identified configuration of the firmware"
  # https://stackoverflow.com/questions/4178526/what-does-make-oldconfig-do-exactly-in-the-linux-kernel-makefile
  LANG=en make ARCH="$KARCH" olddefconfig
  print_ln
  print_output "[*] Starting dry run ..."
  LANG=en make ARCH="$KARCH" target=all -Bndi | tee -a "$LOG_PATH_MODULE"/kernel-compile.output
  print_ln
  print_output "[*] Finished dry run ..."
  cd "$HOME_DIR" || exit
  if [[ -f "$LOG_PATH_MODULE"/kernel-compile.output ]]; then
    tr ' ' '\n' < "$LOG_PATH_MODULE"/kernel-compile.output | grep ".*\.[chS]" | tr -d '"' | tr -d ')' \
      | tr -d '(' | sed 's/^\.\///' | sed '/^\/.*/d' | tr -d ';' | sed 's/^>//' | sed 's/^-o//' | tr -d \' \
      | sed 's/--defines=//' | sed 's/\.$//' | sort -u > "$LOG_PATH_MODULE"/kernel-compile.files
    COMPILE_SOURCE_FILES=$(wc -l "$LOG_PATH_MODULE"/kernel-compile.files | awk '{print $1}')
    print_output "[+] Found $ORANGE$COMPILE_SOURCE_FILES$GREEN used source files during compilation"
  else
    print_output "[-] Found ${RED}NO$NC used source files during compilation"
  fi
  print_bar
}

final_log_kernel_vulns() {
  rm -r "$LOG_PATH_MODULE"/symbols_uniq.split.*
  rm -r "$LOG_PATH_MODULE"/symbols_uniq.split_gpl.*

  local VULN=""
  local SYM_USAGE_VERIFIED=0
  local VULN_PATHS_VERIFIED_SYMBOLS=0
  local VULN_PATHS_VERIFIED_COMPILED=0
  local CVE_VERIFIED_SYMBOLS=0
  local CVE_VERIFIED_COMPILED=0
  local CVE_VERIFIED_ONE=0
  local CVE_VERIFIED_OVERLAP=0
  local CVE_VERIFIED_OVERLAP_CRITICAL=()
  local CVE_VERIFIED_ONE_CRITICAL=()

  print_ln
  print_output "[*] Generating final kernel report ..."
  echo "Kernel version;Architecture;CVE;CVSSv2;CVSSv3;Verified with symbols;Verified with compile files" >> "$LOG_PATH_MODULE"/cve_results_kernel_"$K_VERSION".csv

  for VULN in "${ALL_KVULNS[@]}"; do
    local CVE=""
    local CVSS2=""
    local CVSS3=""
    local CVE_SYMBOL_FOUND=0
    local CVE_COMPILE_FOUND=0
    local CVE_SYMBOL_FOUND=0
    local CVE_COMPILE_FOUND=0

    CVE=$(echo "$VULN" | cut -d: -f1)
    CVSS2="$(echo "$VULN" | cut -d: -f2)"
    CVSS3="$(echo "$VULN" | cut -d: -f3)"
    CVE_SYMBOL_FOUND=$(find "$LOG_PATH_MODULE" -name "${CVE}_symbol_verified.txt" | wc -l)
    CVE_COMPILE_FOUND=$(find "$LOG_PATH_MODULE" -name "${CVE}_compiled_verified.txt" | wc -l)
    echo "$K_VERSION;$ORIG_K_ARCH;$CVE;$CVSS2;$CVSS3;$CVE_SYMBOL_FOUND;$CVE_COMPILE_FOUND" >> "$LOG_PATH_MODULE"/cve_results_kernel_"$K_VERSION".csv
  done

  SYM_USAGE_VERIFIED=$(cat "$LOG_PATH_MODULE"/CVE-*symbol_* | wc -l 2>/dev/null)
  VULN_PATHS_VERIFIED_SYMBOLS=$(cat "$LOG_PATH_MODULE"/CVE-*symbol_verified.txt 2>/dev/null | grep "exported symbol" | sed 's/.*verified - //' | sed 's/.*verified (GPL) - //' | sort -u | wc -l || true)
  VULN_PATHS_VERIFIED_COMPILED=$(cat "$LOG_PATH_MODULE"/CVE-*compiled_verified.txt 2>/dev/null | grep "compiled path verified" | sed 's/.*verified - //' | sort -u | wc -l || true)
  CVE_VERIFIED_SYMBOLS=$(cat "$LOG_PATH_MODULE"/CVE-*symbol_verified.txt 2>/dev/null | grep "exported symbol" | cut -d\  -f1 | sort -u | wc -l || true)
  CVE_VERIFIED_COMPILED=$(cat "$LOG_PATH_MODULE"/CVE-*compiled_verified.txt 2>/dev/null| grep "compiled path verified" | cut -d\  -f1 | sort -u | wc -l || true)
  CVE_VERIFIED_ONE=$(cut -d\; -f6-7 "$LOG_PATH_MODULE"/cve_results_kernel_"$K_VERSION".csv | grep -c "1" || true)
  CVE_VERIFIED_OVERLAP=$(grep -c ";1;1" "$LOG_PATH_MODULE"/cve_results_kernel_"$K_VERSION".csv || true)
  mapfile -t CVE_VERIFIED_OVERLAP_CRITICAL < <(grep ";1;1$" "$LOG_PATH_MODULE"/cve_results_kernel_"$K_VERSION".csv | grep ";9.[0-9];\|;10;" || true)
  mapfile -t CVE_VERIFIED_ONE_CRITICAL < <(grep ";1;\|;1$" "$LOG_PATH_MODULE"/cve_results_kernel_"$K_VERSION".csv | grep ";9.[0-9];\|;10;" || true)

  print_ln
  print_bar
  print_output "[+] Identified $ORANGE${#ALL_KVULNS[@]}$GREEN unverified CVE vulnerabilities for kernel version $ORANGE$K_VERSION$NC"
  print_output "[*] Detected architecture $ORANGE$ORIG_K_ARCH$NC"
  print_output "[*] Extracted $ORANGE$SYMBOLS_CNT$NC unique symbols from kernel and modules"
  print_output "[*] Extracted $ORANGE$COMPILE_SOURCE_FILES$NC used source files during compilation"
  print_output "[*] Found $ORANGE$CNT_PATHS_UNK$NC advisories with missing vulnerable path details"
  print_output "[*] Found $ORANGE$CNT_PATHS_NOT_FOUND$NC path details in CVE advisories but no real kernel path found in vanilla kernel source"
  print_output "[*] Found $ORANGE$CNT_PATHS_FOUND$NC path details in CVE advisories with real kernel path"
  print_output "[*] Found $ORANGE$CNT_PATHS_FOUND_WRONG_ARCH$NC path details in CVE advisories with real kernel path but wrong architecture"
  print_output "[*] $ORANGE$SYM_USAGE_VERIFIED$NC symbol usage verified"
  print_output "[*] $ORANGE$VULN_PATHS_VERIFIED_SYMBOLS$NC vulnerable paths verified via symbols"
  print_output "[*] $ORANGE$VULN_PATHS_VERIFIED_COMPILED$NC vulnerable paths verified via compiled paths"
  print_ln

  if [[ "$CVE_VERIFIED_SYMBOLS" -gt 0 ]]; then
    print_output "[+] Verified CVEs: $ORANGE$CVE_VERIFIED_SYMBOLS$GREEN (exported symbols)"
  fi
  if [[ "$CVE_VERIFIED_SYMBOLS" -gt 0 ]]; then
    print_output "[+] Verified CVEs: $ORANGE$CVE_VERIFIED_COMPILED$GREEN (compiled paths)"
  fi
  if [[ "$CVE_VERIFIED_ONE" -gt 0 ]]; then
    print_output "[+] Verified CVEs: $ORANGE$CVE_VERIFIED_ONE$GREEN (one mechanism success)"
  fi
  if [[ "$CVE_VERIFIED_OVERLAP" -gt 0 ]]; then
    print_output "[+] Verified CVEs: $ORANGE$CVE_VERIFIED_OVERLAP$GREEN (both mechanisms overlap)"
  fi

  if [[ "${#CVE_VERIFIED_ONE_CRITICAL[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Verified CRITICAL CVEs: $ORANGE${#CVE_VERIFIED_ONE_CRITICAL[@]}$GREEN (one mechanisms success)"
    for CVE_VERIFIED_ONE_CRITICAL_ in "${CVE_VERIFIED_ONE_CRITICAL[@]}"; do
      CVE_CRITICAL=$(echo "$CVE_VERIFIED_ONE_CRITICAL_" | cut -d\; -f3)
      CVSS2_CRITICAL=$(echo "$CVE_VERIFIED_ONE_CRITICAL_" | cut -d\; -f4)
      CVSS3_CRITICAL=$(echo "$CVE_VERIFIED_ONE_CRITICAL_" | cut -d\; -f5)
      identify_exploits "$CVE_CRITICAL"
      print_output "$(indent "$(orange "$ORANGE$CVE_CRITICAL$GREEN - $ORANGE$CVSS2_CRITICAL$GREEN / $ORANGE$CVSS3_CRITICAL$GREEN - Exploit/PoC: $ORANGE$EXPLOIT_DETECTED / $POC_DETECTED$NC")")"
    done
  fi

  if [[ "${#CVE_VERIFIED_OVERLAP_CRITICAL[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Verified CRITICAL CVEs: $ORANGE${#CVE_VERIFIED_OVERLAP_CRITICAL[@]}$GREEN (both mechanisms overlap)"
    for CVE_VERIFIED_OVERLAP_CRITICAL_ in "${CVE_VERIFIED_OVERLAP_CRITICAL[@]}"; do
      CVE_CRITICAL=$(echo "$CVE_VERIFIED_OVERLAP_CRITICAL_" | cut -d\; -f3)
      CVSS2_CRITICAL=$(echo "$CVE_VERIFIED_OVERLAP_CRITICAL_" | cut -d\; -f4)
      CVSS3_CRITICAL=$(echo "$CVE_VERIFIED_OVERLAP_CRITICAL_" | cut -d\; -f5)
      identify_exploits "$CVE_CRITICAL"
      print_output "$(indent "$(orange "$ORANGE$CVE_CRITICAL$GREEN - $ORANGE$CVSS2_CRITICAL$GREEN / $ORANGE$CVSS3_CRITICAL$GREEN - Exploit/PoC: $ORANGE$EXPLOIT_DETECTED / $POC_DETECTED$NC")")"
    done
  fi
  print_bar
}

identify_exploits() {
  local CVE_VALUE="${1:-}"
  EXPLOIT_DETECTED="no"
  POC_DETECTED="no"

  local MSF_DB_PATH="$CONFIG_DIR/msf_cve-db.txt"
  local KNOWN_EXP_CSV="$EXT_DIR/known_exploited_vulnerabilities.csv"

  if command -v cve_searchsploit >/dev/null; then
    if cve_searchsploit "$CVE_VALUE" 2>/dev/null | grep -q "Exploit DB Id:"; then
      EXPLOIT_DETECTED="yes"
    fi
  fi
  if [[ -f "$MSF_DB_PATH" ]]; then
    if grep -q -E "$CVE_VALUE"$ "$MSF_DB_PATH"; then
      EXPLOIT_DETECTED="yes"
    fi
  fi
  if [[ -f "$KNOWN_EXP_CSV" ]]; then
    if grep -q \""${CVE_VALUE}"\", "$KNOWN_EXP_CSV"; then
      EXPLOIT_DETECTED="yes"
    fi
  fi
  if [[ -f "$TRICKEST_DB_PATH" ]]; then
    if grep -q -E "$CVE_VALUE\.md" "$TRICKEST_DB_PATH"; then
      POC_DETECTED="yes"
    fi
  fi
  if [[ -f "$CONF_DIR/Snyk_PoC_results.csv" ]]; then
    if grep -q -E "^$CVE_VALUE;" "$CONF_DIR/Snyk_PoC_results.csv"; then
      POC_DETECTED="yes"
    fi
  fi
  if [[ -f "$CONF_DIR/PS_PoC_results.csv" ]]; then
    if grep -q -E "^$CVE_VALUE;" "$CONF_DIR/PS_PoC_results.csv"; then
      POC_DETECTED="yes"
    fi
  fi
}

get_csv_data_s24() {
  local S24_CSV_LOG="${1:-}"

  if ! [[ -f "$S24_CSV_LOG" ]];then
    print_output "[-] No EMBA log found ..."
    return
  fi

  local K_FOUND=0
  local KERNEL_DATA=""
  local KERNEL_ELF_EMBA=()
  export KERNEL_CONFIG_PATH=""
  export KERNEL_ELF_PATH=""
  export K_VERSION=""

  # currently we only support one kernel version
  # if we detect multiple kernel versions we only process the first one after sorting
  K_VERSION=$(cut -d\; -f2 "$S24_CSV_LOG" | tail -n +2 | grep -v "NA" | sort -u | head -1)

  print_output "[+] Identified kernel version: $ORANGE$K_VERSION$NC"

  mapfile -t KERNEL_ELF_EMBA < <(grep "$K_VERSION" "$S24_CSV_LOG" | cut -d\; -f4-7 | \
    grep -v "^NA" | grep -v "config extracted" | sort -u | sort -r -n -t\; -k4 || true)
  
  for KERNEL_DATA in "${KERNEL_ELF_EMBA[@]}"; do
    if ! [[ "$(echo "$KERNEL_DATA" | cut -d\; -f3)" == "NA" ]]; then
      KERNEL_CONFIG_PATH=$(echo "$KERNEL_DATA" | cut -d\; -f3)
      #KERNEL_CONFIG_PATH="${KERNEL_CONFIG/\/logs\//"$EMBA_LOG_PATH"}"
      print_output "[+] Found kernel configuration file: $ORANGE$KERNEL_CONFIG$NC"
      KERNEL_ELF_PATH=$(echo "$KERNEL_DATA" | cut -d\; -f1)
      # we use the first entry with a kernel config detected
      K_FOUND=1
      break
    fi
  done
  
  if [[ "$K_FOUND" -ne 1 ]]; then
    print_output "[-] No kernel configuration file found"
  fi
  if [[ "$K_FOUND" -ne 1 ]]; then
    for KERNEL_DATA in "${KERNEL_ELF_EMBA[@]}"; do
      # now we check for init entries
      if ! [[ "$(echo "$KERNEL_DATA" | cut -d\; -f2)" == "NA" ]]; then
        KERNEL_ELF_PATH=$(echo "$KERNEL_DATA" | cut -d\; -f1)
        # we use the first entry with a kernel init detected
        K_FOUND=1
        break
      fi
    done
  fi
  
  if [[ "$K_FOUND" -ne 1 ]]; then
    for KERNEL_DATA in "${KERNEL_ELF_EMBA[@]}"; do
      # this means we have not kernel configuration found
      # and no init entry -> we just use the first valid elf file
      if ! [[ "$(echo "$KERNEL_DATA" | cut -d\; -f1)" == "NA" ]]; then
        KERNEL_ELF_PATH=$(echo "$KERNEL_DATA" | cut -d\; -f1)
        # we use the first entry as final resort
        K_FOUND=1
        break
      fi
    done
  fi
  
  if [[ "$K_FOUND" -ne 1 ]]; then
    print_output "[-] No valid kernel information found ..."
  fi
}


