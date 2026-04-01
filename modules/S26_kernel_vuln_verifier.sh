#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# ==========================================================================================
# Module: S26_kernel_vuln_verifier (Kernel Vulnerability Verifier)
#
# Description:
#   This module performs kernel vulnerability verification after S24 identifies a Linux kernel:
#   1. Wait for kernel source download (kernel_downloader)
#   2. Extract kernel version from S24 CSV logs
#   3. Use cve-bin-tool to identify CVEs based on version
#   4. Extract kernel symbols for verification
#   5. Compile kernel (dry-run) to get used source files
#   6. Verify vulnerabilities through symbol matching and compile verification
#   7. Generate final vulnerability report
#
# Verification Mechanisms:
#   - Symbol verification: Check if CVE-affected source files use kernel exported symbols
#   - Compile verification: Check if CVE-affected source files are actually used in compilation
#
# Dependencies:
#   - S24_kernel_bin_identifier: Kernel identification module
#   - kernel_downloader: Kernel source downloader
#   - cve-bin-tool: CVE vulnerability database tool
#   - readelf: ELF file analysis
#   - NVD CVE database
#
# Input:
#   - S24_CSV_LOG: S24 module generated kernel information CSV
#   - Kernel source: ${EXT_DIR}/linux_kernel_sources/linux-${version}.tar.gz
#   - CVE database: ${NVD_DIR}
#
# Output:
#   - Vulnerability verification CSV results
#   - Symbol verification result files
#   - Compile verification result files
#   - Final vulnerability report
# ==========================================================================================

# Set thread priority to 1 (low priority)
export THREAD_PRIO=1

# ==========================================================================================
# S26_kernel_vuln_verifier - Main kernel vulnerability verification function
#
# Workflow:
#   1. Initialize module log
#   2. Check if kernel source directory exists
#   3. Wait for S24 module completion
#   4. Extract kernel version from S24 CSV log
#   5. For each kernel version:
#      - Find kernel ELF and config files
#      - Wait and verify kernel source download
#      - Use cve-bin-tool to detect CVEs
#      - Extract kernel symbols
#      - Compile kernel (dry-run) to get used source files
#      - Parallel verify each CVE
#   6. Generate final summary report
# ==========================================================================================
S26_kernel_vuln_verifier() {
  # Initialize module log
  module_log_init "${FUNCNAME[0]}"
  # Display module title
  module_title "Kernel vulnerability identification and verification"
  # Pre-report module status
  pre_module_reporter "${FUNCNAME[0]}"

  # Save current working directory
  export HOME_DIR=""
  HOME_DIR="$(pwd)"
  # lKERNEL_ARCH_PATH is the directory storing all kernel sources
  local lKERNEL_ARCH_PATH="${EXT_DIR}""/linux_kernel_sources"
  local lWAIT_PIDS_S26_ARR=()

  # Check if kernel source directory exists
  if ! [[ -d "${lKERNEL_ARCH_PATH}" ]]; then
    print_output "[-] Missing directory for kernel sources ... exit module now"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # Wait for S24 module completion to get kernel version info
  module_wait "S24_kernel_bin_identifier"

  # Check if S24 CSV log exists
  # shellcheck disable=SC2153
  if ! [[ -f "${S24_CSV_LOG}" ]] || [[ "$(wc -l <"${S24_CSV_LOG}")" -lt 1 ]]; then
    print_output "[-] No Kernel version file (s24 results) identified ..."
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # Extract kernel version from S24 CSV log
  get_kernel_version_csv_data_s24 "${S24_CSV_LOG}"

  # Local variable declarations
  local lKERNEL_DATA=""
  local lKERNEL_ELF_EMBA_ARR=()
  local lALL_KVULNS_ARR=()
  export KERNEL_CONFIG_PATH="NA"
  export KERNEL_ELF_PATH=""
  local lK_VERSION_KORG=""
  export COMPILE_SOURCE_FILES_VERIFIED=0
  local lK_VERSION=""
  export KERNEL_SOURCE_AVAILABLE=0

  # Iterate through all kernel versions from S24
  # K_VERSIONS_ARR is from get_kernel_version_csv_data_s24
  for lK_VERSION in "${K_VERSIONS_ARR[@]}"; do
    export VULN_CNT=1
    # Skip invalid versions (single character version)
    [[ "${lK_VERSION}" =~ ^[0-9\.a-zA-Z]$ ]] && continue

    local lK_FOUND=0
    print_output "[+] Identified kernel version: ${ORANGE}${lK_VERSION}${NC}"

    # Find kernel ELF entries matching current version from S24 CSV
    # Sort by column 4 (version) in descending order, prioritize higher versions
    mapfile -t lKERNEL_ELF_EMBA_ARR < <(grep "${lK_VERSION}" "${S24_CSV_LOG}" |
      grep -v "config extracted" | sort -u | sort -r -n -t\; -k4 || true)

    # ============================================================
    # Step 1: Try to find kernel config file and corresponding ELF file
    # Priority:
    #   1. Has config + has ELF file
    #   2. Has ELF file + has init parameter
    #   3. Only ELF file
    # ============================================================
    for lKERNEL_DATA in "${lKERNEL_ELF_EMBA_ARR[@]}"; do
      # Column 5 is the kernel config file path
      if [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f5)" == "/"* ]]; then
        # field 5 is the kernel config file
        KERNEL_CONFIG_PATH=$(echo "${lKERNEL_DATA}" | cut -d\; -f5)
        print_output "[+] Found kernel configuration file: ${ORANGE}${KERNEL_CONFIG_PATH}${NC}"
        # Use the first entry with kernel config detected
        # Column 1 is the matching kernel elf file - sometimes only config without elf file
        if [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f1)" == "/"* ]]; then
          # field 1 is the matching kernel elf file
          KERNEL_ELF_PATH=$(echo "${lKERNEL_DATA}" | cut -d\; -f1)
          print_output "[+] Found kernel elf file: ${ORANGE}${KERNEL_ELF_PATH}${NC}"
          lK_FOUND=1
          break
        fi
      fi
    done

    # If not found, try to find ELF file with init entry
    if [[ "${lK_FOUND}" -ne 1 ]]; then
      print_output "[-] No kernel configuration file with matching elf file found for kernel ${ORANGE}${lK_VERSION}${NC}."
    fi

    # Try to find kernel with init parameter
    if [[ "${lK_FOUND}" -ne 1 ]]; then
      for lKERNEL_DATA in "${lKERNEL_ELF_EMBA_ARR[@]}"; do
        # check for some path indicator for the elf file
        if [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f1)" == "/"* ]]; then
          # now we check for init entries
          if ! [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f2)" == "NA" ]]; then
            KERNEL_ELF_PATH=$(echo "${lKERNEL_DATA}" | cut -d\; -f1)
            # we use the first entry with a kernel init detected
            print_output "[+] Found kernel elf file with init entry: ${ORANGE}${KERNEL_ELF_PATH}${NC}"
            lK_FOUND=1
            break
          fi
        fi
      done
    fi

    # Last resort: use the first valid ELF file
    if [[ "${lK_FOUND}" -ne 1 ]]; then
      for lKERNEL_DATA in "${lKERNEL_ELF_EMBA_ARR[@]}"; do
        # check for some path indicator for the elf file
        if [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f1)" == "/"* ]]; then
          # this means we have no kernel configuration found
          # and no init entry -> we just use the first valid elf file
          if ! [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f1)" == "NA" ]]; then
            KERNEL_ELF_PATH=$(echo "${lKERNEL_DATA}" | cut -d\; -f1)
            print_output "[+] Found kernel elf file: ${ORANGE}${KERNEL_ELF_PATH}${NC}"
            # we use the first entry as final resort
            lK_FOUND=1
            break
          fi
        fi
      done
    fi

    # Check if user provided kernel config file
    if [[ -f "${KERNEL_CONFIG}" ]]; then
      # check if the provided configuration is for the kernel version under test
      if grep -q "${lK_VERSION}" "${KERNEL_CONFIG}"; then
        KERNEL_CONFIG_PATH="${KERNEL_CONFIG}"
        print_output "[+] Using provided kernel configuration file: ${ORANGE}${KERNEL_CONFIG_PATH}${NC}"
        lK_FOUND=1
      fi
    fi

    # If still not found valid kernel info, skip this version
    if [[ "${lK_FOUND}" -ne 1 ]]; then
      print_output "[-] No valid kernel information found for kernel ${ORANGE}${lK_VERSION}${NC}."
      continue
    fi

    # Check if ELF file exists
    if ! [[ -f "${KERNEL_ELF_PATH}" ]]; then
      print_output "[-] Warning: Kernel ELF file not found"
      module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
      continue
    fi
    if ! [[ -v lK_VERSION ]]; then
      print_output "[-] Missing kernel version ... exit now"
      module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
      continue
    fi

    # ============================================================
    # Step 2: Prepare CVE details path
    # Try to get bom-ref from SBOM
    # ============================================================
    if ! lBOM_REF=$(jq -r '."bom-ref"' "${SBOM_LOG_PATH}"/linux_kernel_linux_kernel_*.json | sort -u | head -1); then
      local lBOM_REF="INVALID"
    fi
    local lPRODUCT_ARR=("linux_kernel")
    # shellcheck disable=SC2034
    local lVENDOR_ARR=("linux")
    local lCVE_DETAILS_PATH="${LOG_PATH_MODULE}/${lBOM_REF}_${lPRODUCT_ARR[0]}_${lK_VERSION}.csv"

    # Extract kernel architecture
    if [[ -f "${KERNEL_ELF_PATH}" ]]; then
      extract_kernel_arch "${KERNEL_ELF_PATH}"
    fi

    # Normalize kernel version (remove trailing .0)
    if [[ "${lK_VERSION}" == *".0" ]]; then
      lK_VERSION_KORG=${lK_VERSION%.0}
    else
      lK_VERSION_KORG="${lK_VERSION}"
    fi

    # ============================================================
    # Step 3: Wait for kernel source download
    # Wait up to 60 times (5 seconds interval = 5 minutes)
    # ============================================================
    local lWAIT_CNT=0
    KERNEL_SOURCE_AVAILABLE=0
    while ! [[ -f "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" ]]; do
      print_output "[*] Waiting for kernel sources ..." "no_log"
      ((lWAIT_CNT += 1))
      # If timeout or download failed, switch to degraded mode
      if [[ "${lWAIT_CNT}" -gt 60 ]] || [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
        print_output "[-] No valid kernel source file available ... switching to symbol-based verification mode"
        KERNEL_SOURCE_AVAILABLE=0
        break
      fi
      sleep 5
    done

    # If source file exists, test archive integrity
    if [[ "${KERNEL_SOURCE_AVAILABLE}" -ne 0 ]] && [[ -f "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" ]]; then
      # Now we have a file with the kernel sources ... we do not know if this file is complete.
      # Probably it is just downloaded partly and we need to wait a bit longer
      lWAIT_CNT=0
      print_output "[*] Testing kernel sources ..." "no_log"
      # Use gunzip -t to test archive integrity
      while ! gunzip -t "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" 2>/dev/null; do
        print_output "[*] Testing kernel sources ..." "no_log"
        ((lWAIT_CNT += 1))
        if [[ "${lWAIT_CNT}" -gt 60 ]] || [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
          print_output "[-] No valid kernel source file available ... switching to symbol-based verification mode"
          KERNEL_SOURCE_AVAILABLE=0
          break
        fi
        sleep 5
      done

      # If passed integrity test, mark as available
      if [[ "${lWAIT_CNT}" -le 60 ]] && ! [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
        KERNEL_SOURCE_AVAILABLE=1
      fi
    fi

    # ============================================================
    # Step 4: Select execution mode based on kernel source availability
    # ============================================================
    if [[ "${KERNEL_SOURCE_AVAILABLE}" -eq 1 ]]; then
      print_output "[*] Kernel sources for version ${ORANGE}${lK_VERSION}${NC} available"
      write_link "${LOG_DIR}/kernel_downloader.log"
    else
      print_output "[*] Kernel sources for version ${ORANGE}${lK_VERSION}${NC} not available - using degraded verification mode"
    fi

    # ============================================================
    # Step 5: Extract kernel sources (only when sources available)
    # ============================================================
    local lKERNEL_DIR=""
    if [[ "${KERNEL_SOURCE_AVAILABLE}" -eq 1 ]]; then
      lKERNEL_DIR="${LOG_PATH_MODULE}/linux-${lK_VERSION_KORG}"
      [[ -d "${lKERNEL_DIR}" ]] && rm -rf "${lKERNEL_DIR}"
      if ! [[ -d "${lKERNEL_DIR}" ]] && [[ "$(file "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz")" == *"gzip compressed data"* ]]; then
        print_output "[*] Kernel version ${ORANGE}${lK_VERSION}${NC} extraction ... "
        tar -xzf "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" -C "${LOG_PATH_MODULE}"
      fi
    fi

    # ============================================================
    # Step 6: Extract kernel symbols (required by both modes)
    # Extract symbols from kernel ELF and kernel modules (.ko)
    # ============================================================
    sub_module_title "Identify kernel symbols ..."
    # Use readelf to extract FUNC and OBJECT type symbols
    readelf -W -s "${KERNEL_ELF_PATH}" | grep "FUNC\|OBJECT" | sed 's/.*FUNC//' | sed 's/.*OBJECT//' | awk '{print $4}' |
      sed 's/\[\.\.\.\]//' >"${LOG_PATH_MODULE}"/symbols.txt || true
    export SYMBOLS_CNT=0
    SYMBOLS_CNT=$(wc -l <"${LOG_PATH_MODULE}"/symbols.txt)
    print_output "[*] Extracted ${ORANGE}${SYMBOLS_CNT}${NC} symbols from kernel (${KERNEL_ELF_PATH})"

    # If no symbols, cannot proceed with verification
    if [[ "${SYMBOLS_CNT}" -eq 0 ]]; then
      print_output "[-] No symbols found for kernel ${lK_VERSION} - ${KERNEL_ELF_PATH}"
      print_output "[*] No further analysis possible for ${lK_VERSION} - ${KERNEL_ELF_PATH}"
      continue
    fi

    # Extract additional symbols from kernel modules in firmware
    if [[ -d "${LOG_DIR}""/firmware" ]]; then
      print_output "[*] Identify kernel modules and extract binary symbols ..." "no_log"
      # shellcheck disable=SC2016
      find "${LOG_DIR}/firmware" -name "*.ko" -print0 | xargs -r -0 -P 16 -I % sh -c 'readelf -W -a "%" | grep FUNC | sed "s/.*FUNC//" | awk "{print \$4}" | sed "s/\[\.\.\.\]//"' >>"${LOG_PATH_MODULE}"/symbols.txt || true
    fi

    # Deduplicate and count unique symbols
    uniq "${LOG_PATH_MODULE}"/symbols.txt >"${LOG_PATH_MODULE}"/symbols_uniq.txt
    SYMBOLS_CNT=$(wc -l <"${LOG_PATH_MODULE}"/symbols_uniq.txt)

    print_ln
    print_output "[+] Extracted ${ORANGE}${SYMBOLS_CNT}${GREEN} unique symbols (kernel+modules)"
    write_link "${LOG_PATH_MODULE}/symbols_uniq.txt"
    print_ln
    # Split symbol file for parallel processing
    split_symbols_file

    # ============================================================
    # Step 7: Execute different CVE detection and verification flows based on mode
    # ============================================================
    if [[ "${KERNEL_SOURCE_AVAILABLE}" -eq 1 ]]; then
      # ============================================================
      # Normal mode: Full CVE detection and verification with source
      # ============================================================
      print_output "[*] Running in normal mode with kernel source verification"

      # Use cve-bin-tool to detect CVEs
      print_output "[*] Kernel version ${ORANGE}${lK_VERSION}${NC} CVE detection ... "
      if ! grep -q "cve-bin-tool database preparation finished" "${TMP_DIR}/tmp_state_data.log"; then
        print_error "[-] cve-bin-tool database not prepared - cve analysis probably not working"
      fi
      cve_bin_tool_threader "${lBOM_REF}" "${lK_VERSION}" "${lORIG_SOURCE:-kernel_verification}" lVENDOR_ARR lPRODUCT_ARR

      # Check if CVE details file was generated
      if ! [[ -f "${lCVE_DETAILS_PATH}" ]]; then
        print_output "[-] No CVE details generated ... check for further kernel version"
        continue
      fi

      # Read all detected CVEs
      print_output "[*] Generate CVE vulnerabilities array for kernel version ${ORANGE}${lK_VERSION}${NC} ..." "no_log"
      mapfile -t lALL_KVULNS_ARR < <(tail -n+2 "${lCVE_DETAILS_PATH}" | sort -u -t, -k4,4)

      print_ln
      print_output "[+] Extracted ${ORANGE}${#lALL_KVULNS_ARR[@]}${GREEN} vulnerabilities based on kernel version only"
      write_link "${LOG_PATH_MODULE}""/kernel-${lK_VERSION}-vulns.log"

      # Compile kernel (dry-run) to get used source files
      if [[ -f "${KERNEL_CONFIG_PATH}" ]] && [[ -d "${lKERNEL_DIR}" ]]; then
        compile_kernel "${KERNEL_CONFIG_PATH}" "${lKERNEL_DIR}" "${ORIG_K_ARCH}"
      fi

      # Parallel verify each CVE
      sub_module_title "Linux kernel vulnerability verification"

      print_output "[*] Checking vulnerabilities for kernel version ${ORANGE}${lK_VERSION}${NC}" "" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      print_ln

      local lVULN=""
      for lVULN in "${lALL_KVULNS_ARR[@]}"; do
        vuln_checker_threader "${lVULN}" "${lKERNEL_DIR}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S26_ARR_MAIN+=("${lTMP_PID}")
        ((VULN_CNT += 1))
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S26_ARR_MAIN
      done

      # Wait for all CVE verification to complete
      wait_for_pid "${lWAIT_PIDS_S26_ARR_MAIN[@]}"

      # Generate final vulnerability report
      final_log_kernel_vulns "${lK_VERSION}" "${lALL_KVULNS_ARR[@]}"
    else
      # ============================================================
      # Degraded mode: Symbol-based CVE filtering without source
      # ============================================================
      print_output "[*] Running in degraded mode without kernel source - using symbol-based CVE filtering"

      # Use cve-bin-tool to detect CVEs
      print_output "[*] Kernel version ${ORANGE}${lK_VERSION}${NC} CVE detection ... "
      if ! grep -q "cve-bin-tool database preparation finished" "${TMP_DIR}/tmp_state_data.log"; then
        print_error "[-] cve-bin-tool database not prepared - cve analysis probably not working"
      fi
      cve_bin_tool_threader "${lBOM_REF}" "${lK_VERSION}" "${lORIG_SOURCE:-kernel_verification}" lVENDOR_ARR lPRODUCT_ARR

      # Check if CVE details file was generated
      if ! [[ -f "${lCVE_DETAILS_PATH}" ]]; then
        print_output "[-] No CVE details generated ... check for further kernel version"
        continue
      fi

      # Read all detected CVEs
      print_output "[*] Generate CVE vulnerabilities array for kernel version ${ORANGE}${lK_VERSION}${NC} ..." "no_log"
      mapfile -t lALL_KVULNS_ARR < <(tail -n+2 "${lCVE_DETAILS_PATH}" | sort -u -t, -k4,4)

      print_ln
      print_output "[+] Extracted ${ORANGE}${#lALL_KVULNS_ARR[@]}${GREEN} vulnerabilities based on kernel version only"
      print_output "[*] Filtering CVEs based on kernel symbols ..."

      # Symbol-based CVE filtering
      sub_module_title "Linux kernel vulnerability filtering (degraded mode)"

      print_output "[*] Checking vulnerabilities for kernel version ${ORANGE}${lK_VERSION}${NC} (symbol-based filtering)" "" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      print_ln

      local lVULN=""
      for lVULN in "${lALL_KVULNS_ARR[@]}"; do
        # In degraded mode, use symbol name verifier
        vuln_checker_threader_degraded "${lVULN}" &
        local lTMP_PID="$!"
        store_kill_pids "${lTMP_PID}"
        lWAIT_PIDS_S26_ARR_MAIN+=("${lTMP_PID}")
        ((VULN_CNT += 1))
        max_pids_protection "${MAX_MOD_THREADS}" lWAIT_PIDS_S26_ARR_MAIN
      done

      # Wait for all CVE verification to complete
      wait_for_pid "${lWAIT_PIDS_S26_ARR_MAIN[@]}"

      # Generate final vulnerability report
      final_log_kernel_vulns "${lK_VERSION}" "${lALL_KVULNS_ARR[@]}"
    fi
  done

  # ============================================================
  # Step 8: Update vulnerability summary with verified CVE info
  # ============================================================
  if [[ -f "${LOG_PATH_MODULE}/vuln_summary.txt" ]]; then
    # Extract verified CVEs:
    # Column description (semicolon separated):
    #   f1: kernel version
    #   f3: CVE number
    #   f6: symbol verification result (1=verified, 0=unverified)
    #   f7: compile verification result (1=verified, 0=unverified)
    # Filter: column 6 or 7 is 1 (at least one verification passed)
    # Extract column 1 (kernel version) and deduplicate
    local lVERIFIED_KERNEL_VERS_ARR=()
    local lVERIFIED_KVERS=""
    mapfile -t lVERIFIED_KERNEL_VERS_ARR < <(cut -d ';' -f1,3,6,7 "${LOG_PATH_MODULE}"/cve_results_kernel_*.csv | grep ";1;\|;1$" | cut -d ';' -f1 | sort -u || true)

    if [[ "${#lVERIFIED_KERNEL_VERS_ARR[@]}" -gt 0 ]]; then
      for lVERIFIED_KVERS in "${lVERIFIED_KERNEL_VERS_ARR[@]}"; do
        local lVERIFIED_CVE_ARR_PER_VERSION=()
        # Get verified CVE list for each version
        mapfile -t lVERIFIED_CVE_ARR_PER_VERSION < <(grep -h "^${lVERIFIED_KVERS}" "${LOG_PATH_MODULE}"/cve_results_kernel_*.csv | cut -d ';' -f3,6,7 | grep ";1;\|;1$" | cut -d ';' -f1 | sort -u || true)

        local lTMP_CVE_ENTRY=""
        local lFULL_ENTRY_LINE=""
        # Get CVE entries from vuln_summary.txt
        lFULL_ENTRY_LINE=$(grep -E "${lVERIFIED_KVERS}.*:\s+CVEs:\ [0-9]+\s+:" "${LOG_PATH_MODULE}/vuln_summary.txt" || true)
        [[ -z "${lFULL_ENTRY_LINE}" ]] && continue
        # Extract CVE count part
        lTMP_CVE_ENTRY=$(echo "${lFULL_ENTRY_LINE}" | grep -o -E ":\s+CVEs:\ [0-9]+\s+:" || true)
        # Replace with verified count -> :  CVEs: 1234 (123):
        lTMP_CVE_ENTRY=$(echo "${lTMP_CVE_ENTRY}" | sed -r 's/(CVEs:\ [0-9]+)\s+/\1 ('"${#lVERIFIED_CVE_ARR_PER_VERSION[@]}"')/')
        # Ensure correct length -> :  CVEs: 1234 (123)  :
        lTMP_CVE_ENTRY=$(printf '%s%*s' "${lTMP_CVE_ENTRY%:}" "$((22 - "${#lTMP_CVE_ENTRY}"))" ":")
        # Final replacement in file
        echo "${lFULL_ENTRY_LINE}" | sed -r 's/:\s+CVEs:\ [0-9]+\s+:/'"${lTMP_CVE_ENTRY}"'/' >>"${LOG_PATH_MODULE}/vuln_summary_new.txt"

        # Mark verified CVEs
        for lVERIFIED_BB_CVE in "${lVERIFIED_CVE_ARR_PER_VERSION[@]}"; do
          local lV_ENTRY="(V)"
          # ensure we have the correct length
          # shellcheck disable=SC2183
          lV_ENTRY=$(printf '%s%*s' "${lV_ENTRY}" "$((19 - "${#lVERIFIED_BB_CVE}" - "${#lV_ENTRY}"))")
          sed -i -r 's/('"${lVERIFIED_BB_CVE}"')\s+/\1 '"${lV_ENTRY}"'/' "${LOG_PATH_MODULE}/cve_sum/"*"${lVERIFIED_KVERS}"_finished.txt || true
        done
      done

      # Merge old and new summary files
      if [[ -f "${LOG_PATH_MODULE}/vuln_summary_new.txt" ]]; then
        local lVULN_SUMMARY_ENTRY=""
        while read -r lVULN_SUMMARY_ENTRY; do
          local lkVERSION=""
          # Extract kernel version from summary entry
          lkVERSION=$(echo "${lVULN_SUMMARY_ENTRY}" | cut -d ':' -f3)
          # Remove all spaces from version
          lkVERSION=${lkVERSION//\ /}
          # Check if this version already exists in new summary file
          if grep -q "${lkVERSION}" "${LOG_PATH_MODULE}/vuln_summary_new.txt"; then
            continue
          fi
          # Append non-duplicate entries to new file
          echo "${lVULN_SUMMARY_ENTRY}" >>"${LOG_PATH_MODULE}/vuln_summary_new.txt"
        done <"${LOG_PATH_MODULE}/vuln_summary.txt"
        # Replace old file with new merged file
        mv "${LOG_PATH_MODULE}/vuln_summary_new.txt" "${LOG_PATH_MODULE}/vuln_summary.txt" || true
      fi
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${VULN_CNT}"
}

# ==========================================================================================
# extract_kernel_arch - Extract architecture from kernel ELF file
#
# Function:
#   Analyze kernel ELF file with readelf to identify target architecture
#   Supports: ARM, x86, MIPS, PowerPC, RISC-V, etc.
#
# Parameters:
#   $1 - Kernel ELF file path
#
# Output:
#   Sets global variable ORIG_K_ARCH
# ==========================================================================================
extract_kernel_arch() {
  local lKERNEL_ELF_PATH="${1:-}"
  export ORIG_K_ARCH=""

  ORIG_K_ARCH=$(grep ";${lKERNEL_ELF_PATH};" "${P99_CSV_LOG}" | cut -d ';' -f8 || true)

  if [[ "${ORIG_K_ARCH}" == *"ARM aarch64"* ]]; then
    # for ARM -> ARM aarch64 to ARM64
    ORIG_K_ARCH="ARM64"
  elif [[ "${ORIG_K_ARCH}" == *"ARM64"* ]]; then
    # for ARM -> ARM aarch64 to ARM64
    ORIG_K_ARCH="ARM64"
  elif [[ "${ORIG_K_ARCH}" == *"ARM32"* ]]; then
    ORIG_K_ARCH="ARM"
  elif [[ "${ORIG_K_ARCH}" == *"ELF 32"*"ARM"* ]]; then
    ORIG_K_ARCH="ARM"
  fi
  if [[ "${ORIG_K_ARCH}" == *"MIPS"* ]]; then
    ORIG_K_ARCH="MIPS"
  fi
  if [[ "${ORIG_K_ARCH}" == *"PowerPC"* ]]; then
    ORIG_K_ARCH="powerpc"
  fi
  if [[ "${ORIG_K_ARCH}" == *"Altera Nios II"* ]]; then
    ORIG_K_ARCH="nios2"
  fi
  if [[ "${ORIG_K_ARCH}" == *"Intel"* ]]; then
    ORIG_K_ARCH="x86"
  fi

  ORIG_K_ARCH="${ORIG_K_ARCH,,}"
  ORIG_K_ARCH="${ORIG_K_ARCH//\ /}"
  print_output "[+] Identified kernel architecture ${ORANGE}${ORIG_K_ARCH}${NC}"
}

# ==========================================================================================
# symbol_verifier - Symbol verification function
#
# Function:
#   Check if CVE-affected source files use kernel exported symbols
#   Matches against EXPORT_SYMBOL and EXPORT_SYMBOL_GPL
#
# Parameters:
#   $1 - lCVE: CVE number
#   $2 - lK_VERSION: Kernel version
#   $3 - lK_PATH: Source file path
#   $4 - lCVSS: CVSS score
#   $5 - lKERNEL_DIR: Kernel source directory
#
# Output:
#   Creates ${CVE}_symbol_verified.txt file with successful verifications
# ==========================================================================================
symbol_verifier() {
  local lCVE="${1:-}"
  local lK_VERSION="${2:-}"
  local lK_PATH="${3:-}"
  local lCVSS="${4:-}"
  local lKERNEL_DIR="${5:-}"
  local lVULN_FOUND=0
  local lCHUNK_FILE=""

  for lCHUNK_FILE in "${LOG_PATH_MODULE}"/symbols_uniq.split.*; do
    if grep -q -f "${lCHUNK_FILE}" "${lKERNEL_DIR}/${lK_PATH}"; then
      local lOUTx="[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS}${GREEN}) - ${ORANGE}${lK_PATH}${GREEN} verified - exported symbol${NC}"
      print_output "${lOUTx}"
      write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      echo "${lCVE} (${lCVSS}) - ${lK_VERSION} - exported symbol verified - ${lK_PATH}" >>"${LOG_PATH_MODULE}""/${lCVE}_symbol_verified.txt"
      lVULN_FOUND=1
      break
    fi
  done

  # if we have already a match for this path we can skip the 2nd check
  # this is only for speed up the process a bit
  [[ "${lVULN_FOUND}" -eq 1 ]] && return

  for lCHUNK_FILE in "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.*; do
    if grep -q -f "${lCHUNK_FILE}" "${lKERNEL_DIR}/${lK_PATH}"; then
      local lOUTx="[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS}${GREEN}) - ${ORANGE}${lK_PATH}${GREEN} verified - exported symbol (GPL)${NC}"
      print_output "${lOUTx}"
      write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      echo "${lCVE} (${lCVSS}) - ${lK_VERSION} - exported symbol verified (gpl) - ${lK_PATH}" >>"${LOG_PATH_MODULE}""/${lCVE}_symbol_verified.txt"
      lVULN_FOUND=1
      break
    fi
  done
}

# ==========================================================================================
# compile_verifier - Compile verification function
#
# Function:
#   Check if CVE-affected source files are actually used during compilation
#   Used together with symbol_verifier for dual verification
#
# Parameters:
#   $1 - lCVE: CVE number
#   $2 - lK_VERSION: Kernel version
#   $3 - lK_PATH: Source file path
#   $4 - lCVSS: CVSS score
#
# Output:
#   Creates ${CVE}_compiled_verified.txt file with successful verifications
# ==========================================================================================
compile_verifier() {
  local lCVE="${1:-}"
  local lK_VERSION="${2:-}"
  local lK_PATH="${3:-}"
  local lCVSS="${4:-}"
  # If no compile verification log file, return directly
  if ! [[ -f "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log ]]; then
    return
  fi

  # Check if source file path is in the list of compiled files
  if grep -q "${lK_PATH}" "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log; then
    print_output "[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS}${GREEN}) - ${ORANGE}${lK_PATH}${GREEN} verified - compiled path${NC}"
    echo "${lCVE} (${lCVSS}) - ${lK_VERSION} - compiled path verified - ${lK_PATH}" >>"${LOG_PATH_MODULE}""/${lCVE}_compiled_verified.txt"
  fi
}

# ==========================================================================================
# compile_kernel - Kernel compilation (dry-run mode) to get used source files
#
# Description:
#   This function is based on the method from https://arxiv.org/pdf/2209.05217.pdf
#   Uses kernel compiler dry-run mode (-Bndi) to get list of source files
#   actually used during compilation without compiling the whole kernel
#
# Workflow:
#   1. Check if config and source directory exist
#   2. Check if architecture directory is supported
#   3. Copy firmware config to kernel source
#   4. Run make olddefconfig to update config
#   5. Execute make -Bndi to get compile file list
#   6. Parse output to extract .c/.h/.S files
#   7. Deduplicate and save to log
#
# Parameters:
#   $1 - lCONFIG: Kernel config file path
#   $2 - lKERNEL_DIR: Kernel source directory
#   $3 - lARCH: Target architecture
#
# Output:
#   - kernel-compile-files.log: All compilation-related files
#   - kernel-compile-files_verified.log: Actually existing source files
# ==========================================================================================
compile_kernel() {
  local lCONFIG="${1:-}"
  local lKERNEL_DIR="${2:-}"
  local lARCH="${3:-}"

  # Check if config file exists
  if ! [[ -f "${lCONFIG}" ]]; then
    print_output "[-] No kernel configuration file available"
    return
  fi

  # Check if kernel source directory exists
  if ! [[ -d "${lKERNEL_DIR}" ]]; then
    print_output "[-] No kernel source directory available"
    return
  fi

  # Check if architecture directory exists
  if ! [[ -d "${lKERNEL_DIR}/arch/${lARCH}" ]]; then
    print_output "[-] Architecture ${ORANGE}${lARCH}${NC} not supported in kernel sources"
    return
  fi

  sub_module_title "Compile kernel - dry run mode"

  print_output "[*] Copy kernel configuration file ${ORANGE}${lCONFIG}${NC} to kernel source directory"
  cp "${lCONFIG}" "${lKERNEL_DIR}/.config" || true

  print_output "[*] Update kernel configuration"
  make -C "${lKERNEL_DIR}" ARCH="${lARCH}" olddefconfig 2>/dev/null || true

  print_output "[*] Compile kernel - dry run mode"
  # Use dry-run mode to get compile file list
  # -B: force rebuild all targets
  # -n: only print commands, don't execute
  # -d: debug mode, output detailed info
  # -i: ignore errors
  # Based on paper: https://arxiv.org/pdf/2209.05217.pdf
  make -C "${lKERNEL_DIR}" ARCH="${lARCH}" -Bndi 2>/dev/null | grep -E "\.c|\.h|\.S" >"${LOG_PATH_MODULE}"/kernel-compile-files.log || true

  print_output "[*] Extract kernel source files from compile log"
  # Extract source file paths from compile log
  # Format: filename:linenumber or full path
  sed -r 's/([0-9]+)\s+//' "${LOG_PATH_MODULE}"/kernel-compile-files.log | sed 's/\s+//' | sort -u >"${LOG_PATH_MODULE}"/kernel-compile-files_uniq.log || true

  # Filter to actually existing source files
  while read -r lCOMPILE_FILE; do
    if [[ -f "${lKERNEL_DIR}/${lCOMPILE_FILE}" ]]; then
      echo "${lCOMPILE_FILE}" >>"${LOG_PATH_MODULE}"/kernel-compile-files_verified.log
    fi
  done <"${LOG_PATH_MODULE}"/kernel-compile-files_uniq.log

  # Count compilation-related source files
  if [[ -f "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log ]]; then
    COMPILE_SOURCE_FILES_VERIFIED=$(wc -l <"${LOG_PATH_MODULE}"/kernel-compile-files_verified.log)
    print_output "[+] Identified ${ORANGE}${COMPILE_SOURCE_FILES_VERIFIED}${GREEN} kernel source files used during compilation"
    write_link "${LOG_PATH_MODULE}/kernel-compile-files_verified.log"
  fi
}

# ==========================================================================================
# split_symbols_file - Split symbol file for parallel processing
#
# Function:
#   Since symbol file can be large, split into smaller files for parallel verification
#   Split into groups of 100 symbols
#
# Output files:
#   - symbols_uniq.split.*: For matching EXPORT_SYMBOL
#   - symbols_uniq.split_gpl.*: For matching EXPORT_SYMBOL_GPL
#
# Format conversion:
#   Original: symbol_name
#   Converted: EXPORT_SYMBOL(symbol_name)
#              EXPORT_SYMBOL_GPL(symbol_name)
# ==========================================================================================
split_symbols_file() {
  print_output "[*] Splitting symbols file for processing ..." "no_log"
  # Split symbol file into 100-line chunks
  split -l 100 "${LOG_PATH_MODULE}"/symbols_uniq.txt "${LOG_PATH_MODULE}"/symbols_uniq.split.
  # Add EXPORT_SYMBOL prefix and parenthesis suffix
  sed -i 's/^/EXPORT_SYMBOL\(/' "${LOG_PATH_MODULE}"/symbols_uniq.split.*
  sed -i 's/$/\)/' "${LOG_PATH_MODULE}"/symbols_uniq.split.*

  # Process GPL version similarly
  split -l 100 "${LOG_PATH_MODULE}"/symbols_uniq.txt "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.
  sed -i 's/^/EXPORT_SYMBOL_GPL\(/' "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.*
  sed -i 's/$/\)/' "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.*
  print_output "[*] Splitting symbols file for processing ... done" "no_log"
}

# ==========================================================================================
# vuln_checker_threader - CVE vulnerability check thread function (Normal mode)
#
# Function:
#   Check and verify a single CVE vulnerability
#
# Verification flow:
#   1. Extract CVE number from CVE entry
#   2. Get CVE details from NVD database
#   3. Extract affected source file paths from description
#   4. For each path, perform symbol verification and compile verification
#   5. Record verification results
#
# Parameters:
#   $1 - lVULN: CVE vulnerability entry (CSV format)
#   $2 - lKERNEL_DIR: Kernel source directory
# ==========================================================================================
vuln_checker_threader() {
  local lVULN="${1:-}"
  local lKERNEL_DIR="${2:-}"
  local lK_PATHS_ARR=()
  local lK_PATHS_FILES_TMP_ARR=()
  local lK_PATH=""
  local lCVE=""
  local lCVSS3=""
  local lSUMMARY=""

  # Extract CVE number from CSV column 4
  lCVE=$(echo "${lVULN}" | cut -d, -f4)
  if ! [[ "${lCVE}" == "CVE-"* ]]; then
    print_output "[-] No CVE identifier extracted for ${lVULN} ..."
    return
  fi

  # Output progress info
  local lOUTx="[*] Testing vulnerability ${ORANGE}${VULN_CNT}${NC} / ${ORANGE}${#lALL_KVULNS_ARR[@]}${NC} / ${ORANGE}${lCVE}${NC}"
  print_output "${lOUTx}" "no_log"
  write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"

  # Extract CVSSv3 score from CSV column 6
  lCVSS3="$(echo "${lVULN}" | cut -d, -f6)"

  # Extract English description from NVD JSON file
  lSUMMARY=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${lCVE%-*}/${lCVE:0:11}"*"xx/${lCVE}.json" 2>/dev/null || true)

  # Extract kernel source file paths from CVE description
  mapfile -t lK_PATHS_ARR < <(echo "${lSUMMARY}" | tr ' ' '\n' | sed 's/\\$//' | grep ".*\.[chS]$" | sed -r 's/CVE-[0-9]+-[0-9]+:[0-9].*://' |
    sed -r 's/CVE-[0-9]+-[0-9]+:null.*://' | sed 's/^(//' | sed 's/)$//' | sed 's/,$//' | sed 's/\.$//' | cut -d: -f1 || true)

  # For files without full path, find matching files in kernel source
  for lK_PATH in "${lK_PATHS_ARR[@]}"; do
    if ! [[ "${lK_PATH}" == *"/"* ]]; then
      lOUTx="[*] Found file name ${ORANGE}${lK_PATH}${NC} for ${ORANGE}${lCVE}${NC} without path details ... looking for candidates now"
      print_output "${lOUTx}" "no_log"
      write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      mapfile -t lK_PATHS_FILES_TMP_ARR < <(find "${lKERNEL_DIR}" -name "${lK_PATH}" | sed "s&${lKERNEL_DIR}\/&&")
    fi
    lK_PATHS_ARR+=("${lK_PATHS_FILES_TMP_ARR[@]}")
  done

  # Verify each found path
  if [[ "${#lK_PATHS_ARR[@]}" -gt 0 ]]; then
    for lK_PATH in "${lK_PATHS_ARR[@]}"; do
      if [[ -f "${lKERNEL_DIR}/${lK_PATH}" ]]; then
        # Check if this is an architecture-specific path
        if [[ "${lK_PATH}" == "arch/"* ]]; then
          if [[ "${lK_PATH}" == "arch/${ORIG_K_ARCH}/"* ]]; then
            write_log "lCNT_PATHS_FOUND" "${TMP_DIR}/s25_counting.tmp"
            if [[ "${SYMBOLS_CNT}" -gt 0 ]]; then
              symbol_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS3}" "${lKERNEL_DIR}" &
              lWAIT_PIDS_S26_ARR+=("$!")
            fi
            if [[ "${COMPILE_SOURCE_FILES_VERIFIED}" -gt 0 ]]; then
              compile_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS3}" &
              lWAIT_PIDS_S26_ARR+=("$!")
            fi
          else
            lOUTx="[-] Vulnerable path for different architecture found for ${ORANGE}${lK_PATH}${NC} - not further processing ${ORANGE}${lCVE}${NC}"
            print_output "${lOUTx}" "no_log"
            write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
            write_log "lCNT_PATHS_FOUND_WRONG_ARCH" "${TMP_DIR}/s25_counting.tmp"
          fi
        else
          write_log "lCNT_PATHS_FOUND" "${TMP_DIR}/s25_counting.tmp"
          if [[ "${SYMBOLS_CNT}" -gt 0 ]]; then
            symbol_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS3}" "${lKERNEL_DIR}" &
            lWAIT_PIDS_S26_ARR+=("$!")
          fi
          if [[ "${COMPILE_SOURCE_FILES_VERIFIED}" -gt 0 ]]; then
            compile_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS3}" &
            lWAIT_PIDS_S26_ARR+=("$!")
          fi
        fi
      else
        lOUTx="[-] No source file ${ORANGE}${lK_PATH}${NC} in kernel sources for ${ORANGE}${lCVE}${NC}"
        print_output "${lOUTx}" "no_log"
        write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
        write_log "lCNT_PATHS_NOT_FOUND" "${TMP_DIR}/s25_counting.tmp"
      fi
    done
  else
    lOUTx="[-] No kernel source paths extracted for ${ORANGE}${lCVE}${NC}"
    print_output "${lOUTx}" "no_log"
    write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
    write_log "lCNT_NO_PATHS" "${TMP_DIR}/s25_counting.tmp"
  fi

  # Wait for all verification processes to complete
  wait_for_pid "${lWAIT_PIDS_S26_ARR[@]}"
}

# ==========================================================================================
# vuln_checker_threader_degraded - CVE vulnerability check thread function (Degraded mode)
#
# Function:
#   When kernel source is unavailable, perform CVE filtering based on symbol name matching
#   Extract CVE-related function names from NVD and match against firmware symbol table
#
# Core principle (Degraded mode):
#   Only record verification results that pass function name matching.
#   CVEs that fail function name matching are NOT written to any verification files
#   and are NOT included in the final report.
#
# Verification flow:
#   1. Extract CVE number from CVE entry
#   2. Get CVE details from NVD database
#   3. Extract affected function names from description (Pattern 1: func_name(; Pattern 2: ALL_CAPS identifiers)
#   4. Check if extracted function names are in firmware symbol table
#   5. Only write to ${lCVE}_symbol_verified.txt with "degraded" marker on successful match
#   6. Unmatched CVEs only logged, no verification files generated
#
# Parameters:
#   $1 - lVULN: CVE vulnerability entry (CSV format)
#
# Output:
#   Match success -> ${LOG_PATH_MODULE}/${lCVE}_symbol_verified.txt (with "degraded" marker)
#   No match     -> Only detailed log, no verification file
# ==========================================================================================
vuln_checker_threader_degraded() {
  local lVULN="${1:-}"
  local lCVE=""
  local lCVSS3=""
  local lSUMMARY=""
  # lVULN_FOUND=0 means no verification result found through function name matching yet
  local lVULN_FOUND=0

  # Extract CVE number from CSV column 4
  lCVE=$(echo "${lVULN}" | cut -d, -f4)
  if ! [[ "${lCVE}" == "CVE-"* ]]; then
    print_output "[-] No CVE identifier extracted for ${lVULN} ..."
    return
  fi

  # Output progress info
  local lOUTx="[*] Testing vulnerability ${ORANGE}${VULN_CNT}${NC} / ${ORANGE}${#lALL_KVULNS_ARR[@]}${NC} / ${ORANGE}${lCVE}${NC} (degraded mode)"
  print_output "${lOUTx}" "no_log"
  write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"

  # Extract CVSSv3 score from CSV column 6
  lCVSS3="$(echo "${lVULN}" | cut -d, -f6)"

  # Extract English description from NVD JSON file
  lSUMMARY=$(jq -r '.descriptions[]? | select(.lang=="en") | .value' "${NVD_DIR}/${lCVE%-*}/${lCVE:0:11}"*"xx/${lCVE}.json" 2>/dev/null || true)

  # ------------------------------------------------------------------
  # Step 1: Extract function names from CVE description
  #   Pattern 1: func_name( or func_name () call-style notation
  # ------------------------------------------------------------------
  local lAFFECTED_FUNCS=()
  mapfile -t lAFFECTED_FUNCS < <(echo "${lSUMMARY}" | grep -oE '[a-zA-Z_][a-zA-Z0-9_]*\s*\(' | sed 's/\s*($//' | sort -u || true)

  # ------------------------------------------------------------------
  # Step 2: If Pattern 1 found nothing, try ALL_CAPS identifier pattern
  #   Pattern 2: SOME_FUNC for ALL_CAPS macros/constants/function names
  # ------------------------------------------------------------------
  if [[ "${#lAFFECTED_FUNCS[@]}" -eq 0 ]]; then
    mapfile -t lAFFECTED_FUNCS < <(echo "${lSUMMARY}" | grep -oE '\b[A-Z_][A-Z0-9_]*\b' | sort -u || true)
  fi

  # ------------------------------------------------------------------
  # Step 3: Check if extracted function names are in firmware symbol table
  #   Only when exact match found in symbol table, write to verification file
  #   and set lVULN_FOUND=1
  #   Stop after first match to avoid duplicate records
  # ------------------------------------------------------------------
  if [[ "${#lAFFECTED_FUNCS[@]}" -gt 0 ]]; then
    for lFUNC in "${lAFFECTED_FUNCS[@]}"; do
      # Skip common noise identifiers: CVE prefix, LINUX, KERNEL, etc.
      if [[ "${lFUNC}" == "CVE"* ]] || [[ "${lFUNC}" == "LINUX"* ]] || [[ "${lFUNC}" == "KERNEL"* ]]; then
        continue
      fi

      # Match function name exactly in symbol table (whole line match to avoid false positives)
      if grep -q "^${lFUNC}$" "${LOG_PATH_MODULE}/symbols_uniq.txt"; then
        lOUTx="[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS3}${GREEN}) - function ${ORANGE}${lFUNC}${GREEN} found in kernel symbols (degraded mode)${NC}"
        print_output "${lOUTx}"
        write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
        # Write to verification file: with "degraded" marker for final_log_kernel_vulns to distinguish
        echo "${lCVE} (${lCVSS3}) - ${lK_VERSION} - symbol verified (degraded) - ${lFUNC}" >>"${LOG_PATH_MODULE}/${lCVE}_symbol_verified.txt"
        lVULN_FOUND=1
        # Stop after first match - in degraded mode we just need to prove "existence"
        break
      fi
    done
  fi

  # ------------------------------------------------------------------
  # Step 4: Record count based on match result
  #   Only lVULN_FOUND=1 (matched through function name) counts as verified
  #   Unmatched CVEs not written to any verification file, skipped in final report
  # ------------------------------------------------------------------
  if [[ "${lVULN_FOUND}" -eq 1 ]]; then
    # Function name matching verification success -> write verified count
    write_log "lCNT_SYMBOL_VERIFIED_DEGRADED" "${TMP_DIR}/s25_counting.tmp"
  else
    # No matching function name found -> only log, no verification file, not recorded in report
    lOUTx="[-] ${ORANGE}${lCVE}${NC} - no matching function name found in kernel symbols (degraded mode)"
    print_output "${lOUTx}" "no_log"
    write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
    write_log "lCNT_NO_SYMBOL_MATCH" "${TMP_DIR}/s25_counting.tmp"
  fi
}

# ==========================================================================================
# final_log_kernel_vulns - Generate final kernel vulnerability report
#
# Function:
#   Summarize all verification results and generate final CSV report
#   (cve_results_kernel_${lK_VERSION}.csv)
#   Count verified and unverified CVEs
#
# Output differences for two modes:
#   Normal mode (KERNEL_SOURCE_AVAILABLE=1):
#     - Count symbol_verified + compile_verified results
#     - Unverified CVEs also counted in lNOT_VERIFIED
#     - CSV contains all CVEs with verification records (including dual verification)
#
#   Degraded mode (KERNEL_SOURCE_AVAILABLE=0):
#     - Only count CVEs matched through function name (symbol_verified.txt contains "degraded" marker)
#     - Unmatched CVEs NOT written to CSV report, implementing "only record found ones" principle
#     - Statistics output clearly marked as "degraded mode (function name matching)"
#
# Parameters:
#   $1 - lK_VERSION: Kernel version
#   $@ - lALL_KVULNS_ARR: All CVE vulnerability array
# ==========================================================================================
final_log_kernel_vulns() {
  local lK_VERSION="${1:-}"
  shift
  local lALL_KVULNS_ARR=("$@")
  local lVERIFIED_SYMBOL=0
  local lVERIFIED_COMPILE=0
  local lVERIFIED_BOTH=0
  local lNOT_VERIFIED=0
  local lVULN=""
  local lCVE=""

  print_output "[*] Generating final vulnerability report for kernel ${ORANGE}${lK_VERSION}${NC}"

  # Create CSV report file (header)
  echo "kernel_version;cve;cvss;verified_symbol;verified_compile;status" >"${LOG_PATH_MODULE}/cve_results_kernel_${lK_VERSION}.csv"

  if [[ "${KERNEL_SOURCE_AVAILABLE:-0}" -eq 0 ]]; then
    # ================================================================
    # Degraded mode: Only record CVEs found through function name matching
    #   - Check if ${lCVE}_symbol_verified.txt exists and contains "degraded" marker
    #   - Match success -> write CSV, mark verified_symbol=1
    #   - No match     -> Skip, NOT written to CSV (implement "only record found ones" principle)
    # ================================================================
    for lVULN in "${lALL_KVULNS_ARR[@]}"; do
      lCVE=$(echo "${lVULN}" | cut -d, -f4)
      local lCVSS="${lVULN}"
      lCVSS=$(echo "${lVULN}" | cut -d, -f6)
      local lSYMBOL_VERIFIED=0

      # Only record when verification file exists AND contains "degraded" marker
      # This ensures only CVEs matched through function name are in final report
      if [[ -f "${LOG_PATH_MODULE}/${lCVE}_symbol_verified.txt" ]] &&
        grep -q "degraded" "${LOG_PATH_MODULE}/${lCVE}_symbol_verified.txt" 2>/dev/null; then
        lSYMBOL_VERIFIED=1
        ((lVERIFIED_SYMBOL += 1))
        # Write CSV: compile_verified fixed at 0 (degraded mode has no compile verification capability)
        echo "${lK_VERSION};${lCVE};${lCVSS};${lSYMBOL_VERIFIED};0;verified_degraded" >>"${LOG_PATH_MODULE}/cve_results_kernel_${lK_VERSION}.csv"
      fi
      # Unmatched CVEs: NOT written to CSV, NOT counted in any verification statistics
      # (lNOT_VERIFIED not counted in degraded mode to avoid misleading users)
    done

    # Output degraded mode statistics (clearly marked as "degraded mode")
    print_output "[+] Verification statistics for kernel ${ORANGE}${lK_VERSION}${NC} (degraded mode - function name matching):"
    print_output "    - Function name matched (symbol verified): ${ORANGE}${lVERIFIED_SYMBOL}${NC}"
    print_output "    - Total CVEs checked: ${ORANGE}${#lALL_KVULNS_ARR[@]}${NC}"
    if [[ "${#lALL_KVULNS_ARR[@]}" -gt 0 ]]; then
      local lMATCH_RATE=$((lVERIFIED_SYMBOL * 100 / ${#lALL_KVULNS_ARR[@]}))
      print_output "    - Match rate: ${ORANGE}${lMATCH_RATE}%${NC}"
    fi
    print_output "    - Note: Only CVEs with function name match are recorded in the report"
  else
    # ================================================================
    # Normal mode: Count symbol_verified + compile_verified results
    #   - Has symbol_verified.txt -> lSYMBOL_VERIFIED=1
    #   - Has compiled_verified.txt -> lCOMPILE_VERIFIED=1
    #   - Both -> lVERIFIED_BOTH++
    #   - Neither -> lNOT_VERIFIED++
    # Note: If both verifications exist, write only one CSV row (merged)
    # ================================================================
    for lVULN in "${lALL_KVULNS_ARR[@]}"; do
      lCVE=$(echo "${lVULN}" | cut -d, -f4)
      local lCVSS="${lVULN}"
      lCVSS=$(echo "${lVULN}" | cut -d, -f6)
      local lSYMBOL_VERIFIED=0
      local lCOMPILE_VERIFIED=0

      # Check for symbol verification
      if [[ -f "${LOG_PATH_MODULE}/${lCVE}_symbol_verified.txt" ]]; then
        lSYMBOL_VERIFIED=1
        ((lVERIFIED_SYMBOL += 1))
      fi

      # Check for compile verification
      if [[ -f "${LOG_PATH_MODULE}/${lCVE}_compiled_verified.txt" ]]; then
        lCOMPILE_VERIFIED=1
        ((lVERIFIED_COMPILE += 1))
      fi

      # Count dual verification (passed both symbol and compile verification)
      if [[ "${lSYMBOL_VERIFIED}" -eq 1 ]] && [[ "${lCOMPILE_VERIFIED}" -eq 1 ]]; then
        ((lVERIFIED_BOTH += 1))
      fi

      # Count unverified (neither verification passed)
      if [[ "${lSYMBOL_VERIFIED}" -eq 0 ]] && [[ "${lCOMPILE_VERIFIED}" -eq 0 ]]; then
        ((lNOT_VERIFIED += 1))
      fi

      # If any verification passed, write to CSV (avoid duplicate rows: merge both verifications into one row)
      if [[ "${lSYMBOL_VERIFIED}" -eq 1 ]] || [[ "${lCOMPILE_VERIFIED}" -eq 1 ]]; then
        echo "${lK_VERSION};${lCVE};${lCVSS};${lSYMBOL_VERIFIED};${lCOMPILE_VERIFIED};verified" >>"${LOG_PATH_MODULE}/cve_results_kernel_${lK_VERSION}.csv"
      fi
    done

    # Output normal mode statistics
    print_output "[+] Verification statistics for kernel ${ORANGE}${lK_VERSION}${NC}:"
    print_output "    - Symbol verified: ${ORANGE}${lVERIFIED_SYMBOL}${NC}"
    print_output "    - Compile verified: ${ORANGE}${lVERIFIED_COMPILE}${NC}"
    print_output "    - Both verified: ${ORANGE}${lVERIFIED_BOTH}${NC}"
    print_output "    - Not verified: ${ORANGE}${lNOT_VERIFIED}${NC}"
  fi
}

get_kernel_version_csv_data_s24() {
  local lS24_CSV_LOG="${1:-}"

  if ! [[ -f "${lS24_CSV_LOG}" ]]; then
    print_output "[-] No EMBA log found ..."
    return
  fi

  export K_VERSIONS_ARR=()

  # currently we only support one kernel version
  # if we detect multiple kernel versions we only process the first one after sorting
  mapfile -t K_VERSIONS_ARR < <(cut -d\; -f2 "${lS24_CSV_LOG}" | tail -n +2 | grep -v "NA" | sort -u)
}
