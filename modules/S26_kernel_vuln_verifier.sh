#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  After module s24 was able to identify the kernel, the downloader
#               helper function "kernel_downloader" has downloaded the kernel sources
#               This module checks if we have symbols and/or the kernel config extracted,
#               identifies vulnerabilities via the version number and tries to verify the
#               CVEs

export THREAD_PRIO=1

S26_kernel_vuln_verifier()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Kernel vulnerability identification and verification"
  pre_module_reporter "${FUNCNAME[0]}"

  export HOME_DIR=""
  HOME_DIR="$(pwd)"
  # lKERNEL_ARCH_PATH is the directory where we store all the kernels
  local lKERNEL_ARCH_PATH="${EXT_DIR}""/linux_kernel_sources"
  local lWAIT_PIDS_S26_ARR=()
  export NEG_LOG=0

  if ! [[ -d "${lKERNEL_ARCH_PATH}" ]]; then
    print_output "[-] Missing directory for kernel sources ... exit module now"
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
    return
  fi

  # we wait until the s24 module is finished and hopefully shows us a kernel version
  module_wait "S24_kernel_bin_identifier"

  # now we should have a csv log with a kernel version:
  if ! [[ -f "${S24_CSV_LOG}" ]] || [[ "$(wc -l "${S24_CSV_LOG}" | awk '{print $1}')" -lt 2 ]]; then
    print_output "[-] No Kernel version file (s24 results) identified ..."
    module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
    return
  fi

  # extract kernel version
  get_kernel_version_csv_data_s24 "${S24_CSV_LOG}"

  local lKERNEL_DATA=""
  local lKERNEL_ELF_EMBA_ARR=()
  local lALL_KVULNS_ARR=()
  export KERNEL_CONFIG_PATH="NA"
  export KERNEL_ELF_PATH=""
  local lK_VERSION_KORG=""
  export COMPILE_SOURCE_FILES_VERIFIED=0
  local lK_VERSION=""

  # K_VERSIONS_ARR is from get_kernel_version_csv_data_s24
  for lK_VERSION in "${K_VERSIONS_ARR[@]}"; do
    [[ "${lK_VERSION}" =~ ^[0-9\.a-zA-Z]$ ]] && continue

    local lK_FOUND=0
    print_output "[+] Identified kernel version: ${ORANGE}${lK_VERSION}${NC}"

    mapfile -t lKERNEL_ELF_EMBA_ARR < <(grep "${lK_VERSION}" "${S24_CSV_LOG}" | cut -d\; -f4-7 | \
      grep -v "config extracted" | sort -u | sort -r -n -t\; -k4 || true)

    # we check for a kernel configuration
    for lKERNEL_DATA in "${lKERNEL_ELF_EMBA_ARR[@]}"; do
      if [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f3)" == "/"* ]]; then
        # field 3 is the kernel config file
        KERNEL_CONFIG_PATH=$(echo "${lKERNEL_DATA}" | cut -d\; -f3)
        print_output "[+] Found kernel configuration file: ${ORANGE}${KERNEL_CONFIG_PATH}${NC}"
        # we use the first entry with a kernel config detected
        if [[ "$(echo "${lKERNEL_DATA}" | cut -d\; -f1)" == "/"* ]]; then
          # field 1 is the matching kernel elf file - sometimes we have a config but no elf file
          KERNEL_ELF_PATH=$(echo "${lKERNEL_DATA}" | cut -d\; -f1)
          print_output "[+] Found kernel elf file: ${ORANGE}${KERNEL_ELF_PATH}${NC}"
          lK_FOUND=1
          break
        fi
      fi
    done

    if [[ "${lK_FOUND}" -ne 1 ]]; then
      print_output "[-] No kernel configuration file with matching elf file found for kernel ${ORANGE}${lK_VERSION}${NC}."
    fi

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

    if [[ -f "${KERNEL_CONFIG}" ]]; then
      # check if the provided configuration is for the kernel version under test
      if grep -q "${lK_VERSION}" "${KERNEL_CONFIG}"; then
        KERNEL_CONFIG_PATH="${KERNEL_CONFIG}"
        print_output "[+] Using provided kernel configuration file: ${ORANGE}${KERNEL_CONFIG_PATH}${NC}"
        lK_FOUND=1
      fi
    fi

    if [[ "${lK_FOUND}" -ne 1 ]]; then
      print_output "[-] No valid kernel information found for kernel ${ORANGE}${lK_VERSION}${NC}."
      continue
    fi

    if ! [[ -f "${KERNEL_ELF_PATH}" ]]; then
      print_output "[-] Warning: Kernel ELF file not found"
      module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
      continue
    fi
    if ! [[ -v lK_VERSION ]]; then
      print_output "[-] Missing kernel version .. exit now"
      module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
      continue
    fi

    local lCVE_DETAILS_PATH="${LOG_PATH_MODULE}""/linux_kernel_${lK_VERSION}.txt"

    if [[ -f "${KERNEL_ELF_PATH}" ]]; then
      extract_kernel_arch "${KERNEL_ELF_PATH}"
    fi

    if [[ "${lK_VERSION}" == *".0" ]]; then
      lK_VERSION_KORG=${lK_VERSION%.0}
    else
      lK_VERSION_KORG="${lK_VERSION}"
    fi
    # we need to wait for the downloaded linux kernel sources from the host
    local lWAIT_CNT=0
    while ! [[ -f "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" ]]; do
      print_output "[*] Waiting for kernel sources ..." "no_log"
      ((lWAIT_CNT+=1))
      if [[ "${lWAIT_CNT}" -gt 60 ]] || [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
        print_output "[-] No valid kernel source file available ... check for further kernel versions"
        continue 2
      fi
      sleep 5
    done

    # now we have a file with the kernel sources ... we do not know if this file is complete.
    # Probably it is just downloaded partly and we need to wait a bit longer
    lWAIT_CNT=0
    print_output "[*] Testing kernel sources ..." "no_log"
    while ! gunzip -t "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" 2> /dev/null; do
      print_output "[*] Testing kernel sources ..." "no_log"
      ((lWAIT_CNT+=1))
      if [[ "${lWAIT_CNT}" -gt 60 ]] || [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
        print_output "[-] No valid kernel source file available ... check for further kernel versions"
        continue 2
      fi
      sleep 5
    done

    print_output "[*] Kernel sources for version ${ORANGE}${lK_VERSION}${NC} available"
    write_link "${LOG_DIR}/kernel_downloader.log"

    lKERNEL_DIR="${LOG_PATH_MODULE}/linux-${lK_VERSION_KORG}"
    [[ -d "${lKERNEL_DIR}" ]] && rm -rf "${lKERNEL_DIR}"
    if ! [[ -d "${lKERNEL_DIR}" ]] && [[ "$(file "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz")" == *"gzip compressed data"* ]]; then
      print_output "[*] Kernel version ${ORANGE}${lK_VERSION}${NC} extraction ... "
      tar -xzf "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION_KORG}.tar.gz" -C "${LOG_PATH_MODULE}"
    fi

    print_output "[*] Kernel version ${ORANGE}${lK_VERSION}${NC} CVE detection ... "
    prepare_cve_search_module
    export F20_DEEP=0
    export S26_LOG_DIR="${LOG_DIR}""/s26_kernel_vuln_verifier/"
    export SYMBOLS_CNT=0

    cve_db_lookup_version "linux_kernel:${lK_VERSION}"

    if ! [[ -f "${lCVE_DETAILS_PATH}" ]]; then
      print_output "[-] No CVE details generated ... check for further kernel version"
      continue
    fi

    print_output "[*] Generate CVE vulnerabilities array for kernel version ${ORANGE}${lK_VERSION}${NC} ..." "no_log"
    # mapfile -t lALL_KVULNS_ARR < <(jq -rc '"\(.id):\(.cvss):\(.cvss3):\(.summary)"' "${lCVE_DETAILS_PATH}")
    mapfile -t lALL_KVULNS_ARR < "${lCVE_DETAILS_PATH}"
    # readable log file for the web report:
    # jq -rc '"\(.id):\(.cvss):\(.cvss3):\(.summary)"' "${lCVE_DETAILS_PATH}" > "${LOG_PATH_MODULE}""/kernel-${lK_VERSION}-vulns.log"

    print_ln
    print_output "[+] Extracted ${ORANGE}${#lALL_KVULNS_ARR[@]}${GREEN} vulnerabilities based on kernel version only"
    write_link "${LOG_PATH_MODULE}""/kernel-${lK_VERSION}-vulns.log"

    if [[ -f "${KERNEL_CONFIG_PATH}" ]] && [[ -d "${lKERNEL_DIR}" ]]; then
      compile_kernel "${KERNEL_CONFIG_PATH}" "${lKERNEL_DIR}" "${ORIG_K_ARCH}"
    fi

    sub_module_title "Identify kernel symbols ..."
    readelf -s "${KERNEL_ELF_PATH}" | grep "FUNC\|OBJECT" | sed 's/.*FUNC//' | sed 's/.*OBJECT//' | awk '{print $4}' | \
      sed 's/\[\.\.\.\]//' > "${LOG_PATH_MODULE}"/symbols.txt
    SYMBOLS_CNT=$(wc -l "${LOG_PATH_MODULE}"/symbols.txt | awk '{print $1}')
    print_output "[*] Extracted ${ORANGE}${SYMBOLS_CNT}${NC} symbols from kernel"

    if [[ -d "${LOG_DIR}""/firmware" ]]; then
      print_output "[*] Identify kernel modules symbols ..." "no_log"
      find "${LOG_DIR}/firmware" -name "*.ko" -exec readelf -a {} \; | grep FUNC | sed 's/.*FUNC//' | \
        awk '{print $4}' | sed 's/\[\.\.\.\]//' >> "${LOG_PATH_MODULE}"/symbols.txt || true
    fi

    uniq "${LOG_PATH_MODULE}"/symbols.txt > "${LOG_PATH_MODULE}"/symbols_uniq.txt
    SYMBOLS_CNT=$(wc -l "${LOG_PATH_MODULE}"/symbols_uniq.txt | awk '{print $1}')

    if [[ "${SYMBOLS_CNT}" -eq 0 ]]; then
      print_output "[-] No symbols found ... check for further kernel version"
      continue
    fi

    print_ln
    print_output "[+] Extracted ${ORANGE}${SYMBOLS_CNT}${GREEN} unique symbols"
    write_link "${LOG_PATH_MODULE}/symbols_uniq.txt"
    print_ln
    split_symbols_file

    sub_module_title "Linux kernel vulnerability verification"

    export CNT_PATHS_UNK=0
    export CNT_PATHS_FOUND=0
    export CNT_PATHS_NOT_FOUND=0
    export VULN_CNT=1
    export CNT_PATHS_FOUND_WRONG_ARCH=0

    print_output "[*] Checking vulnerabilities for kernel version ${ORANGE}${lK_VERSION}${NC}" "" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
    print_ln

    for lVULN in "${lALL_KVULNS_ARR[@]}"; do
      NEG_LOG=1
      local lK_PATHS_ARR=()
      local lK_PATHS_FILES_TMP_ARR=()
      local lSUMMARY=""
      local lCVSS2=""
      local lCVSS3=""

      # lK_PATH is now defined with some backup text for output if lK_PATHS_ARR population without results
      local lK_PATH="missing vulnerability path from advisory"

      lCVE=$(echo "${lVULN}" | cut -d: -f1)
      local lOUTx="[*] Testing vulnerability ${ORANGE}${VULN_CNT}${NC} / ${ORANGE}${#lALL_KVULNS_ARR[@]}${NC} / ${ORANGE}${lCVE}${NC}"
      print_output "${lOUTx}" "no_log"
      write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"

      lCVSS2="$(echo "${lVULN}" | cut -d: -f2)"
      lCVSS3="$(echo "${lVULN}" | cut -d: -f3)"
      lSUMMARY="$(echo "${lVULN}" | cut -d: -f6-)"
      # print_output "$(indent "CVSSv2: ${ORANGE}${lCVSS2}${NC} / CVSSv3: ${ORANGE}${lCVSS3}${NC} / Summary: ${ORANGE}${lSUMMARY}${NC}")"

      # extract kernel source paths from summary -> we use these paths to check if they are used by our
      # symbols or during kernel compilation
      mapfile -t lK_PATHS_ARR < <(echo "${lSUMMARY}" | tr ' ' '\n' | sed 's/\\$//' | grep ".*\.[chS]$" | sed -r 's/CVE-[0-9]+-[0-9]+:[0-9].*://' \
        | sed -r 's/CVE-[0-9]+-[0-9]+:null.*://' | sed 's/^(//' | sed 's/)$//' | sed 's/,$//' | sed 's/\.$//' | cut -d: -f1 || true)

      for lK_PATH in "${lK_PATHS_ARR[@]}"; do
        # we have only a filename without path -> we search for possible candidate files in the kernel sources
        if ! [[ "${lK_PATH}" == *"/"* ]]; then
          lOUTx="[*] Found file name ${ORANGE}${lK_PATH}${NC} for ${ORANGE}${lCVE}${NC} without path details ... looking for candidates now"
          print_output "${lOUTx}" "no_log"
          write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
          mapfile -t lK_PATHS_FILES_TMP_ARR < <(find "${lKERNEL_DIR}" -name "${lK_PATH}" | sed "s&${lKERNEL_DIR}\/&&")
        fi
        lK_PATHS_ARR+=("${lK_PATHS_FILES_TMP_ARR[@]}")
      done

      if [[ "${#lK_PATHS_ARR[@]}" -gt 0 ]]; then
        for lK_PATH in "${lK_PATHS_ARR[@]}"; do
          if [[ -f "${lKERNEL_DIR}/${lK_PATH}" ]]; then
            # check if arch is in path -> if so we check if our architecture is also in the path
            # if we find our architecture then we can proceed with symbol_verifier
            if [[ "${lK_PATH}" == "arch/"* ]]; then
              if [[ "${lK_PATH}" == "arch/${ORIG_K_ARCH}/"* ]]; then
                ((CNT_PATHS_FOUND+=1))
                if [[ "${SYMBOLS_CNT}" -gt 0 ]]; then
                  symbol_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS2}/${lCVSS3}" "${lKERNEL_DIR}" &
                  lWAIT_PIDS_S26_ARR+=( "$!" )
                fi
                if [[ "${COMPILE_SOURCE_FILES_VERIFIED}" -gt 0 ]]; then
                  compile_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS2}/${lCVSS3}" &
                  lWAIT_PIDS_S26_ARR+=( "$!" )
                fi
              else
                # this vulnerability is for a different architecture -> we can skip it for our kernel
                lOUTx="[-] Vulnerable path for different architecture found for ${ORANGE}${lK_PATH}${NC} - not further processing ${ORANGE}${lCVE}${NC}"
                print_output "${lOUTx}" "no_log"
                write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
                ((CNT_PATHS_FOUND_WRONG_ARCH+=1))
              fi
            else
              ((CNT_PATHS_FOUND+=1))
              if [[ "${SYMBOLS_CNT}" -gt 0 ]]; then
                symbol_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS2}/${lCVSS3}" "${lKERNEL_DIR}" &
                lWAIT_PIDS_S26_ARR+=( "$!" )
              fi
              if [[ "${COMPILE_SOURCE_FILES_VERIFIED}" -gt 0 ]]; then
                compile_verifier "${lCVE}" "${lK_VERSION}" "${lK_PATH}" "${lCVSS2}/${lCVSS3}" &
                lWAIT_PIDS_S26_ARR+=( "$!" )
              fi
            fi
          else
            # no source file in our kernel sources -> no vulns
            lOUTx="[-] ${ORANGE}${lCVE}${NC} - ${ORANGE}${lK_PATH}${NC} - vulnerable source file not found in kernel sources"
            print_output "${lOUTx}" "no_log"
            write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
            ((CNT_PATHS_NOT_FOUND+=1))
          fi
          max_pids_protection 20 "${lWAIT_PIDS_S26_ARR[@]}"
        done
      else
        lOUTx="[-] ${lCVE} - ${lK_PATH}"
        print_output "${lOUTx}" "no_log"
        write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
        ((CNT_PATHS_UNK+=1))
      fi
      ((VULN_CNT+=1))
    done

    wait_for_pid "${lWAIT_PIDS_S26_ARR[@]}"

    final_log_kernel_vulns "${lK_VERSION}" "${lALL_KVULNS_ARR[@]}"
  done

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

split_symbols_file() {
  print_output "[*] Splitting symbols file for processing ..." "no_log"
  split -l 100 "${LOG_PATH_MODULE}"/symbols_uniq.txt "${LOG_PATH_MODULE}"/symbols_uniq.split.
  sed -i 's/^/EXPORT_SYMBOL\(/' "${LOG_PATH_MODULE}"/symbols_uniq.split.*
  sed -i 's/$/\)/' "${LOG_PATH_MODULE}"/symbols_uniq.split.*

  split -l 100 "${LOG_PATH_MODULE}"/symbols_uniq.txt "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.
  sed -i 's/^/EXPORT_SYMBOL_GPL\(/' "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.*
  sed -i 's/$/\)/' "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.*
  print_output "[*] Splitting symbols file for processing ... done" "no_log"
}

extract_kernel_arch() {
  local lKERNEL_ELF_PATH="${1:-}"
  export ORIG_K_ARCH=""

  ORIG_K_ARCH=$(file "${lKERNEL_ELF_PATH}" | cut -d, -f2)

  # for ARM -> ARM aarch64 to ARM64
  ORIG_K_ARCH=${ORIG_K_ARCH/ARM\ aarch64/arm64}
  # for MIPS64 -> MIPS64 to MIPS
  ORIG_K_ARCH=${ORIG_K_ARCH/MIPS64/MIPS}
  ORIG_K_ARCH=${ORIG_K_ARCH/*PowerPC*/powerpc}

  # ORIG_K_ARCH=$(echo "${ORIG_K_ARCH}" | tr -d ' ' | tr "[:upper:]" "[:lower:]")
  ORIG_K_ARCH="${ORIG_K_ARCH,,}"
  ORIG_K_ARCH="${ORIG_K_ARCH//\ }"
  print_output "[+] Identified kernel architecture ${ORANGE}${ORIG_K_ARCH}${NC}"
}

symbol_verifier() {
  local lCVE="${1:-}"
  local lK_VERSION="${2:-}"
  local lK_PATH="${3:-}"
  local lCVSS="${4:-}"
  local lKERNEL_DIR="${5:-}"
  local lVULN_FOUND=0
  local lCHUNK_FILE=""

  for lCHUNK_FILE in "${LOG_PATH_MODULE}"/symbols_uniq.split.* ; do
    # echo "testing chunk file $lCHUNK_FILE"
    if grep -q -f "${lCHUNK_FILE}" "${lKERNEL_DIR}/${lK_PATH}" ; then
      # echo "verified chunk file $lCHUNK_FILE"
      local lOUTx="[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS}${GREEN}) - ${ORANGE}${lK_PATH}${GREEN} verified - exported symbol${NC}"
      print_output "${lOUTx}"
      write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      echo "${lCVE} (${lCVSS}) - ${lK_VERSION} - exported symbol verified - ${lK_PATH}" >> "${LOG_PATH_MODULE}""/${lCVE}_symbol_verified.txt"
      lVULN_FOUND=1
      break
    fi
  done

  # if we have already a match for this path we can skip the 2nd check
  # this is only for speed up the process a bit
  [[ "${lVULN_FOUND}" -eq 1 ]] && return

  for lCHUNK_FILE in "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.* ; do
    # echo "testing chunk file $lCHUNK_FILE"
    if grep -q -f "${lCHUNK_FILE}" "${lKERNEL_DIR}/${lK_PATH}" ; then
      # print_output "[*] verified chunk file $lCHUNK_FILE (GPL)"
      local lOUTx="[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS}${GREEN}) - ${ORANGE}${lK_PATH}${GREEN} verified - exported symbol (GPL)${NC}"
      print_output "${lOUTx}"
      write_log "${lOUTx}" "${LOG_PATH_MODULE}/kernel_verification_${lK_VERSION}_detailed.log"
      echo "${lCVE} (${lCVSS}) - ${lK_VERSION} - exported symbol verified (gpl) - ${lK_PATH}" >> "${LOG_PATH_MODULE}""/${lCVE}_symbol_verified.txt"
      lVULN_FOUND=1
      break
    fi
  done
}

compile_verifier() {
  local lCVE="${1:-}"
  local lK_VERSION="${2:-}"
  local lK_PATH="${3:-}"
  local lCVSS="${4:-}"
  if ! [[ -f "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log ]]; then
    return
  fi

  if grep -q "${lK_PATH}" "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log ; then
    print_output "[+] ${ORANGE}${lCVE}${GREEN} (${ORANGE}${lCVSS}${GREEN}) - ${ORANGE}${lK_PATH}${GREEN} verified - compiled path${NC}"
    echo "${lCVE} (${lCVSS}) - ${lK_VERSION} - compiled path verified - ${lK_PATH}" >> "${LOG_PATH_MODULE}""/${lCVE}_compiled_verified.txt"
  fi
}

compile_kernel() {
  # this is based on the great work shown here https://arxiv.org/pdf/2209.05217.pdf
  local lKERNEL_CONFIG_FILE="${1:-}"
  local lKERNEL_DIR="${2:-}"
  local lKARCH="${3:-}"
  # lKARCH=$(echo "${lKARCH}" | tr '[:upper:]' '[:lower:]')
  lKARCH="${lKARCH,,}"
  export COMPILE_SOURCE_FILES=0
  export COMPILE_SOURCE_FILES_VERIFIED=0

  if ! [[ -f "${lKERNEL_CONFIG_FILE}" ]]; then
    print_output "[-] No supported kernel config found - ${ORANGE}${lKERNEL_CONFIG_FILE}${NC}"
    return
  fi
  if ! [[ -d "${lKERNEL_DIR}" ]]; then
    print_output "[-] No supported kernel source directory found - ${ORANGE}${lKERNEL_DIR}${NC}"
    return
  fi
  print_ln
  sub_module_title "Compile Linux kernel - dry run mode"

  if ! [[ -d "${lKERNEL_DIR}"/arch/"${lKARCH}" ]]; then
    print_output "[!] No supported architecture found - ${ORANGE}${lKARCH}${NC}"
    return
  else
    print_output "[*] Supported architecture found - ${ORANGE}${lKARCH}${NC}"
  fi

  cd "${lKERNEL_DIR}" || exit
  # print_output "[*] Create default kernel config for $ORANGE$lKARCH$NC architecture"
  # LANG=en make ARCH="${lKARCH}" defconfig | tee -a "${LOG_PATH_MODULE}"/kernel-compile-defconfig.log || true
  # print_output "[*] Finished creating default kernel config for $ORANGE$lKARCH$NC architecture" "" "$LOG_PATH_MODULE/kernel-compile-defconfig.log"
  print_ln

  print_output "[*] Install kernel config of the identified configuration of the firmware"
  cp "${lKERNEL_CONFIG_FILE}" .config
  # https://stackoverflow.com/questions/4178526/what-does-make-oldconfig-do-exactly-in-the-linux-kernel-makefile
  local LANG=""
  LANG=en make ARCH="${lKARCH}" olddefconfig | tee -a "${LOG_PATH_MODULE}"/kernel-compile-olddefconfig.log || true
  print_output "[*] Finished updating kernel config with the identified firmware configuration" "" "${LOG_PATH_MODULE}/kernel-compile-olddefconfig.log"
  print_ln

  print_output "[*] Starting kernel compile dry run ..."
  LANG=en make ARCH="${lKARCH}" target=all -Bndi | tee -a "${LOG_PATH_MODULE}"/kernel-compile.log
  print_ln
  print_output "[*] Finished kernel compile dry run ... generated used source files" "" "${LOG_PATH_MODULE}/kernel-compile.log"

  cd "${HOME_DIR}" || exit

  if [[ -f "${LOG_PATH_MODULE}"/kernel-compile.log ]]; then
    tr ' ' '\n' < "${LOG_PATH_MODULE}"/kernel-compile.log | grep ".*\.[chS]" | tr -d '"' | tr -d ')' | tr -d '<' | tr -d '>' \
      | tr -d '(' | sed 's/^\.\///' | sed '/^\/.*/d' | tr -d ';' | sed 's/^>//' | sed 's/^-o//' | tr -d \' \
      | sed 's/--defines=//' | sed 's/\.$//' | sort -u > "${LOG_PATH_MODULE}"/kernel-compile-files.log
    COMPILE_SOURCE_FILES=$(wc -l "${LOG_PATH_MODULE}"/kernel-compile-files.log | awk '{print $1}')
    print_output "[+] Found ${ORANGE}${COMPILE_SOURCE_FILES}${GREEN} used source files during compilation" "" "${LOG_PATH_MODULE}/kernel-compile-files.log"

    # lets check the entries and verify them in our kernel sources
    # entries without a real file are not further processed
    # with this mechanism we can eliminate garbage
    while read -r COMPILE_SOURCE_FILE; do
      if [[ -f "${lKERNEL_DIR}""/""${COMPILE_SOURCE_FILE}" ]]; then
        # print_output "[*] Verified Source file $ORANGE$lKERNEL_DIR/$COMPILE_SOURCE_FILE$NC is available"
        echo "${COMPILE_SOURCE_FILE}" >> "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log
      fi
    done < "${LOG_PATH_MODULE}"/kernel-compile-files.log
    COMPILE_SOURCE_FILES_VERIFIED=$(wc -l "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log | awk '{print $1}')
    print_ln
    print_output "[+] Found ${ORANGE}${COMPILE_SOURCE_FILES_VERIFIED}${GREEN} used and available source files during compilation" "" "${LOG_PATH_MODULE}/kernel-compile-files_verified.log"
  else
    print_output "[-] Found ${RED}NO${NC} used source files during compilation"
  fi
}

report_kvulns_csv() {
  local lVULN="${1:-}"
  local lK_VERSION="${1:-}"
  local lCVE=""
  local lCVSS2=""
  local lCVSS3=""
  local lCVE_SYMBOL_FOUND=0
  local lCVE_COMPILE_FOUND=0

  lCVE=$(echo "${lVULN}" | cut -d: -f1)
  lCVSS2="$(echo "${lVULN}" | cut -d: -f2)"
  lCVSS3="$(echo "${lVULN}" | cut -d: -f3)"
  lCVE_SYMBOL_FOUND=$(find "${LOG_PATH_MODULE}" -name "${lCVE}_symbol_verified.txt" | wc -l)
  lCVE_COMPILE_FOUND=$(find "${LOG_PATH_MODULE}" -name "${lCVE}_compiled_verified.txt" | wc -l)
  echo "${lK_VERSION};${ORIG_K_ARCH};${lCVE};${lCVSS2};${lCVSS3};${lCVE_SYMBOL_FOUND:-0};${lCVE_COMPILE_FOUND:-0}" >> "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv
}

final_log_kernel_vulns() {
  sub_module_title "Linux kernel verification results"
  local lK_VERSION="${1:-}"
  shift
  local lALL_KVULNS_ARR=("$@")

  if ! [[ -v lALL_KVULNS_ARR ]]; then
    print_output "[-] No module results"
    return
  fi

  find "${LOG_PATH_MODULE}" -name "symbols_uniq.split.*" -delete || true
  find "${LOG_PATH_MODULE}" -name "symbols_uniq.split_gpl.*" -delete || true

  NEG_LOG=1

  local lVULN=""
  local lSYM_USAGE_VERIFIED=0
  local lVULN_PATHS_VERIFIED_SYMBOLS=0
  local lVULN_PATHS_VERIFIED_COMPILED=0
  local lCVE_VERIFIED_SYMBOLS=0
  local lCVE_VERIFIED_COMPILED=0
  local lCVE_VERIFIED_ONE=0
  local lCVE_VERIFIED_OVERLAP=0
  local lCVE_VERIFIED_OVERLAP_CRITICAL_ARR=()
  local lCVE_VERIFIED_ONE_CRITICAL_ARR=()
  local lCVE_VERIFIED_ONE_CRITICAL=""
  local lCVE_VERIFIED_OVERLAP_CRITICAL_ARR=()
  local lCVE_CRITICAL=""
  local lCVSS2_CRITICAL=""
  local lCVSS3_CRITICAL=""
  local lWAIT_PIDS_S26_1_ARR=()

  print_output "[*] Generating final kernel report ..." "no_log"
  echo "Kernel version;Architecture;CVE;CVSSv2;CVSSv3;Verified with symbols;Verified with compile files" >> "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv

  if [[ -f "${LOG_PATH_MODULE}/kernel_cve_version_issues.log" ]]; then
    print_output "[*] Multiple possible version mismatches identified and reported."
    write_link "${LOG_PATH_MODULE}/kernel_cve_version_issues.log"
  fi
  # we walk through the original version based kernel vulnerabilities and report the results
  # from symbols and kernel configuration
  for lVULN in "${lALL_KVULNS_ARR[@]}"; do
    if [[ "${THREADED}" -eq 1 ]]; then
      report_kvulns_csv "${lVULN}" "${lK_VERSION}" &
      local lTMP_PID="$!"
      lWAIT_PIDS_S26_1_ARR+=( "${lTMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_S26_1_ARR[@]}"
    else
      report_kvulns_csv "${lVULN}" "${lK_VERSION}"
    fi
  done

  lSYM_USAGE_VERIFIED=$(wc -l "${LOG_PATH_MODULE}"/CVE-*symbol_* 2>/dev/null | tail -1 | awk '{print $1}' 2>/dev/null || true)
  # nosemgrep
  lVULN_PATHS_VERIFIED_SYMBOLS=$(cat "${LOG_PATH_MODULE}"/CVE-*symbol_verified.txt 2>/dev/null | grep "exported symbol" | sed 's/.*verified - //' | sed 's/.*verified (GPL) - //' | sort -u | wc -l || true)
  # nosemgrep
  lVULN_PATHS_VERIFIED_COMPILED=$(cat "${LOG_PATH_MODULE}"/CVE-*compiled_verified.txt 2>/dev/null | grep "compiled path verified" | sed 's/.*verified - //' | sort -u | wc -l || true)
  # nosemgrep
  lCVE_VERIFIED_SYMBOLS=$(cat "${LOG_PATH_MODULE}"/CVE-*symbol_verified.txt 2>/dev/null | grep "exported symbol" | cut -d\  -f1 | sort -u | wc -l || true)
  # nosemgrep
  lCVE_VERIFIED_COMPILED=$(cat "${LOG_PATH_MODULE}"/CVE-*compiled_verified.txt 2>/dev/null| grep "compiled path verified" | cut -d\  -f1 | sort -u | wc -l || true)

  print_output "[+] Identified ${ORANGE}${#lALL_KVULNS_ARR[@]}${GREEN} unverified CVE vulnerabilities for kernel version ${ORANGE}${lK_VERSION}${NC}"
  write_link "${LOG_PATH_MODULE}/cve_results_kernel_${lK_VERSION}.csv"
  print_output "[*] Detected architecture ${ORANGE}${ORIG_K_ARCH}${NC}"
  print_output "[*] Extracted ${ORANGE}${SYMBOLS_CNT}${NC} unique symbols from kernel and modules"
  write_link "${LOG_PATH_MODULE}/symbols_uniq.txt"
  if [[ -v COMPILE_SOURCE_FILES ]]; then
    print_output "[*] Extracted ${ORANGE}${COMPILE_SOURCE_FILES}${NC} used source files during compilation"
  fi
  print_output "[*] Found ${ORANGE}${CNT_PATHS_UNK}${NC} advisories with missing vulnerable path details"
  print_output "[*] Found ${ORANGE}${CNT_PATHS_NOT_FOUND}${NC} path details in CVE advisories but no real kernel path found in vanilla kernel source"
  print_output "[*] Found ${ORANGE}${CNT_PATHS_FOUND}${NC} path details in CVE advisories with real kernel path"
  print_output "[*] Found ${ORANGE}${CNT_PATHS_FOUND_WRONG_ARCH}${NC} path details in CVE advisories with real kernel path but wrong architecture"
  print_output "[*] ${ORANGE}${lSYM_USAGE_VERIFIED}${NC} symbol usage verified"
  print_output "[*] ${ORANGE}${lVULN_PATHS_VERIFIED_SYMBOLS}${NC} vulnerable paths verified via symbols"
  print_output "[*] ${ORANGE}${lVULN_PATHS_VERIFIED_COMPILED}${NC} vulnerable paths verified via compiled paths"
  print_ln

  # we need to wait for the cve_results_kernel_"${lK_VERSION}".csv
  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S26_1_ARR[@]}"

  lCVE_VERIFIED_ONE=$(cut -d\; -f6-7 "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv | grep -c "1" || true)
  lCVE_VERIFIED_OVERLAP=$(grep -c ";1;1" "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv || true)
  mapfile -t lCVE_VERIFIED_OVERLAP_CRITICAL_ARR < <(grep ";1;1$" "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv | grep ";9.[0-9];\|;10;" || true)
  mapfile -t lCVE_VERIFIED_ONE_CRITICAL_ARR < <(grep ";1;\|;1$" "${LOG_PATH_MODULE}"/cve_results_kernel_"${lK_VERSION}".csv | grep ";9.[0-9];\|;10;" || true)

  if [[ "${lCVE_VERIFIED_SYMBOLS}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${lCVE_VERIFIED_SYMBOLS}${GREEN} (exported symbols)"
  fi
  if [[ "${lCVE_VERIFIED_COMPILED}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${lCVE_VERIFIED_COMPILED}${GREEN} (compiled paths)"
  fi
  if [[ "${lCVE_VERIFIED_ONE}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${lCVE_VERIFIED_ONE}${GREEN} (one mechanism succeeded)"
  fi
  if [[ "${lCVE_VERIFIED_OVERLAP}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${lCVE_VERIFIED_OVERLAP}${GREEN} (both mechanisms overlap)"
  fi

  if [[ "${#lCVE_VERIFIED_ONE_CRITICAL_ARR[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Verified CRITICAL CVEs: ${ORANGE}${#lCVE_VERIFIED_ONE_CRITICAL_ARR[@]}${GREEN} (one mechanism succeeded)"
    for lCVE_VERIFIED_ONE_CRITICAL in "${lCVE_VERIFIED_ONE_CRITICAL_ARR[@]}"; do
      lCVE_CRITICAL=$(echo "${lCVE_VERIFIED_ONE_CRITICAL}" | cut -d\; -f3)
      lCVSS2_CRITICAL=$(echo "${lCVE_VERIFIED_ONE_CRITICAL}" | cut -d\; -f4)
      lCVSS3_CRITICAL=$(echo "${lCVE_VERIFIED_ONE_CRITICAL}" | cut -d\; -f5)
      # disabled because it is too slow
      # identify_exploits "${lCVE_CRITICAL}"
      if [[ "${EXPLOIT_DETECTED:-"no"}" == "yes" ]] || [[ "${POC_DETECTED:-"no"}" == "yes" ]]; then
        print_output "$(indent "$(orange "${ORANGE}${lCVE_CRITICAL}${GREEN}\t-\t${ORANGE}${lCVSS2_CRITICAL}${GREEN} / ${ORANGE}${lCVSS3_CRITICAL}${GREEN}\t-\tExploit/PoC: ${ORANGE}${EXPLOIT_DETECTED} ${EXP} / ${POC_DETECTED} ${POC}${NC}")")"
      else
        print_output "$(indent "$(orange "${ORANGE}${lCVE_CRITICAL}${GREEN}\t-\t${ORANGE}${lCVSS2_CRITICAL}${GREEN} / ${ORANGE}${lCVSS3_CRITICAL}${GREEN}")")"
      fi
    done
  fi

  if [[ "${#lCVE_VERIFIED_OVERLAP_CRITICAL_ARR[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Verified CRITICAL CVEs: ${ORANGE}${#lCVE_VERIFIED_OVERLAP_CRITICAL_ARR[@]}${GREEN} (both mechanisms overlap)"
    for lCVE_VERIFIED_OVERLAP_CRITICAL in "${lCVE_VERIFIED_OVERLAP_CRITICAL_ARR[@]}"; do
      lCVE_CRITICAL=$(echo "${lCVE_VERIFIED_OVERLAP_CRITICAL}" | cut -d\; -f3)
      lCVSS2_CRITICAL=$(echo "${lCVE_VERIFIED_OVERLAP_CRITICAL}" | cut -d\; -f4)
      lCVSS3_CRITICAL=$(echo "${lCVE_VERIFIED_OVERLAP_CRITICAL}" | cut -d\; -f5)
      # disabled because it is too slow
      # identify_exploits "${lCVE_CRITICAL}"
      if [[ "${EXPLOIT_DETECTED:-"no"}" == "yes" ]] || [[ "${POC_DETECTED:-"no"}" == "yes" ]]; then
        print_output "$(indent "$(orange "${ORANGE}${lCVE_CRITICAL}${GREEN}\t-\t${ORANGE}${lCVSS2_CRITICAL}${GREEN} / ${ORANGE}${lCVSS3_CRITICAL}${GREEN}\t-\tExploit/PoC: ${ORANGE}${EXPLOIT_DETECTED} ${EXP} / ${POC_DETECTED} ${POC}${NC}")")"
      else
        print_output "$(indent "$(orange "${ORANGE}${lCVE_CRITICAL}${GREEN}\t-\t${ORANGE}${lCVSS2_CRITICAL}${GREEN} / ${ORANGE}${lCVSS3_CRITICAL}${GREEN}")")"
      fi
    done
  fi
  write_log "[*] Statistics:${lK_VERSION}:${#lALL_KVULNS_ARR[@]}:${lCVE_VERIFIED_SYMBOLS}:${lCVE_VERIFIED_COMPILED}"
}

identify_exploits() {
  local lCVE_VALUE="${1:-}"
  export EXPLOIT_DETECTED="no"
  export POC_DETECTED="no"
  export POC=""
  export EXP=""

  if command -v cve_searchsploit >/dev/null; then
    if cve_searchsploit "${lCVE_VALUE}" 2>/dev/null | grep -q "Exploit DB Id:"; then
      EXPLOIT_DETECTED="yes"
      EXP="(EDB)"
    fi
  fi
  if [[ -f "${MSF_DB_PATH}" ]]; then
    if grep -q -E "${lCVE_VALUE}"$ "${MSF_DB_PATH}"; then
      EXPLOIT_DETECTED="yes"
      EXP="${EXP}(MSF)"
    fi
  fi
  if [[ -f "${KNOWN_EXP_CSV}" ]]; then
    if grep -q \""${lCVE_VALUE}"\", "${KNOWN_EXP_CSV}"; then
      EXPLOIT_DETECTED="yes"
      EXP="${EXP}(KNOWN)"
    fi
  fi
  if [[ -f "${CONFIG_DIR}/Snyk_PoC_results.csv" ]]; then
    if grep -q -E "^${lCVE_VALUE};" "${CONFIG_DIR}/Snyk_PoC_results.csv"; then
      POC_DETECTED="yes"
      POC="${POC}(SNYK)"
    fi
  fi
  if [[ -f "${CONFIG_DIR}/PS_PoC_results.csv" ]]; then
    if grep -q -E "^${lCVE_VALUE};" "${CONFIG_DIR}/PS_PoC_results.csv"; then
      POC_DETECTED="yes"
      POC="${POC}(PS)"
    fi
  fi
}

get_kernel_version_csv_data_s24() {
  local lS24_CSV_LOG="${1:-}"

  if ! [[ -f "${lS24_CSV_LOG}" ]];then
    print_output "[-] No EMBA log found ..."
    return
  fi

  export K_VERSIONS_ARR=()

  # currently we only support one kernel version
  # if we detect multiple kernel versions we only process the first one after sorting
  mapfile -t K_VERSIONS_ARR < <(cut -d\; -f2 "${lS24_CSV_LOG}" | tail -n +2 | grep -v "NA" | sort -u)
}
