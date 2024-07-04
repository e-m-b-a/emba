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
  # KERNEL_ARCH_PATH is the directory where we store all the kernels
  local KERNEL_ARCH_PATH="${EXT_DIR}""/linux_kernel_sources"
  S24_CSV_LOG="${CSV_DIR}""/s24_kernel_bin_identifier.csv"
  local WAIT_PIDS_S26=()
  export NEG_LOG=0

  if ! [[ -d "${KERNEL_ARCH_PATH}" ]]; then
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
  get_csv_data_s24 "${S24_CSV_LOG}"

  local KERNEL_DATA=""
  local KERNEL_ELF_EMBA=()
  local ALL_KVULNS=()
  export KERNEL_CONFIG_PATH="NA"
  export KERNEL_ELF_PATH=""
  local K_VERSION_KORG=""
  export COMPILE_SOURCE_FILES_VERIFIED=0

  for K_VERSION in "${K_VERSIONS[@]}"; do
    [[ "${K_VERSION}" != *"[0-9]"* ]] && continue

    local K_FOUND=0
    print_output "[+] Identified kernel version: ${ORANGE}${K_VERSION}${NC}"

    mapfile -t KERNEL_ELF_EMBA < <(grep "${K_VERSION}" "${S24_CSV_LOG}" | cut -d\; -f4-7 | \
      grep -v "config extracted" | sort -u | sort -r -n -t\; -k4 || true)

    # we check for a kernel configuration
    for KERNEL_DATA in "${KERNEL_ELF_EMBA[@]}"; do
      if [[ "$(echo "${KERNEL_DATA}" | cut -d\; -f3)" == "/"* ]]; then
        # field 3 is the kernel config file
        KERNEL_CONFIG_PATH=$(echo "${KERNEL_DATA}" | cut -d\; -f3)
        print_output "[+] Found kernel configuration file: ${ORANGE}${KERNEL_CONFIG_PATH}${NC}"
        # we use the first entry with a kernel config detected
        if [[ "$(echo "${KERNEL_DATA}" | cut -d\; -f1)" == "/"* ]]; then
          # field 1 is the matching kernel elf file - sometimes we have a config but no elf file
          KERNEL_ELF_PATH=$(echo "${KERNEL_DATA}" | cut -d\; -f1)
          print_output "[+] Found kernel elf file: ${ORANGE}${KERNEL_ELF_PATH}${NC}"
          K_FOUND=1
          break
        fi
      fi
    done

    if [[ "${K_FOUND}" -ne 1 ]]; then
      print_output "[-] No kernel configuration file with matching elf file found for kernel ${ORANGE}${K_VERSION}${NC}."
    fi

    if [[ "${K_FOUND}" -ne 1 ]]; then
      for KERNEL_DATA in "${KERNEL_ELF_EMBA[@]}"; do
        # check for some path indicator for the elf file
        if [[ "$(echo "${KERNEL_DATA}" | cut -d\; -f1)" == "/"* ]]; then
          # now we check for init entries
          if ! [[ "$(echo "${KERNEL_DATA}" | cut -d\; -f2)" == "NA" ]]; then
            KERNEL_ELF_PATH=$(echo "${KERNEL_DATA}" | cut -d\; -f1)
            # we use the first entry with a kernel init detected
            print_output "[+] Found kernel elf file with init entry: ${ORANGE}${KERNEL_ELF_PATH}${NC}"
            K_FOUND=1
            break
          fi
        fi
      done
    fi

    if [[ "${K_FOUND}" -ne 1 ]]; then
      for KERNEL_DATA in "${KERNEL_ELF_EMBA[@]}"; do
        # check for some path indicator for the elf file
        if [[ "$(echo "${KERNEL_DATA}" | cut -d\; -f1)" == "/"* ]]; then
          # this means we have no kernel configuration found
          # and no init entry -> we just use the first valid elf file
          if ! [[ "$(echo "${KERNEL_DATA}" | cut -d\; -f1)" == "NA" ]]; then
            KERNEL_ELF_PATH=$(echo "${KERNEL_DATA}" | cut -d\; -f1)
            print_output "[+] Found kernel elf file: ${ORANGE}${KERNEL_ELF_PATH}${NC}"
            # we use the first entry as final resort
            K_FOUND=1
            break
          fi
        fi
      done
    fi

    if [[ -f "${KERNEL_CONFIG}" ]]; then
      # check if the provided configuration is for the kernel version under test
      if grep -q "${K_VERSION}" "${KERNEL_CONFIG}"; then
        KERNEL_CONFIG_PATH="${KERNEL_CONFIG}"
        print_output "[+] Using provided kernel configuration file: ${ORANGE}${KERNEL_CONFIG_PATH}${NC}"
        K_FOUND=1
      fi
    fi

    if [[ "${K_FOUND}" -ne 1 ]]; then
      print_output "[-] No valid kernel information found for kernel ${ORANGE}${K_VERSION}${NC}."
      continue
    fi

    if ! [[ -f "${KERNEL_ELF_PATH}" ]]; then
      print_output "[-] Warning: Kernel ELF file not found"
      module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
      continue
    fi
    if ! [[ -v K_VERSION ]]; then
      print_output "[-] Missing kernel version .. exit now"
      module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
      continue
    fi

    local CVE_DETAILS_PATH="${LOG_PATH_MODULE}""/linux_kernel_${K_VERSION}.txt"

    if [[ -f "${KERNEL_ELF_PATH}" ]]; then
      extract_kernel_arch "${KERNEL_ELF_PATH}"
    fi

    if [[ "${K_VERSION}" == *".0" ]]; then
      K_VERSION_KORG=${K_VERSION%.0}
    else
      K_VERSION_KORG="${K_VERSION}"
    fi
    # we need to wait for the downloaded linux kernel sources from the host
    local WAIT_CNT=0
    while ! [[ -f "${KERNEL_ARCH_PATH}/linux-${K_VERSION_KORG}.tar.gz" ]]; do
      print_output "[*] Waiting for kernel sources ..." "no_log"
      ((WAIT_CNT+=1))
      if [[ "${WAIT_CNT}" -gt 60 ]] || [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
        print_output "[-] No valid kernel source file available ... check for further kernel versions"
        continue 2
      fi
      sleep 5
    done

    # now we have a file with the kernel sources ... we do not know if this file is complete.
    # Probably it is just downloaded partly and we need to wait a bit longer
    WAIT_CNT=0
    print_output "[*] Testing kernel sources ..." "no_log"
    while ! gunzip -t "${KERNEL_ARCH_PATH}/linux-${K_VERSION_KORG}.tar.gz" 2> /dev/null; do
      print_output "[*] Testing kernel sources ..." "no_log"
      ((WAIT_CNT+=1))
      if [[ "${WAIT_CNT}" -gt 60 ]] || [[ -f "${TMP_DIR}"/linux_download_failed ]]; then
        print_output "[-] No valid kernel source file available ... check for further kernel versions"
        continue 2
      fi
      sleep 5
    done

    print_output "[*] Kernel sources for version ${ORANGE}${K_VERSION}${NC} available"
    write_link "${LOG_DIR}/kernel_downloader.log"

    KERNEL_DIR="${LOG_PATH_MODULE}/linux-${K_VERSION_KORG}"
    [[ -d "${KERNEL_DIR}" ]] && rm -rf "${KERNEL_DIR}"
    if ! [[ -d "${KERNEL_DIR}" ]] && [[ "$(file "${KERNEL_ARCH_PATH}/linux-${K_VERSION_KORG}.tar.gz")" == *"gzip compressed data"* ]]; then
      print_output "[*] Kernel version ${ORANGE}${K_VERSION}${NC} extraction ... "
      tar -xzf "${KERNEL_ARCH_PATH}/linux-${K_VERSION_KORG}.tar.gz" -C "${LOG_PATH_MODULE}"
    fi

    print_output "[*] Kernel version ${ORANGE}${K_VERSION}${NC} CVE detection ... "
    prepare_cve_search_module
    export F20_DEEP=0
    export S26_LOG_DIR="${LOG_DIR}""/s26_kernel_vuln_verifier/"
    export SYMBOLS_CNT=0

    cve_db_lookup_version "linux_kernel:${K_VERSION}"

    if ! [[ -f "${CVE_DETAILS_PATH}" ]]; then
      print_output "[-] No CVE details generated ... check for further kernel version"
      continue
    fi

    print_output "[*] Generate CVE vulnerabilities array for kernel version ${ORANGE}${K_VERSION}${NC} ..." "no_log"
    # mapfile -t ALL_KVULNS < <(jq -rc '"\(.id):\(.cvss):\(.cvss3):\(.summary)"' "${CVE_DETAILS_PATH}")
    mapfile -t ALL_KVULNS < "${CVE_DETAILS_PATH}"
    # readable log file for the web report:
    # jq -rc '"\(.id):\(.cvss):\(.cvss3):\(.summary)"' "${CVE_DETAILS_PATH}" > "${LOG_PATH_MODULE}""/kernel-${K_VERSION}-vulns.log"

    print_ln
    print_output "[+] Extracted ${ORANGE}${#ALL_KVULNS[@]}${GREEN} vulnerabilities based on kernel version only"
    write_link "${LOG_PATH_MODULE}""/kernel-${K_VERSION}-vulns.log"

    if [[ -f "${KERNEL_CONFIG_PATH}" ]] && [[ -d "${KERNEL_DIR}" ]]; then
      compile_kernel "${KERNEL_CONFIG_PATH}" "${KERNEL_DIR}" "${ORIG_K_ARCH}"
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

    print_output "[*] Checking vulnerabilities for kernel version ${ORANGE}${K_VERSION}${NC}" "" "${LOG_PATH_MODULE}/kernel_verification_${K_VERSION}_detailed.log"
    print_ln

    for VULN in "${ALL_KVULNS[@]}"; do
      NEG_LOG=1
      local K_PATHS=()
      local K_PATHS_FILES_TMP=()
      local SUMMARY=""
      K_PATH="missing vulnerability path from advisory"

      CVE=$(echo "${VULN}" | cut -d: -f1)
      local OUTx="[*] Testing vulnerability ${ORANGE}${VULN_CNT}${NC} / ${ORANGE}${#ALL_KVULNS[@]}${NC} / ${ORANGE}${CVE}${NC}"
      print_output "${OUTx}" "no_log"
      write_log "${OUTx}" "${LOG_PATH_MODULE}/kernel_verification_${K_VERSION}_detailed.log"

      CVSS2="$(echo "${VULN}" | cut -d: -f2)"
      CVSS3="$(echo "${VULN}" | cut -d: -f3)"
      SUMMARY="$(echo "${VULN}" | cut -d: -f4-)"
      # print_output "$(indent "CVSSv2: ${ORANGE}${CVSS2}${NC} / CVSSv3: ${ORANGE}${CVSS3}${NC} / Summary: ${ORANGE}${SUMMARY}${NC}")"

      # extract kernel source paths from summary -> we use these paths to check if they are used by our
      # symbols or during kernel compilation
      mapfile -t K_PATHS < <(echo "${SUMMARY}" | tr ' ' '\n' | sed 's/\\$//' | grep ".*\.[chS]$" | sed -r 's/CVE-[0-9]+-[0-9]+:[0-9].*://' \
        | sed -r 's/CVE-[0-9]+-[0-9]+:null.*://' | sed 's/^(//' | sed 's/)$//' | sed 's/,$//' | sed 's/\.$//' | cut -d: -f1 || true)

      for K_PATH in "${K_PATHS[@]}"; do
        # we have only a filename without path -> we search for possible candidate files in the kernel sources
        if ! [[ "${K_PATH}" == *"/"* ]]; then
          OUTx="[*] Found file name ${ORANGE}${K_PATH}${NC} for ${ORANGE}${CVE}${NC} without path details ... looking for candidates now"
          print_output "${OUTx}" "no_log"
          write_log "${OUTx}" "${LOG_PATH_MODULE}/kernel_verification_${K_VERSION}_detailed.log"
          mapfile -t K_PATHS_FILES_TMP < <(find "${KERNEL_DIR}" -name "${K_PATH}" | sed "s&${KERNEL_DIR}\/&&")
        fi
        K_PATHS+=("${K_PATHS_FILES_TMP[@]}")
      done

      if [[ "${#K_PATHS[@]}" -gt 0 ]]; then
        for K_PATH in "${K_PATHS[@]}"; do
          if [[ -f "${KERNEL_DIR}/${K_PATH}" ]]; then
            # check if arch is in path -> if so we check if our architecture is also in the path
            # if we find our architecture then we can proceed with symbol_verifier
            if [[ "${K_PATH}" == "arch/"* ]]; then
              if [[ "${K_PATH}" == "arch/${ORIG_K_ARCH}/"* ]]; then
                ((CNT_PATHS_FOUND+=1))
                if [[ "${SYMBOLS_CNT}" -gt 0 ]]; then
                  symbol_verifier "${CVE}" "${K_VERSION}" "${K_PATH}" "${CVSS2}/${CVSS3}" &
                  WAIT_PIDS_S26+=( "$!" )
                fi
                if [[ "${COMPILE_SOURCE_FILES_VERIFIED}" -gt 0 ]]; then
                  compile_verifier "${CVE}" "${K_VERSION}" "${K_PATH}" "${CVSS2}/${CVSS3}" &
                  WAIT_PIDS_S26+=( "$!" )
                fi
              else
                # this vulnerability is for a different architecture -> we can skip it for our kernel
                OUTx="[-] Vulnerable path for different architecture found for ${ORANGE}${K_PATH}${NC} - not further processing ${ORANGE}${CVE}${NC}"
                print_output "${OUTx}" "no_log"
                write_log "${OUTx}" "${LOG_PATH_MODULE}/kernel_verification_${K_VERSION}_detailed.log"
                ((CNT_PATHS_FOUND_WRONG_ARCH+=1))
              fi
            else
              ((CNT_PATHS_FOUND+=1))
              if [[ "${SYMBOLS_CNT}" -gt 0 ]]; then
                symbol_verifier "${CVE}" "${K_VERSION}" "${K_PATH}" "${CVSS2}/${CVSS3}" &
                WAIT_PIDS_S26+=( "$!" )
              fi
              if [[ "${COMPILE_SOURCE_FILES_VERIFIED}" -gt 0 ]]; then
                compile_verifier "${CVE}" "${K_VERSION}" "${K_PATH}" "${CVSS2}/${CVSS3}" &
                WAIT_PIDS_S26+=( "$!" )
              fi
            fi
          else
            # no source file in our kernel sources -> no vulns
            OUTx="[-] ${ORANGE}${CVE}${NC} - ${ORANGE}${K_PATH}${NC} - vulnerable source file not found in kernel sources"
            print_output "${OUTx}" "no_log"
            write_log "${OUTx}" "${LOG_PATH_MODULE}/kernel_verification_${K_VERSION}_detailed.log"
            ((CNT_PATHS_NOT_FOUND+=1))
          fi
          max_pids_protection 20 "${WAIT_PIDS_S26[@]}"
        done
      else
        OUTx="[-] ${CVE} - ${K_PATH}"
        print_output "${OUTx}" "no_log"
        write_log "${OUTx}" "${LOG_PATH_MODULE}/kernel_verification_${K_VERSION}_detailed.log"
        ((CNT_PATHS_UNK+=1))
      fi
      ((VULN_CNT+=1))
    done

    wait_for_pid "${WAIT_PIDS_S26[@]}"

    final_log_kernel_vulns "${K_VERSION}" "${ALL_KVULNS[@]}"
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
  local CVE="${1:-}"
  local K_VERSION="${2:-}"
  local K_PATH="${3:-}"
  local CVSS="${4:-}"
  local VULN_FOUND=0
  local CHUNK_FILE=""

  for CHUNK_FILE in "${LOG_PATH_MODULE}"/symbols_uniq.split.* ; do
    # echo "testing chunk file $CHUNK_FILE"
    if grep -q -f "${CHUNK_FILE}" "${KERNEL_DIR}/${K_PATH}" ; then
      # echo "verified chunk file $CHUNK_FILE"
      local OUTx="[+] ${ORANGE}${CVE}${GREEN} (${ORANGE}${CVSS}${GREEN}) - ${ORANGE}${K_PATH}${GREEN} verified - exported symbol${NC}"
      print_output "${OUTx}"
      write_log "${OUTx}" "${LOG_PATH_MODULE}/kernel_verification_${K_VERSION}_detailed.log"
      echo "${CVE} (${CVSS}) - ${K_VERSION} - exported symbol verified - ${K_PATH}" >> "${LOG_PATH_MODULE}""/${CVE}_symbol_verified.txt"
      VULN_FOUND=1
      break
    fi
  done

  # if we have already a match for this path we can skip the 2nd check
  # this is only for speed up the process a bit
  [[ "${VULN_FOUND}" -eq 1 ]] && return

  for CHUNK_FILE in "${LOG_PATH_MODULE}"/symbols_uniq.split_gpl.* ; do
    # echo "testing chunk file $CHUNK_FILE"
    if grep -q -f "${CHUNK_FILE}" "${KERNEL_DIR}/${K_PATH}" ; then
      # print_output "[*] verified chunk file $CHUNK_FILE (GPL)"
      local OUTx="[+] ${ORANGE}${CVE}${GREEN} (${ORANGE}${CVSS}${GREEN}) - ${ORANGE}${K_PATH}${GREEN} verified - exported symbol (GPL)${NC}"
      print_output "${OUTx}"
      write_log "${OUTx}" "${LOG_PATH_MODULE}/kernel_verification_${K_VERSION}_detailed.log"
      echo "${CVE} (${CVSS}) - ${K_VERSION} - exported symbol verified (gpl) - ${K_PATH}" >> "${LOG_PATH_MODULE}""/${CVE}_symbol_verified.txt"
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
  if ! [[ -f "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log ]]; then
    return
  fi

  if grep -q "${K_PATH}" "${LOG_PATH_MODULE}"/kernel-compile-files_verified.log ; then
    print_output "[+] ${ORANGE}${CVE_}${GREEN} (${ORANGE}${CVSS}${GREEN}) - ${ORANGE}${K_PATH}${GREEN} verified - compiled path${NC}"
    echo "${CVE_} (${CVSS}) - ${K_VERSION} - compiled path verified - ${K_PATH}" >> "${LOG_PATH_MODULE}""/${CVE_}_compiled_verified.txt"
  fi
}

compile_kernel() {
  # this is based on the great work shown here https://arxiv.org/pdf/2209.05217.pdf
  local KERNEL_CONFIG_FILE="${1:-}"
  local KERNEL_DIR="${2:-}"
  local KARCH="${3:-}"
  # KARCH=$(echo "${KARCH}" | tr '[:upper:]' '[:lower:]')
  KARCH="${KARCH,,}"
  export COMPILE_SOURCE_FILES=0
  export COMPILE_SOURCE_FILES_VERIFIED=0

  if ! [[ -f "${KERNEL_CONFIG_FILE}" ]]; then
    print_output "[-] No supported kernel config found - ${ORANGE}${KERNEL_CONFIG_FILE}${NC}"
    return
  fi
  if ! [[ -d "${KERNEL_DIR}" ]]; then
    print_output "[-] No supported kernel source directory found - ${ORANGE}${KERNEL_DIR}${NC}"
    return
  fi
  print_ln
  sub_module_title "Compile Linux kernel - dry run mode"

  if ! [[ -d "${KERNEL_DIR}"/arch/"${KARCH}" ]]; then
    print_output "[!] No supported architecture found - ${ORANGE}${KARCH}${NC}"
    return
  else
    print_output "[*] Supported architecture found - ${ORANGE}${KARCH}${NC}"
  fi

  cd "${KERNEL_DIR}" || exit
  # print_output "[*] Create default kernel config for $ORANGE$KARCH$NC architecture"
  # LANG=en make ARCH="${KARCH}" defconfig | tee -a "${LOG_PATH_MODULE}"/kernel-compile-defconfig.log || true
  # print_output "[*] Finished creating default kernel config for $ORANGE$KARCH$NC architecture" "" "$LOG_PATH_MODULE/kernel-compile-defconfig.log"
  print_ln

  print_output "[*] Install kernel config of the identified configuration of the firmware"
  cp "${KERNEL_CONFIG_FILE}" .config
  # https://stackoverflow.com/questions/4178526/what-does-make-oldconfig-do-exactly-in-the-linux-kernel-makefile
  local LANG=""
  LANG=en make ARCH="${KARCH}" olddefconfig | tee -a "${LOG_PATH_MODULE}"/kernel-compile-olddefconfig.log || true
  print_output "[*] Finished updating kernel config with the identified firmware configuration" "" "${LOG_PATH_MODULE}/kernel-compile-olddefconfig.log"
  print_ln

  print_output "[*] Starting kernel compile dry run ..."
  LANG=en make ARCH="${KARCH}" target=all -Bndi | tee -a "${LOG_PATH_MODULE}"/kernel-compile.log
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
      if [[ -f "${KERNEL_DIR}""/""${COMPILE_SOURCE_FILE}" ]]; then
        # print_output "[*] Verified Source file $ORANGE$KERNEL_DIR/$COMPILE_SOURCE_FILE$NC is available"
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
  local VULN="${1:-}"
  local CVE=""
  local CVSS2=""
  local CVSS3=""
  local CVE_SYMBOL_FOUND=0
  local CVE_COMPILE_FOUND=0
  local CVE_SYMBOL_FOUND=0
  local CVE_COMPILE_FOUND=0

  CVE=$(echo "${VULN}" | cut -d: -f1)
  CVSS2="$(echo "${VULN}" | cut -d: -f2)"
  CVSS3="$(echo "${VULN}" | cut -d: -f3)"
  CVE_SYMBOL_FOUND=$(find "${LOG_PATH_MODULE}" -name "${CVE}_symbol_verified.txt" | wc -l)
  CVE_COMPILE_FOUND=$(find "${LOG_PATH_MODULE}" -name "${CVE}_compiled_verified.txt" | wc -l)
  echo "${K_VERSION};${ORIG_K_ARCH};${CVE};${CVSS2};${CVSS3};${CVE_SYMBOL_FOUND};${CVE_COMPILE_FOUND}" >> "${LOG_PATH_MODULE}"/cve_results_kernel_"${K_VERSION}".csv
}

final_log_kernel_vulns() {
  sub_module_title "Linux kernel verification results"
  local K_VERSION="${1:-}"
  shift
  local ALL_KVULNS=("$@")

  if ! [[ -v ALL_KVULNS ]]; then
    print_output "[-] No module results"
    return
  fi

  find "${LOG_PATH_MODULE}" -name "symbols_uniq.split.*" -delete || true
  find "${LOG_PATH_MODULE}" -name "symbols_uniq.split_gpl.*" -delete || true

  NEG_LOG=1

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
  local CVE_VERIFIED_ONE_CRITICAL_=""
  local CVE_VERIFIED_OVERLAP_CRITICAL_=()
  local CVE_CRITICAL=""
  local CVSS2_CRITICAL=""
  local CVSS3_CRITICAL=""
  local WAIT_PIDS_S26_1=()

  print_output "[*] Generating final kernel report ..." "no_log"
  echo "Kernel version;Architecture;CVE;CVSSv2;CVSSv3;Verified with symbols;Verified with compile files" >> "${LOG_PATH_MODULE}"/cve_results_kernel_"${K_VERSION}".csv

  if [[ -f "${LOG_PATH_MODULE}/kernel_cve_version_issues.log" ]]; then
    print_output "[*] Multiple possible version mismatches identified and reported."
    write_link "${LOG_PATH_MODULE}/kernel_cve_version_issues.log"
  fi
  # we walk through the original version based kernel vulnerabilities and report the results
  # from symbols and kernel configuration
  for VULN in "${ALL_KVULNS[@]}"; do
    if [[ "${THREADED}" -eq 1 ]]; then
      report_kvulns_csv "${VULN}" &
      local TMP_PID="$!"
      WAIT_PIDS_S26_1+=( "${TMP_PID}" )
      max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_S26_1[@]}"
    else
      report_kvulns_csv "${VULN}"
    fi
  done

  SYM_USAGE_VERIFIED=$(wc -l "${LOG_PATH_MODULE}"/CVE-*symbol_* 2>/dev/null | tail -1 | awk '{print $1}' 2>/dev/null || true)
  # nosemgrep
  VULN_PATHS_VERIFIED_SYMBOLS=$(cat "${LOG_PATH_MODULE}"/CVE-*symbol_verified.txt 2>/dev/null | grep "exported symbol" | sed 's/.*verified - //' | sed 's/.*verified (GPL) - //' | sort -u | wc -l || true)
  # nosemgrep
  VULN_PATHS_VERIFIED_COMPILED=$(cat "${LOG_PATH_MODULE}"/CVE-*compiled_verified.txt 2>/dev/null | grep "compiled path verified" | sed 's/.*verified - //' | sort -u | wc -l || true)
  # nosemgrep
  CVE_VERIFIED_SYMBOLS=$(cat "${LOG_PATH_MODULE}"/CVE-*symbol_verified.txt 2>/dev/null | grep "exported symbol" | cut -d\  -f1 | sort -u | wc -l || true)
  # nosemgrep
  CVE_VERIFIED_COMPILED=$(cat "${LOG_PATH_MODULE}"/CVE-*compiled_verified.txt 2>/dev/null| grep "compiled path verified" | cut -d\  -f1 | sort -u | wc -l || true)

  print_output "[+] Identified ${ORANGE}${#ALL_KVULNS[@]}${GREEN} unverified CVE vulnerabilities for kernel version ${ORANGE}${K_VERSION}${NC}"
  write_link "${LOG_PATH_MODULE}/cve_results_kernel_${K_VERSION}.csv"
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
  print_output "[*] ${ORANGE}${SYM_USAGE_VERIFIED}${NC} symbol usage verified"
  print_output "[*] ${ORANGE}${VULN_PATHS_VERIFIED_SYMBOLS}${NC} vulnerable paths verified via symbols"
  print_output "[*] ${ORANGE}${VULN_PATHS_VERIFIED_COMPILED}${NC} vulnerable paths verified via compiled paths"
  print_ln

  # we need to wait for the cve_results_kernel_"${K_VERSION}".csv
  [[ ${THREADED} -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S26_1[@]}"

  CVE_VERIFIED_ONE=$(cut -d\; -f6-7 "${LOG_PATH_MODULE}"/cve_results_kernel_"${K_VERSION}".csv | grep -c "1" || true)
  CVE_VERIFIED_OVERLAP=$(grep -c ";1;1" "${LOG_PATH_MODULE}"/cve_results_kernel_"${K_VERSION}".csv || true)
  mapfile -t CVE_VERIFIED_OVERLAP_CRITICAL < <(grep ";1;1$" "${LOG_PATH_MODULE}"/cve_results_kernel_"${K_VERSION}".csv | grep ";9.[0-9];\|;10;" || true)
  mapfile -t CVE_VERIFIED_ONE_CRITICAL < <(grep ";1;\|;1$" "${LOG_PATH_MODULE}"/cve_results_kernel_"${K_VERSION}".csv | grep ";9.[0-9];\|;10;" || true)

  if [[ "${CVE_VERIFIED_SYMBOLS}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${CVE_VERIFIED_SYMBOLS}${GREEN} (exported symbols)"
  fi
  if [[ "${CVE_VERIFIED_COMPILED}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${CVE_VERIFIED_COMPILED}${GREEN} (compiled paths)"
  fi
  if [[ "${CVE_VERIFIED_ONE}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${CVE_VERIFIED_ONE}${GREEN} (one mechanism succeeded)"
  fi
  if [[ "${CVE_VERIFIED_OVERLAP}" -gt 0 ]]; then
    print_output "[+] Verified CVEs: ${ORANGE}${CVE_VERIFIED_OVERLAP}${GREEN} (both mechanisms overlap)"
  fi

  if [[ "${#CVE_VERIFIED_ONE_CRITICAL[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Verified CRITICAL CVEs: ${ORANGE}${#CVE_VERIFIED_ONE_CRITICAL[@]}${GREEN} (one mechanism succeeded)"
    for CVE_VERIFIED_ONE_CRITICAL_ in "${CVE_VERIFIED_ONE_CRITICAL[@]}"; do
      CVE_CRITICAL=$(echo "${CVE_VERIFIED_ONE_CRITICAL_}" | cut -d\; -f3)
      CVSS2_CRITICAL=$(echo "${CVE_VERIFIED_ONE_CRITICAL_}" | cut -d\; -f4)
      CVSS3_CRITICAL=$(echo "${CVE_VERIFIED_ONE_CRITICAL_}" | cut -d\; -f5)
      # disabled because it is too slow
      # identify_exploits "${CVE_CRITICAL}"
      if [[ "${EXPLOIT_DETECTED:-"no"}" == "yes" ]] || [[ "${POC_DETECTED:-"no"}" == "yes" ]]; then
        print_output "$(indent "$(orange "${ORANGE}${CVE_CRITICAL}${GREEN}\t-\t${ORANGE}${CVSS2_CRITICAL}${GREEN} / ${ORANGE}${CVSS3_CRITICAL}${GREEN}\t-\tExploit/PoC: ${ORANGE}${EXPLOIT_DETECTED} ${EXP} / ${POC_DETECTED} ${POC}${NC}")")"
      else
        print_output "$(indent "$(orange "${ORANGE}${CVE_CRITICAL}${GREEN}\t-\t${ORANGE}${CVSS2_CRITICAL}${GREEN} / ${ORANGE}${CVSS3_CRITICAL}${GREEN}")")"
      fi
    done
  fi

  if [[ "${#CVE_VERIFIED_OVERLAP_CRITICAL[@]}" -gt 0 ]]; then
    print_ln
    print_output "[+] Verified CRITICAL CVEs: ${ORANGE}${#CVE_VERIFIED_OVERLAP_CRITICAL[@]}${GREEN} (both mechanisms overlap)"
    for CVE_VERIFIED_OVERLAP_CRITICAL_ in "${CVE_VERIFIED_OVERLAP_CRITICAL[@]}"; do
      CVE_CRITICAL=$(echo "${CVE_VERIFIED_OVERLAP_CRITICAL_}" | cut -d\; -f3)
      CVSS2_CRITICAL=$(echo "${CVE_VERIFIED_OVERLAP_CRITICAL_}" | cut -d\; -f4)
      CVSS3_CRITICAL=$(echo "${CVE_VERIFIED_OVERLAP_CRITICAL_}" | cut -d\; -f5)
      # disabled because it is too slow
      # identify_exploits "${CVE_CRITICAL}"
      if [[ "${EXPLOIT_DETECTED:-"no"}" == "yes" ]] || [[ "${POC_DETECTED:-"no"}" == "yes" ]]; then
        print_output "$(indent "$(orange "${ORANGE}${CVE_CRITICAL}${GREEN}\t-\t${ORANGE}${CVSS2_CRITICAL}${GREEN} / ${ORANGE}${CVSS3_CRITICAL}${GREEN}\t-\tExploit/PoC: ${ORANGE}${EXPLOIT_DETECTED} ${EXP} / ${POC_DETECTED} ${POC}${NC}")")"
      else
        print_output "$(indent "$(orange "${ORANGE}${CVE_CRITICAL}${GREEN}\t-\t${ORANGE}${CVSS2_CRITICAL}${GREEN} / ${ORANGE}${CVSS3_CRITICAL}${GREEN}")")"
      fi
    done
  fi
  write_log "[*] Statistics:${K_VERSION}:${#ALL_KVULNS[@]}:${CVE_VERIFIED_SYMBOLS}:${CVE_VERIFIED_COMPILED}"
}

identify_exploits() {
  local CVE_VALUE="${1:-}"
  export EXPLOIT_DETECTED="no"
  export POC_DETECTED="no"
  export POC=""
  export EXP=""

  if command -v cve_searchsploit >/dev/null; then
    if cve_searchsploit "${CVE_VALUE}" 2>/dev/null | grep -q "Exploit DB Id:"; then
      EXPLOIT_DETECTED="yes"
      EXP="(EDB)"
    fi
  fi
  if [[ -f "${MSF_DB_PATH}" ]]; then
    if grep -q -E "${CVE_VALUE}"$ "${MSF_DB_PATH}"; then
      EXPLOIT_DETECTED="yes"
      EXP="${EXP}(MSF)"
    fi
  fi
  if [[ -f "${KNOWN_EXP_CSV}" ]]; then
    if grep -q \""${CVE_VALUE}"\", "${KNOWN_EXP_CSV}"; then
      EXPLOIT_DETECTED="yes"
      EXP="${EXP}(KNOWN)"
    fi
  fi
  if [[ -f "${CONFIG_DIR}/Snyk_PoC_results.csv" ]]; then
    if grep -q -E "^${CVE_VALUE};" "${CONFIG_DIR}/Snyk_PoC_results.csv"; then
      POC_DETECTED="yes"
      POC="${POC}(SNYK)"
    fi
  fi
  if [[ -f "${CONFIG_DIR}/PS_PoC_results.csv" ]]; then
    if grep -q -E "^${CVE_VALUE};" "${CONFIG_DIR}/PS_PoC_results.csv"; then
      POC_DETECTED="yes"
      POC="${POC}(PS)"
    fi
  fi
}

get_csv_data_s24() {
  local S24_CSV_LOG="${1:-}"

  if ! [[ -f "${S24_CSV_LOG}" ]];then
    print_output "[-] No EMBA log found ..."
    return
  fi

  export K_VERSIONS=()

  # currently we only support one kernel version
  # if we detect multiple kernel versions we only process the first one after sorting
  mapfile -t K_VERSIONS < <(cut -d\; -f2 "${S24_CSV_LOG}" | tail -n +2 | grep -v "NA" | sort -u)
}
