#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Benedikt Kuehne

# Description: Multiple useful helpers used to access online resources


# kernel downloader waits for s24 results. If we were able to identify a kernel version,
# a kernel config or at least kernel symbols we can use these details to verify the
# vulnerabilities which we identified based on the kernel version
kernel_downloader() {
  local lKERNEL_ARCH_PATH="${EXT_DIR}"/linux_kernel_sources/
  local LOG_PATH_MODULE="${LOG_DIR}/s24_kernel_bin_identifier"
  local LOG_FILE="${LOG_PATH_MODULE}/kernel_downloader.log"

  if ! [[ -d "${lKERNEL_ARCH_PATH}" ]]; then
    mkdir "${lKERNEL_ARCH_PATH}"
  fi

  # we wait until the s24 module is finished and hopefully shows us a kernel version
  while ! [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; do
    sleep 1
    if check_emba_ended; then
      # as this is a threaded fct we can just exit it.
      exit
    fi
  done
  if [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; then
    while [[ $(grep -c S24_kernel_bin_identifier "${LOG_DIR}"/"${MAIN_LOG_FILE}") -lt 2 ]]; do
      sleep 1
      if check_emba_ended; then
        # as this is a threaded fct we can just exit it.
        exit
      fi
    done
  fi

  if ! [[ -d "${LOG_PATH_MODULE}" ]]; then
    mkdir "${LOG_PATH_MODULE}"
  fi
  # now we should have a csv log with a kernel version:
  if ! [[ -f "${S24_CSV_LOG}" ]]; then
    print_output "[-] $(print_date) - No Kernel version identified ... exit kernel downloader process"
    return
  fi
  print_output "[*] $(print_date) - Kernel downloader running ..."
  local lK_VERSIONS_ARR=()
  local lK_VERSION=""

  mapfile -t lK_VERSIONS_ARR < <(cut -d\; -f2 "${S24_CSV_LOG}" | sort -u | grep -E "[0-9]+(\.[0-9]+)+?" || true)
  print_output "[*] $(print_date) - Detected kernel details:"
  mapfile -t lKERNEL_DETAILS_TMP_ARR < "${S24_CSV_LOG}"
  for lKERNEL_DETAILS_TMP_ENTRY in "${lKERNEL_DETAILS_TMP_ARR[@]}"; do
    local lKERNEL_DETAILS_TMP_FILE=""
    local lKERNEL_DETAILS_TMP_VERSION=""
    local lKERNEL_DETAILS_TMP_ARCH=""
    local lKERNEL_DETAILS_TMP_END=""

    lKERNEL_DETAILS_TMP_FILE=$(echo "${lKERNEL_DETAILS_TMP_ENTRY}" | cut -d ';' -f1)
    lKERNEL_DETAILS_TMP_VERSION=$(echo "${lKERNEL_DETAILS_TMP_ENTRY}" | cut -d ';' -f2)
    lKERNEL_DETAILS_TMP_ARCH=$(echo "${lKERNEL_DETAILS_TMP_ENTRY}" | cut -d ';' -f7)
    lKERNEL_DETAILS_TMP_END=$(echo "${lKERNEL_DETAILS_TMP_ENTRY}" | cut -d ';' -f8)
    if [[ -z "${lKERNEL_DETAILS_TMP_VERSION}" ]]; then
      continue
    fi
    print_output "$(indent "$(orange "${lKERNEL_DETAILS_TMP_FILE} - ${lKERNEL_DETAILS_TMP_VERSION} - ${lKERNEL_DETAILS_TMP_ARCH}-${lKERNEL_DETAILS_TMP_END}")")"
  done

  for lK_VERSION in "${lK_VERSIONS_ARR[@]}"; do
    print_output "[*] $(print_date) - Checking download of kernel version ${ORANGE}${lK_VERSION}${NC}"
    local lK_VER_DOWNLOAD=""
    local lK_VER_1st=""
    local lK_VER_2nd=""
    # local K_VER_3rd=""

    lK_VER_1st=$(echo "${lK_VERSION}" | cut -d. -f1)
    lK_VER_2nd=$(echo "${lK_VERSION}" | cut -d. -f2)
    # K_VER_3rd=$(echo "${lK_VERSION}" | cut -d. -f3)

    # prepare the path in the URL:
    if [[ "${lK_VER_1st}" -lt 3 ]]; then
      lK_VER_DOWNLOAD="${lK_VER_1st}"".""${lK_VER_2nd}"
    elif [[ "${lK_VER_1st}" -eq 3 && "${lK_VER_2nd}" -eq 0 ]]; then
      lK_VER_DOWNLOAD="${lK_VER_1st}"".""${lK_VER_2nd}"
    else
      lK_VER_DOWNLOAD="${lK_VER_1st}"".x"
    fi

    # prepare the download filename:
    if [[ "${lK_VERSION}" == *".0" ]]; then
      # for download we need to modify versions like 3.1.0 to 3.1
      lK_VERSION=${lK_VERSION%.0}
    fi

    # we check if the sources archive is already available and is a valid tgz file:
    if ! [[ -f "${lKERNEL_ARCH_PATH}"/linux-"${lK_VERSION}".tar.gz ]] || ! gunzip -t "${lKERNEL_ARCH_PATH}/linux-${lK_VERSION}.tar.gz" > /dev/null; then
      print_output "[*] $(print_date) - Kernel download for version ${ORANGE}${lK_VERSION}${NC}"

      if ! [[ -d "${TMP_DIR}" ]]; then
        mkdir "${TMP_DIR}"
      fi

      disable_strict_mode "${STRICT_MODE}" 0
      wget -q --output-file="${TMP_DIR}"/wget.log https://mirrors.edge.kernel.org/pub/linux/kernel/v"${lK_VER_DOWNLOAD}"/linux-"${lK_VERSION}".tar.gz -O "${lKERNEL_ARCH_PATH}"/linux-"${lK_VERSION}".tar.gz
      local lD_RETURN="$?"
      enable_strict_mode "${STRICT_MODE}" 0

      if [[ -f "${TMP_DIR}"/wget.log ]]; then
        tee -a "${LOG_FILE}" < "${TMP_DIR}"/wget.log || true
        rm "${TMP_DIR}"/wget.log
      fi
      # if we have a non zero return something failed and we need to communicate this to the container modules (s26) which
      # checks for the file "${TMP_DIR}"/linux_download_failed. If this file is available it stops waiting for the kernel
      # sources
      if [[ ${lD_RETURN} -ne 0 ]] ; then
        print_output "[-] $(print_date) - Kernel download for version ${ORANGE}${lK_VERSION}${NC} failed"

        echo "failed" > "${TMP_DIR}"/linux_download_failed
        if [[ -f "${lKERNEL_ARCH_PATH}"/linux-"${lK_VERSION}".tar.gz ]]; then
          rm "${lKERNEL_ARCH_PATH}"/linux-"${lK_VERSION}".tar.gz
        fi
      fi
    else
      print_output "[*] $(print_date) - Kernel sources of version ${ORANGE}${lK_VERSION}${NC} already available"
    fi

    if ! [[ -f "${lKERNEL_ARCH_PATH}"/linux-"${lK_VERSION}".tar.gz ]]; then
      print_output "[-] $(print_date) - Kernel sources not available ..."
      continue
    fi
    if ! file "${lKERNEL_ARCH_PATH}"/linux-"${lK_VERSION}".tar.gz | grep -q "gzip compressed data"; then
      print_output "[-] $(print_date) - Kernel sources not available ..."
      continue
    fi
    print_output "[*] $(print_date) - Kernel source for version ${ORANGE}${lK_VERSION}${NC} stored in ${ORANGE}${lKERNEL_ARCH_PATH}${NC}"
  done
}
