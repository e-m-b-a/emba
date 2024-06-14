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
# Author(s): Michael Messner, Benedikt Kuehne

# Description: Multiple useful helpers used to access online resources


# kernel downloader waits for s24 results. If we were able to identify a kernel version,
# a kernel config or at least kernel symbols we can use these details to verify the
# vulnerabilities which we identified based on the kernel version
kernel_downloader() {
  local LOG_FILE_KERNEL="${CSV_DIR}"/s24_kernel_bin_identifier.csv
  local KERNEL_ARCH_PATH="${EXT_DIR}"/linux_kernel_sources/
  local OUTPUTTER=""

  if ! [[ -d "${KERNEL_ARCH_PATH}" ]]; then
    mkdir "${KERNEL_ARCH_PATH}"
  fi

  # we wait until the s24 module is finished and hopefully shows us a kernel version
  while ! [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; do
    sleep 1
  done
  if [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]]; then
    while [[ $(grep -c S24_kernel_bin_identifier "${LOG_DIR}"/"${MAIN_LOG_FILE}") -lt 2 ]]; do
      sleep 1
    done
  fi

  if ! [[ -d "${LOG_DIR}/s24_kernel_bin_identifier" ]]; then
    mkdir "${LOG_DIR}/s24_kernel_bin_identifier"
  fi
  # now we should have a csv log with a kernel version:
  if ! [[ -f "${LOG_FILE_KERNEL}" ]]; then
    OUTPUTTER="[-] $(print_date) - No Kernel version identified ..."
    print_output "${OUTPUTTER}" "no_log"
    write_log "${OUTPUTTER}" "${LOG_DIR}/s24_kernel_bin_identifier/kernel_downloader.log"
    return
  fi
  local K_VERSIONS=()
  local K_VERSION=""

  mapfile -t K_VERSIONS < <(cut -d\; -f2 "${LOG_FILE_KERNEL}" | tail -n +2 | sort -u | grep -E "[0-9]+(\.[0-9]+)+?" || true)

  for K_VERSION in "${K_VERSIONS[@]}"; do
    OUTPUTTER="[*] $(print_date) - Checking download of kernel version ${ORANGE}${K_VERSION}${NC}"
    print_output "${OUTPUTTER}" "no_log"
    write_log "${OUTPUTTER}" "${LOG_DIR}/s24_kernel_bin_identifier/kernel_downloader.log"
    local K_VER_DOWNLOAD=""
    local K_VER_1st=""
    local K_VER_2nd=""
    # local K_VER_3rd=""

    K_VER_1st=$(echo "${K_VERSION}" | cut -d. -f1)
    K_VER_2nd=$(echo "${K_VERSION}" | cut -d. -f2)
    # K_VER_3rd=$(echo "${K_VERSION}" | cut -d. -f3)

    # prepare the path in the URL:
    if [[ "${K_VER_1st}" -lt 3 ]]; then
      K_VER_DOWNLOAD="${K_VER_1st}"".""${K_VER_2nd}"
    elif [[ "${K_VER_1st}" -eq 3 && "${K_VER_2nd}" -eq 0 ]]; then
      K_VER_DOWNLOAD="${K_VER_1st}"".""${K_VER_2nd}"
    else
      K_VER_DOWNLOAD="${K_VER_1st}"".x"
    fi

    # prepare the download filename:
    if [[ "${K_VERSION}" == *".0" ]]; then
      # for download we need to modify versions like 3.1.0 to 3.1
      K_VERSION=${K_VERSION%.0}
    fi

    # we check if the sources archive is already available and is a valid tgz file:
    if ! [[ -f "${KERNEL_ARCH_PATH}"/linux-"${K_VERSION}".tar.gz ]] || ! gunzip -t "${KERNEL_ARCH_PATH}/linux-${K_VERSION}.tar.gz" > /dev/null; then
      OUTPUTTER="[*] $(print_date) - Kernel download for version ${ORANGE}${K_VERSION}${NC}"
      print_output "${OUTPUTTER}" "no_log"
      write_log "${OUTPUTTER}" "${LOG_DIR}/s24_kernel_bin_identifier/kernel_downloader.log"

      if ! [[ -d "${TMP_DIR}" ]]; then
        mkdir "${TMP_DIR}"
      fi

      disable_strict_mode "${STRICT_MODE}" 0
      wget -q --output-file="${TMP_DIR}"/wget.log https://mirrors.edge.kernel.org/pub/linux/kernel/v"${K_VER_DOWNLOAD}"/linux-"${K_VERSION}".tar.gz -O "${KERNEL_ARCH_PATH}"/linux-"${K_VERSION}".tar.gz
      local lD_RETURN="$?"
      enable_strict_mode "${STRICT_MODE}" 0

      if [[ -f "${TMP_DIR}"/wget.log ]]; then
        tee -a "${LOG_DIR}/s24_kernel_bin_identifier/kernel_downloader.log" < "${TMP_DIR}"/wget.log || true
        rm "${TMP_DIR}"/wget.log
      fi
      # if we have a non zero return something failed and we need to communicate this to the container modules (s26) which
      # checks for the file "${TMP_DIR}"/linux_download_failed. If this file is available it stops waiting for the kernel
      # sources
      if [[ ${lD_RETURN} -ne 0 ]] ; then
        OUTPUTTER="[-] $(print_date) - Kernel download for version ${ORANGE}${K_VERSION}${NC} failed"
        print_output "${OUTPUTTER}" "no_log"
        write_log "${OUTPUTTER}" "${LOG_DIR}/s24_kernel_bin_identifier/kernel_downloader.log"

        echo "failed" > "${TMP_DIR}"/linux_download_failed
        if [[ -f "${KERNEL_ARCH_PATH}"/linux-"${K_VERSION}".tar.gz ]]; then
          rm "${KERNEL_ARCH_PATH}"/linux-"${K_VERSION}".tar.gz
        fi
      fi
    else
      OUTPUTTER="[*] $(print_date) - Kernel sources of version ${ORANGE}${K_VERSION}${NC} already available"
      print_output "${OUTPUTTER}" "no_log"
      write_log "${OUTPUTTER}" "${LOG_DIR}/s24_kernel_bin_identifier/kernel_downloader.log"
    fi

    if ! [[ -f "${KERNEL_ARCH_PATH}"/linux-"${K_VERSION}".tar.gz ]]; then
      OUTPUTTER="[-] $(print_date) - Kernel sources not available ..."
      print_output "${OUTPUTTER}" "no_log"
      write_log "${OUTPUTTER}" "${LOG_DIR}/s24_kernel_bin_identifier/kernel_downloader.log"
      continue
    fi
    if ! file "${KERNEL_ARCH_PATH}"/linux-"${K_VERSION}".tar.gz | grep -q "gzip compressed data"; then
      OUTPUTTER="[-] $(print_date) - Kernel sources not available ..."
      print_output "${OUTPUTTER}" "no_log"
      write_log "${OUTPUTTER}" "${LOG_DIR}/s24_kernel_bin_identifier/kernel_downloader.log"
      continue
    fi
    OUTPUTTER="[*] $(print_date) - Kernel source for version ${ORANGE}${K_VERSION}${NC} stored in ${ORANGE}${KERNEL_ARCH_PATH}${NC}"
    print_output "${OUTPUTTER}" "no_log"
    write_log "${OUTPUTTER}" "${LOG_DIR}/s24_kernel_bin_identifier/kernel_downloader.log"
  done
}
