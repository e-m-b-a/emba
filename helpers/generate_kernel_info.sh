#!/bin/bash -p
# see: https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html#//apple_ref/doc/uid/TP40004268-CH8-SW29

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2024-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner
# Based on the original idea from Thomas Riedmaier

# Description:  Update script for kernel details

if ! [[ -d "./helpers" ]]; then
  echo "[-] WARNING: Please start this script from the EMBA base directory"
  exit 1
fi

source ./helpers/helpers_emba_print.sh

KERNEL_RELEASES_URL="https://mirrors.edge.kernel.org/pub/linux/kernel/"
KERNEL_RELEASES_FILE="/tmp/kernel_releases.log"
KERNEL_OUTPUT_CSV="./config/kernel_details.csv"

curl -s "${KERNEL_RELEASES_URL}" > "${KERNEL_RELEASES_FILE}"

if ! [[ -f "${KERNEL_RELEASES_FILE}" ]]; then
  print_output "[-] Error downloading ${KERNEL_RELEASES_FILE}" "no_log"
  exit 1
fi

[[ -f "${KERNEL_OUTPUT_CSV}" ]] && rm "${KERNEL_OUTPUT_CSV}"

# get initial site with sub directories per kernel version
mapfile -t KERNEL_SUB_DIR_ARR < <(grep "a href=\"v[0-9]\." "${KERNEL_RELEASES_FILE}")

# extracting all sub directories and store the kernel version data and release date
for KERNEL_SUB_DIR in "${KERNEL_SUB_DIR_ARR[@]}"; do
  KERNEL_SUB_DIR=${KERNEL_SUB_DIR/<a href=\"}
  KERNEL_SUB_DIR=${KERNEL_SUB_DIR/\">v*}
  print_output "[*] Testing kernel sub dir: ${ORANGE}${KERNEL_SUB_DIR}${NC}" "no_log"
  curl -s "${KERNEL_RELEASES_URL}""${KERNEL_SUB_DIR}" >> "${KERNEL_RELEASES_FILE}"
done

# extract kernel versions and release dates:
mapfile -t KERNEL_VER_ARR < <(grep "<a href=\"linux-[0-9].*.tar.gz" "${KERNEL_RELEASES_FILE}")

for KERNEL_ENTRY in "${KERNEL_VER_ARR[@]}"; do
  KERNEL_VER=${KERNEL_ENTRY/*\">}
  KERNEL_VER=${KERNEL_VER/.tar.gz*}
  KERNEL_RELEASE=${KERNEL_ENTRY/*<\/a>}
  KERNEL_RELEASE=$(echo "${KERNEL_RELEASE}" | awk '{print $1}')
  print_output "[*] Kernel version: ${ORANGE}${KERNEL_VER}${NC} / release date: ${ORANGE}${KERNEL_RELEASE}${NC}" "no_log"
  echo "${KERNEL_VER};${KERNEL_RELEASE}" >> "${KERNEL_OUTPUT_CSV}"
done

[[ -f "${KERNEL_RELEASES_FILE}" ]] && rm "${KERNEL_RELEASES_FILE}"
