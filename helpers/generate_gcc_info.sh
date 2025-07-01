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

# Description:  Update script for GCC details

if ! [[ -d "./helpers" ]]; then
  echo "[-] WARNING: Please start this script from the EMBA base directory"
  exit 1
fi

source ./helpers/helpers_emba_print.sh

# download urls:
GCC_RELEASES_HTML="https://gcc.gnu.org/releases.html"

# local temp files
GCC_RELEASES_FILE="/tmp/gcc_releases.html"

# final EMBA csv config file
GCC_OUTPUT_CSV="./config/gcc_details.csv"

curl -sf "${GCC_RELEASES_HTML}" > "${GCC_RELEASES_FILE}"

if ! [[ -f "${GCC_RELEASES_FILE}" ]]; then
  print_output "[-] Error downloading ${GCC_RELEASES_FILE}" "no_log"
  exit 1
fi

[[ -f "${GCC_OUTPUT_CSV}" ]] && rm "${GCC_OUTPUT_CSV}"

mapfile -t GCC_RELEASES_ARR < <(grep "<tr><td>.*GCC [0-9].*</td></tr>" "${GCC_RELEASES_FILE}")

for GCC_ENTRY in "${GCC_RELEASES_ARR[@]}"; do
  print_output "[*] Testing GCC matching entry: ${ORANGE}${GCC_ENTRY}${NC}" "no_log"
  GCC_VERSION=${GCC_ENTRY/<tr><td><a href=\"*\">GCC/GCC}
  GCC_RELEASE_DATE="${GCC_VERSION/*<td>}"
  GCC_VERSION=${GCC_VERSION/<\/a><\/td>*}
  GCC_RELEASE_DATE=${GCC_RELEASE_DATE/<\/td><\/tr>}

  print_output "[*] GCC version: ${GCC_VERSION} / GCC release date: ${GCC_RELEASE_DATE}" "no_log"
  echo "${GCC_VERSION};${GCC_RELEASE_DATE}" >> "${GCC_OUTPUT_CSV}"
done

[[ -f "${GCC_RELEASES_FILE}" ]] && rm "${GCC_RELEASES_FILE}"
