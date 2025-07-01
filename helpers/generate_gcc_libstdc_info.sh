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
GCC_STD_HTML="https://gcc.gnu.org/onlinedocs/libstdc++/manual/abi.html"

# local temp files
GCC_RELEASES_FILE="$(mktemp)"
GCC_STC_MATCHING_FILE="$(mktemp)"

# final EMBA csv config file
GCC_OUTPUT_CSV="./config/gcc_libstdc_details.csv"

curl -f "${GCC_RELEASES_HTML}" > "${GCC_RELEASES_FILE}"
curl -f "${GCC_STD_HTML}" > "${GCC_STC_MATCHING_FILE}"

if ! [[ -f "${GCC_STC_MATCHING_FILE}" ]]; then
  print_output "[-] Error downloading ${GCC_STD_HTML}" "no_log"
  exit 1
fi
if ! [[ -f "${GCC_RELEASES_FILE}" ]]; then
  print_output "[-] Error downloading ${GCC_RELEASES_FILE}" "no_log"
  exit 1
fi

[[ -f "${GCC_OUTPUT_CSV}" ]] && rm "${GCC_OUTPUT_CSV}"

mapfile -t GCC_STC_MATCHING_ARR < <(grep "div\ class.*libstdc" "${GCC_STC_MATCHING_FILE}" | tr '<p>' '\n' | grep GCC | grep -v "next")

for GCC_STC_MATCHING_ENTRY in "${GCC_STC_MATCHING_ARR[@]}"; do
  # print_output "[*] Testing GCC matching entry: ${ORANGE}${GCC_STC_MATCHING_ENTRY}${NC}" "no_log"
  GCC_ENTRY=${GCC_STC_MATCHING_ENTRY/:*/}
  LIBSTDC_ENTRY=${GCC_STC_MATCHING_ENTRY/*:/}
  LIBSTDC_ENTRY=${LIBSTDC_ENTRY/ /}
  GCC_RELEASE_DATE="$(grep ">${GCC_ENTRY}<" "${GCC_RELEASES_FILE}")"
  if [[ -z "${GCC_RELEASE_DATE}" ]] && [[ "${GCC_ENTRY}" =~ ^GCC\ [0-9]+\.[0-9]\.0 ]]; then
    GCC_ENTRY="${GCC_ENTRY%.0}"
    GCC_RELEASE_DATE="$(grep ">${GCC_ENTRY}<" "${GCC_RELEASES_FILE}")"
  fi

  GCC_RELEASE_DATE="${GCC_RELEASE_DATE/*<td>}"
  GCC_RELEASE_DATE="${GCC_RELEASE_DATE/<\/td>*}"
  print_output "[*] GCC version: ${GCC_ENTRY} / matching libstdc identified: ${LIBSTDC_ENTRY} / GCC release date: ${GCC_RELEASE_DATE}" "no_log"
  echo "${GCC_ENTRY};${LIBSTDC_ENTRY};${GCC_RELEASE_DATE}" >> "${GCC_OUTPUT_CSV}"
done

[[ -f "${GCC_STC_MATCHING_FILE}" ]] && rm "${GCC_STC_MATCHING_FILE}"
[[ -f "${GCC_RELEASES_FILE}" ]] && rm "${GCC_RELEASES_FILE}"
