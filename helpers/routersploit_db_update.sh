#!/bin/bash -p
# see: https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html#//apple_ref/doc/uid/TP40004268-CH8-SW29

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
# Author(s): Michael Messner

# Description:  Update script for Routersploit Exploit collection

set -euo pipefail

if [[ -z "${1}" ]]; then
  echo "Usage: $0 <routersploit_install_path>"
  exit 1
fi

EMBA_CONFIG_PATH="./config"
ROUTERSPLOIT_CVE_PATH="${EMBA_CONFIG_PATH}"/routersploit_cve-db.txt
ROUTERSPLOIT_EDB_PATH="${EMBA_CONFIG_PATH}"/routersploit_exploit-db.txt
ROUTERSPLOIT_MOD_PATH="${1:-}"

## Color definition
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
NC="\033[0m"  # no color

if ! [[ -d "${EMBA_CONFIG_PATH}" ]]; then
  echo "[-] No EMBA config directory found! Please start this crawler from the EMBA directory"
  exit 1
fi
if ! [[ -d "${ROUTERSPLOIT_MOD_PATH}" ]]; then
  echo "[-] No Routersploit directory found! Please install Routersploit and re-try it"
  echo "[*] Current Routersploit directory configuration: ${ORANGE}${ROUTERSPLOIT_MOD_PATH}${NC}."
  exit 1
fi

if [[ -f "${ROUTERSPLOIT_CVE_PATH}" ]]; then
  CNT_TMP=$(wc -l "${ROUTERSPLOIT_CVE_PATH}")
  echo -e "${GREEN}[*] Routersploit exploit database has ${ORANGE}${CNT_TMP/\ *}${GREEN} CVE matching exploit entries (before update).${NC}"
fi
if [[ -f "${ROUTERSPLOIT_EDB_PATH}" ]]; then
  CNT_TMP=$(wc -l "${ROUTERSPLOIT_EDB_PATH}")
  echo -e "${GREEN}[*] Routersploit exploit database has ${ORANGE}${CNT_TMP/\ *}${GREEN} EDB matching exploit entries (before update).${NC}"
fi

echo "[*] Building the Routersploit exploit database"
# search all ruby files in the routersploit directory and create a temporary file with the module path and CVE:
find "${ROUTERSPLOIT_MOD_PATH}" -type f -iname "*.py" -exec grep -i -o -H -E "CVE-[0-9]{4}-[0-9]+" {} \; | sed 's/.*external\/routersploit//' | sed 's/cve-/CVE-/' | sort -u > "${ROUTERSPLOIT_CVE_PATH}"
find "${ROUTERSPLOIT_MOD_PATH}" -type f -iname "*.py" -exec grep -i -o -H -E "exploit-db.com/exploits/[0-9]+" {} \; | sed 's/exploit-db\.com\/exploits\///' | sed 's/.*external\/routersploit//' | sort -u > "${ROUTERSPLOIT_EDB_PATH}"

if [[ -f "${ROUTERSPLOIT_CVE_PATH}" ]]; then
  echo -e "${GREEN}[*] Routersploit exploit database has ${ORANGE}$(wc -l "${ROUTERSPLOIT_CVE_PATH}" | awk '{print $1}')${GREEN} CVE matching exploit entries (after update).${NC}"
fi
if [[ -f "${ROUTERSPLOIT_EDB_PATH}" ]]; then
  echo -e "${GREEN}[*] Routersploit exploit database has ${ORANGE}$(wc -l "${ROUTERSPLOIT_EDB_PATH}" | awk '{print $1}')${GREEN} EDB matching exploit entries (after update).${NC}"
fi
