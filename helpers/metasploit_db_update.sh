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

# Description:  Update script for Metasploit Exploit collection

set -euo pipefail

if [[ -z "${1:-}" ]]; then
  echo "Usage: $(basename "$0") <metasploit_installation_directory>"
  echo "Example: $(basename "$0") /usr/share/metasploit-framework/"
  exit 1
fi

EMBA_CONFIG_PATH="./config"
MSF_DB_PATH="${EMBA_CONFIG_PATH}"/msf_cve-db.txt
MSF_MOD_PATH="${1}"

## Color definition
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
NC="\033[0m"  # no color

if ! [[ -d "${EMBA_CONFIG_PATH}" ]]; then
  echo "[-] No EMBA config directory found! Please start this crawler from the EMBA directory"
  exit 1
fi
if ! [[ -d "${MSF_MOD_PATH}" ]]; then
  echo "[-] No Metasploit directory found! Please install Metasploit and re-try it"
  echo -e "[*] Current Metasploit directory configuration: ${ORANGE}${MSF_MOD_PATH}${NC}."
  exit 1
fi

if [[ -f "${MSF_DB_PATH}" ]]; then
  MSF_EXPLOIT_ENTRIES_INIT=$(wc -l < "${MSF_DB_PATH}")
  echo -e "${GREEN}[*] Metasploit exploit database has ${ORANGE}${MSF_EXPLOIT_ENTRIES_INIT}${GREEN} exploit entries (before update).${NC}"
fi

# echo "[*] Updating the Metasploit framework package"
# sudo apt-get update -y
# sudo apt-get --only-upgrade install metasploit-framework -y

echo "[*] Building the Metasploit exploit database"
# search all ruby files in the metasploit directory and create a temporary file with the module path and CVE:
find "${MSF_MOD_PATH}" -type f -iname "*.rb" -exec grep -a -H -E -o "CVE', '[0-9]{4}-[0-9]+" {} \; | sed "s/', '/-/g" \
  | sed "s@${MSF_MOD_PATH}@@"| sort > "${MSF_DB_PATH}"

# Validate that the output file was created and is not empty
if [[ ! -f "${MSF_DB_PATH}" ]] || [[ ! -s "${MSF_DB_PATH}" ]]; then
  echo -e "${ORANGE}[!] Warning: No CVEs found or database creation failed${NC}"
  exit 1
fi

MSF_EXPLOIT_ENTRIES=$(wc -l < "${MSF_DB_PATH}")
echo -e "${GREEN}[*] Metasploit exploit database now has ${ORANGE}${MSF_EXPLOIT_ENTRIES}${GREEN} exploit entries (after update).${NC}"
