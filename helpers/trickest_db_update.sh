#!/bin/bash -p
# see: https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html#//apple_ref/doc/uid/TP40004268-CH8-SW29

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

# Description:  Update script for trickest PoC collection

EMBA_CONFIG_PATH="./config"
EMBA_EXT_DIR="./external"
TRICKEST_DB_PATH="${EMBA_CONFIG_PATH}"/trickest_cve-db.txt

## Color definition
GREEN="\033[0;32m"
ORANGE="\033[0;33m"
NC="\033[0m"  # no color

if ! [[ -d "${EMBA_CONFIG_PATH}" ]]; then
  echo "[-] No EMBA config directory found! Please start this crawler from the EMBA directory"
  exit 1
fi

echo -e "[*] Update the trickest database\n"
if [[ -f "${TRICKEST_DB_PATH}" ]]; then
  TRICKEST_DB_ENTRIES_INIT="$(wc -l "${TRICKEST_DB_PATH}" | awk '{print $1}')"
  echo -e "${GREEN}[*] Trickest CVE database has ${ORANGE}${TRICKEST_DB_ENTRIES_INIT}${GREEN} exploit entries (before update).${NC}"
fi

if [[ -d "${EMBA_EXT_DIR}"/trickest-cve ]]; then
  echo "[*] Update and build the Trickest CVE/exploit database"
  cd "${EMBA_EXT_DIR}"/trickest-cve || (echo "[-] Something was going wrong during trickest update" && exit 1)
  git pull || (echo "[-] Something was going wrong during trickest update" && exit 1)
  cd ../.. || (echo "[-] Something was going wrong during trickest update" && exit 1)
else
  echo "[*] Clone and build the Trickest CVE/exploit database"
  git clone https://github.com/trickest/cve.git "${EMBA_EXT_DIR}"/trickest-cve || (echo "[-] Something was going wrong during trickest update" && exit 1)
fi

if [[ -d "${EMBA_EXT_DIR}"/trickest-cve ]]; then
  echo "[*] Generate the EMBA database"
  find "${EMBA_EXT_DIR}"/trickest-cve -type f -iname "*.md" -exec grep -o -H "^\-\ https://github.com.*" {} \; | sed 's/:-\ /:/g' | sort > "${TRICKEST_DB_PATH}" || (echo "[-] Something was going wrong during trickest update" && exit 1)

  # if we have a blacklist file we are going to apply it to the generated trickest database
  if [[ -f "${EMBA_CONFIG_PATH}"/trickest_blacklist.txt ]]; then
    grep -Fvf "${EMBA_CONFIG_PATH}"/trickest_blacklist.txt "${TRICKEST_DB_PATH}" > /tmp/trickest_db-cleaned.txt || (echo "[-] Something was going wrong during trickest update" && exit 1)
    mv /tmp/trickest_db-cleaned.txt "${TRICKEST_DB_PATH}" || (echo "[-] Something was going wrong during trickest update" && exit 1)
  fi

  # remove non existent sites - should we really crawl all urls?:
  if [[ -f /tmp/trickest_db-cleaned-DISABLED.txt ]]; then
    rm "${TRICKEST_DB_PATH}" || true
    while read -r TRICKEST_ENTRY; do
      TRICKEST_FS="$(echo "${TRICKEST_ENTRY}" | cut -d: -f1)"
      TRICKEST_URL="$(echo "${TRICKEST_ENTRY}" | cut -d: -f2-)"
      echo "[*] Testing ${TRICKEST_URL} for reachability"
      RETURN_CODE=$(curl -I -s -o /dev/null -w "%{http_code}" "${TRICKEST_URL}" | head -1 || true)
      if [[ "${RETURN_CODE}" -ne 404 ]]; then
        echo "[+] Valid URL ${TRICKEST_URL} found"
        echo "${TRICKEST_FS}:${TRICKEST_URL}" >> "${TRICKEST_DB_PATH}"
      fi
    done < /tmp/trickest_db-cleaned.txt
  # else
  #  exit 1
  fi

  if [[ -f "${TRICKEST_DB_PATH}" ]]; then
    echo -e "${GREEN}[+] Trickest CVE database now has ${ORANGE}$(wc -l "${TRICKEST_DB_PATH}" | awk '{print $1}')${GREEN} exploit entries (after update)."
    echo -e "${GREEN}[+] Before update: ${ORANGE}${TRICKEST_DB_ENTRIES_INIT}${NC}."
  fi
else
  echo "[-] No update of the Trickest exploit database performed."
  exit 1
fi
