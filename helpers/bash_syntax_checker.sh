#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2026-2026 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description: Checks all EMBA source files with bash -n for syntax errors
#

GREEN='\033[0;32m'
ORANGE='\033[0;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # no color

EMBA_SOURCES_ARR=()
EMBA_SOURCE_FILE=""
MODULES_TO_CHECK_ARR=()

import_emba_scripts() {
  local lFILES_ARR=()
  local lEMBA_FILE=""

  mapfile -t lFILES_ARR < <(find ./ \( -name .git -o -name external \) -prune -o -type f -print 2>/dev/null)
  for lEMBA_FILE in "${lFILES_ARR[@]}"; do
    if file "${lEMBA_FILE}" | grep -q "shell script"; then
      echo "${lEMBA_FILE}"
      EMBA_SOURCES_ARR+=("${lEMBA_FILE}")
    fi
  done
}

echo -e "\\n${ORANGE}${BOLD}Embedded Linux Analyzer Bash syntax checker${NC}"
echo -e "${BOLD}=================================================================${NC}"

echo -e "\\n${GREEN}Load all sources to check:${NC}\\n"
import_emba_scripts

echo -e "\\n${GREEN}Check all source files for correct bash syntax:${NC}\\n"
for EMBA_SOURCE_FILE in "${EMBA_SOURCES_ARR[@]}"; do
  [[ ! -f "${EMBA_SOURCE_FILE}" ]] && continue
  echo -e "\\n${GREEN}Run ${ORANGE}bash -n${GREEN} on ${ORANGE}${EMBA_SOURCE_FILE}${NC}\\n"
  if bash -n "${EMBA_SOURCE_FILE}" 2>/dev/null; then
    echo -e "${GREEN}${BOLD}==> SUCCESS${NC}\\n"
  else
    echo -e "\\n${ORANGE}${BOLD}==> FIX ERRORS${NC}\\n"
    bash -n "${EMBA_SOURCE_FILE}"
    MODULES_TO_CHECK_ARR+=("${EMBA_SOURCE_FILE}")
  fi
done

if [[ "${#MODULES_TO_CHECK_ARR[@]}" -gt 0 ]]; then
  echo -e "${RED}[-] WARNING: Syntax errors detected -> Fix before pushing to EMBA repo${NC}"
  exit 1
fi
exit 0
