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

# Description:  EMBA helper script to identify currently running EMBA modules
#               start it with "watch". E.g.,
#               watch -c ./helpers/running_modules.sh ~/firmware-stuff/emba_logs_dir300_new_bins


GREEN="\033[0;32m"
ORANGE="\033[0;33m"
NC="\033[0m"  # no color

if [[ $# -eq 0 ]]; then
  echo -e "\\n${ORANGE}In order to be able to use this script, you have to specify an EMBA firmware log directory${NC}"
  exit 1
fi

EMBA_LOG_DIR="${1:-}"
EMBA_LOG_FILE="${EMBA_LOG_DIR%/}/emba.log"

if ! [[ -f "${EMBA_LOG_FILE}" ]]; then
  echo -e "\\n${ORANGE}No valid EMBA firmware log directory found.${NC}"
  exit 1
fi

mapfile -t STARTED_EMBA_PROCESSES < <(grep -w starting "${EMBA_LOG_FILE}" | awk '{print $9}'|| true)

for EMBA_STARTED_PROC in "${STARTED_EMBA_PROCESSES[@]}"; do
  if ! grep -i -q "${EMBA_STARTED_PROC} finished ${EMBA_LOG_FILE}"; then
    echo -e "[*] EMBA module ${GREEN}${EMBA_STARTED_PROC}${NC} currently running"
  fi
done
