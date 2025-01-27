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

# Description:  Update script for binary identifiers. Checks every identifier if there are CVEs available
#               and creates a limited bin_version_strings_quick.cfg file for the quick scanning profile


ORIG_CNT=$(wc -l config/bin_version_strings.cfg)
ORIG_CNT=${ORIG_CNT/\ *}
if [[ -f "config/bin_version_strings_quick.cfg" ]]; then
  QUICK_CNT=$(wc -l config/bin_version_strings.cfg)
  QUICK_CNT=${QUICK_CNT/\ *}
fi

mapfile -t STRING_ENTRY_ARR < <(grep -v "^#" config/bin_version_strings.cfg)
if [[ -f "config/bin_version_strings_quick.cfg" ]]; then
  rm config/bin_version_strings_quick.cfg
fi

for STRING_ENTRY in "${STRING_ENTRY_ARR[@]}"; do
  # extract only the component name for cpe search:
  COMPONENT="$(echo "${STRING_ENTRY}" | cut -d ';' -f 5 | rev | cut -d '/' -f2 | rev | cut -d ':' -f3)"
  STRICT_MODE="$(echo "${STRING_ENTRY}" | cut -d ';' -f 2)"
  [[ "${STRICT_MODE}" == "strict" ]] && continue

  echo "[*] Testing SBOM entry ${COMPONENT//::}"

  if [[ "$(rg -I -N "cpe.*${COMPONENT//::}:" external/nvd-json-data-feeds/* | wc -l 2>/dev/null)" -gt 0 ]]; then
    # we can add the entry to our quick scan profile
    echo "[*] Adding component entry for ${COMPONENT} to our quick scan profile"
    echo "${STRING_ENTRY}" >> config/bin_version_strings_quick.cfg
  fi
done
echo "[*] Started with ${ORIG_CNT} identifier entries -> quick scan profile now has ${QUICK_CNT} entries."
