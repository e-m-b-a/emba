#!/bin/bash -p

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

# Description:  Searches for files with a specified password pattern inside.

S107_deep_password_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Deep analysis of files for password hashes"
  pre_module_reporter "${FUNCNAME[0]}"

  local lPW_HASH_CONFIG="${CONFIG_DIR}"/password_regex.cfg
  local lPW_COUNTER=0
  local lPW_PATH=""
  local lPW_HASHES_ARR=()
  local lPW_HASH=""

  find "${FIRMWARE_PATH}" -xdev -type f -print0|xargs -r -0 -P 16 -I % sh -c 'grep --color -n -a -E -H -f '"${lPW_HASH_CONFIG}"' "%" || true' > "${TMP_DIR}"/pw_hashes.txt || true

  if [[ $(wc -l < "${TMP_DIR}"/pw_hashes.txt) -gt 0 ]]; then
    print_output "[+] Found the following password hash values:"
    write_csv_log "PW_PATH" "PW_HASH"
    while read -r lPW_HASH; do
      lPW_PATH="${lPW_HASH/:*}"
      mapfile -t lPW_HASHES_ARR < <(strings "${lPW_PATH}" | grep --color -a -E -f "${lPW_HASH_CONFIG}" || true)
      for lPW_HASH in "${lPW_HASHES_ARR[@]}"; do
        print_output "[+] PATH: ${ORANGE}$(print_path "${lPW_PATH}")${GREEN}\t-\tHash: ${ORANGE}${lPW_HASH}${GREEN}."
        write_csv_log "${lPW_PATH}" "${lPW_HASH}"
        ((lPW_COUNTER+=1))
      done
    done < "${TMP_DIR}"/pw_hashes.txt

    print_ln
    print_output "[*] Found ${ORANGE}${lPW_COUNTER}${NC} password hashes."
  fi
  write_log ""
  write_log "[*] Statistics:${lPW_COUNTER}"

  module_end_log "${FUNCNAME[0]}" "${lPW_COUNTER}"
}
