#!/bin/bash -p

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

# Description:  Searches for files with a specified password pattern inside.

S107_deep_password_search()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Deep analysis of files for password hashes"
  pre_module_reporter "${FUNCNAME[0]}"

  local PW_HASH_CONFIG="${CONFIG_DIR}"/password_regex.cfg
  local PW_COUNTER=0
  local PW_PATH=""
  local PW_HASHES=()
  local PW_HASH=""

  find "${FIRMWARE_PATH}" -xdev -type f -print0|xargs -0 -P 16 -I % sh -c 'grep --color -n -a -E -H -f '"${PW_HASH_CONFIG}"' % || true' > "${TMP_DIR}"/pw_hashes.txt

  if [[ $(wc -l "${TMP_DIR}"/pw_hashes.txt | awk '{print $1}') -gt 0 ]]; then
    print_output "[+] Found the following password hash values:"
    write_csv_log "PW_PATH" "PW_HASH"
    while read -r PW_HASH; do
      PW_PATH="${PW_HASH/:*}"
      mapfile -t PW_HASHES < <(strings "${PW_PATH}" | grep --color -a -E -f "${PW_HASH_CONFIG}")
      for PW_HASH in "${PW_HASHES[@]}"; do
        print_output "[+] PATH: ${ORANGE}$(print_path "${PW_PATH}")${GREEN}\t-\tHash: ${ORANGE}${PW_HASH}${GREEN}."
        write_csv_log "NA" "${PW_PATH}" "${PW_HASH}"
        ((PW_COUNTER+=1))
      done
    done < "${TMP_DIR}"/pw_hashes.txt

    print_ln
    print_output "[*] Found ${ORANGE}${PW_COUNTER}${NC} password hashes."
  fi
  write_log ""
  write_log "[*] Statistics:${PW_COUNTER}"

  module_end_log "${FUNCNAME[0]}" "${PW_COUNTER}"
}
