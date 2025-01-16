#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Searches in /var/mail for mail files.

S90_mail_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search Mail files"
  pre_module_reporter "${FUNCNAME[0]}"

  local lFINDING=0

  local lMAILS_PATH_ARR=()
  local lELEM=""
  local lMAILS=""

  mapfile -t lMAILS_PATH_ARR < <(find "${FIRMWARE_PATH}" -xdev -type d -iwholename "/var/mail")
  for lELEM in "${lMAILS_PATH_ARR[@]}" ; do
    if [[ -e "${lELEM}" ]] ; then
      # lMAILS="$(ls -la "${lELEM}" 2>/dev/null)"
      lMAILS="$(find "${lELEM}" -xdev -ls 2>/dev/null)"
      if [[ -n "${lMAILS}" ]] ; then
        print_output "[+] Content of ""$(print_path "${lELEM}")"":"
        print_output "$(indent "$(orange "${lMAILS}")")"
        ((lFINDING+=1))
      fi
    fi
  done

  local lMAILS_PATH_ROOT=()
  local lELEM=""
  local lMAILS_ROOT=""

  mapfile -t lMAILS_PATH_ROOT < <(find "${FIRMWARE_PATH}" -xdev -type d -iwholename "/var/mail/root")
  for lELEM in "${lMAILS_PATH_ROOT[@]}" ; do
    if [[ -e "${lELEM}" ]] ; then
      lMAILS_ROOT="$(head "${lELEM}" 2>/dev/null)"
      if [[ -n "${lMAILS_ROOT}" ]] ; then
        print_output "[+] Content of ""$(print_path "${lELEM}")"":"
        print_output "$(indent "$(orange "${lMAILS_ROOT}")")"
        ((lFINDING+=1))
      fi
    fi
  done

  module_end_log "${FUNCNAME[0]}" "${lFINDING}"
}

