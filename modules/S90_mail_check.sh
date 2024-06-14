#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2024 Siemens Energy AG
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

  local FINDING=0

  local MAILS_PATH=()
  local ELEM=""
  local MAILS=""

  mapfile -t MAILS_PATH < <(find "${FIRMWARE_PATH}" -xdev -type d -iwholename "/var/mail")
  for ELEM in "${MAILS_PATH[@]}" ; do
    if [[ -e "${ELEM}" ]] ; then
      # MAILS="$(ls -la "${ELEM}" 2>/dev/null)"
      MAILS="$(find "${ELEM}" -xdev -ls 2>/dev/null)"
      if [[ -n "${MAILS}" ]] ; then
        print_output "[+] Content of ""$(print_path "${ELEM}")"":"
        print_output "$(indent "$(orange "${MAILS}")")"
        ((FINDING+=1))
      fi
    fi
  done

  local MAILS_PATH_ROOT=()
  local ELEM=""
  local MAILS_ROOT=""

  mapfile -t MAILS_PATH_ROOT < <(find "${FIRMWARE_PATH}" -xdev -type d -iwholename "/var/mail/root")
  for ELEM in "${MAILS_PATH_ROOT[@]}" ; do
    if [[ -e "${ELEM}" ]] ; then
      MAILS_ROOT="$(head "${ELEM}" 2>/dev/null)"
      if [[ -n "${MAILS_ROOT}" ]] ; then
        print_output "[+] Content of ""$(print_path "${ELEM}")"":"
        print_output "$(indent "$(orange "${MAILS_ROOT}")")"
        ((FINDING+=1))
      fi
    fi
  done

  module_end_log "${FUNCNAME[0]}" "${FINDING}"
}

