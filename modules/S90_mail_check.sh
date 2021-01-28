#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Search for mail related files
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}
export HTML_REPORT

S90_mail_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search Mail files"

  local FINDING

  local MAILS
  local MAILS_PATH
  mapfile -t MAILS_PATH < <(mod_path "/var/mail")
  for ELEM in "${MAILS_PATH[@]}" ; do
    if [[ -e "$ELEM" ]] ; then
      MAILS="$(ls -la "$ELEM" 2>/dev/null)"
      if [[ -n "$MAILS" ]] ; then
        print_output "[+] Content of ""$(print_path "$ELEM")"":"
        print_output "$(indent "$(orange "$MAILS")")"
        FINDING=1
        HTML_REPORT=1
      fi
    fi
  done

  local MAILS_ROOT
  local MAILS_PATH_ROOT
  mapfile -t MAILS_PATH_ROOT < <(mod_path "/var/mail/root")
  for ELEM in "${MAILS_PATH_ROOT[@]}" ; do
    if [[ -e "$ELEM" ]] ; then
      MAILS_ROOT="$(head "$ELEM" 2>/dev/null)"
      if [[ -n "$MAILS_ROOT" ]] ; then
        print_output "[+] Content of ""$(print_path "$ELEM")"":"
        print_output "$(indent "$(orange "$MAILS_ROOT")")"
        FINDING=1
        HTML_REPORT=1
      fi
    fi
  done

  if [[ "$FINDING" -eq 0 ]] ; then
    print_output "[-] No mail files found!"
  fi
}

