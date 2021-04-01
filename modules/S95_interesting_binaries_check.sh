#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Searches explicitly for binaries like gcc or gdb and also binaries for post exploitation like wget or ftp.

S95_interesting_binaries_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check interesting binaries"

  LOG_FILE="$( get_log_file )"

  interesting_binaries
  post_exploitation

  echo -e "\\n[*] Statistics:$INT_COUNT:$POST_COUNT" >> "$LOG_FILE"

  if [[ "$INT_COUNT" -gt 0 || "$POST_COUNT" -gt 0 ]]; then
    NEG_LOG=1
  fi
  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

interesting_binaries()
{
  sub_module_title "Interesting binaries"

  local COUNT=0
  declare -a MD5_DONE_INT
  INT_COUNT=0

  mapfile -t INT_BIN < <(config_find "$CONFIG_DIR""/interesting_binaries.cfg")
  if [[ "${INT_BIN[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#INT_BIN[@]}" -ne 0 ]] ; then
    for LINE in "${INT_BIN[@]}" ; do
      if [[ -f "$LINE" ]] && file "$LINE" | grep -q "executable" ; then
        # we need every binary only once. So calculate the checksum and store it for checking
        BIN_MD5=$(md5sum "$LINE" | cut -d\  -f1)
        if [[ ! " ${MD5_DONE_INT[*]} " =~ ${BIN_MD5} ]]; then
          if [[ $COUNT -eq 0 ]] ; then
            print_output "[+] Found interesting binaries:"
            COUNT=1
          fi
          print_output "$(indent "$(orange "$(print_path "$LINE")")")"
          ((INT_COUNT++))
          MD5_DONE_INT+=( "$BIN_MD5" )
        fi
      fi
    done
  fi
  if [[ $COUNT -eq 0 ]] ; then
    print_output "[-] No interesting binaries found"
  fi
}

post_exploitation()
{
  sub_module_title "Interesting binaries for post exploitation"

  local COUNT=0
  declare -a MD5_DONE_POST
  POST_COUNT=0

  mapfile -t INT_BIN_PE < <(config_find "$CONFIG_DIR""/interesting_post_binaries.cfg")
  if [[ "${INT_BIN_PE[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#INT_BIN_PE[@]}" -ne 0 ]] ; then
    for LINE in "${INT_BIN_PE[@]}" ; do
      if [[ -f "$LINE" ]] && file "$LINE" | grep -q "executable" ; then
        # we need every binary only once. So calculate the checksum and store it for checking
        BIN_MD5=$(md5sum "$LINE" | cut -d\  -f1)
        if [[ ! " ${MD5_DONE_POST[*]} " =~ ${BIN_MD5} ]]; then
          if [[ $COUNT -eq 0 ]] ; then
            print_output "[+] Found interesting binaries for post exploitation:"
            COUNT=1
          fi
          print_output "$(indent "$(orange "$(print_path "$LINE")")")"
          ((POST_COUNT++))
          MD5_DONE_POST+=( "$BIN_MD5" )
        fi
      fi
    done
  fi
  if [[ $COUNT -eq 0 ]] ; then
    print_output "[-] No interesting binaries for post exploitation found"
  fi
}

