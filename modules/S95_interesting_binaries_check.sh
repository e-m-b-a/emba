#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann, Stefan Haböck

# Description:  Check for interesting executables and possible post exploitation
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S95_interesting_binaries_check()
{
  module_log_init "s95_check_interesting_binaries"
  module_title "Check interesting binaries"
  CONTENT_AVAILABLE=0

  interesting_binaries
  post_exploitation
  
  if [[ $HTML == 1 ]]; then
    generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

interesting_binaries()
{
  sub_module_title "Interesting binaries"

  local INT_BIN
  INT_BIN="$(config_find "$CONFIG_DIR""/interesting_binaries.cfg" "")"
  local COUNT=0

  if [[ "$INT_BIN" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$INT_BIN" ]] ; then
    for LINE in $INT_BIN ; do
      if [[ -f "$LINE" ]] && file "$LINE" | grep -q "executable" ; then
        if [[ $COUNT -eq 0 ]] ; then
          print_output "[+] Found interesting binaries:"
          COUNT=1
        fi
        print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      fi
    done
  fi
  if [[ $COUNT -eq 0 ]] ; then
    print_output "[-] No interesting binaries found"
  else
    CONTENT_AVAILABLE=1
  fi
}

post_exploitation()
{
  sub_module_title "Interesting binaries for post exploitation"

  local INT_BIN_PE
  INT_BIN_PE="$(config_find "$CONFIG_DIR""/interesting_post_binaries.cfg" "")"
  local COUNT=0

  if [[ "$INT_BIN_PE" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$INT_BIN_PE" ]] ; then
    for LINE in $INT_BIN_PE ; do
      if [[ -f "$LINE" ]] && file "$LINE" | grep -q "executable" ; then
        if [[ $COUNT -eq 0 ]] ; then
          print_output "[+] Found interesting binaries for post exploitation:"
          COUNT=1
        fi
        print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      fi
    done
  fi
  if [[ $COUNT -eq 0 ]] ; then
    print_output "[-] No interesting binaries for post exploitation found"
  else
    CONTENT_AVAILABLE=1
  fi
}

