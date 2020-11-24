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

# Description:  Search ssh related files and check squid proxy server
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S85_ssh_check()
{
  module_log_init "s85_check_ssh"
  module_title "Check SSH"
  CONTENT_AVAILABLE=0

  search_ssh_files
  check_squid
  
  if [[ $HTML == 1 ]]; then
    generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

search_ssh_files()
{
  sub_module_title "Search ssh files"

  local SSH_FILES
  SSH_FILES="$(config_find "$CONFIG_DIR""/ssh_files.cfg" "")"

  if [[ "$SSH_FILES" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$SSH_FILES" ]] ; then
    local KEY_COUNT
    KEY_COUNT="$(echo "$SSH_FILES" | wc -w)"
    print_output "[+] Found ""$KEY_COUNT"" ssh configuration files:"
    for LINE in $SSH_FILES ; do
      if [[ -f "$LINE" ]] ; then
        print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      fi
    done
    CONTENT_AVAILABLE=1
  else
    print_output "[-] No ssh configuration files found"
  fi
}

# This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_squid
# Detailed tests possible, check if necessary
check_squid()
{
  sub_module_title "Check squid"

  local CHECK=0
  for BIN_FILE in "${BINARIES[@]}"; do
    if [[ "$BIN_FILE" == *"squid"* ]] && ( file "$BIN_FILE" | grep -q ELF ) ; then
      print_output "[+] Found possible squid executable: ""$(print_path "$BIN_FILE")"
      CHECK=1
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No possible squid executable found"
  else
    CONTENT_AVAILABLE=1
  fi

  CHECK=0
  SQUID_DAEMON_CONFIG_LOCS=("$FIRMWARE_PATH""/ETC_PATHS/" "$FIRMWARE_PATH""/ETC_PATHS/squid" "$FIRMWARE_PATH""/ETC_PATHS/squid3" "$FIRMWARE_PATH""/usr/local/etc/squid" "$FIRMWARE_PATH""/usr/local/squid/etc")
  SQUID_PATHS_ARR="$(mod_path_array "${SQUID_DAEMON_CONFIG_LOCS[@]}")"
  if [[ "$SQUID_PATHS_ARR" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif [[ -n "$SQUID_PATHS_ARR" ]] ; then
    for SQUID_E in $SQUID_PATHS_ARR; do
      if [[ -f "$SQUID_E""/squid.conf" ]] ; then
        CHECK=1
        print_output "[+] Found squid config: ""$(print_path "$SQUID_E")"
      elif [[ -f "$SQUID_E""/squid3.conf" ]] ; then
        CHECK=1
        print_output "[+] Found squid config: ""$(print_path "$SQUID_E")"
      fi
      if [[ $CHECK -eq 1 ]] ; then
        print_output "[*] Check external access control list type:"
        print_output "$(indent "$(grep "^external_acl_type" "$SQUID_E")")"
        print_output "[*] Check access control list:"
        print_output "$(indent "$(grep "^acl" "$SQUID_E" | sed 's/ /!space!/g')")"
      fi
    done
  fi
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No squid configuration found"
  else
    CONTENT_AVAILABLE=1
  fi
}
