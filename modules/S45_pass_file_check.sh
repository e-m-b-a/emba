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

# Description:  Check for files which could contain passwords
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S45_pass_file_check()
{
  module_log_init "s45_search_password_files"
  module_title "Search password files"

  CONTENT_AVAILABLE=0
  local PASSWD_STUFF
  PASSWD_STUFF="$(config_find "$CONFIG_DIR""/pass_files.cfg" "")"

  if [[ "$PASSWD_STUFF" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$PASSWD_STUFF" ]] ; then
    local PASSWD_COUNT
    PASSWD_COUNT=$(echo "$PASSWD_STUFF" | wc -w)

    # pull out vital sudoers info
    # This test is based on the source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    local SUDOERS
    SUDOERS=""
    SUDOERS_FILE_PATH="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/sudoers")"
    for SUDOERS_FILE in $SUDOERS_FILE_PATH ; do
      if [[ -e "$SUDOERS_FILE" ]] ; then
        SUDOERS="$SUDOERS""\\n""$(grep -v -e '^$' "$SUDOERS_FILE" 2>/dev/null | grep -v "#" 2>/dev/null)"
      fi
    done
    # who has sudoed in the past
    # This test is based on the source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    WHO_HAS_BEEN_SUDO=$(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -name .sudo_as_admin_successful 2>/dev/null)

    if [[ "$PASSWD_COUNT" -gt 0 ]] || [[ -n "$SUDOERS" ]] || [[ -n "$WHO_HAS_BEEN_SUDO" ]] ; then
      print_output "[+] Found ""$PASSWD_COUNT"" password related files:"
      for LINE in $PASSWD_STUFF ; do
        print_output "$(indent "$(print_path "$LINE")")"
        if [[ -f "$LINE" ]] && ! [[ -x "$LINE" ]] ; then
	        local POSSIBLE_PASSWD
          # regex source: https://serverfault.com/questions/972572/regex-for-etc-passwd-content
          POSSIBLE_PASSWD=$(grep -hIE '^([^:]*:){6}[^:]*$' "$LINE" | grep -v ":x:" | grep -v ":\*:" | grep -v ":!:" 2> /dev/null)

	        local POSSIBLE_SHADOWS
          POSSIBLE_SHADOWS=$(grep -hIE '^([^:]*:){8}[^:]*$' "$LINE" | grep -v ":x:" | grep -v ":\*:" | grep -v ":!:" 2> /dev/null)

          local ROOT_ACCOUNTS
          # This test is based on the source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
          ROOT_ACCOUNTS=$(grep -v -E "^#" "$LINE" 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2>/dev/null 2> /dev/null)

          local L_BREAK=0
          if [[ "$(echo "$ROOT_ACCOUNTS" | wc -w)" -gt 0 ]] ; then
            print_output "$(indent "$(green "Identified the following root accounts:")")"
            print_output "$(indent "$(indent "$(orange "$ROOT_ACCOUNTS")")")"
            L_BREAK=1
          fi

	        if [[ "$(echo "$POSSIBLE_SHADOWS" | wc -w)" -gt 0 ]] || [[ "$(echo "$POSSIBLE_PASSWD" | wc -w)" -gt 0 ]] || [[ "$(echo "$POSSIBLE_HASH" | wc -w)" -gt 0 ]] ; then
	          print_output "$(indent "$(green "Found passwords or weak configuration:")")"
            if [[ "$(echo "$POSSIBLE_SHADOWS" | wc -w)" -gt 0 ]] ; then
              print_output "$(indent "$(indent "$(orange "$POSSIBLE_SHADOWS")")")"
            fi
            if [[ "$(echo "$POSSIBLE_PASSWD" | wc -w)" -gt 0 ]] ; then
              print_output "$(indent "$(indent "$(orange "$POSSIBLE_PASSWD")")")"
            fi
            L_BREAK=1
	        fi
	        if ! [[ $L_BREAK -eq 0 ]] ; then
            print_output ""
          fi
        fi
      done
      if [[ -n "$SUDOERS" ]] ; then
        print_output "[+] Sudoers configuration:"
        print_output "$(indent "$(orange "$SUDOERS")")"
      fi
      if [[ -n "$WHO_HAS_BEEN_SUDO" ]] ; then
        print_output "[+] Accounts that have recently used sudo:"
        print_output "$(indent "$(orange "$WHO_HAS_BEEN_SUDO")")"
      fi
    fi
    CONTENT_AVAILABLE=1
  else
    print_output "[-] No password files found"
  fi
  
  if [[ $HTML == 1 ]]; then
     generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

