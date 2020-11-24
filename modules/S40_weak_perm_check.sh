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

# Description:  Search files with setuid, setgid, world writeable flags and weak shadow files
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S40_weak_perm_check() {
  module_log_init "s40_search_files_with_weak_permissions"
  module_title "Search files with weak permissions"

  local SETUID_FILES SETGID_FILES WORLD_WRITE_FILES WEAK_SHADOW_FILES WEAK_RC_FILES WEAK_INIT_FILES
  CONTENT_AVAILABLE=0

  local ETC_ARR
  ETC_ARR=("$(mod_path "$FIRMWARE_PATH""/ETC_PATHS")")
  readarray -t SETUID_FILES < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -user root -perm -4000 2>/dev/null)
  readarray -t SETGID_FILES < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -user root -perm -2000 2>/dev/null)
  readarray -t WORLD_WRITE_FILES < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -type f -perm -o+w 2>/dev/null)
  readarray -t WEAK_SHADOW_FILES < <(find "${ETC_ARR[@]}" "${EXCL_FIND[@]}" -xdev -type f -iname "shadow*" -perm -600 2>/dev/null)

  ETC_ARR=("$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/rc.d")")
  # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.s
  readarray -t WEAK_RC_FILES < <(find "${ETC_ARR[@]}" "${EXCL_FIND[@]}" \! -uid 0 -type f 2>/dev/null)
  ETC_ARR=("$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/init.d")")
  # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.s
  readarray -t WEAK_INIT_FILES < <(find "${ETC_ARR[@]}" "${EXCL_FIND[@]}" \! -uid 0 -type f 2>/dev/null)

  if [[ ${#SETUID_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#SETUID_FILES[@]}"" setuid files:"
    for LINE in "${SETUID_FILES[@]}" ; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
    echo
  else
    print_output "[-] No setuid files found"
  fi

  if [[ ${#SETGID_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#SETGID_FILES[@]}"" setgid files:"
    for LINE in "${SETGID_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
    echo
  else
    print_output "[-] No setgid files found"
  fi

  if [[ ${#WORLD_WRITE_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WORLD_WRITE_FILES[@]}"" world writeable files:"
    for LINE in "${WORLD_WRITE_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
    echo
  else
    print_output "[-] No world writable files found"
  fi

  if [[ ${#WEAK_SHADOW_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WEAK_SHADOW_FILES[@]}"" weak shadow files:"
    for LINE in "${WEAK_SHADOW_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
    echo
  else
    print_output "[-] No shadow files found"
  fi

  if [[ ${#WEAK_RC_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WEAK_RC_FILES[@]}"" rc.d files not belonging to root:"
    for LINE in "${WEAK_RC_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
    echo
  else
    print_output "[-] No rc.d files with weak permissions found"
  fi

  if [[ ${#WEAK_INIT_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WEAK_INIT_FILES[@]}"" init.d files not belonging to root:"
    for LINE in "${WEAK_INIT_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    CONTENT_AVAILABLE=1
    echo
  else
    print_output "[-] No init.d files with weak permissions found"
  fi
  
  if [[ $HTML == 1 ]]; then
     generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}
