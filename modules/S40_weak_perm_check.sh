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

# Description:  Scans everything for setuid, setgid, world writable and shadow files and checks if all rc.d and init.d files 
#               have weak permissions.

S40_weak_perm_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Search files with weak permissions"

  LOG_FILE="$( get_log_file )"

  local SETUID_FILES SETGID_FILES WORLD_WRITE_FILES WEAK_SHADOW_FILES WEAK_RC_FILES WEAK_INIT_FILES
  local WEAK_PERM_COUNTER=0

  local ETC_ARR
  ETC_ARR=("$(mod_path "/ETC_PATHS")")
  readarray -t SETUID_FILES < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -user root -perm -4000 -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 2>/dev/null)
  readarray -t SETGID_FILES < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -user root -perm -2000 -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 2>/dev/null)
  readarray -t WORLD_WRITE_FILES < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -type f -perm -o+w -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 2>/dev/null)
  readarray -t WEAK_SHADOW_FILES < <(find "${ETC_ARR[@]}" "${EXCL_FIND[@]}" -xdev -type f -iname "shadow*" -perm -600 -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 2>/dev/null)

  ETC_ARR=("$(mod_path "/ETC_PATHS/rc.d")")
  # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.s
  readarray -t WEAK_RC_FILES < <(find "${ETC_ARR[@]}" "${EXCL_FIND[@]}" -xdev \! -uid 0 -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 2>/dev/null)
  ETC_ARR=("$(mod_path "/ETC_PATHS/init.d")")
  # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.s
  readarray -t WEAK_INIT_FILES < <(find "${ETC_ARR[@]}" "${EXCL_FIND[@]}" -xdev \! -uid 0 -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 2>/dev/null)

  if [[ ${#SETUID_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#SETUID_FILES[@]}"" setuid files:"
    for LINE in "${SETUID_FILES[@]}" ; do
      print_output "$(indent "$(print_path "$LINE")")"
      ((WEAK_PERM_COUNTER++))
    done
    echo
  else
    print_output "[-] No setuid files found"
  fi

  if [[ ${#SETGID_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#SETGID_FILES[@]}"" setgid files:"
    for LINE in "${SETGID_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
      ((WEAK_PERM_COUNTER++))
    done
    echo
  else
    print_output "[-] No setgid files found"
  fi

  if [[ ${#WORLD_WRITE_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WORLD_WRITE_FILES[@]}"" world writeable files:"
    for LINE in "${WORLD_WRITE_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
      ((WEAK_PERM_COUNTER++))
    done
    echo
  else
    print_output "[-] No world writable files found"
  fi

  if [[ ${#WEAK_SHADOW_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WEAK_SHADOW_FILES[@]}"" weak shadow files:"
    for LINE in "${WEAK_SHADOW_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
      ((WEAK_PERM_COUNTER++))
    done
    echo
  else
    print_output "[-] No shadow files found"
  fi

  if [[ ${#WEAK_RC_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WEAK_RC_FILES[@]}"" rc.d files not belonging to root:"
    for LINE in "${WEAK_RC_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
      ((WEAK_PERM_COUNTER++))
    done
    echo
  else
    print_output "[-] No rc.d files with weak permissions found"
  fi

  if [[ ${#WEAK_INIT_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WEAK_INIT_FILES[@]}"" init.d files not belonging to root:"
    for LINE in "${WEAK_INIT_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
      ((WEAK_PERM_COUNTER++))
    done
    echo
  else
    print_output "[-] No init.d files with weak permissions found"
  fi

  echo -e "\\n[*] Statistics:$WEAK_PERM_COUNTER" >> "$LOG_FILE"

  module_end_log "${FUNCNAME[0]}" "$WEAK_PERM_COUNTER"
}
