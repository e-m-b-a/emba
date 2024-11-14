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

# Description:  Scans everything for setuid, setgid, world writable and shadow files and checks if all rc.d and init.d files
#               have weak permissions.

S40_weak_perm_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Search files with weak permissions"
  pre_module_reporter "${FUNCNAME[0]}"

  local SETUID_FILES SETGID_FILES WORLD_WRITE_FILES WEAK_SHADOW_FILES WEAK_RC_FILES WEAK_INIT_FILES
  local WEAK_PERM_COUNTER=0
  local LINE=""
  local SETUID_NAME=""
  local GTFO_LINK=""
  local ETC_ARR=""
  ETC_ARR=("$(mod_path "/ETC_PATHS")")

  readarray -t SETUID_FILES < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -user root -perm -4000 -print0|xargs -0 -P 16 -I % sh -c 'md5sum % 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 2>/dev/null || true)
  readarray -t SETGID_FILES < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -user root -perm -2000 -print0|xargs -0 -P 16 -I % sh -c 'md5sum % 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 2>/dev/null || true)
  readarray -t WORLD_WRITE_FILES < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -type f -perm -o+w -print0|xargs -0 -P 16 -I % sh -c 'md5sum % 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 2>/dev/null || true)
  readarray -t WEAK_SHADOW_FILES < <(find "${ETC_ARR[@]}" "${EXCL_FIND[@]}" -xdev -type f -iname "shadow*" -perm -600 -print0|xargs -0 -P 16 -I % sh -c 'md5sum % 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 2>/dev/null || true)

  ETC_ARR=("$(mod_path "/ETC_PATHS/rc.d")")
  # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.s
  readarray -t WEAK_RC_FILES < <(find "${ETC_ARR[@]}" "${EXCL_FIND[@]}" -xdev \! -uid 0 -type f -print0|xargs -0 -P 16 -I % sh -c 'md5sum % 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 2>/dev/null || true)
  ETC_ARR=("$(mod_path "/ETC_PATHS/init.d")")
  # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.s
  readarray -t WEAK_INIT_FILES < <(find "${ETC_ARR[@]}" "${EXCL_FIND[@]}" -xdev \! -uid 0 -type f -print0|xargs -0 -P 16 -I % sh -c 'md5sum % 2>/dev/null' | sort -u -k1,1 | cut -d\  -f3 2>/dev/null || true)

  if [[ ${#SETUID_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#SETUID_FILES[@]}"" setuid files:"
    for LINE in "${SETUID_FILES[@]}" ; do
      SETUID_NAME=$(basename "${LINE}")
      GTFO_LINK=$(grep "/${SETUID_NAME}/" "${GTFO_CFG}" || true)
      if [[ "${GTFO_LINK}" == "https://"* ]]; then
        print_output "$(indent "${GREEN}$(print_path "${LINE}")${NC}")"
        write_link "${GTFO_LINK}"
      else
        print_output "$(indent "$(print_path "${LINE}")")"
      fi
      ((WEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No setuid files found"
  fi

  if [[ ${#SETGID_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#SETGID_FILES[@]}"" setgid files:"
    for LINE in "${SETGID_FILES[@]}"; do
      print_output "$(indent "$(print_path "${LINE}")")"
      ((WEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No setgid files found"
  fi

  if [[ ${#WORLD_WRITE_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WORLD_WRITE_FILES[@]}"" world writeable files:"
    for LINE in "${WORLD_WRITE_FILES[@]}"; do
      print_output "$(indent "$(print_path "${LINE}")")"
      ((WEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No world writable files found"
  fi

  if [[ ${#WEAK_SHADOW_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WEAK_SHADOW_FILES[@]}"" weak shadow files:"
    for LINE in "${WEAK_SHADOW_FILES[@]}"; do
      print_output "$(indent "$(print_path "${LINE}")")"
      ((WEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No shadow files found"
  fi

  if [[ ${#WEAK_RC_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WEAK_RC_FILES[@]}"" rc.d files not belonging to root:"
    for LINE in "${WEAK_RC_FILES[@]}"; do
      print_output "$(indent "$(print_path "${LINE}")")"
      ((WEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No rc.d files with weak permissions found"
  fi

  if [[ ${#WEAK_INIT_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#WEAK_INIT_FILES[@]}"" init.d files not belonging to root:"
    for LINE in "${WEAK_INIT_FILES[@]}"; do
      print_output "$(indent "$(print_path "${LINE}")")"
      ((WEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No init.d files with weak permissions found"
  fi

  write_log ""
  write_log "[*] Statistics:${WEAK_PERM_COUNTER}"

  module_end_log "${FUNCNAME[0]}" "${WEAK_PERM_COUNTER}"
}
