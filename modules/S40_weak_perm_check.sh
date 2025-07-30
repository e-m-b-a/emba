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

# Description:  Scans everything for setuid, setgid, world writable and shadow files and checks if all rc.d and init.d files
#               have weak permissions.

S40_weak_perm_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Search files with weak permissions"
  pre_module_reporter "${FUNCNAME[0]}"

  local lSETUID_FILES_ARR=()
  local lSETGID_FILES_ARR=()
  local lWORLD_WRITE_FILES_ARR=()
  local lWEAK_SHADOW_FILES_ARR=()
  local lWEAK_RC_FILES_ARR=()
  local lWEAK_INIT_FILES_ARR=()

  local lWEAK_PERM_COUNTER=0
  local lLINE=""
  local lSETUID_NAME=""
  local lGTFO_LINK=""
  local lETC_ARR=""
  lETC_ARR=("$(mod_path "/ETC_PATHS")")

  readarray -t lSETUID_FILES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -user root -perm -4000 -print0 2>/dev/null |xargs -r -0 -P 16 -I % sh -c 'md5sum "%"' | sort -u -k1,1 | cut -d\  -f3 || true)
  readarray -t lSETGID_FILES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -user root -perm -2000 -print0 2>/dev/null |xargs -r -0 -P 16 -I % sh -c 'md5sum "%"' | sort -u -k1,1 | cut -d\  -f3 || true)
  readarray -t lWORLD_WRITE_FILES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -type f -perm -o+w -print0 2>/dev/null |xargs -r -0 -P 16 -I % sh -c 'md5sum "%"' | sort -u -k1,1 | cut -d\  -f3 || true)
  # -perm -600 ! -perm 600 -> find files with at least -rw --- --- but do not have exactly these permissions
  # => we look for higher permissions
  readarray -t lWEAK_SHADOW_FILES_ARR < <(find "${lETC_ARR[@]}" "${EXCL_FIND[@]}" -xdev -type f -iname "shadow*" -perm -600 ! -perm 600 -print0 2>/dev/null |xargs -r -0 -P 16 -I % sh -c 'md5sum "%"' | sort -u -k1,1 | cut -d\  -f3 || true)

  lETC_ARR=("$(mod_path "/ETC_PATHS/rc.d")")
  # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.s
  readarray -t lWEAK_RC_FILES_ARR < <(find "${lETC_ARR[@]}" "${EXCL_FIND[@]}" -xdev \! -uid 0 -type f -print0 2>/dev/null |xargs -r -0 -P 16 -I % sh -c 'md5sum "%"' | sort -u -k1,1 | cut -d\  -f3 || true)
  lETC_ARR=("$(mod_path "/ETC_PATHS/init.d")")
  # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.s
  readarray -t lWEAK_INIT_FILES_ARR < <(find "${lETC_ARR[@]}" "${EXCL_FIND[@]}" -xdev \! -uid 0 -type f -print0 2>/dev/null |xargs -r -0 -P 16 -I % sh -c 'md5sum "%"' | sort -u -k1,1 | cut -d\  -f3 || true)

  if [[ ${#lSETUID_FILES_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found ${#lSETUID_FILES_ARR[@]} setuid files:"
    for lLINE in "${lSETUID_FILES_ARR[@]}" ; do
      lSETUID_NAME=$(basename "${lLINE}")
      lGTFO_LINK=$(grep "/${lSETUID_NAME}/" "${GTFO_CFG}" || true)
      if [[ "${lGTFO_LINK}" == "https://"* ]]; then
        print_output "$(indent "${GREEN}$(print_path "${lLINE}")${NC}")"
        write_link "${lGTFO_LINK}"
      else
        print_output "$(indent "$(print_path "${lLINE}")")"
      fi
      ((lWEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No setuid files found"
  fi

  if [[ ${#lSETGID_FILES_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found ${#lSETGID_FILES_ARR[@]} setgid files:"
    for lLINE in "${lSETGID_FILES_ARR[@]}"; do
      print_output "$(indent "$(print_path "${lLINE}")")"
      ((lWEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No setgid files found"
  fi

  if [[ ${#lWORLD_WRITE_FILES_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found ${#lWORLD_WRITE_FILES_ARR[@]} world writable files:"
    for lLINE in "${lWORLD_WRITE_FILES_ARR[@]}"; do
      print_output "$(indent "$(print_path "${lLINE}")")"
      ((lWEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No world writable files found"
  fi

  if [[ ${#lWEAK_SHADOW_FILES_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found ${#lWEAK_SHADOW_FILES_ARR[@]} weak shadow files:"
    for lLINE in "${lWEAK_SHADOW_FILES_ARR[@]}"; do
      print_output "$(indent "$(print_path "${lLINE}")")"
      ((lWEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No shadow files found"
  fi

  if [[ ${#lWEAK_RC_FILES_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found ${#lWEAK_RC_FILES_ARR[@]} rc.d files not belonging to root:"
    for lLINE in "${lWEAK_RC_FILES_ARR[@]}"; do
      print_output "$(indent "$(print_path "${lLINE}")")"
      ((lWEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No rc.d files with weak permissions found"
  fi

  if [[ ${#lWEAK_INIT_FILES_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found ${#lWEAK_INIT_FILES_ARR[@]} init.d files not belonging to root:"
    for lLINE in "${lWEAK_INIT_FILES_ARR[@]}"; do
      print_output "$(indent "$(print_path "${lLINE}")")"
      ((lWEAK_PERM_COUNTER+=1))
    done
    print_ln "no_log"
  else
    print_output "[-] No init.d files with weak permissions found"
  fi

  write_log ""
  write_log "[*] Statistics:${lWEAK_PERM_COUNTER}"

  module_end_log "${FUNCNAME[0]}" "${lWEAK_PERM_COUNTER}"
}
