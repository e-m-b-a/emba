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

# Description:  Scans system for typical config files, e.g. *.cfg or fstab and analyzes fstab for user details.

S65_config_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search/scan config files"

  scan_config
  check_fstab

  if [[ "${#CONF_FILES_ARR[@]}" -gt 0 || "${#FSTAB_ARR[@]}" -ne 0 ]]; then
    NEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

scan_config()
{
  sub_module_title "Search for config file"

  readarray -t CONF_FILES_ARR < <(config_find "$CONFIG_DIR""/config_files.cfg")

  if [[ "${CONF_FILES_ARR[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ ${#CONF_FILES_ARR[@]} -ne 0 ]] ; then
    print_output "[+] Found ""${#CONF_FILES_ARR[@]}"" possible configuration files:"
    for LINE in "${CONF_FILES_ARR[@]}" ; do
      print_output "$(indent "$(orange "$LINE")")" # "$(print_path "$LINE")"
    done
  else
    print_output "[-] No configuration files found"
  fi
}

check_fstab()
{
  sub_module_title "Scan fstab"

  IFS=" " read -r -a FSTAB_ARR < <(printf '%s' "$(mod_path "/ETC_PATHS/fstab")")

  if [[ ${#FSTAB_ARR[@]} -ne 0 ]] ; then
    readarray -t FSTAB_USER_FILES < <(printf '%s' "$(find "${FSTAB_ARR[@]}" "${EXCL_FIND[@]}" -xdev -exec grep "username" {} \;)")
    readarray -t FSTAB_PASS_FILES < <(printf '%s' "$(find "${FSTAB_ARR[@]}" "${EXCL_FIND[@]}" -xdev -exec grep "password" {} \;)")
  fi

  if [[ ${#FSTAB_USER_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#FSTAB_USER_FILES[@]}"" fstab files with user details included:"
    for LINE in "${FSTAB_USER_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    echo
  else
    print_output "[-] No fstab files with user details found"
  fi

  if [[ ${#FSTAB_PASS_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#FSTAB_PASS_FILES[@]}"" fstab files with password credentials included:"
    for LINE in "${FSTAB_PASS_FILES[@]}"; do
      print_output "$(indent "$(print_path "$LINE")")"
    done
    echo
  else
    print_output "[-] No fstab files with passwords found"
  fi

}
