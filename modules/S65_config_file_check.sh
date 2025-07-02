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

# Description:  Scans system for typical config files, e.g. *.cfg or fstab and analyzes fstab for user details.

S65_config_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search/scan config files"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0
  export CONF_FILES_ARR=()

  scan_config
  check_fstab

  if [[ "${#CONF_FILES_ARR[@]}" -gt 0 ]] || [[ -v FSTAB_USER_FILES[@] ]] || [[ -v FSTAB_PASS_FILES[@] ]]; then
    lNEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

scan_config()
{
  sub_module_title "Search for config file"
  local lCONFIG_FILE=""

  readarray -t CONF_FILES_ARR < <(config_find "${CONFIG_DIR}""/config_files.cfg")

  if [[ "${CONF_FILES_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ ${#CONF_FILES_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#CONF_FILES_ARR[@]}"" possible configuration files:"
    for lCONFIG_FILE in "${CONF_FILES_ARR[@]}" ; do
      print_output "$(indent "$(orange "$(print_path "${lCONFIG_FILE}")")")"
    done
  else
    print_output "[-] No configuration files found"
  fi
}

check_fstab() {
  sub_module_title "Scan fstab"
  local lFSTAB_ARR=()
  local lFSTAB_FILE=""

  mapfile -t lFSTAB_ARR < <(mod_path "/ETC_PATHS/fstab")

  if [[ ${#lFSTAB_ARR[@]} -gt 0 ]] ; then
    readarray -t FSTAB_USER_FILES < <(printf '%s' "$(find "${lFSTAB_ARR[@]}" "${EXCL_FIND[@]}" -xdev -print0|xargs -r -0 -P 16 -I % sh -c 'grep "username" "%"' 2>/dev/null || true)")
    readarray -t FSTAB_PASS_FILES < <(printf '%s' "$(find "${lFSTAB_ARR[@]}" "${EXCL_FIND[@]}" -xdev -print0|xargs -r -0 -P 16 -I % sh -c 'grep "password" "%"' 2>/dev/null || true)")
  fi

  if [[ ${#FSTAB_USER_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#FSTAB_USER_FILES[@]}"" fstab files with user details included:"
    for lFSTAB_FILE in "${FSTAB_USER_FILES[@]}"; do
      print_output "$(indent "$(print_path "${lFSTAB_FILE}")")"
    done
    print_ln "no_log"
  else
    print_output "[-] No fstab files with user details found"
  fi

  if [[ ${#FSTAB_PASS_FILES[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#FSTAB_PASS_FILES[@]}"" fstab files with password credentials included:"
    for lFSTAB_FILE in "${FSTAB_PASS_FILES[@]}"; do
      print_output "$(indent "$(print_path "${lFSTAB_FILE}")")"
    done
    print_ln "no_log"
  else
    print_output "[-] No fstab files with passwords found"
  fi
}
