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

# Description:  Searches for password related files and tries to extract passwords and root accounts.

S45_pass_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search password files"
  pre_module_reporter "${FUNCNAME[0]}"

  local lPASS_FILES_FOUND=0
  local lSUDOERS_FILE_PATH_ARR=()
  local lSUDOERS_FILE=""
  local lWHO_HAS_BEEN_SUDO=""
  local lLINE=""
  local lPASSWD_STUFF_ARR=()

  mapfile -t lPASSWD_STUFF_ARR < <(config_find "${CONFIG_DIR}""/pass_files.cfg")

  if [[ "${lPASSWD_STUFF_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#lPASSWD_STUFF_ARR[@]}" -ne 0 ]] ; then
    # pull out vital sudoers info
    # This test is based on the source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    local lSUDOERS=""
    mapfile -t lSUDOERS_FILE_PATH_ARR < <(mod_path "/ETC_PATHS/sudoers")

    for lSUDOERS_FILE in "${lSUDOERS_FILE_PATH_ARR[@]}" ; do
      if [[ -e "${lSUDOERS_FILE}" ]] ; then
        lSUDOERS="${lSUDOERS}""\\n""$(grep -v -e '^$' "${lSUDOERS_FILE}" 2>/dev/null | grep -v "#" 2>/dev/null)"
      fi
    done
    # who has sudoed in the past
    # This test is based on the source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    lWHO_HAS_BEEN_SUDO=$(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name .sudo_as_admin_successful 2>/dev/null)

    if [[ "${#lPASSWD_STUFF_ARR[@]}" -gt 0 ]] || [[ -n "${lSUDOERS}" ]] || [[ -n "${lWHO_HAS_BEEN_SUDO}" ]] ; then
      print_output "[+] Found ""${#lPASSWD_STUFF_ARR[@]}"" password related files:"
      for lLINE in "${lPASSWD_STUFF_ARR[@]}" ; do
        print_output "$(indent "$(print_path "${lLINE}")")"
        if [[ -f "${lLINE}" ]] && ! [[ -x "${lLINE}" ]] ; then
          local lPOSSIBLE_PASSWD=""
          # regex source: https://serverfault.com/questions/972572/regex-for-etc-passwd-content
          # lPOSSIBLE_PASSWD=$(grep -hIE '^([^:]*:){6}[^:]*$' "${lLINE}" | grep -v ":x:" | grep -v ":\*:" | grep -v ":!:" 2> /dev/null)
          lPOSSIBLE_PASSWD=$(grep -hIE '^[a-zA-Z0-9]+:.:[0-9]+:[0-9]+([^:]*:){3}[^:]*$' "${lLINE}" | grep -v ":x:" | grep -v ":\*:" | grep -v ":!:" 2> /dev/null || true)

          local lPOSSIBLE_SHADOWS=""
          # lPOSSIBLE_SHADOWS=$(grep -hIE '^([^:]*:){8}[^:]*$' "${lLINE}" | grep -v ":x:" | grep -v ":\*:" | grep -v ":!:" 2> /dev/null)
          lPOSSIBLE_SHADOWS=$(grep -hIE '^[a-zA-Z0-9]+:\$[0-9a-z]\$.*:[0-9]+:[0-9]+:[0-9]+([^:]*:){4}[^:]*' "${lLINE}" | grep -v ":x:" | grep -v ":\*:" | grep -v ":!:" 2> /dev/null || true)

          local lROOT_ACCOUNTS=""
          # This test is based on the source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
          lROOT_ACCOUNTS=$(grep -v -E "^#" "${lLINE}" 2>/dev/null| awk -F: '$3 == 0 { print $1}' 2> /dev/null || true)

          local lL_BREAK=0
          if [[ "$(echo "${lROOT_ACCOUNTS}" | wc -w)" -gt 0 ]] ; then
            print_output "$(indent "$(green "Identified the following root accounts:")")"
            print_output "$(indent "$(indent "$(orange "${lROOT_ACCOUNTS}")")")"
            lL_BREAK=1
          fi

          if [[ "$(echo "${lPOSSIBLE_SHADOWS}" | wc -w)" -gt 0 ]] || [[ "$(echo "${lPOSSIBLE_PASSWD}" | wc -w)" -gt 0 ]] ; then
            print_output "$(indent "$(green "Found passwords or weak configuration:")")"
            lPASS_FILES_FOUND=1
            if [[ "$(echo "${lPOSSIBLE_SHADOWS}" | wc -w)" -gt 0 ]] ; then
              print_output "$(indent "$(indent "$(orange "${lPOSSIBLE_SHADOWS}")")")"
            fi
            if [[ "$(echo "${lPOSSIBLE_PASSWD}" | wc -w)" -gt 0 ]] ; then
              print_output "$(indent "$(indent "$(orange "${lPOSSIBLE_PASSWD}")")")"
            fi
            lL_BREAK=1
          fi
          if ! [[ ${lL_BREAK} -eq 0 ]] ; then
            print_ln
          fi
        fi
      done
      if [[ -n "${lSUDOERS}" ]] ; then
        print_output "[+] Sudoers configuration:"
        print_output "$(indent "$(orange "${lSUDOERS}")")"
      fi
      if [[ -n "${lWHO_HAS_BEEN_SUDO}" ]] ; then
        print_output "[+] Accounts that have recently used sudo:"
        print_output "$(indent "$(orange "${lWHO_HAS_BEEN_SUDO}")")"
      fi
    fi
    write_log ""
    write_log "[*] Statistics:${lPASS_FILES_FOUND}"
  else
    print_output "[-] No password files found"
  fi

  module_end_log "${FUNCNAME[0]}" "${#lPASSWD_STUFF_ARR[@]}"
}

