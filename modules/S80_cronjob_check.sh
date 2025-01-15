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

# Description:  Examine all files for cronjob configuration, e.g. cron or crontab
#               and lists their jobs and other possible intriguing details.

S80_cronjob_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check cronjobs"
  pre_module_reporter "${FUNCNAME[0]}"

  local lRESULTS=0
  local lCJ_FILE_PATH_ARR=()
  local lCJ_FILE=""
  local lCT_VAR=""

  mapfile -t lCJ_FILE_PATH_ARR < <(mod_path "/ETC_PATHS/cron")
  for lCJ_FILE in "${lCJ_FILE_PATH_ARR[@]}"; do
    if [[ -e "${lCJ_FILE}" ]] ; then
      local lCRONJOBS=""
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      # lCRONJOBS=$(ls -la "${lCJ_FILE}"* 2>/dev/null)
      lCRONJOBS=$(find "${lCJ_FILE}"* -xdev -type f 2>/dev/null)
      if [[ "${lCRONJOBS}" ]] ; then
        print_output "[+] Cronjobs:"
        print_output "$(indent "${lCRONJOBS}")"
        ((lRESULTS+=1))
      fi
    fi
  done

  for lCJ_FILE in "${lCJ_FILE_PATH_ARR[@]}" ; do
    if [[ -e "${lCJ_FILE}" ]] ; then
      local lCRONJOBWWPERMS=""
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      lCRONJOBWWPERMS=$(find "${lCJ_FILE}"* -xdev -perm -0002 -type f -exec ls -la {} \; -exec cat {} \; 2>/dev/null)
      if [[ "${lCRONJOBWWPERMS}" ]] ; then
        print_output "[+] World-writable cron jobs and file contents:"
        print_output "$(indent "${lCRONJOBWWPERMS}")"
        ((lRESULTS+=1))
      fi
    fi
  done

  mapfile -t lCJ_FILE_PATH_ARR < <(mod_path "/ETC_PATHS/crontab")
  for lCJ_FILE in "${lCJ_FILE_PATH_ARR[@]}"; do
    if [[ -e "${lCJ_FILE}" ]] ; then
      local lCRONTABVALUE=""
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      lCRONTABVALUE=$(cat "${lCJ_FILE}" 2>/dev/null)
      if [[ "${lCRONTABVALUE}" ]] ; then
        print_output "[+] Crontab content:"
        print_output "$(indent "${lCRONTABVALUE}")"
        ((lRESULTS+=1))
      fi
    fi
  done

  # mapfile -t lCJ_FILE_PATH_ARR < <(mod_path "/var/spool/cron/crontabs")
  mapfile -t lCJ_FILE_PATH_ARR < <(find "${FIRMWARE_PATH}" -xdev -type d -iwholename "/var/spool/cron/crontabs")
  for lCT_VAR in "${lCJ_FILE_PATH_ARR[@]}"; do
    local lCRONTABVAR=""
    # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    # lCRONTABVAR=$(ls -la "${lCT_VAR}" 2>/dev/null)
    lCRONTABVAR=$(find "${lCT_VAR}"* -type f -ls 2>/dev/null)
    if [[ "${lCRONTABVAR}" ]] ; then
      print_output "[+] Anything interesting in ""$(print_path "${lCT_VAR}")"
      print_output "$(indent "${lCRONTABVAR}")"
      ((lRESULTS+=1))
    fi
  done

  mapfile -t lCJ_FILE_PATH_ARR < <(mod_path "/ETC_PATHS/anacrontab")
  for lCJ_FILE in "${lCJ_FILE_PATH_ARR[@]}"; do
    if [[ -e "${lCJ_FILE}" ]] ; then
      local lANACRONJOBS=""
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      lANACRONJOBS=$(ls -la "${lCJ_FILE}" 2>/dev/null; cat "${lCJ_FILE}" 2>/dev/null)
      if [[ "${lANACRONJOBS}" ]] ; then
        print_output "[+] Anacron jobs and associated file permissions:"
        print_output "$(indent "${lANACRONJOBS}")"
        ((lRESULTS+=1))
      fi
    fi
  done

  # mapfile -t lCJ_FILE_PATH_ARR < <(mod_path "/var/spool/anacron")
  mapfile -t lCJ_FILE_PATH_ARR < <(find "${FIRMWARE_PATH}" -xdev -type d -iwholename "/var/spool/anacron")
  for lCT_VAR in "${lCJ_FILE_PATH_ARR[@]}"; do
    local lANACRONTAB=""
    # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    lANACRONTAB=$(ls -la "${lCT_VAR}" 2>/dev/null || true)
    if [[ "${lANACRONTAB}" ]] ; then
      print_output "[+] When were jobs last executed (""$(print_path "${lCT_VAR}")"")"
      print_output "$(indent "${lANACRONTAB}")"
      ((lRESULTS+=1))
    fi
  done

  module_end_log "${FUNCNAME[0]}" "${lRESULTS}"
}

