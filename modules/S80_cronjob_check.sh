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

# Description:  Examine all files for cronjob configuration, e.g. cron or crontab
#               and lists their jobs and other possible intriguing details.

S80_cronjob_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check cronjobs"
  pre_module_reporter "${FUNCNAME[0]}"

  local RESULTS=0
  local CJ_FILE_PATH=()
  local CJ_FILE=""
  local CT_VAR=""

  mapfile -t CJ_FILE_PATH < <(mod_path "/ETC_PATHS/cron")
  for CJ_FILE in "${CJ_FILE_PATH[@]}"; do
    if [[ -e "${CJ_FILE}" ]] ; then
      local CRONJOBS=""
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      # CRONJOBS=$(ls -la "${CJ_FILE}"* 2>/dev/null)
      CRONJOBS=$(find "${CJ_FILE}"* -xdev -type f 2>/dev/null)
      if [[ "${CRONJOBS}" ]] ; then
        print_output "[+] Cronjobs:"
        print_output "$(indent "${CRONJOBS}")"
        ((RESULTS+=1))
      fi
    fi
  done

  for CJ_FILE in "${CJ_FILE_PATH[@]}" ; do
    if [[ -e "${CJ_FILE}" ]] ; then
      local CRONJOBWWPERMS=""
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      CRONJOBWWPERMS=$(find "${CJ_FILE}"* -xdev -perm -0002 -type f -exec ls -la {} \; -exec cat {} \; 2>/dev/null)
      if [[ "${CRONJOBWWPERMS}" ]] ; then
        print_output "[+] World-writable cron jobs and file contents:"
        print_output "$(indent "${CRONJOBWWPERMS}")"
        ((RESULTS+=1))
      fi
    fi
  done

  mapfile -t CJ_FILE_PATH < <(mod_path "/ETC_PATHS/crontab")
  for CJ_FILE in "${CJ_FILE_PATH[@]}"; do
    if [[ -e "${CJ_FILE}" ]] ; then
      local CRONTABVALUE=""
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      CRONTABVALUE=$(cat "${CJ_FILE}" 2>/dev/null)
      if [[ "${CRONTABVALUE}" ]] ; then
        print_output "[+] Crontab content:"
        print_output "$(indent "${CRONTABVALUE}")"
        ((RESULTS+=1))
      fi
    fi
  done

  # mapfile -t CJ_FILE_PATH < <(mod_path "/var/spool/cron/crontabs")
  mapfile -t CJ_FILE_PATH < <(find "${FIRMWARE_PATH}" -xdev -type d -iwholename "/var/spool/cron/crontabs")
  for CT_VAR in "${CJ_FILE_PATH[@]}"; do
    local CRONTABVAR=""
    # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    # CRONTABVAR=$(ls -la "${CT_VAR}" 2>/dev/null)
    CRONTABVAR=$(find "${CT_VAR}"* -type f -ls 2>/dev/null)
    if [[ "${CRONTABVAR}" ]] ; then
      print_output "[+] Anything interesting in ""$(print_path "${CT_VAR}")"
      print_output "$(indent "${CRONTABVAR}")"
      ((RESULTS+=1))
    fi
  done

  mapfile -t CJ_FILE_PATH < <(mod_path "/ETC_PATHS/anacrontab")
  for CJ_FILE in "${CJ_FILE_PATH[@]}"; do
    if [[ -e "${CJ_FILE}" ]] ; then
      local ANACRONJOBS=""
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      ANACRONJOBS=$(ls -la "${CJ_FILE}" 2>/dev/null; cat "${CJ_FILE}" 2>/dev/null)
      if [[ "${ANACRONJOBS}" ]] ; then
        print_output "[+] Anacron jobs and associated file permissions:"
        print_output "$(indent "${ANACRONJOBS}")"
        ((RESULTS+=1))
      fi
    fi
  done

  # mapfile -t CJ_FILE_PATH < <(mod_path "/var/spool/anacron")
  mapfile -t CJ_FILE_PATH < <(find "${FIRMWARE_PATH}" -xdev -type d -iwholename "/var/spool/anacron")
  for CT_VAR in "${CJ_FILE_PATH[@]}"; do
    local ANACRONTAB=""
    # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    ANACRONTAB=$(ls -la "${CT_VAR}" 2>/dev/null || true)
    if [[ "${ANACRONTAB}" ]] ; then
      print_output "[+] When were jobs last executed (""$(print_path "${CT_VAR}")"")"
      print_output "$(indent "${ANACRONTAB}")"
      ((RESULTS+=1))
    fi
  done

  module_end_log "${FUNCNAME[0]}" "${RESULTS}"
}

