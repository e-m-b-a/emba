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

# Description:  Examine all files for cronjob configuration, e.g. cron or crontab and lists their jobs and other possible intriguing details.

S80_cronjob_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check cronjobs"

  local RESULTS
  RESULTS=0

  local CJ_FILE_PATH
  mapfile -t CJ_FILE_PATH < <(mod_path "/ETC_PATHS/cron")
  for CJ_FILE in "${CJ_FILE_PATH[@]}"; do
    if [[ -e "$CJ_FILE" ]] ; then
      local CRONJOBS
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      CRONJOBS=$(ls -la "$CJ_FILE"* 2>/dev/null)
      if [[ "$CRONJOBS" ]] ; then
        print_output "[+] Cronjobs:"
        print_output "$(indent "$CRONJOBS")"
        ((RESULTS++))
      fi
    fi
  done

  for CJ_FILE in "${CJ_FILE_PATH[@]}" ; do
    if [[ -e "$CJ_FILE" ]] ; then
      local CRONJOBWWPERMS
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      CRONJOBWWPERMS=$(find "$CJ_FILE"* -xdev -perm -0002 -type f -exec ls -la {} \; -exec cat {} \; 2>/dev/null)
      if [[ "$CRONJOBWWPERMS" ]] ; then
        print_output "[+] World-writable cron jobs and file contents:"
        print_output "$(indent "$CRONJOBWWPERMS")"
        ((RESULTS++))
      fi
    fi
  done

  mapfile -t CJ_FILE_PATH < <(mod_path "/ETC_PATHS/crontab")
  for CJ_FILE in "${CJ_FILE_PATH[@]}"; do
    if [[ -e "$CJ_FILE" ]] ; then
      local CRONTABVALUE
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      CRONTABVALUE=$(cat "$CJ_FILE" 2>/dev/null)
      if [[ "$CRONTABVALUE" ]] ; then
        print_output "[+] Crontab content:"
        print_output "$(indent "$CRONTABVALUE")"
        ((RESULTS++))
      fi
    fi
  done

  mapfile -t CJ_FILE_PATH < <(mod_path "/var/spool/cron/crontabs")
  for CT_VAR in "${CJ_FILE_PATH[@]}"; do
    local CRONTABVAR
    # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    CRONTABVAR=$(ls -la "$CT_VAR" 2>/dev/null)
    if [[ "$CRONTABVAR" ]] ; then
      print_output "[+] Anything interesting in ""$(print_path "$CT_VAR")"
      print_output "$(indent "$CRONTABVAR")"
      ((RESULTS++))
    fi
  done

  mapfile -t CJ_FILE_PATH < <(mod_path "/ETC_PATHS/anacrontab")
  for CJ_FILE in "${CJ_FILE_PATH[@]}"; do
    if [[ -e "$CJ_FILE" ]] ; then
      local ANACRONJOBS
      # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
      ANACRONJOBS=$(ls -la "$CJ_FILE" 2>/dev/null; cat "$CJ_FILE" 2>/dev/null)
      if [[ "$ANACRONJOBS" ]] ; then
        print_output "[+] Anacron jobs and associated file permissions:"
        print_output "$(indent "$ANACRONJOBS")"
        ((RESULTS++))
      fi
    fi
  done

  mapfile -t CJ_FILE_PATH < <(mod_path "/var/spool/anacron")
  for CT_VAR in "${CJ_FILE_PATH[@]}"; do
    local ANACRONTAB
    # This check is based on source code from LinEnum: https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
    ANACRONTAB=$(ls -la "$CT_VAR" 2>/dev/null)
    if [[ "$ANACRONTAB" ]] ; then
      print_output "[+] When were jobs last executed (""$(print_path "$CT_VAR")"")"
      print_output "$(indent "$ANACRONTAB")"
      ((RESULTS++))
    fi
  done

  module_end_log "${FUNCNAME[0]}" "$RESULTS"
}

