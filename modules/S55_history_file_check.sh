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

# Description:  Searches for possible history files like .bash_history.

S55_history_file_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search history files"
  pre_module_reporter "${FUNCNAME[0]}"

  local HIST_FILES=()
  local LINE=""

  mapfile -t HIST_FILES < <(config_find "${CONFIG_DIR}""/history_files.cfg")

  if [[ "${HIST_FILES[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#HIST_FILES[@]}" -ne 0 ]] ; then
      print_output "[+] Found history files:"
      for LINE in "${HIST_FILES[@]}" ; do
        print_output "$(indent "$(orange "$(print_path "${LINE}")")")"
      done
  else
    print_output "[-] No history files found"
  fi

  write_log ""
  write_log "[*] Statistics:${#HIST_FILES[@]}"

  module_end_log "${FUNCNAME[0]}" "${#HIST_FILES[@]}"
}

