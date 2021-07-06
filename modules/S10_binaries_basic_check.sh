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

# Description:  This module was the first module that existed in emba. The main idea was to identify the binaries that were using weak 
#               functions and to establish a ranking of areas to look at first.

S10_binaries_basic_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries for critical functions"

  COUNTER=0
  local BIN_COUNT=0
  local VULNERABLE_FUNCTIONS

  VULNERABLE_FUNCTIONS="$(config_list "$CONFIG_DIR""/functions.cfg")"
  print_output "[*] Interesting functions: ""$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
  IFS=" " read -r -a VUL_FUNC_GREP <<<"$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ -e /g')"

  if [[ "$VULNERABLE_FUNCTIONS" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$VULNERABLE_FUNCTIONS" ]] ; then
    for LINE in "${BINARIES[@]}" ; do
      if ( file "$LINE" | grep -q "ELF" ) ; then
        local VUL_FUNC_RESULT
        BIN_COUNT=$((BIN_COUNT+1))
        mapfile -t VUL_FUNC_RESULT < <("$OBJDUMP" -T "$LINE" 2> /dev/null | grep -we "${VUL_FUNC_GREP[@]}" | grep -v "file format")
        if [[ "${#VUL_FUNC_RESULT[@]}" -ne 0 ]] ; then
          print_output ""
          print_output "[+] Interesting function in ""$(print_path "$LINE")"" found:"
          for VUL_FUNC in "${VUL_FUNC_RESULT[@]}" ; do
            # shellcheck disable=SC2001
            VUL_FUNC="$(echo "$VUL_FUNC" | sed -e 's/[[:space:]]\+/\t/g')"
            print_output "$(indent "$VUL_FUNC")"
          done
          COUNTER=$((COUNTER+1))
        fi
      fi
    done
    print_output "[*] Found ""$COUNTER"" binaries with interesting functions in ""$BIN_COUNT"" files (vulnerable functions: ""$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ /g' )"")"
  fi

  module_end_log "${FUNCNAME[0]}" "$COUNTER"
}
