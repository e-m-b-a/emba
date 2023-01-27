#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Looks for ssh-related files and checks squid configuration.

S85_ssh_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check SSH"
  pre_module_reporter "${FUNCNAME[0]}"

  export SSH_VUL_CNT=0
  export SQUID_VUL_CNT=0
  local NEG_LOG=0

  search_ssh_files
  check_squid

  write_log ""
  write_log "[*] Statistics:$SSH_VUL_CNT:$SQUID_VUL_CNT"

  if [[ "$SQUID_VUL_CNT" -gt 0 || "$SSH_VUL_CNT" -gt 0 ]]; then
    NEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

search_ssh_files()
{
  sub_module_title "Search ssh files"

  local SSH_FILES=()
  local LINE=""
  local SSHD_ISSUES=()
  local S_ISSUE=""

  mapfile -t SSH_FILES < <(config_find "$CONFIG_DIR""/ssh_files.cfg")

  if [[ "${SSH_FILES[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#SSH_FILES[@]}" -ne 0 ]] ; then
    print_output "[+] Found ""${#SSH_FILES[@]}"" ssh configuration files:"
    for LINE in "${SSH_FILES[@]}" ; do
      if [[ -f "$LINE" ]] ; then
        print_output "$(indent "$(orange "$(print_path "$LINE")")")" "" "$LINE"
        if [[ -f "$EXT_DIR"/sshdcc ]]; then
          local PRINTER=0
          if [[ "$(basename "$LINE")" == "sshd_config"  ]]; then
            print_output "[*] Testing sshd configuration file with sshdcc"
            readarray SSHD_ISSUES < <("$EXT_DIR"/sshdcc -ns -nc -f "$LINE")
            for S_ISSUE in "${SSHD_ISSUES[@]}"; do
              if [[ "$S_ISSUE" == *RESULTS* || "$PRINTER" -eq 1 ]]; then
                # print finding title as EMBA finding:
                if [[ "$S_ISSUE" =~ ^\([0-9+]\)\ \[[A-Z]+\]\  ]]; then
                  print_output "[+] $S_ISSUE"
                  ((SSH_VUL_CNT+=1))
                # print everything else (except RESULTS and done) as usual output
                elif ! [[ "$S_ISSUE" == *RESULTS* || "$S_ISSUE" == *done* ]]; then
                  print_output "[*] $S_ISSUE"
                  # with indent the output looks weird:
                  # print_output "$(indent "$(orange "$S_ISSUE")")"
                fi
                PRINTER=1
              fi
            done
          elif [[ "$(basename "$LINE")" == *"authorized_key"*  ]]; then
            print_output "[+] Warning: Possible ${ORANGE}authorized_key${GREEN} backdoor detected: ${ORANGE}$LINE${NC}"
            ((SSH_VUL_CNT+=1))
          fi
        fi
      fi
    done
  else
    print_output "[-] No ssh configuration files found"
  fi
}

# This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_squid
# Detailed tests possible, check if necessary
check_squid()
{
  sub_module_title "Check squid"
  local BIN_FILE=""
  local CHECK=0
  local SQUID_E=""

  for BIN_FILE in "${BINARIES[@]}"; do
    if [[ "$BIN_FILE" == *"squid"* ]] && ( file "$BIN_FILE" | grep -q ELF ) ; then
      print_output "[+] Found possible squid executable: ""$ORANGE$(print_path "$BIN_FILE")$NC"
      ((SQUID_VUL_CNT+=1))
    fi
  done
  [[ $SQUID_VUL_CNT -eq 0 ]] && print_output "[-] No possible squid executable found"

  local SQUID_DAEMON_CONFIG_LOCS=("/ETC_PATHS" "/ETC_PATHS/squid" "/ETC_PATHS/squid3" "/usr/local/etc/squid" "/usr/local/squid/etc")
  mapfile -t SQUID_PATHS_ARR < <(mod_path_array "${SQUID_DAEMON_CONFIG_LOCS[@]}")
  if [[ "${SQUID_PATHS_ARR[0]-}" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif [[ "${#SQUID_PATHS_ARR[@]}" -ne 0 ]] ; then
    for SQUID_E in "${SQUID_PATHS_ARR[@]}"; do
      if [[ -f "$SQUID_E""/squid.conf" ]] ; then
        CHECK=1
        print_output "[+] Found squid config: ""$ORANGE$(print_path "$SQUID_E")$NC"
        ((SQUID_VUL_CNT+=1))
      elif [[ -f "$SQUID_E""/squid3.conf" ]] ; then
        CHECK=1
        print_output "[+] Found squid config: ""$ORANGE$(print_path "$SQUID_E")$NC"
        ((SQUID_VUL_CNT+=1))
      fi
      if [[ $CHECK -eq 1 ]] ; then
        print_output "[*] Check external access control list type:"
        print_output "$(indent "$(grep "^external_acl_type" "$SQUID_E")")"
        print_output "[*] Check access control list:"
        print_output "$(indent "$(grep "^acl" "$SQUID_E" | sed 's/ /!space!/g')")"
      fi
    done
  fi
  [[ $CHECK -eq 0 ]] && print_output "[-] No squid configuration found"
}
