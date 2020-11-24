#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann, Stefan Haböck

# Description:  Check user authentication:
#                 Users with UID 0, non unique accounts, non unique group id, non unique group name, user accounts,
#                 NIS(+) authentication, sudoers, permissions for sudo config, pam related files and configs
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


# This module is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_authentication

S50_authentication_check() {
  module_log_init "s50_check_user_group_and_authentication"
  module_title "Check users, groups and authentication"
  CONTENT_AVAILABLE=0
  
  user_zero
  non_unique_acc
  non_unique_group_id
  non_unique_group_name
  query_user_acc
  query_nis_plus_auth_supp
  check_sudoers
  check_owner_perm_sudo_config
  search_pam_testing_libs
  scan_pam_conf
  search_pam_configs
  search_pam_files
  
  if [[ $HTML == 1 ]]; then
     generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

user_zero() {
  sub_module_title "Users with UID zero (0)"

  print_output "[*] Searching accounts with UID 0"
  local CHECK=0
  local PASSWD_FILE_PATHS
  PASSWD_FILE_PATHS="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/passwd")"
  for PASSWD_FILE in $PASSWD_FILE_PATHS; do
    if [[ -f "$PASSWD_FILE" ]] ; then
      CHECK=1
      local FIND
      FIND=$(grep ':0:' "$PASSWD_FILE" | grep -v '^#|^root:|^(\+:\*)?:0:0:::' | cut -d ":" -f1,3 | grep ':0')
      if [[ -n "$FIND" ]] ; then
        print_output "[+] Found administrator account/s with UID 0 in ""$(print_path "$PASSWD_FILE")"
        print_output "$(indent "$(orange "Administrator account: $FIND")")"
      else
        print_output "[-] Found no administrator account (root) with UID 0"
      fi
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] /etc/passwd not available"
  else
    CONTENT_AVAILABLE=1
  fi
}

non_unique_acc() {
  sub_module_title "Non-unique accounts"

  print_output "[*] Searching non-unique accounts"
  local CHECK=0
  local PASSWD_FILE_PATHS
  PASSWD_FILE_PATHS="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/passwd")"
  for PASSWD_FILE in $PASSWD_FILE_PATHS; do
    if [[ -f "$PASSWD_FILE" ]] ; then
      CHECK=1
      local FIND
      FIND=$(grep -v '^#' "$PASSWD_FILE" | cut -d ':' -f3 | sort | uniq -d)
      if [[ "$FIND" = "" ]] ; then
        print_output "[-] All accounts found in ""$(print_path "$PASSWD_FILE")"" are unique"
      else
        print_output "[+] Non-unique accounts found in ""$(print_path "$PASSWD_FILE")"
        print_output "$(indent "$(orange "$FIND")")"
      fi
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] /etc/passwd not available"
  else
    CONTENT_AVAILABLE=1
  fi
}

non_unique_group_id() {
  sub_module_title "Unique group IDs"

  print_output "[*] Searching non-unique group ID's"
  local CHECK=0
  local GROUP_PATHS
  GROUP_PATHS="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/group")"
  for GROUP_PATH in $GROUP_PATHS; do
    if [[ -f "$GROUP_PATH" ]] ; then
      CHECK=1
      local FIND
      FIND=$(grep -v '^#' "$GROUP_PATH" | grep -v '^$' | awk -F: '{ print $3 }' | sort | uniq -d)
      if [[ "$FIND" = "" ]] ; then
        print_output "[-] All group ID's found in ""$(print_path "$GROUP_PATH")"" are unique"
      else
        print_output "[+] Found the same group ID multiple times"
        print_output "$(indent "$(orange "Non-unique group id: ""$FIND")")"
      fi
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] /etc/group not available"
  else
    CONTENT_AVAILABLE=1
  fi
}

non_unique_group_name() {
  sub_module_title "Unique group name"

  print_output "[*] Searching non-unique group names"
  local CHECK=0
  local GROUP_PATHS
  GROUP_PATHS="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/group")"
  for GROUP_PATH in $GROUP_PATHS; do
    if [[ -f "$GROUP_PATH" ]] ; then
      CHECK=1
      local FIND
      FIND=$(grep -v '^#' "$GROUP_PATH" | grep -v '^$' | awk -F: '{ print $1 }' | sort | uniq -d)
      if [[ "$FIND" = "" ]] ; then
        print_output "[-] All group names found in ""$(print_path "$GROUP_PATH")"" are unique"
      else
        print_output "[+] Found the same group name multiple times"
        print_output "$(indent "$(orange "Non-unique group name: ""$FIND")")"
      fi
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] /etc/group not available"
  else
    CONTENT_AVAILABLE=1
  fi
}

query_user_acc() {
  sub_module_title "Query user accounts"

  print_output "[*] Reading system users"
  local CHECK=0
  local PASSWD_FILE_PATHS
  PASSWD_FILE_PATHS="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/passwd")"
  for PASSWD_FILE in $PASSWD_FILE_PATHS; do
    if [[ -f "$PASSWD_FILE" ]] ; then
      CHECK=1
      local UID_MIN LOGIN_DEFS_PATH
      UID_MIN=""
      LOGIN_DEFS_PATH="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/login.defs")"
      for LOGIN_DEF in $LOGIN_DEFS_PATH; do
        if [[ -f "$LOGIN_DEF" ]] ; then
          UID_MIN=$(grep "^UID_MIN" "$LOGIN_DEF" | awk '{print $2}')
          print_output "[*] Found minimal user id specified: ""$UID_MIN"
        fi
      done
      if [[ "$UID_MIN" = "" ]] ; then
        UID_MIN="1000"
      fi
      print_output "[*] Linux real users output (ID = 0, or ""$UID_MIN""+, but not 65534):"
      FIND=$(awk -v UID_MIN="$UID_MIN" -F: '($3 >= UID_MIN && $3 != 65534) || ($3 == 0) { print $1","$3 }' "$PASSWD_FILE")

      if [[ "$FIND" = "" ]] ; then
        print_output "[-] No users found/unknown result"
      else
        print_output "[+] Query system user"
        print_output "$(indent "$(orange "$FIND")")"
      fi
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] /etc/passwd not available"
  else
    CONTENT_AVAILABLE=1
  fi
}

query_nis_plus_auth_supp() {
  sub_module_title "Query NIS and NIS+ authentication support"

  print_output "[*] Check nsswitch.conf"
  local CHECK=0
  local NSS_PATH_L
  NSS_PATH_L="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/nsswitch.conf")"
  for NSS_PATH in $NSS_PATH_L; do
    if [[ -f "$NSS_PATH" ]] ; then
      CHECK=1
      print_output "[+] ""$(print_path "$NSS_PATH")"" exist"
      local FIND
      FIND="$(grep "^passwd" "$NSS_PATH" | grep "compat|nis" | grep -v "nisplus")"
      if [[ -z "$FIND" ]] ; then
        print_output "[-] NIS/NIS+ authentication not enabled"
      else
        local FIND2, FIND3, FIND4, FIND5
        FIND2=$(grep "^passwd_compat" "$NSS_PATH" | grep "nis" | grep -v "nisplus")
        FIND3=$(grep "^passwd" "$NSS_PATH" | grep "nis" | grep -v "nisplus")
        if [[ -n "$FIND2" ]] || [[ -n "$FIND3" ]] ; then
          print_output "[+] Result: NIS authentication enabled"
        else
          print_output "[+] Result: NIS authentication not enabled"
        fi
        FIND4=$(grep "^passwd_compat" "$NSS_PATH" | grep "nisplus")
        FIND5=$(grep "^passwd" "$NSS_PATH" | grep "nisplus")
        if [[ -n "$FIND4" ]] || [[ -n "$FIND5" ]] ; then
          print_output "[+] Result: NIS+ authentication enabled"
        else
          print_output "[+] Result: NIS+ authentication not enabled"
        fi
      fi
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] /etc/nsswitch.conf not available"
  else
    CONTENT_AVAILABLE=1
  fi
}

check_sudoers() {
  sub_module_title "Scan for sudoers files"
  SUDOERS_FILES_COUNT="0"
  SUDOERS_FILES="$(config_find "$CONFIG_DIR""/sudoers_files.cfg" "")"

  if [[ "$SUDOERS_FILES" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif ! [[ "$SUDOERS_FILES" == "" ]] ; then
    SUDOERS_FILES_COUNT="$(echo "$SUDOERS_FILES" | wc -w)"

    if [[ "$SUDOERS_FILES_COUNT" != "0" ]] ; then
      print_output "[+] ""$SUDOERS_FILES_COUNT"" sudoers files found"
      readarray -t SUDOERS_FILES_ARR < <(printf '%s' "$SUDOERS_FILES")
      for SUDOERS_FILE in "${SUDOERS_FILES_ARR[@]}"; do
        print_output "$(indent "$(orange "$(print_path "$SUDOERS_FILE")")")"
      done
    fi
    CONTENT_AVAILABLE=1
  else
    print_output "[-] No sudoers files found"
  fi
}

check_owner_perm_sudo_config() {
  sub_module_title "Ownership and permissions for sudo configuration files"

  if [[ "$SUDOERS_FILES_COUNT" == "0" ]] ; then
    print_output "[-] No sudoers files found - no check possible"
  else
    local SUDOERS_FILES_ARR
    readarray -t SUDOERS_FILES_ARR < <(printf '%s' "$SUDOERS_FILES")
    for FILE in "${SUDOERS_FILES_ARR[@]}"; do
      local SUDOERS_D
      SUDOERS_D="$FILE"".d"
      if [[ -d "$SUDOERS_D" ]] ; then
        print_output "[*] Checking drop-in directory (""$(print_path "$SUDOERS_D")"")"
        local FIND FIND2 FIND3 FIND4

        FIND="$(permission_clean "$SUDOERS_D")"
        FIND2="$(owner_clean "$SUDOERS_D")"":""$(group_clean "$SUDOERS_D")"

        print_output "[*] ""$(print_path "$SUDOERS_D")"": Found permissions: $FIND and owner UID GID: $FIND2"

        case "$FIND" in
        drwx[r-][w-][x-]---)
          print_output "[-] ""$(print_path "$SUDOERS_D")"" permissions OK"
          if [[ "$FIND2" = "0:0" ]] ; then
            print_output "[-] ""$(print_path "$SUDOERS_D")"" ownership OK"
          else
            print_output "[+] ""$(print_path "$SUDOERS_D")"" ownership unsafe"
          fi
          ;;
        *)
          print_output "[+] ""$(print_path "$SUDOERS_D")"" permissions possibly unsafe"
          if [[ "$FIND2" = "0:0" ]] ; then
            print_output "[-] ""$(print_path "$SUDOERS_D")"" ownership OK"
          else
            print_output "[+] ""$(print_path "$SUDOERS_D")"" ownership unsafe"
          fi
          ;;
        esac
      fi

      FIND3="$(permission_clean "$FILE")"
      FIND4="$(owner_clean "$FILE")"":""$(group_clean "$FILE")"

      print_output "[*] ""$(print_path "$FILE")"": Found permissions: ""$FIND3"" and owner UID GID: ""$FIND4"

      case "$FIND3" in
      rwx[r-][w-][x-]---)
        print_output "[-] ""$(print_path "$FILE")"" permissions OK"
        if [[ "$FIND4" = "0:0" ]] ; then
          print_output "[-] ""$(print_path "$FILE")"" ownership OK"
        else
          print_output "[+] ""$(print_path "$FILE")"" ownership unsafe"
          CONTENT_AVAILABLE=1
        fi
        ;;
      *)
        print_output "[+] ""$(print_path "$FILE")"" permissions possibly unsafe"
        if [[ "$FIND4" = "0:0" ]] ; then
          print_output "[-] ""$(print_path "$FILE")"" ownership OK"
        else
          print_output "[+] ""$(print_path "$FILE")"" ownership unsafe"
          CONTENT_AVAILABLE=1
        fi
        ;;
      esac
    done
  fi
}

search_pam_testing_libs() {
  sub_module_title "Search for PAM password strength testing libraries"

  print_output "[*] Searching PAM password testing modules (cracklib, passwdqc, pwquality)"

  local FILE_PATH FOUND FOUND_CRACKLIB FOUND_PASSWDQC FOUND_PWQUALITY
  FILE_PATH="$(mod_path_array "$(config_list "$CONFIG_DIR""/pam_files.cfg" "")")"

  if [[ "$FILE_PATH" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif ! [[ "$FILE_PATH" == "" ]] ; then
    local FOUND=0
    FOUND_CRACKLIB=0
    FOUND_PASSWDQC=0
    FOUND_PWQUALITY=0

    for PATH_F in $FILE_PATH; do
      local FULL_PATH
      FULL_PATH="$FIRMWARE_PATH""/""$PATH_F"

      if [[ -f "$FULL_PATH""/pam_cracklib.so" ]] ; then
        FOUND_CRACKLIB=1
        FOUND=1
        print_output "[+] Found pam_cracklib.so (crack library PAM) in ""$(print_path "$FULL_PATH")"
      fi

      if [[ -f "$FULL_PATH""/pam_passwdqc.so" ]] ; then
        FOUND_PASSWDQC=1
        FOUND=1
        print_output "[+] Found pam_passwdqc.so (passwd quality control PAM) in ""$(print_path "$FULL_PATH")"
      fi

      if [[ -f "$FULL_PATH""/pam_pwquality.so" ]] ; then
        FOUND_PWQUALITY=1
        FOUND=1
        print_output "[+] Found pam_pwquality.so (password quality control PAM) in ""$(print_path "$FULL_PATH")"
      fi
    done

    # Cracklib
    if [[ $FOUND_CRACKLIB -eq 1 ]] ; then
      print_output "[+] pam_cracklib.so found"
      CONTENT_AVAILABLE=1
    else
      print_output "[-] pam_cracklib.so not found"
    fi

    # Password quality control
    if [[ $FOUND_PASSWDQC -eq 1 ]] ; then
      print_output "[+] pam_passwdqc.so found"
      CONTENT_AVAILABLE=1
    else
      print_output "[-] pam_passwdqc.so not found"
    fi

    # pwquality module
    if [[ $FOUND_PWQUALITY -eq 1 ]] ; then
      print_output "[+] pam_pwquality.so found"
      CONTENT_AVAILABLE=1
    else
      print_output "[-] pam_pwquality.so not found"
    fi

    if [[ $FOUND -eq 0 ]] ; then
      print_output "[-] No PAM modules for password strength testing found"
    else
      print_output "[-] Found at least one PAM module for password strength testing"
    fi

  else
    print_output "[-] No pam files found"
  fi

}

scan_pam_conf() {
  sub_module_title "Scan PAM configuration file"

  local CHECK=0
  local PAM_PATH_L
  PAM_PATH_L="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/pam.conf")"
  for PAM_PATH in $PAM_PATH_L; do
    if [[ -f "$PAM_PATH" ]] ; then
      CHECK=1
      print_output "[+] ""$(print_path "$PAM_PATH")"" exist"
      local FIND
      FIND=$(grep -v "^#" "$PAM_PATH" | grep -v "^$" | sed 's/[[:space:]]/ /g' | sed 's/  / /g' | sed 's/ /:space:/g')
      if [[ -z "$FIND" ]] ; then
        print_output "[-] File has no configuration options defined (empty, or only filled with comments and empty lines)"
      else
        print_output "[+] Found one or more configuration lines"
        CONTENT_AVAILABLE=1
        local LINE
        LINE=$(echo "$FIND" | ${SEDBINARY} 's/:space:/ /g')
        print_output "$(indent "$(orange "$LINE")")"
      fi
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] /etc/pam.conf not available"
  fi
}

search_pam_configs() {
  sub_module_title "Searching PAM configurations and LDAP support in PAM files"

  local CHECK
  CHECK=0
  local PAM_PATH_L
  PAM_PATH_L="$(mod_path "$FIRMWARE_PATH""/ETC_PATHS/pam.d")"
  for PAM_PATH in $PAM_PATH_L; do
    if [[ -d "$PAM_PATH" ]] ; then
      CHECK=1
      print_output "[+] ""$(print_path "${PAM_PATH}")"" exist"
      local FIND
      FIND=$(find "${PAM_PATH}" -not -name "*.pam-old" -type f -print | sort)
      readarray -t FILES_ARR < <(printf '%s' "$FIND")
      for FILE in "${FILES_ARR[@]}"; do
        print_output "$(indent "$(orange "$(print_path "$FILE")")")"
      done
      local AUTH_FILES
      AUTH_FILES=("$PAM_PATH""/common-auth" "$PAM_PATH""/system-auth")
      for FILE in "${AUTH_FILES[@]}"; do
        print_output "[*] Check if LDAP support in PAM files"
        if [[ -f "$FILE" ]] ; then
          print_output "[+] ""$(print_path "$FILE")"" exist"
          local FIND2
          FIND2=$(grep "^auth.*ldap" "$FILE")
          if [[ -n "$FIND2" ]] ; then
            print_output "[+] LDAP module present"
            print_output "$(indent "$(orange "$FIND2")")"
            CONTENT_AVAILABLE=1
          else
            print_output "[-] LDAP module not found"
          fi
        else
          print_output "[-] ""$(print_path "$FILE")"" not found"
        fi
      done
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] /etc/pam.d not available"
  fi
}

search_pam_files() {
  sub_module_title "Searching available PAM files"

  local CHECK=0
  local PAM_FILES
  readarray -t PAM_FILES < <(config_find "$CONFIG_DIR""/pam_files.cfg")

  if [[ "${PAM_FILES[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ ${#PAM_FILES[@]} -ne 0 ]] ; then
    print_output "[*] Found ""${#PAM_FILES[@]}"" possible interesting file/s and/or directory/ies for PAM:"
    for LINE in "${PAM_FILES[@]}" ; do
      if [[ -f "$LINE" ]] ; then
        CHECK=1
        print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      fi
      if [[ -d "$LINE" ]] && [[ ! -L "$LINE" ]] ; then
        print_output "$(indent "$(print_path "$LINE")")"
        local FIND
        FIND=$(find "$LINE" -maxdepth 1 -type f -name "pam_*.so" -print | sort)
        for FIND_FILE in $FIND; do
          CHECK=1
          print_output "$(indent "$(orange "$FIND_FILE")")"
        done
      fi
    done
    if [[ $CHECK -eq 0 ]] ; then
      print_output "[-] Nothing interesting found"
    else
      CONTENT_AVAILABLE=1
    fi
  else
    print_output "[-] Nothing found"
  fi
}
