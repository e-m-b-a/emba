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

# Description:  Checks for users with UID 0; for non-unique accounts, group IDs, group names; scans all available user accounts
#               and possible NIS(+) authentication support. It looks up sudoers file and analyzes it for possible vulnerabilities.
#               It also searches for PAM authentication files and analyze their usage.

# This module is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_authentication
S50_authentication_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Check users, groups and authentication"
  pre_module_reporter "${FUNCNAME[0]}"

  local lAUTH_ISSUES=0
  local lWAIT_PIDS_S50=()

  # disabled internal module threading as the output is not readable anymore
  if [[ "${THREADED}" -eq 9 ]]; then
    user_zero &
    lWAIT_PIDS_S50+=( "$!" )
    search_shadow &
    lWAIT_PIDS_S50+=( "$!" )
    non_unique_acc &
    lWAIT_PIDS_S50+=( "$!" )
    non_unique_group_id &
    lWAIT_PIDS_S50+=( "$!" )
    non_unique_group_name &
    lWAIT_PIDS_S50+=( "$!" )
    query_user_acc &
    lWAIT_PIDS_S50+=( "$!" )
    query_nis_plus_auth_supp &
    lWAIT_PIDS_S50+=( "$!" )
    check_sudoers &
    lWAIT_PIDS_S50+=( "$!" )
    check_owner_perm_sudo_config &
    lWAIT_PIDS_S50+=( "$!" )
    search_pam_testing_libs &
    lWAIT_PIDS_S50+=( "$!" )
    scan_pam_conf &
    lWAIT_PIDS_S50+=( "$!" )
    search_pam_configs &
    lWAIT_PIDS_S50+=( "$!" )
    search_pam_files &
    lWAIT_PIDS_S50+=( "$!" )
  else
    user_zero
    search_shadow
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
  fi

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S50[@]}"

  if [[ -f "${TMP_DIR}"/S50_AUTH_ISSUES.tmp ]]; then
    lAUTH_ISSUES=$(awk '{sum += $1 } END { print sum }' "${TMP_DIR}"/S50_AUTH_ISSUES.tmp)
  fi
  write_log ""
  write_log "[*] Statistics:${lAUTH_ISSUES}"
  module_end_log "${FUNCNAME[0]}" "${lAUTH_ISSUES}"
}

search_shadow() {
  sub_module_title "Shadow file identification"

  print_output "[*] Searching shadow files"
  local lAUTH_ISSUES=0
  local lSHADOW_FILE_PATHS_ARR=()
  local lHASHES_ARR=()
  local lSHADOW_FILE=""
  local lHASH=""
  local lCHECK=0

  mapfile -t lSHADOW_FILE_PATHS_ARR < <(find "${LOG_DIR}"/firmware -xdev -name "*shadow*"  -print0|xargs -0 -P 16 -I % sh -c 'file % | grep "ASCII text" | cut -d: -f1' || true)
  for lSHADOW_FILE in "${lSHADOW_FILE_PATHS_ARR[@]}"; do
    if [[ -f "${lSHADOW_FILE}" ]] ; then
      mapfile -t lHASHES_ARR < <(grep -E '\$[1-6][ay]?\$' "${lSHADOW_FILE}" || true)
      for lHASH in "${lHASHES_ARR[@]}"; do
        local HTYPE="unknown"
        if [[ "${lHASH}" =~ .*\$1\$.* ]]; then
          HTYPE="MD5"
        elif [[ "${lHASH}" =~ .*\$2a\$.* ]]; then
          HTYPE="Blowfish"
        elif [[ "${lHASH}" =~ .*\$2y\$.* ]]; then
          HTYPE="Eksblowfish"
        elif [[ "${lHASH}" =~ .*\$5\$.* ]]; then
          HTYPE="SHA-256"
        elif [[ "${lHASH}" =~ .*\$6\$.* ]]; then
          HTYPE="SHA-512"
        fi
        if [[ "${HTYPE}" == "unknown" ]]; then
          print_output "[+] Found shadow file ""${ORANGE}$(print_path "${lSHADOW_FILE}")${GREEN} with possible hash ${ORANGE}${lHASH}${NC}"
          ((lAUTH_ISSUES+=1))
          continue
        fi
        print_output "[+] Found shadow file ""${ORANGE}$(print_path "${lSHADOW_FILE}")${GREEN} with possible hash ${ORANGE}${lHASH}${GREEN} of hashtype: ${ORANGE}${HTYPE}${NC}"
        ((lAUTH_ISSUES+=1))
      done
      lCHECK=1
    fi
  done
  if [[ ${lCHECK} -eq 0 ]] ; then
    print_output "[-] shadow file not available"
  fi
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

user_zero() {
  sub_module_title "Users with UID zero (0)"

  print_output "[*] Searching accounts with UID 0"
  local lCHECK=0
  local lAUTH_ISSUES=0
  local lPASSWD_FILE_PATHS=()
  local lPASSWD_FILE=""
  mapfile -t lPASSWD_FILE_PATHS_ARR < <(mod_path "/ETC_PATHS/passwd")

  for PASSWD_FILE in "${lPASSWD_FILE_PATHS_ARR[@]}"; do
    if [[ -f "${lPASSWD_FILE}" ]] ; then
      lCHECK=1
      local lFIND=""
      lFIND=$(grep ':0:' "${lPASSWD_FILE}" | grep -v '^#|^root:|^(\+:\*)?:0:0:::' | cut -d ":" -f1,3 | grep ':0' || true)
      if [[ -n "${lFIND}" ]] ; then
        print_output "[+] Found administrator account/s with UID 0 in ""$(print_path "${lPASSWD_FILE}")"
        print_output "$(indent "$(orange "Administrator account: ${lFIND}")")"
        ((lAUTH_ISSUES+=1))
      else
        print_output "[-] Found no administrator account (root) with UID 0"
      fi
    fi
  done
  [[ ${lCHECK} -eq 0 ]] && print_output "[-] /etc/passwd not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

non_unique_acc() {
  sub_module_title "Non-unique accounts"

  print_output "[*] Searching non-unique accounts"
  local CHECK=0
  local lAUTH_ISSUES=0
  local PASSWD_FILE_PATHS=()
  local PASSWD_FILE=""

  mapfile -t PASSWD_FILE_PATHS < <(mod_path "/ETC_PATHS/passwd")

  for PASSWD_FILE in "${PASSWD_FILE_PATHS[@]}"; do
    if [[ -f "${PASSWD_FILE}" ]] ; then
      CHECK=1
      local FIND=""
      FIND=$(grep -v '^#' "${PASSWD_FILE}" | cut -d ':' -f3 | sort | uniq -d || true)
      if [[ "${FIND}" = "" ]] ; then
        print_output "[-] All accounts found in ""$(print_path "${PASSWD_FILE}")"" are unique"
      else
        print_output "[+] Non-unique accounts found in ""$(print_path "${PASSWD_FILE}")"
        print_output "$(indent "$(orange "${FIND}")")"
        ((lAUTH_ISSUES+=1))
      fi
    fi
  done
  [[ ${CHECK} -eq 0 ]] && print_output "[-] /etc/passwd not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

non_unique_group_id() {
  sub_module_title "Unique group IDs"

  print_output "[*] Searching non-unique group ID's"
  local lCHECK=0
  local lAUTH_ISSUES=0
  local lGROUP_PATHS_ARR=()
  local lGROUP_PATH=""

  mapfile -t lGROUP_PATHS_ARR < <(mod_path "/ETC_PATHS/group")

  for lGROUP_PATH in "${lGROUP_PATHS_ARR[@]}"; do
    if [[ -f "${lGROUP_PATH}" ]] ; then
      lCHECK=1
      local lFIND=""
      lFIND=$(grep -v '^#' "${lGROUP_PATH}" | grep -v '^$' | awk -F: '{ print $3 }' | sort | uniq -d || true)
      if [[ "${lFIND}" = "" ]] ; then
        print_output "[-] All group ID's found in ""$(print_path "${lGROUP_PATH}")"" are unique"
      else
        print_output "[+] Found the same group ID multiple times"
        print_output "$(indent "$(orange "Non-unique group id: ""${lFIND}")")"
        ((lAUTH_ISSUES+=1))
      fi
    fi
  done
  [[ ${lCHECK} -eq 0 ]] && print_output "[-] /etc/group not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

non_unique_group_name() {
  sub_module_title "Unique group name"

  print_output "[*] Searching non-unique group names"
  local lCHECK=0
  local lAUTH_ISSUES=0
  local lGROUP_PATHS_ARR=()
  local lGROUP_PATH=""
  mapfile -t lGROUP_PATHS_ARR < <(mod_path "/ETC_PATHS/group")

  for lGROUP_PATH in "${lGROUP_PATHS_ARR[@]}"; do
    if [[ -f "${lGROUP_PATH}" ]] ; then
      lCHECK=1
      local lFIND=""
      lFIND=$(grep -v '^#' "${lGROUP_PATH}" | grep -v '^$' | awk -F: '{ print $1 }' | sort | uniq -d || true)
      if [[ "${lFIND}" = "" ]] ; then
        print_output "[-] All group names found in ""$(print_path "${lGROUP_PATH}")"" are unique"
      else
        print_output "[+] Found the same group name multiple times"
        print_output "$(indent "$(orange "Non-unique group name: ""${lFIND}")")"
        ((lAUTH_ISSUES+=1))
      fi
    fi
  done
  [[ ${lCHECK} -eq 0 ]] && print_output "[-] /etc/group not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

query_user_acc() {
  sub_module_title "Query user accounts"

  print_output "[*] Reading system users"
  local lCHECK=0
  local lAUTH_ISSUES=0
  local PASSWD_FILE_PATHS=()
  local PASSWD_FILE=""

  mapfile -t lPASSWD_FILE_PATHS_ARR < <(mod_path "/ETC_PATHS/passwd")

  for PASSWD_FILE in "${lPASSWD_FILE_PATHS_ARR[@]}"; do
    if [[ -f "${PASSWD_FILE}" ]] ; then
      lCHECK=1
      local UID_MIN=""
      local LOGIN_DEFS_PATH=""
      mapfile -t LOGIN_DEFS_PATH < <(mod_path "/ETC_PATHS/login.defs")
      for LOGIN_DEF in "${LOGIN_DEFS_PATH[@]}"; do
        if [[ -f "${LOGIN_DEF}" ]] ; then
          UID_MIN=$(grep "^UID_MIN" "${LOGIN_DEF}" | awk '{print $2}')
          print_output "[*] Found minimal user id specified: ""${UID_MIN}"
        fi
      done
      [[ "${UID_MIN}" = "" ]] && UID_MIN="1000"
      print_output "[*] Linux real users output (ID = 0, or ""${UID_MIN}""+, but not 65534):"
      FIND=$(awk -v UID_MIN="${UID_MIN}" -F: '($3 >= UID_MIN && $3 != 65534) || ($3 == 0) { print $1","$3 }' "${PASSWD_FILE}")

      if [[ "${FIND}" = "" ]] ; then
        print_output "[-] No users found/unknown result"
      else
        print_output "[+] Query system user"
        print_output "$(indent "$(orange "${FIND}")")"
      fi
    fi
  done
  [[ ${lCHECK} -eq 0 ]] && print_output "[-] /etc/passwd not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

query_nis_plus_auth_supp() {
  sub_module_title "Query NIS and NIS+ authentication support"

  print_output "[*] Check nsswitch.conf"
  local CHECK=0
  local lAUTH_ISSUES=0
  local NSS_PATH_L=()
  local NSS_PATH=""

  mapfile -t NSS_PATH_L < <(mod_path "/ETC_PATHS/nsswitch.conf")

  for NSS_PATH in "${NSS_PATH_L[@]}"; do
    if [[ -f "${NSS_PATH}" ]] ; then
      CHECK=1
      print_output "[+] ""$(print_path "${NSS_PATH}")"" exist"
      local FIND=""
      FIND="$(grep "^passwd" "${NSS_PATH}" | grep "compat|nis" | grep -v "nisplus" || true)"
      if [[ -z "${FIND}" ]] ; then
        print_output "[-] NIS/NIS+ authentication not enabled"
      else
        local FIND2=""
        local FIND3=""
        local FIND4=""
        local FIND5=""
        FIND2=$(grep "^passwd_compat" "${NSS_PATH}" | grep "nis" | grep -v "nisplus" || true)
        FIND3=$(grep "^passwd" "${NSS_PATH}" | grep "nis" | grep -v "nisplus" || true)
        if [[ -n "${FIND2}" ]] || [[ -n "${FIND3}" ]] ; then
          print_output "[+] Result: NIS authentication enabled"
        else
          print_output "[+] Result: NIS authentication not enabled"
        fi
        FIND4=$(grep "^passwd_compat" "${NSS_PATH}" | grep "nisplus" || true)
        FIND5=$(grep "^passwd" "${NSS_PATH}" | grep "nisplus" || true)
        if [[ -n "${FIND4}" ]] || [[ -n "${FIND5}" ]] ; then
          print_output "[+] Result: NIS+ authentication enabled"
        else
          print_output "[+] Result: NIS+ authentication not enabled"
        fi
      fi
    fi
  done
  [[ ${CHECK} -eq 0 ]] && print_output "[-] /etc/nsswitch.conf not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

check_sudoers() {
  sub_module_title "Scan and test sudoers files"
  local SUDOERS_ISSUES=()
  local lAUTH_ISSUES=0
  local S_ISSUE=""
  local R_PATH=""
  export SUDOERS_FILES_ARR=()
  local SUDOERS_FILE=""

  for R_PATH in "${ROOT_PATH[@]}"; do
    # as we only have one search term we can handle it like this:
    readarray -t SUDOERS_FILES_ARR < <(find "${R_PATH}" -xdev -type f -name sudoers 2>/dev/null)
    if [[ "${#SUDOERS_FILES_ARR[@]}" -gt 0 ]]; then
      for SUDOERS_FILE in "${SUDOERS_FILES_ARR[@]}"; do
        print_output "$(indent "$(orange "$(print_path "${SUDOERS_FILE}")")")"
        if [[ -f "${EXT_DIR}"/sudo-parser.pl ]]; then
          print_output "[*] Testing sudoers file with sudo-parse.pl:"
          readarray SUDOERS_ISSUES < <("${EXT_DIR}"/sudo-parser.pl -f "${SUDOERS_FILE}" -r "${R_PATH}" | grep -E "^E:\ " || true)
          for S_ISSUE in "${SUDOERS_ISSUES[@]}"; do
            print_output "[+] ${S_ISSUE}"
            ((lAUTH_ISSUES+=1))
          done
        fi
      done
    else
      print_output "[-] No sudoers files found in ${R_PATH}"
    fi
  done
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

check_owner_perm_sudo_config() {
  sub_module_title "Ownership and permissions for sudo configuration files"

  local lAUTH_ISSUES=0
  local FILE=""

  if [[ "${#SUDOERS_FILES_ARR[@]}" -gt 0 ]]; then
    for FILE in "${SUDOERS_FILES_ARR[@]}"; do
      local SUDOERS_D="${FILE}"".d"
      if [[ -d "${SUDOERS_D}" ]] ; then
        print_output "[*] Checking drop-in directory (""$(print_path "${SUDOERS_D}")"")"
        local FIND=""
        local FIND2=""
        local FIND3=""
        local FIND4=""

        FIND="$(permission_clean "${SUDOERS_D}")"
        FIND2="$(owner_clean "${SUDOERS_D}")"":""$(group_clean "${SUDOERS_D}")"

        print_output "[*] ""$(print_path "${SUDOERS_D}")"": Found permissions: ${FIND} and owner UID GID: ${FIND2}"

        case "${FIND}" in
        drwx[r-][w-][x-]---)
          print_output "[-] ""$(print_path "${SUDOERS_D}")"" permissions OK"
          if [[ "${FIND2}" = "0:0" ]] ; then
            print_output "[-] ""$(print_path "${SUDOERS_D}")"" ownership OK"
          else
            print_output "[+] ""$(print_path "${SUDOERS_D}")"" ownership unsafe"
            ((lAUTH_ISSUES+=1))
          fi
          ;;
        *)
          print_output "[+] ""$(print_path "${SUDOERS_D}")"" permissions possibly unsafe"
          if [[ "${FIND2}" = "0:0" ]] ; then
            print_output "[-] ""$(print_path "${SUDOERS_D}")"" ownership OK"
          else
            print_output "[+] ""$(print_path "${SUDOERS_D}")"" ownership unsafe"
            ((lAUTH_ISSUES+=1))
          fi
          ;;
        esac
      fi

      FIND3="$(permission_clean "${FILE}")"
      FIND4="$(owner_clean "${FILE}")"":""$(group_clean "${FILE}")"

      print_output "[*] ""$(print_path "${FILE}")"": Found permissions: ""${FIND3}"" and owner UID GID: ""${FIND4}"

      case "${FIND3}" in
      rwx[r-][w-][x-]---)
        print_output "[-] ""$(print_path "${FILE}")"" permissions OK"
        if [[ "${FIND4}" = "0:0" ]] ; then
          print_output "[-] ""$(print_path "${FILE}")"" ownership OK"
        else
          print_output "[+] ""$(print_path "${FILE}")"" ownership unsafe"
          ((lAUTH_ISSUES+=1))
        fi
        ;;
      *)
        print_output "[+] ""$(print_path "${FILE}")"" permissions possibly unsafe"
        if [[ "${FIND4}" = "0:0" ]] ; then
          print_output "[-] ""$(print_path "${FILE}")"" ownership OK"
        else
          print_output "[+] ""$(print_path "${FILE}")"" ownership unsafe"
          ((lAUTH_ISSUES+=1))
        fi
        ;;
      esac
    done
  else
    print_output "[-] No sudoers files found - no check possible"
  fi
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

search_pam_testing_libs() {
  sub_module_title "Search for PAM password strength testing libraries"

  print_output "[*] Searching PAM password testing modules (cracklib, passwdqc, pwquality)"

  local FILE_PATH FOUND=0
  local FOUND_CRACKLIB=0
  local FOUND_PASSWDQC=0
  local FOUND_PWQUALITY=0
  local lAUTH_ISSUES=0
  local PATH_F=""
  local FILE_PATH=()

  mapfile -t FILE_PATH < <(mod_path_array "$(config_list "${CONFIG_DIR}""/pam_files.cfg" "")")

  if [[ "${FILE_PATH[0]-}" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif ! [[ "${#FILE_PATH[@]}" -eq 0 ]] ; then
    local FOUND=0
    FOUND_CRACKLIB=0
    FOUND_PASSWDQC=0
    FOUND_PWQUALITY=0

    for PATH_F in "${FILE_PATH[@]}"; do
      local FULL_PATH="${FIRMWARE_PATH}""/""${PATH_F}"

      if [[ -f "${FULL_PATH}""/pam_cracklib.so" ]] ; then
        FOUND_CRACKLIB=1
        FOUND=1
        print_output "[+] Found pam_cracklib.so (crack library PAM) in ""$(print_path "${FULL_PATH}")"
        ((lAUTH_ISSUES+=1))
      fi

      if [[ -f "${FULL_PATH}""/pam_passwdqc.so" ]] ; then
        FOUND_PASSWDQC=1
        FOUND=1
        print_output "[+] Found pam_passwdqc.so (passwd quality control PAM) in ""$(print_path "${FULL_PATH}")"
        ((lAUTH_ISSUES+=1))
      fi

      if [[ -f "${FULL_PATH}""/pam_pwquality.so" ]] ; then
        FOUND_PWQUALITY=1
        FOUND=1
        print_output "[+] Found pam_pwquality.so (password quality control PAM) in ""$(print_path "${FULL_PATH}")"
        ((lAUTH_ISSUES+=1))
      fi
    done

    # Cracklib
    if [[ ${FOUND_CRACKLIB} -eq 1 ]] ; then
      print_output "[+] pam_cracklib.so found"
      ((lAUTH_ISSUES+=1))
    else
      print_output "[-] pam_cracklib.so not found"
    fi

    # Password quality control
    if [[ ${FOUND_PASSWDQC} -eq 1 ]] ; then
      print_output "[+] pam_passwdqc.so found"
      ((lAUTH_ISSUES+=1))
    else
      print_output "[-] pam_passwdqc.so not found"
    fi

    # pwquality module
    if [[ ${FOUND_PWQUALITY} -eq 1 ]] ; then
      print_output "[+] pam_pwquality.so found"
      ((lAUTH_ISSUES+=1))
    else
      print_output "[-] pam_pwquality.so not found"
    fi

    if [[ ${FOUND} -eq 0 ]] ; then
      print_output "[-] No PAM modules for password strength testing found"
    else
      print_output "[-] Found at least one PAM module for password strength testing"
      ((lAUTH_ISSUES+=1))
    fi

  else
    print_output "[-] No pam files found"
  fi
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

scan_pam_conf() {
  sub_module_title "Scan PAM configuration file"

  local CHECK=0
  local lAUTH_ISSUES=0
  local PAM_PATH_L=()
  local PAM_PATH=""

  mapfile -t PAM_PATH_L < <(mod_path "/ETC_PATHS/pam.conf")
  for PAM_PATH in "${PAM_PATH_L[@]}"; do
    if [[ -f "${PAM_PATH}" ]] ; then
      CHECK=1
      print_output "[+] ""$(print_path "${PAM_PATH}")"" exist"
      local FIND=""
      FIND=$(grep -v "^#" "${PAM_PATH}" | grep -v "^$" | sed 's/[[:space:]]/ /g' | sed 's/  / /g' | sed 's/ /:space:/g' || true)
      if [[ -z "${FIND}" ]] ; then
        print_output "[-] File has no configuration options defined (empty, or only filled with comments and empty lines)"
      else
        print_output "[+] Found one or more configuration lines"
        local LINE=${FIND//[[:space:]]/}
        print_output "$(indent "$(orange "${LINE}")")"
        ((lAUTH_ISSUES+=1))
      fi
    fi
  done
  [[ ${CHECK} -eq 0 ]] && print_output "[-] /etc/pam.conf not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

search_pam_configs() {
  sub_module_title "Searching PAM configurations and LDAP support in PAM files"

  local CHECK=0
  local lAUTH_ISSUES=0
  local PAM_PATH_L=()
  local FILES_ARR=()
  local FILE=""
  local PAM_PATH=""

  mapfile -t PAM_PATH_L < <(mod_path "/ETC_PATHS/pam.d")
  for PAM_PATH in "${PAM_PATH_L[@]}"; do
    if [[ -d "${PAM_PATH}" ]] ; then
      CHECK=1
      print_output "[+] ""$(print_path "${PAM_PATH}")"" exist"
      local FIND=""
      FIND=$(find "${PAM_PATH}" -xdev -not -name "*.pam-old" -type f -print | sort)
      readarray -t FILES_ARR < <(printf '%s' "${FIND}")
      for FILE in "${FILES_ARR[@]}"; do
        print_output "$(indent "$(orange "$(print_path "${FILE}")")")"
      done
      local AUTH_FILES=""
      AUTH_FILES=("${PAM_PATH}""/common-auth" "${PAM_PATH}""/system-auth")
      for FILE in "${AUTH_FILES[@]}"; do
        print_output "[*] Check if LDAP support in PAM files"
        if [[ -f "${FILE}" ]] ; then
          ((lAUTH_ISSUES+=1))
          print_output "[+] ""$(print_path "${FILE}")"" exist"
          local FIND2=""
          FIND2=$(grep "^auth.*ldap" "${FILE}" || true)
          if [[ -n "${FIND2}" ]] ; then
            print_output "[+] LDAP module present"
            print_output "$(indent "$(orange "${FIND2}")")"
          else
            print_output "[-] LDAP module not found"
          fi
        else
          print_output "[-] ""$(print_path "${FILE}")"" not found"
        fi
      done
    fi
  done
  [[ ${CHECK} -eq 0 ]] && print_output "[-] /etc/pam.d not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

search_pam_files() {
  sub_module_title "Searching available PAM files"

  local CHECK=0
  local lAUTH_ISSUES=0
  local PAM_FILES=()
  local PAM_FILE=""
  local FIND_FILE=""
  readarray -t PAM_FILES < <(config_find "${CONFIG_DIR}""/pam_files.cfg")

  if [[ "${PAM_FILES[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ ${#PAM_FILES[@]} -ne 0 ]] ; then
    print_output "[*] Found ""${ORANGE}${#PAM_FILES[@]}${NC}"" possible interesting areas for PAM:"
    for PAM_FILE in "${PAM_FILES[@]}" ; do
      if [[ -f "${PAM_FILE}" ]] ; then
        CHECK=1
        print_output "$(indent "$(orange "$(print_path "${PAM_FILE}")")")"
        ((lAUTH_ISSUES+=1))
      fi
      if [[ -d "${PAM_FILE}" ]] && [[ ! -L "${PAM_FILE}" ]] ; then
        print_output "$(indent "$(print_path "${PAM_FILE}")")"
        local FIND=""
        mapfile -t FIND < <(find "${PAM_FILE}" -xdev -maxdepth 1 -type f -name "pam_*.so" -print | sort)
        for FIND_FILE in "${FIND[@]}"; do
          CHECK=1
          print_output "$(indent "$(orange "${FIND_FILE}")")"
        done
        ((lAUTH_ISSUES+=1))
      fi
    done
    [[ ${CHECK} -eq 0 ]] && print_output "[-] Nothing interesting found"
  else
    print_output "[-] Nothing found"
  fi
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}
