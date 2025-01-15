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

# Description:  Checks for users with UID 0; for non-unique accounts, group IDs, group names; scans all available user accounts
#               and possible NIS(+) authentication support. It looks up sudoers file and analyzes it for possible vulnerabilities.
#               It also searches for PAM authentication files and analyze their usage.

# This module is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_authentication
S50_authentication_check() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Check users, groups and authentication"
  pre_module_reporter "${FUNCNAME[0]}"

  local lAUTH_ISSUES=0
  local lWAIT_PIDS_S50_ARR=()

  # disabled internal module threading as the output is not readable anymore
  if [[ "${THREADED}" -eq 9 ]]; then
    user_zero &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    search_shadow &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    non_unique_acc &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    non_unique_group_id &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    non_unique_group_name &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    query_user_acc &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    query_nis_plus_auth_supp &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    check_sudoers &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    check_owner_perm_sudo_config &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    search_pam_testing_libs &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    scan_pam_conf &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    search_pam_configs &
    lWAIT_PIDS_S50_ARR+=( "$!" )
    search_pam_files &
    lWAIT_PIDS_S50_ARR+=( "$!" )
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

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S50_ARR[@]}"

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

  mapfile -t lSHADOW_FILE_PATHS_ARR < <(find "${LOG_DIR}"/firmware -xdev -name "*shadow*"  -print0|xargs -r -0 -P 16 -I % sh -c 'file "%" | grep "ASCII text" | cut -d: -f1' || true)
  for lSHADOW_FILE in "${lSHADOW_FILE_PATHS_ARR[@]}"; do
    if [[ -f "${lSHADOW_FILE}" ]] ; then
      mapfile -t lHASHES_ARR < <(grep -E '\$[1-6][ay]?\$' "${lSHADOW_FILE}" || true)
      for lHASH in "${lHASHES_ARR[@]}"; do
        local lHTYPE="unknown"
        if [[ "${lHASH}" =~ .*\$1\$.* ]]; then
          lHTYPE="MD5"
        elif [[ "${lHASH}" =~ .*\$2a\$.* ]]; then
          lHTYPE="Blowfish"
        elif [[ "${lHASH}" =~ .*\$2y\$.* ]]; then
          lHTYPE="Eksblowfish"
        elif [[ "${lHASH}" =~ .*\$5\$.* ]]; then
          lHTYPE="SHA-256"
        elif [[ "${lHASH}" =~ .*\$6\$.* ]]; then
          lHTYPE="SHA-512"
        fi
        if [[ "${lHTYPE}" == "unknown" ]]; then
          print_output "[+] Found shadow file ""${ORANGE}$(print_path "${lSHADOW_FILE}")${GREEN} with possible hash ${ORANGE}${lHASH}${NC}"
          ((lAUTH_ISSUES+=1))
          continue
        fi
        print_output "[+] Found shadow file ""${ORANGE}$(print_path "${lSHADOW_FILE}")${GREEN} with possible hash ${ORANGE}${lHASH}${GREEN} of hashtype: ${ORANGE}${lHTYPE}${NC}"
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
  local lPASSWD_FILE_PATHS_ARR=()
  local lPASSWD_FILE=""
  mapfile -t lPASSWD_FILE_PATHS_ARR < <(mod_path "/ETC_PATHS/passwd")

  for lPASSWD_FILE in "${lPASSWD_FILE_PATHS_ARR[@]}"; do
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
  local lCHECK=0
  local lAUTH_ISSUES=0
  local lPASSWD_FILE_PATHS_ARR=()
  local lPASSWD_FILE=""

  mapfile -t lPASSWD_FILE_PATHS_ARR < <(mod_path "/ETC_PATHS/passwd")

  for lPASSWD_FILE in "${lPASSWD_FILE_PATHS_ARR[@]}"; do
    if [[ -f "${lPASSWD_FILE}" ]] ; then
      lCHECK=1
      local lFIND=""
      lFIND=$(grep -v '^#' "${lPASSWD_FILE}" | cut -d ':' -f3 | sort | uniq -d || true)
      if [[ "${lFIND}" = "" ]] ; then
        print_output "[-] All accounts found in ""$(print_path "${lPASSWD_FILE}")"" are unique"
      else
        print_output "[+] Non-unique accounts found in ""$(print_path "${lPASSWD_FILE}")"
        print_output "$(indent "$(orange "${lFIND}")")"
        ((lAUTH_ISSUES+=1))
      fi
    fi
  done
  [[ ${lCHECK} -eq 0 ]] && print_output "[-] /etc/passwd not available"
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
  local lPASSWD_FILE_PATHS_ARR=()
  local lPASSWD_FILE=""

  mapfile -t lPASSWD_FILE_PATHS_ARR < <(mod_path "/ETC_PATHS/passwd")

  for lPASSWD_FILE in "${lPASSWD_FILE_PATHS_ARR[@]}"; do
    if [[ -f "${lPASSWD_FILE}" ]] ; then
      lCHECK=1
      local lUID_MIN=""
      local lLOGIN_DEFS_PATH_ARR=()
      local lLOGIN_DEF=""
      mapfile -t lLOGIN_DEFS_PATH_ARR < <(mod_path "/ETC_PATHS/login.defs")
      for lLOGIN_DEF in "${lLOGIN_DEFS_PATH_ARR[@]}"; do
        if [[ -f "${lLOGIN_DEF}" ]] ; then
          lUID_MIN=$(grep "^UID_MIN" "${lLOGIN_DEF}" | awk '{print $2}')
          print_output "[*] Found minimal user id specified: ""${lUID_MIN}"
        fi
      done
      [[ "${lUID_MIN}" = "" ]] && lUID_MIN="1000"
      print_output "[*] Linux real users output (ID = 0, or ""${lUID_MIN}""+, but not 65534):"
      lFIND=$(awk -v lUID_MIN="${lUID_MIN}" -F: '($3 >= lUID_MIN && $3 != 65534) || ($3 == 0) { print $1","$3 }' "${lPASSWD_FILE}")

      if [[ "${lFIND}" = "" ]] ; then
        print_output "[-] No users found/unknown result"
      else
        print_output "[+] Query system user"
        print_output "$(indent "$(orange "${lFIND}")")"
      fi
    fi
  done
  [[ ${lCHECK} -eq 0 ]] && print_output "[-] /etc/passwd not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

query_nis_plus_auth_supp() {
  sub_module_title "Query NIS and NIS+ authentication support"

  print_output "[*] Check nsswitch.conf"
  local lCHECK=0
  local lAUTH_ISSUES=0
  local lNSS_PATH_L_ARR=()
  local lNSS_PATH=""

  mapfile -t lNSS_PATH_L_ARR < <(mod_path "/ETC_PATHS/nsswitch.conf")

  for lNSS_PATH in "${lNSS_PATH_L_ARR[@]}"; do
    if [[ -f "${lNSS_PATH}" ]] ; then
      lCHECK=1
      print_output "[+] ""$(print_path "${lNSS_PATH}")"" exist"
      local lFIND=""
      lFIND="$(grep "^passwd" "${lNSS_PATH}" | grep "compat|nis" | grep -v "nisplus" || true)"
      if [[ -z "${lFIND}" ]] ; then
        print_output "[-] NIS/NIS+ authentication not enabled"
      else
        local lFIND2=""
        local lFIND3=""
        local lFIND4=""
        local lFIND5=""
        lFIND2=$(grep "^passwd_compat" "${lNSS_PATH}" | grep "nis" | grep -v "nisplus" || true)
        lFIND3=$(grep "^passwd" "${lNSS_PATH}" | grep "nis" | grep -v "nisplus" || true)
        if [[ -n "${lFIND2}" ]] || [[ -n "${lFIND3}" ]] ; then
          print_output "[+] Result: NIS authentication enabled"
        else
          print_output "[+] Result: NIS authentication not enabled"
        fi
        lFIND4=$(grep "^passwd_compat" "${lNSS_PATH}" | grep "nisplus" || true)
        lFIND5=$(grep "^passwd" "${lNSS_PATH}" | grep "nisplus" || true)
        if [[ -n "${lFIND4}" ]] || [[ -n "${lFIND5}" ]] ; then
          print_output "[+] Result: NIS+ authentication enabled"
        else
          print_output "[+] Result: NIS+ authentication not enabled"
        fi
      fi
    fi
  done
  [[ ${lCHECK} -eq 0 ]] && print_output "[-] /etc/nsswitch.conf not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

check_sudoers() {
  sub_module_title "Scan and test sudoers files"
  local lSUDOERS_ISSUES_ARR=()
  local lAUTH_ISSUES=0
  local lS_ISSUE=""
  local lR_PATH=""
  export SUDOERS_FILES_ARR=()
  local lSUDOERS_FILE=""

  for lR_PATH in "${ROOT_PATH[@]}"; do
    # as we only have one search term we can handle it like this:
    readarray -t SUDOERS_FILES_ARR < <(find "${lR_PATH}" -xdev -type f -name sudoers 2>/dev/null)
    if [[ "${#SUDOERS_FILES_ARR[@]}" -gt 0 ]]; then
      for lSUDOERS_FILE in "${SUDOERS_FILES_ARR[@]}"; do
        print_output "$(indent "$(orange "$(print_path "${lSUDOERS_FILE}")")")"
        if [[ -f "${EXT_DIR}"/sudo-parser.pl ]]; then
          print_output "[*] Testing sudoers file with sudo-parse.pl:"
          readarray lSUDOERS_ISSUES_ARR < <("${EXT_DIR}"/sudo-parser.pl -f "${lSUDOERS_FILE}" -r "${lR_PATH}" | grep -E "^E:\ " || true)
          for lS_ISSUE in "${lSUDOERS_ISSUES_ARR[@]}"; do
            print_output "[+] ${lS_ISSUE}"
            ((lAUTH_ISSUES+=1))
          done
        fi
      done
    else
      print_output "[-] No sudoers files found in ${lR_PATH}"
    fi
  done
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

check_owner_perm_sudo_config() {
  sub_module_title "Ownership and permissions for sudo configuration files"

  local lAUTH_ISSUES=0
  local lFILE=""

  if [[ "${#SUDOERS_FILES_ARR[@]}" -gt 0 ]]; then
    for lFILE in "${SUDOERS_FILES_ARR[@]}"; do
      local lSUDOERS_D="${lFILE}"".d"
      if [[ -d "${lSUDOERS_D}" ]] ; then
        print_output "[*] Checking drop-in directory (""$(print_path "${lSUDOERS_D}")"")"
        local lFIND=""
        local lFIND2=""
        local lFIND3=""
        local lFIND4=""

        lFIND="$(permission_clean "${lSUDOERS_D}")"
        lFIND2="$(owner_clean "${lSUDOERS_D}")"":""$(group_clean "${lSUDOERS_D}")"

        print_output "[*] ""$(print_path "${lSUDOERS_D}")"": Found permissions: ${lFIND} and owner UID GID: ${lFIND2}"

        case "${lFIND}" in
        drwx[r-][w-][x-]---)
          print_output "[-] ""$(print_path "${lSUDOERS_D}")"" permissions OK"
          if [[ "${lFIND2}" = "0:0" ]] ; then
            print_output "[-] ""$(print_path "${lSUDOERS_D}")"" ownership OK"
          else
            print_output "[+] ""$(print_path "${lSUDOERS_D}")"" ownership unsafe"
            ((lAUTH_ISSUES+=1))
          fi
          ;;
        *)
          print_output "[+] ""$(print_path "${lSUDOERS_D}")"" permissions possibly unsafe"
          if [[ "${lFIND2}" = "0:0" ]] ; then
            print_output "[-] ""$(print_path "${lSUDOERS_D}")"" ownership OK"
          else
            print_output "[+] ""$(print_path "${lSUDOERS_D}")"" ownership unsafe"
            ((lAUTH_ISSUES+=1))
          fi
          ;;
        esac
      fi

      lFIND3="$(permission_clean "${lFILE}")"
      lFIND4="$(owner_clean "${lFILE}")"":""$(group_clean "${lFILE}")"

      print_output "[*] ""$(print_path "${lFILE}")"": Found permissions: ""${lFIND3}"" and owner UID GID: ""${lFIND4}"

      case "${lFIND3}" in
      rwx[r-][w-][x-]---)
        print_output "[-] ""$(print_path "${lFILE}")"" permissions OK"
        if [[ "${lFIND4}" = "0:0" ]] ; then
          print_output "[-] ""$(print_path "${lFILE}")"" ownership OK"
        else
          print_output "[+] ""$(print_path "${lFILE}")"" ownership unsafe"
          ((lAUTH_ISSUES+=1))
        fi
        ;;
      *)
        print_output "[+] ""$(print_path "${lFILE}")"" permissions possibly unsafe"
        if [[ "${lFIND4}" = "0:0" ]] ; then
          print_output "[-] ""$(print_path "${lFILE}")"" ownership OK"
        else
          print_output "[+] ""$(print_path "${lFILE}")"" ownership unsafe"
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

  local lFILE_PATH_ARR=()
  local lFOUND=0
  local lFOUND_CRACKLIB=0
  local lFOUND_PASSWDQC=0
  local lFOUND_PWQUALITY=0
  local lAUTH_ISSUES=0
  local lPATH_F=""

  mapfile -t lFILE_PATH_ARR < <(mod_path_array "$(config_list "${CONFIG_DIR}""/pam_files.cfg" "")")

  if [[ "${lFILE_PATH_ARR[0]-}" == "C_N_F" ]] ; then
    print_output "[!] Config not found"
  elif ! [[ "${#lFILE_PATH_ARR[@]}" -eq 0 ]] ; then
    local lFOUND=0

    for lPATH_F in "${lFILE_PATH_ARR[@]}"; do
      local lFULL_PATH="${FIRMWARE_PATH}""/""${lPATH_F}"

      if [[ -f "${lFULL_PATH}""/pam_cracklib.so" ]] ; then
        lFOUND_CRACKLIB=1
        lFOUND=1
        print_output "[+] Found pam_cracklib.so (crack library PAM) in ""$(print_path "${lFULL_PATH}")"
        ((lAUTH_ISSUES+=1))
      fi

      if [[ -f "${lFULL_PATH}""/pam_passwdqc.so" ]] ; then
        lFOUND_PASSWDQC=1
        lFOUND=1
        print_output "[+] Found pam_passwdqc.so (passwd quality control PAM) in ""$(print_path "${lFULL_PATH}")"
        ((lAUTH_ISSUES+=1))
      fi

      if [[ -f "${lFULL_PATH}""/pam_pwquality.so" ]] ; then
        lFOUND_PWQUALITY=1
        lFOUND=1
        print_output "[+] Found pam_pwquality.so (password quality control PAM) in ""$(print_path "${lFULL_PATH}")"
        ((lAUTH_ISSUES+=1))
      fi
    done

    # Cracklib
    if [[ ${lFOUND_CRACKLIB} -eq 1 ]] ; then
      print_output "[+] pam_cracklib.so found"
      ((lAUTH_ISSUES+=1))
    else
      print_output "[-] pam_cracklib.so not found"
    fi

    # Password quality control
    if [[ ${lFOUND_PASSWDQC} -eq 1 ]] ; then
      print_output "[+] pam_passwdqc.so found"
      ((lAUTH_ISSUES+=1))
    else
      print_output "[-] pam_passwdqc.so not found"
    fi

    # pwquality module
    if [[ ${lFOUND_PWQUALITY} -eq 1 ]] ; then
      print_output "[+] pam_pwquality.so found"
      ((lAUTH_ISSUES+=1))
    else
      print_output "[-] pam_pwquality.so not found"
    fi

    if [[ ${lFOUND} -eq 0 ]] ; then
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

  local lCHECK=0
  local lAUTH_ISSUES=0
  local lPAM_PATH_L_ARR=()
  local lPAM_PATH=""

  mapfile -t lPAM_PATH_L_ARR < <(mod_path "/ETC_PATHS/pam.conf")
  for lPAM_PATH in "${lPAM_PATH_L_ARR[@]}"; do
    if [[ -f "${lPAM_PATH}" ]] ; then
      lCHECK=1
      print_output "[+] ""$(print_path "${lPAM_PATH}")"" exist"
      local lFIND=""
      lFIND=$(grep -v "^#" "${lPAM_PATH}" | grep -v "^$" | sed 's/[[:space:]]/ /g' | sed 's/  / /g' | sed 's/ /:space:/g' || true)
      if [[ -z "${lFIND}" ]] ; then
        print_output "[-] File has no configuration options defined (empty, or only filled with comments and empty lines)"
      else
        print_output "[+] Found one or more configuration lines"
        local lLINE=${lFIND//[[:space:]]/}
        print_output "$(indent "$(orange "${lLINE}")")"
        ((lAUTH_ISSUES+=1))
      fi
    fi
  done
  [[ ${lCHECK} -eq 0 ]] && print_output "[-] /etc/pam.conf not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

search_pam_configs() {
  sub_module_title "Searching PAM configurations and LDAP support in PAM files"

  local lCHECK=0
  local lAUTH_ISSUES=0
  local lPAM_PATH_L_ARR=()
  local lFILES_ARR=()
  local lFILE=""
  local lPAM_PATH=""

  mapfile -t lPAM_PATH_L_ARR < <(mod_path "/ETC_PATHS/pam.d")
  for lPAM_PATH in "${lPAM_PATH_L_ARR[@]}"; do
    if [[ -d "${lPAM_PATH}" ]] ; then
      lCHECK=1
      print_output "[+] ""$(print_path "${lPAM_PATH}")"" exist"
      local lFIND=""
      lFIND=$(find "${lPAM_PATH}" -xdev -not -name "*.pam-old" -type f -print | sort)
      readarray -t lFILES_ARR < <(printf '%s' "${lFIND}")
      for lFILE in "${lFILES_ARR[@]}"; do
        print_output "$(indent "$(orange "$(print_path "${lFILE}")")")"
      done
      local lAUTH_FILES_ARR=()
      lAUTH_FILES_ARR=("${lPAM_PATH}""/common-auth" "${lPAM_PATH}""/system-auth")
      for lFILE in "${lAUTH_FILES_ARR[@]}"; do
        print_output "[*] Check if LDAP support in PAM files"
        if [[ -f "${lFILE}" ]] ; then
          ((lAUTH_ISSUES+=1))
          print_output "[+] ""$(print_path "${lFILE}")"" exist"
          local lFIND2=""
          lFIND2=$(grep "^auth.*ldap" "${lFILE}" || true)
          if [[ -n "${lFIND2}" ]] ; then
            print_output "[+] LDAP module present"
            print_output "$(indent "$(orange "${lFIND2}")")"
          else
            print_output "[-] LDAP module not found"
          fi
        else
          print_output "[-] ""$(print_path "${lFILE}")"" not found"
        fi
      done
    fi
  done
  [[ ${lCHECK} -eq 0 ]] && print_output "[-] /etc/pam.d not available"
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}

search_pam_files() {
  sub_module_title "Searching available PAM files"

  local lCHECK=0
  local lAUTH_ISSUES=0
  local lPAM_FILES_ARR=()
  local lPAM_FILE=""
  local lFIND_FILE=""
  readarray -t lPAM_FILES_ARR < <(config_find "${CONFIG_DIR}""/pam_files.cfg")

  if [[ "${lPAM_FILES_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ ${#lPAM_FILES_ARR[@]} -ne 0 ]] ; then
    print_output "[*] Found ""${ORANGE}${#lPAM_FILES_ARR[@]}${NC}"" possible interesting areas for PAM:"
    for lPAM_FILE in "${lPAM_FILES_ARR[@]}" ; do
      if [[ -f "${lPAM_FILE}" ]] ; then
        lCHECK=1
        print_output "$(indent "$(orange "$(print_path "${lPAM_FILE}")")")"
        ((lAUTH_ISSUES+=1))
      fi
      if [[ -d "${lPAM_FILE}" ]] && [[ ! -L "${lPAM_FILE}" ]] ; then
        print_output "$(indent "$(print_path "${lPAM_FILE}")")"
        local lFIND=""
        mapfile -t lFIND < <(find "${lPAM_FILE}" -xdev -maxdepth 1 -type f -name "pam_*.so" -print | sort)
        for lFIND_FILE in "${lFIND[@]}"; do
          lCHECK=1
          print_output "$(indent "$(orange "${lFIND_FILE}")")"
        done
        ((lAUTH_ISSUES+=1))
      fi
    done
    [[ ${lCHECK} -eq 0 ]] && print_output "[-] Nothing interesting found"
  else
    print_output "[-] Nothing found"
  fi
  echo "${lAUTH_ISSUES}" >> "${TMP_DIR}"/S50_AUTH_ISSUES.tmp
}
