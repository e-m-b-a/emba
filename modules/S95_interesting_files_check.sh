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

# Description:  Searches explicitly for binaries like gcc or gdb and also binaries for post exploitation like wget or ftp.

S95_interesting_files_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check for interesting files"
  pre_module_reporter "${FUNCNAME[0]}"

  local lNEG_LOG=0
  local lINT_COUNT=0
  local lPOST_COUNT=0
  local lHID_COUNT=0
  local lCOMP_COUNT=0
  local lWAIT_PIDS_S95_ARR=()

  if [[ "${THREADED}" -eq 1 ]]; then
    interesting_binaries &
    lWAIT_PIDS_S95_ARR+=( "$!" )
    post_exploitation &
    lWAIT_PIDS_S95_ARR+=( "$!" )
    hidden_files &
    lWAIT_PIDS_S95_ARR+=( "$!" )
    compile_files &
    lWAIT_PIDS_S95_ARR+=( "$!" )
  else
    interesting_binaries
    post_exploitation
    hidden_files
    compile_files
  fi

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_S95_ARR[@]}"

  if [[ -f "${LOG_PATH_MODULE}"/interesting_binaries.txt ]]; then
    sub_module_title "Interesting binaries"
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/interesting_binaries.txt
  fi
  if [[ -f "${LOG_PATH_MODULE}"/post_exploitation_binaries.txt ]]; then
    sub_module_title "Interesting binaries for post exploitation"
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/post_exploitation_binaries.txt
  fi
  if [[ -f "${LOG_PATH_MODULE}"/hidden_files.txt ]]; then
    sub_module_title "Hidden files"
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/hidden_files.txt
  fi
  if [[ -f "${LOG_PATH_MODULE}"/compile_files.txt ]]; then
    sub_module_title "Toolchain related files"
    tee -a "${LOG_FILE}" < "${LOG_PATH_MODULE}"/compile_files.txt
  fi

  if [[ -f "${TMP_DIR}"/INT_COUNT.tmp || -f "${TMP_DIR}"/POST_COUNT.tmp || -f "${TMP_DIR}"/HID_COUNT.tmp || -f "${TMP_DIR}"/COMP_COUNT.tmp ]]; then
    lPOST_COUNT=$(cat "${TMP_DIR}"/POST_COUNT.tmp 2>/dev/null || true)
    lINT_COUNT=$(cat "${TMP_DIR}"/INT_COUNT.tmp 2>/dev/null || true)
    lHID_COUNT=$(cat "${TMP_DIR}"/HID_COUNT.tmp 2>/dev/null || true)
    lCOMP_COUNT=$(cat "${TMP_DIR}"/COMP_COUNT.tmp 2>/dev/null || true)
    if [[ "${lPOST_COUNT}" -gt 0 || "${lINT_COUNT}" -gt 0 || "${lHID_COUNT}" -gt 0 || "${lCOMP_COUNT}" -gt 0 ]]; then
      lNEG_LOG=1
    fi
  fi

  write_log ""
  write_log "[*] Statistics:${lINT_COUNT}:${lPOST_COUNT}"

  module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
}

compile_files() {
  local lCOMPILE_FILES_ARR=()
  local lTOOLCHAIN_FILE=""
  local lCOUNT=0
  local lCOMP_COUNT=0

  # mapfile -t lCOMPILE_FILES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -type f \( -name "libstdc++.so*" -o -name "libgcc_s.so*" \) )
  mapfile -t lCOMPILE_FILES_ARR < <(grep "libstdc++.so\|libgcc_s.so" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)

  if [[ ${#lCOMPILE_FILES_ARR[@]} -gt 0 ]] ; then
    write_log "[+] Found ""${#lCOMPILE_FILES_ARR[@]}"" files for identification of used toolchain:" "${LOG_PATH_MODULE}"/compile_files.txt
    for lTOOLCHAIN_FILE in "${lCOMPILE_FILES_ARR[@]}" ; do
      # print_output "$(indent "$(orange "$(print_path "${lTOOLCHAIN_FILE}")")")"
      write_log "$(indent "$(orange "$(print_path "${lTOOLCHAIN_FILE}")")")" "${LOG_PATH_MODULE}"/compile_files.txt
      write_csv_log "compile file" "${lTOOLCHAIN_FILE}"
      ((lCOMP_COUNT+=1))
      lCOUNT=1
    done
  fi

  if [[ ${lCOUNT} -eq 0 ]] ; then
    write_log "[-] No compile related files found" "${LOG_PATH_MODULE}"/compile_files.txt
  fi
  echo "${lCOMP_COUNT}" >> "${TMP_DIR}"/COMP_COUNT.tmp
}

hidden_files() {
  local lHIDDEN_FILES_ARR=()
  local lHIDDEN_FILE=""
  local lCOUNT=0
  local lHID_COUNT=0

  mapfile -t lHIDDEN_FILES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name ".*" -type f)

  if [[ ${#lHIDDEN_FILES_ARR[@]} -gt 0 ]] ; then
    write_log "[+] Found ""${#lHIDDEN_FILES_ARR[@]}"" hidden files:" "${LOG_PATH_MODULE}"/hidden_files.txt
    for lHIDDEN_FILE in "${lHIDDEN_FILES_ARR[@]}" ; do
      # print_output "$(indent "$(orange "$(print_path "${lHIDDEN_FILE}")")")"
      write_log "$(indent "$(orange "$(print_path "${lHIDDEN_FILE}")")")" "${LOG_PATH_MODULE}"/hidden_files.txt
      write_csv_log "hidden file" "${lHIDDEN_FILE}"
      ((lHID_COUNT+=1))
      lCOUNT=1
    done
  fi

  if [[ ${lCOUNT} -eq 0 ]] ; then
    write_log "[-] No hidden files found" "${LOG_PATH_MODULE}"/hidden_files.txt
  fi
  echo "${lHID_COUNT}" >> "${TMP_DIR}"/HID_COUNT.tmp
}

interesting_binaries() {
  local lCOUNT=0
  local lINT_COUNT=0
  local lINT_BIN_ARR=()
  local lINT_TESTING_BIN=""
  local lMD5_DONE_INT_ARR=()
  local lBIN_MD5=""

  mapfile -t lINT_BIN_ARR < <(config_find "${CONFIG_DIR}""/interesting_binaries.cfg")
  if [[ "${lINT_BIN_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#lINT_BIN_ARR[@]}" -ne 0 ]] ; then
    for lINT_TESTING_BIN in "${lINT_BIN_ARR[@]}" ; do
      if [[ -f "${lINT_TESTING_BIN}" ]] && file "${lINT_TESTING_BIN}" | grep -q "executable" ; then
        # we need every binary only once. So calculate the checksum and store it for checking
        lBIN_MD5=$(md5sum "${lINT_TESTING_BIN}" | cut -d\  -f1)
        if [[ ! " ${lMD5_DONE_INT_ARR[*]} " =~ ${lBIN_MD5} ]]; then
          if [[ ${lCOUNT} -eq 0 ]] ; then
            write_log "[+] Found interesting binaries:" "${LOG_PATH_MODULE}"/interesting_binaries.txt
            lCOUNT=1
          fi
          write_log "$(indent "$(orange "$(print_path "${lINT_TESTING_BIN}")")")" "${LOG_PATH_MODULE}"/interesting_binaries.txt
          write_csv_log "interesting binary" "${lINT_TESTING_BIN}"
          ((lINT_COUNT+=1))
          lMD5_DONE_INT_ARR+=( "${lBIN_MD5}" )
        fi
      fi
    done
  fi

  if [[ ${lCOUNT} -eq 0 ]] ; then
    write_log "[-] No interesting binaries found" "${LOG_PATH_MODULE}"/interesting_binaries.txt
  fi
  echo "${lINT_COUNT}" >> "${TMP_DIR}"/INT_COUNT.tmp
}

post_exploitation() {
  local lCOUNT=0
  local lMD5_DONE_POST_ARR=()
  local lPOST_COUNT=0
  local lINT_BIN_PE_ARR=()
  local lINT_POST_BIN=""
  local lBIN_MD5=""

  mapfile -t lINT_BIN_PE_ARR < <(config_find "${CONFIG_DIR}""/interesting_post_binaries.cfg")
  if [[ "${lINT_BIN_PE_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#lINT_BIN_PE_ARR[@]}" -ne 0 ]] ; then
    for lINT_POST_BIN in "${lINT_BIN_PE_ARR[@]}" ; do
      if [[ -f "${lINT_POST_BIN}" ]] && file "${lINT_POST_BIN}" | grep -q "executable" ; then
        # we need every binary only once. Calculate the checksum and store it for checking
        lBIN_MD5=$(md5sum "${lINT_POST_BIN}" | cut -d\  -f1)
        if [[ ! " ${lMD5_DONE_POST_ARR[*]} " =~ ${lBIN_MD5} ]]; then
          if [[ ${lCOUNT} -eq 0 ]] ; then
            write_log "[+] Found interesting binaries for post exploitation:" "${LOG_PATH_MODULE}"/post_exploitation_binaries.txt
            lCOUNT=1
          fi
          write_log "$(indent "$(orange "$(print_path "${lINT_POST_BIN}")")")" "${LOG_PATH_MODULE}"/post_exploitation_binaries.txt
          write_csv_log "post exploitation binary" "${lINT_POST_BIN}"
          ((lPOST_COUNT+=1))
          lMD5_DONE_POST_ARR+=( "${lBIN_MD5}" )
        fi
      fi
    done
  fi
  if [[ ${lCOUNT} -eq 0 ]] ; then
    write_log "[-] No interesting binaries for post exploitation found" "${LOG_PATH_MODULE}"/post_exploitation_binaries.txt
  fi
  echo "${lPOST_COUNT}" >> "${TMP_DIR}"/POST_COUNT.tmp
}

