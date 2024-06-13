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

# Description:  Searches explicitly for binaries like gcc or gdb and also binaries for post exploitation like wget or ftp.

S95_interesting_files_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check for interesting files"
  pre_module_reporter "${FUNCNAME[0]}"

  local NEG_LOG=0
  local INT_COUNT=0
  local POST_COUNT=0
  local HID_COUNT=0
  local WAIT_PIDS_S95=()

  if [[ "${THREADED}" -eq 1 ]]; then
    interesting_binaries &
    WAIT_PIDS_S95+=( "$!" )
    post_exploitation &
    WAIT_PIDS_S95+=( "$!" )
    hidden_files &
    WAIT_PIDS_S95+=( "$!" )
    compile_files &
    WAIT_PIDS_S95+=( "$!" )
  else
    interesting_binaries
    post_exploitation
    hidden_files
    compile_files
  fi

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_S95[@]}"

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
    POST_COUNT=$(cat "${TMP_DIR}"/POST_COUNT.tmp 2>/dev/null || true)
    INT_COUNT=$(cat "${TMP_DIR}"/INT_COUNT.tmp 2>/dev/null || true)
    HID_COUNT=$(cat "${TMP_DIR}"/HID_COUNT.tmp 2>/dev/null || true)
    COMP_COUNT=$(cat "${TMP_DIR}"/COMP_COUNT.tmp 2>/dev/null || true)
    if [[ "${POST_COUNT}" -gt 0 || "${INT_COUNT}" -gt 0 || "${HID_COUNT}" -gt 0 || "${COMP_COUNT}" -gt 0 ]]; then
      NEG_LOG=1
    fi
  fi

  write_log ""
  write_log "[*] Statistics:${INT_COUNT}:${POST_COUNT}"

  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

compile_files() {
  local COMPILE_FILES=()
  local LINE=""
  local COUNT=0
  local COMP_COUNT=0

  mapfile -t COMPILE_FILES < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -type f \( -name "libstdc++.so*" -o -name "libgcc_s.so*" \) )

  if [[ ${#COMPILE_FILES[@]} -gt 0 ]] ; then
    write_log "[+] Found ""${#COMPILE_FILES[@]}"" files for identification of used toolchain:" "${LOG_PATH_MODULE}"/compile_files.txt
    for LINE in "${COMPILE_FILES[@]}" ; do
      # print_output "$(indent "$(orange "$(print_path "${LINE}")")")"
      write_log "$(indent "$(orange "$(print_path "${LINE}")")")" "${LOG_PATH_MODULE}"/compile_files.txt
      write_csv_log "compile file" "${LINE}"
      ((COMP_COUNT+=1))
      COUNT=1
    done
  fi

  if [[ ${COUNT} -eq 0 ]] ; then
    write_log "[-] No compile related files found" "${LOG_PATH_MODULE}"/compile_files.txt
  fi
  echo "${COMP_COUNT}" >> "${TMP_DIR}"/COMP_COUNT.tmp

}

hidden_files() {
  local HIDDEN_FILES=()
  local LINE=""
  local COUNT=0
  local HID_COUNT=0

  mapfile -t HIDDEN_FILES < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -name ".*" -type f)

  if [[ ${#HIDDEN_FILES[@]} -gt 0 ]] ; then
    write_log "[+] Found ""${#HIDDEN_FILES[@]}"" hidden files:" "${LOG_PATH_MODULE}"/hidden_files.txt
    for LINE in "${HIDDEN_FILES[@]}" ; do
      # print_output "$(indent "$(orange "$(print_path "${LINE}")")")"
      write_log "$(indent "$(orange "$(print_path "${LINE}")")")" "${LOG_PATH_MODULE}"/hidden_files.txt
      write_csv_log "hidden file" "${LINE}"
      ((HID_COUNT+=1))
      COUNT=1
    done
  fi

  if [[ ${COUNT} -eq 0 ]] ; then
    write_log "[-] No hidden files found" "${LOG_PATH_MODULE}"/hidden_files.txt
  fi
  echo "${HID_COUNT}" >> "${TMP_DIR}"/HID_COUNT.tmp
}

interesting_binaries() {
  local COUNT=0
  local INT_COUNT=0
  local INT_BIN=()
  local LINE=""
  local MD5_DONE_INT=()
  local BIN_MD5=""

  mapfile -t INT_BIN < <(config_find "${CONFIG_DIR}""/interesting_binaries.cfg")
  if [[ "${INT_BIN[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#INT_BIN[@]}" -ne 0 ]] ; then
    for LINE in "${INT_BIN[@]}" ; do
      if [[ -f "${LINE}" ]] && file "${LINE}" | grep -q "executable" ; then
        # we need every binary only once. So calculate the checksum and store it for checking
        BIN_MD5=$(md5sum "${LINE}" | cut -d\  -f1)
        if [[ ! " ${MD5_DONE_INT[*]} " =~ ${BIN_MD5} ]]; then
          if [[ ${COUNT} -eq 0 ]] ; then
            write_log "[+] Found interesting binaries:" "${LOG_PATH_MODULE}"/interesting_binaries.txt
            COUNT=1
          fi
          write_log "$(indent "$(orange "$(print_path "${LINE}")")")" "${LOG_PATH_MODULE}"/interesting_binaries.txt
          write_csv_log "interesting binary" "${LINE}"
          ((INT_COUNT+=1))
          MD5_DONE_INT+=( "${BIN_MD5}" )
        fi
      fi
    done
  fi

  if [[ ${COUNT} -eq 0 ]] ; then
    write_log "[-] No interesting binaries found" "${LOG_PATH_MODULE}"/interesting_binaries.txt
  fi
  echo "${INT_COUNT}" >> "${TMP_DIR}"/INT_COUNT.tmp
}

post_exploitation() {
  local COUNT=0
  local MD5_DONE_POST=()
  local POST_COUNT=0
  local INT_BIN_PE=()
  local LINE=""
  local BIN_MD5=""
  local MD5_DONE_POST=()

  mapfile -t INT_BIN_PE < <(config_find "${CONFIG_DIR}""/interesting_post_binaries.cfg")
  if [[ "${INT_BIN_PE[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ "${#INT_BIN_PE[@]}" -ne 0 ]] ; then
    for LINE in "${INT_BIN_PE[@]}" ; do
      if [[ -f "${LINE}" ]] && file "${LINE}" | grep -q "executable" ; then
        # we need every binary only once. Calculate the checksum and store it for checking
        BIN_MD5=$(md5sum "${LINE}" | cut -d\  -f1)
        if [[ ! " ${MD5_DONE_POST[*]} " =~ ${BIN_MD5} ]]; then
          if [[ ${COUNT} -eq 0 ]] ; then
            write_log "[+] Found interesting binaries for post exploitation:" "${LOG_PATH_MODULE}"/post_exploitation_binaries.txt
            COUNT=1
          fi
          write_log "$(indent "$(orange "$(print_path "${LINE}")")")" "${LOG_PATH_MODULE}"/post_exploitation_binaries.txt
          write_csv_log "post exploitation binary" "${LINE}"
          ((POST_COUNT+=1))
          MD5_DONE_POST+=( "${BIN_MD5}" )
        fi
      fi
    done
  fi
  if [[ ${COUNT} -eq 0 ]] ; then
    write_log "[-] No interesting binaries for post exploitation found" "${LOG_PATH_MODULE}"/post_exploitation_binaries.txt
  fi
  echo "${POST_COUNT}" >> "${TMP_DIR}"/POST_COUNT.tmp
}

