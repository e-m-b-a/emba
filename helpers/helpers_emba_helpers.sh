#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description: Multiple useful helpers

run_web_reporter_mod_name() {
  local lMOD_NAME="${1:-}"
  local lLOG_FILES_ARR=()
  local lLOG_FILE=""

  if [[ ${HTML} -eq 1 ]]; then
    # usually we should only find one file:
    mapfile -t lLOG_FILES_ARR < <(find "${LOG_DIR}" -maxdepth 1 -type f -iname "${lMOD_NAME}*.txt" | sort)
    for lLOG_FILE in "${lLOG_FILES_ARR[@]}"; do
      if [[ -f "${lLOG_FILE}" ]]; then
        lMOD_NAME=$(basename -s .txt "${lLOG_FILE}")
        generate_report_file "${lLOG_FILE}"
        sed -i -E '/^\[REF\]|\[ANC\]|\[LOV\].*/d' "${lLOG_FILE}"
      else
        print_error "[-] Some error occured during web report building for ${lLOG_FILE}"
      fi
    done
  fi
}

wait_for_pid() {
  local lWAIT_PIDS_ARR=("$@")
  local lPID=""

  # print_output "[*] wait pid protection: ${#lWAIT_PIDS_ARR[@]}"
  for lPID in "${lWAIT_PIDS_ARR[@]}"; do
    # print_output "[*] wait pid protection: $lPID"
    print_dot
    if ! [[ -e /proc/"${lPID}" ]]; then
      continue
    fi
    while [[ -e /proc/"${lPID}" ]]; do
      # print_output "[*] wait pid protection - running pid: $lPID"
      print_dot
      # if S115 is running we have to kill old qemu processes
      if [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]] && [[ $(grep -i -c S115_ "${LOG_DIR}"/"${MAIN_LOG_FILE}") -gt 0 && -n "${QRUNTIME}" ]]; then
        killall -9 --quiet --older-than "${QRUNTIME}" -r .*qemu-.*-sta.* || true
      fi
    done
  done
}

max_pids_protection() {
  local lMAX_PIDS_="${1:-}"
  local -n lrWAIT_PIDS_ARR=${2:-}

  local lPID=""

  # echo "INTRO - checking pids #${#lrWAIT_PIDS_ARR[@]} / max: ${lMAX_PIDS_}"
  while [[ ${#lrWAIT_PIDS_ARR[@]} -gt "${lMAX_PIDS_}" ]]; do
    local lTEMP_PIDS_ARR=()
    # check for really running PIDs and re-create the array
    for lPID in "${lrWAIT_PIDS_ARR[@]}"; do
      # print_output "[*] max pid protection: ${#lrWAIT_PIDS_ARR[@]}"
      if [[ -e /proc/"${lPID}" ]]; then
        if ! grep -q "State:.*zombie.*" "/proc/${lPID}/status" 2>/dev/null; then
          lTEMP_PIDS_ARR+=( "${lPID}" )
        fi
      fi
    done
    # if S115 is running we have to kill old qemu processes
    if [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" ]] && [[ $(grep -i -c S115_ "${LOG_DIR}"/"${MAIN_LOG_FILE}" || true) -eq 1 && -n "${QRUNTIME}" ]]; then
      killall -9 --quiet --older-than "${QRUNTIME}" -r .*qemu.*sta.* || true
    fi

    # print_output "[!] really running pids: ${#lTEMP_PIDS_ARR[@]}"

    # recreate the arry with the current running PIDS
    lrWAIT_PIDS_ARR=()
    lrWAIT_PIDS_ARR=("${lTEMP_PIDS_ARR[@]}")
    print_dot
    # echo "checking pids #${#lrWAIT_PIDS_ARR[@]} / ${#lTEMP_PIDS_ARR[@]} / max: ${lMAX_PIDS_}"
  done
}

check_emba_ended() {
  if grep -q "Test ended" "${LOG_DIR}""/""${MAIN_LOG_FILE}"; then
    # EMBA is already finished
    return 0
  fi
  if ! [[ -d "${LOG_DIR}" ]]; then
    # this usually happens if we automate analysis and remove the logging directory while this module was not finished at all
    return 0
  fi
  return 1
}

# $1 - 1 some interrupt detected
# $1 - 0 default exit 0
cleaner() {
  local lINTERRUPT_CLEAN="${1:-1}"
  [[ "${CLEANED}" -eq 1 ]] && return
  if [[ "${lINTERRUPT_CLEAN}" -eq 1 ]]; then
    print_output "[*] $(print_date) - Interrupt detected!" "no_log"
  fi
  print_output "[*] $(print_date) - Final cleanup started." "no_log"
  if [[ "${IN_DOCKER}" -eq 0 ]] && [[ -n "${QUEST_CONTAINER}" ]]; then
    if [[ "$(docker container inspect -f '{{.State.Status}}' "${QUEST_CONTAINER}" 2>/dev/null)" == "running" ]]; then
      print_output "[*] $(print_date) - Stopping Quest Container ..." "no_log"
      docker kill "${QUEST_CONTAINER}" 2>/dev/null
    fi
  fi
  if [[ "${IN_DOCKER}" -eq 0 ]] && [[ -n "${MAIN_CONTAINER}" ]]; then
    if [[ "$(docker container inspect -f '{{.State.Status}}' "${MAIN_CONTAINER}" 2>/dev/null)" == "running" ]]; then
      print_output "[*] $(print_date) - Stopping EMBA main Container ..." "no_log"
      docker kill "${MAIN_CONTAINER}" 2>/dev/null
    fi
  fi
  # stop inotifywait on host
  if [[ "${IN_DOCKER}" -eq 0 ]] && pgrep -f "inotifywait.*${LOG_DIR}.*" &> /dev/null 2>&1; then
    print_output "[*] $(print_date) - Stopping inotify ..." "no_log"
    pkill -f "inotifywait.*${LOG_DIR}.*" >/dev/null || true
  fi

  # Remove status bar and reset screen
  [[ "${DISABLE_STATUS_BAR}" -eq 0 ]] && remove_status_bar

  # if S115 is found only once in main.log the module was started and we have to clean it up
  # additionally we need to check some variable from a running EMBA instance
  # otherwise the unmounter runs crazy in some corner cases
  if [[ -f "${LOG_DIR}"/"${MAIN_LOG_FILE}" && "${#FILE_ARR[@]}" -gt 0 ]]; then
    if [[ $(grep -i -c S115 "${LOG_DIR}"/"${MAIN_LOG_FILE}") -eq 1 ]]; then

      print_output "[*] $(print_date) - Terminating qemu processes - check it with ps" "no_log"
      killall -9 --quiet -r .*qemu-.*-sta.* > /dev/null || true
      print_output "[*] $(print_date) - Cleaning the emulation environment\\n" "no_log"
      find "${FIRMWARE_PATH_CP}" -xdev -iname "qemu*static" -exec rm {} \; 2>/dev/null || true
      find "${LOG_DIR}/s115_usermode_emulator" -xdev -iname "qemu*static" -exec rm {} \; 2>/dev/null || true

      print_output "[*] $(print_date) - Umounting proc, sys and run" "no_log"
      local lCHECK_MOUNTS_ARR=()
      local lMOUNT=""
      mapfile -t lCHECK_MOUNTS_ARR < <(mount | grep "s115_usermode_emulator" 2>/dev/null || true)
      # now we can unmount the stuff from emulator and delete temporary stuff
      for lMOUNT in "${lCHECK_MOUNTS_ARR[@]}"; do
        print_output "[*] $(print_date) - Unmounting ${lMOUNT}" "no_log"
        lMOUNT=$(echo "${lMOUNT}" | cut -d\  -f3)
        umount -l "${lMOUNT}" || true
      done

      if [[ -d "${LOG_DIR}/s115_usermode_emulator/firmware" ]]; then
        print_output "[*] $(print_date) - Removing emulation directory ${ORANGE}${LOG_DIR}/s115_usermode_emulator/firmware${NC}" "no_log"
        rm -r "${LOG_DIR}/s115_usermode_emulator/firmware" || true
      fi
    fi

    if [[ $(grep -i -c S120 "${LOG_DIR}"/"${MAIN_LOG_FILE}") -eq 1 ]]; then
      print_output "[*] $(print_date) - Terminating cwe-checker processes - check it with ps" "no_log"
      killall -9 --quiet -r .*cwe_checker.* > /dev/null || true
    fi

    # If SYS_ONLINE is 1 and some qemu system process is running, the live system tester (system mode emulator)
    # was able to setup the box we need to do a cleanup
    if pgrep -f "qemu-system-.*${LOG_DIR}"; then
      if [[ "${SYS_ONLINE:-0}" -eq 1 ]] || [[ $(grep -i -c L10 "${LOG_DIR}"/"${MAIN_LOG_FILE}") -gt 0 ]]; then
        print_output "[*] $(print_date) - Resetting system emulation environment" "no_log"
        stopping_emulation_process
        reset_network_emulation 2
      fi
    fi
  fi
  [[ "${IN_DOCKER}" -eq 1 ]] && restore_permissions

  if [[ "${IN_DOCKER}" -eq 0 ]]; then
    pkill -f "tail.*-f ${LOG_DIR}/emba.log" > /dev/null || true
    remove_status_bar
  fi

  if [[ "${IN_DOCKER}" -eq 0 ]] && [[ -v K_DOWN_PID ]]; then
    if ps -p "${K_DOWN_PID}" > /dev/null; then
      # kernel downloader is running in a thread on the host and needs to be stopped now
      print_output "[*] $(print_date) - Stopping kernel downloader thread with PID ${K_DOWN_PID}" "no_log"
      kill "${K_DOWN_PID}" > /dev/null || true
    fi
  fi

  if [[ -f "${TMP_DIR}"/orig_logdir ]]; then
    local lLOG_DIR_HOST=""
    lLOG_DIR_HOST=$(cat "${TMP_DIR}"/orig_logdir)
    pkill -f "inotifywait.*${lLOG_DIR_HOST}" 2>/dev/null || true
  fi

  if [[ "${IN_DOCKER}" -eq 1 ]]; then
    fuser -k "${LOG_DIR}" || true
    fuser -k "${FIRMWARE_PATH}" || true
  fi

  if [[ "${IN_DOCKER}" -eq 0 ]] && [[ -f "${TMP_DIR}"/EXIT_KILL_PIDS.log ]]; then
    while read -r KILL_PID; do
      if [[ -e /proc/"${KILL_PID}" ]]; then
        print_output "[*] $(print_date) - Stopping EMBA process with PID ${KILL_PID}" "no_log"
        kill -9 "${KILL_PID}" > /dev/null || true
      fi
    done < "${TMP_DIR}"/EXIT_KILL_PIDS.log
  fi

  if [[ "${IN_DOCKER}" -eq 1 ]] && [[ -f "${TMP_DIR}"/EXIT_KILL_PIDS_DOCKER.log ]]; then
    while read -r KILL_PID; do
      if [[ -e /proc/"${KILL_PID}" ]]; then
        print_output "[*] $(print_date) - Stopping EMBA process with PID ${KILL_PID} in docker" "no_log"
        kill -9 "${KILL_PID}" > /dev/null || true
      fi
    done < "${TMP_DIR}"/EXIT_KILL_PIDS_DOCKER.log
  fi


  if [[ -f "${LOG_DIR}"/emba_error.log ]]; then
    if ! [[ -s "${LOG_DIR}"/emba_error.log ]]; then
      rm "${LOG_DIR}"/emba_error.log > /dev/null || true
    fi
  fi

  if [[ "${IN_DOCKER}" -eq 0 ]] && [[ -d "${TMP_DIR}" ]]; then
    rm -r "${TMP_DIR}" 2>/dev/null || true
  fi
  export CLEANED=1
  if [[ "${lINTERRUPT_CLEAN}" -eq 1 ]]; then
    print_output "[!] Test ended on ""$(print_date)"" and took about ""$(show_runtime)"" \\n" "no_log"
    exit 1
  fi
}

emba_updater() {
  print_output "[*] EMBA update starting ..." "no_log"
  local lHOME_DIR=""
  lHOME_DIR=$(pwd)
  local lUPDATE_TIMEOUT="360s"

  if [[ -d ./.git ]]; then
    timeout "${lUPDATE_TIMEOUT}" git pull origin master
  else
    print_output "[-] WARNING: Can't update non git version of EMBA" "no_log"
  fi

  EMBA="${INVOCATION_PATH}" FIRMWARE="${FIRMWARE_PATH}" LOG="${LOG_DIR}" docker pull embeddedanalyzer/emba

  if [[ -d "${EXT_DIR}"/EPSS-data ]]; then
    print_output "[*] EMBA update - EPSS database update" "no_log"
    cd "${EXT_DIR}"/EPSS-data || ( print_output "[-] WARNING: Can't update EPSS database" "no_log" && exit 1 )
    if [[ -d ./.git ]]; then
      timeout "${lUPDATE_TIMEOUT}" git pull
    else
      print_output "[-] WARNING: Can't update EPSS database" "no_log"
    fi
    cd "${lHOME_DIR}" || ( print_output "[-] WARNING: Can't update EPSS database" "no_log" && exit 1 )
  else
    print_output "[-] WARNING: Can't update EPSS database" "no_log"
  fi

  if [[ -d "${NVD_DIR}" ]]; then
    print_output "[*] EMBA update - CVE database update" "no_log"
    cd "${NVD_DIR}" || ( print_output "[-] WARNING: Can't update CVE database" "no_log" && exit 1 )
    if [[ -d ./.git ]]; then
      timeout "${lUPDATE_TIMEOUT}" git pull
    else
      print_output "[-] WARNING: Can't update CVE database" "no_log"
    fi
    cd "${lHOME_DIR}" || ( print_output "[-] WARNING: Can't update CVE database" "no_log" && exit 1 )
  else
    print_output "[-] WARNING: Can't update CVE database" "no_log"
  fi

  print_output "[*] EMBA update - docker image" "no_log"
  docker pull embeddedanalyzer/emba

  print_output "[*] Please note that this was no update of installed system packages." "no_log"
  print_output "[*] Please restart your EMBA scan to apply the updates ..." "no_log"
}

# this checks if a function is available
# this means the EMBA module was loaded
function_exists() {
  local lFCT_TO_CHECK="${1:-}"
  declare -f -F "${lFCT_TO_CHECK}" > /dev/null
  return $?
}

# used by CSV search to get the search rule for csv search:
get_csv_rule() {
  local lVERSION_STRING="${1:-}"
  local lCSV_REGEX=""
  lCSV_REGEX=$(echo "${2:-}" | sed 's/^\"//' | sed 's/\"$//')
  local lCSV_RULE="NA"

  lCSV_RULE="$(echo "${lVERSION_STRING}" | eval "${lCSV_REGEX}" || true)"

  echo "${lCSV_RULE}"
}

restore_permissions() {
  local lORIG_USER=""
  local lORIG_UID=""
  local lORIG_GID=""

  if [[ -f "${LOG_DIR}"/orig_user.log ]]; then
    lORIG_USER=$(head -1 "${LOG_DIR}"/orig_user.log)
    print_output "[*] $(print_date) - Restoring directory permissions for user: ${ORANGE}${lORIG_USER}${NC}" "no_log"
    lORIG_UID="$(grep "UID" "${LOG_DIR}"/orig_user.log | awk '{print $2}')"
    lORIG_GID="$(grep "GID" "${LOG_DIR}"/orig_user.log | awk '{print $2}')"
    chown "${lORIG_UID}":"${lORIG_GID}" "${LOG_DIR}" -R || true
    rm "${LOG_DIR}"/orig_user.log || true
  fi
}

backup_var() {
  local lVAR_NAME="${1:-}"
  local lVAR_VALUE="${2:-}"
  local lBACKUP_FILE="${LOG_DIR}""/backup_vars.log"

  echo "export ${lVAR_NAME}=\"${lVAR_VALUE}\"" >> "${lBACKUP_FILE}"
}

module_wait() {
  local lMODULE_TO_WAIT="${1:-}"
  # if the module we should wait is not in our module array we return without waiting
  if ! [[ " ${MODULES_EXPORTED[*]} " == *"${lMODULE_TO_WAIT}"* ]]; then
    print_output "[-] $(print_date) - ${lMODULE_TO_WAIT} not in module array - this will result in unexpected behavior" "main"
    return
  fi

  while ! [[ -f "${MAIN_LOG}" ]]; do
    sleep 1
  done

  while [[ $(grep -i -c "${lMODULE_TO_WAIT} finished" "${MAIN_LOG}" || true) -ne 1 ]]; do
    if grep -q "${lMODULE_TO_WAIT} not executed - blacklist triggered" "${MAIN_LOG}"; then
      print_output "[-] $(print_date) - ${lMODULE_TO_WAIT} blacklisted - not waiting" "main"
      # if our module which we are waiting is on the blacklist we can just return
      return
    fi
    if [[ -f "${LOG_DIR}"/emba_error.log ]]; then
      if grep -q "${lMODULE_TO_WAIT}" "${LOG_DIR}"/emba_error.log; then
        print_output "[-] $(print_date) - WARNING: Module to wait for is probably crashed and will never end. Check the EMBA error log ${LOG_DIR}/emba_error.log" "main"
        cat "${LOG_DIR}"/emba_error.log >> "${MAIN_LOG}"
        return
      fi
    fi
    sleep 1
  done
}

store_kill_pids() {
  local lPID="${1:-}"
  ! [[ -d "${TMP_DIR}" ]] && mkdir -p "${TMP_DIR}"
  [[ "${IN_DOCKER}" -eq 0 ]] && echo "${lPID}" >> "${TMP_DIR}"/EXIT_KILL_PIDS.log
  [[ "${IN_DOCKER}" -eq 1 ]] && echo "${lPID}" >> "${TMP_DIR}"/EXIT_KILL_PIDS_DOCKER.log
  return 0
}

disk_space_monitor() {
  local lDDISK="${LOG_DIR}"
  local lFREE_SPACE=""

  while ! [[ -f "${MAIN_LOG}" ]]; do
    sleep 1
  done

  while true; do
    # print_output "[*] Disk space monitoring active" "no_log"
    lFREE_SPACE=$(df --output=avail "${lDDISK}" | awk 'NR==2')
    if [[ "${lFREE_SPACE}" -lt 10000000 ]]; then
      print_ln "no_log"
      print_output "[!] WARNING: EMBA is running out of disk space!" "main"
      print_output "[!] WARNING: EMBA is stopping now" "main"
      df -h || true
      print_ln "no_log"
      # give the container some more seconds for the cleanup process
      [[ "${IN_DOCKER}" -eq 0 ]] && sleep 5
      cleaner 1
    fi

    if [[ -f "${MAIN_LOG}" ]]; then
      if check_emba_ended; then
        break
      fi
    fi

    sleep 5
  done
}

safe_logging() {
  # forced utf8 logging into file
  # $1 File to log into
  # $2 suppress stdout
  # Example/test:
  # printf "%b" 'Hi from foo\n' |& safe_logging ./test.log 0
  # printf "%b" '\xE2\x98\xA0\n' |& safe_logging ./test.log
  # printf "%b" '\xF5\xFF\n' |& safe_logging ./test.log
  # printf "%b" 'end from bar\n' |& safe_logging ./test.log 1
  local lLOG_FILE_="${1:-}"
  local lALT_OUT_="${2:-}"
  local lINPUT_=""

  ## Force UTF-8 charset
  while read -r lINPUT_; do
    if [[ "${lALT_OUT_}" -eq 1 ]]; then
      echo "${lINPUT_}" | iconv -c --to-code=UTF-8 >> "${lLOG_FILE_}"
    else
      echo "${lINPUT_}" | iconv -c --to-code=UTF-8 | tee -a "${lLOG_FILE_}"
    fi
  done
}
