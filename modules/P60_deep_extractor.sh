#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Analyzes firmware with unblob, checks entropy and extracts firmware to the log directory.

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# This module extracts the firmware and is blocking modules that needs executed before the following modules can run
export PRE_THREAD_ENA=0

P60_deep_extractor() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware deep extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  export DISK_SPACE_CRIT=0
  local FILES_EXT=0
  local UNIQUE_FILES=0
  local DIRS_EXT=0
  local BINS=0
  local R_PATH=""

  # If we have not found a linux filesystem we try to do an extraction round on every file multiple times
  # If we already know it is a linux (RTOS -> 0) or it is UEFI (UEFI_VERIFIED -> 1) we do not need to run
  # the deep extractor
  if [[ "${RTOS}" -eq 0 ]] || [[ "${UEFI_VERIFIED}" -eq 1 ]] || [[ "${DJI_DETECTED}" -eq 1 ]] || [[ "${DISABLE_DEEP:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  check_disk_space
  if ! [[ "${DISK_SPACE}" -gt "${MAX_EXT_SPACE}" ]]; then
    deep_extractor
  else
    print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
    print_output "[!] $(print_date) - Ending extraction processes - no deep extraction performed" "main"
    DISK_SPACE_CRIT=1
  fi

  sub_module_title "Extration results"

  FILES_EXT=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )
  UNIQUE_FILES=$(find "${FIRMWARE_PATH_CP}" "${EXCL_FIND[@]}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
  DIRS_EXT=$(find "${FIRMWARE_PATH_CP}" -xdev -type d | wc -l )
  BINS=$(find "${FIRMWARE_PATH_CP}" "${EXCL_FIND[@]}" -xdev -type f -exec file {} \; | grep -c "ELF" || true)

  if [[ "${BINS}" -gt 0 || "${UNIQUE_FILES}" -gt 0 ]]; then
    export LINUX_PATH_COUNTER=0
    linux_basic_identification_helper "${FIRMWARE_PATH_CP}"
    print_ln
    print_output "[*] Found ${ORANGE}${FILES_EXT}${NC} files (${ORANGE}${UNIQUE_FILES}${NC} unique files) and ${ORANGE}${DIRS_EXT}${NC} directories at all."
    print_output "[*] Found ${ORANGE}${BINS}${NC} binaries."
    print_output "[*] Additionally the Linux path counter is ${ORANGE}${LINUX_PATH_COUNTER}${NC}."

    tree -csh "${FIRMWARE_PATH_CP}" | tee -a "${LOG_FILE}"

    # now it should be fine to also set the FIRMWARE_PATH ot the FIRMWARE_PATH_CP
    export FIRMWARE_PATH="${FIRMWARE_PATH_CP}"

    if [[ "${#ROOT_PATH[@]}" -gt 0 ]] ; then
      write_csv_log "FILES" "UNIQUE_FILES" "DIRS" "Binaries" "LINUX_PATH_COUNTER" "Root PATH detected"
      for R_PATH in "${ROOT_PATH[@]}"; do
        write_csv_log "${FILES_EXT}" "${UNIQUE_FILES}" "${DIRS_EXT}" "${BINS}" "${LINUX_PATH_COUNTER}" "${R_PATH}"
      done
    fi
    backup_var "FILES_EXT" "${FILES_EXT}"
  fi

  module_end_log "${FUNCNAME[0]}" "${FILES_EXT}"
}

check_disk_space() {
  export DISK_SPACE
  DISK_SPACE=$(du -hm "${FIRMWARE_PATH_CP}" --max-depth=1 --exclude="proc" 2>/dev/null | awk '{ print $1 }' | sort -hr | head -1 || true)
}

disk_space_protection() {
  local SEARCHER="${1:-}"
  local DDISK="${LOG_DIR}"
  local FREE_SPACE=""

  check_disk_space
  FREE_SPACE=$(df --output=avail "${DDISK}" | awk 'NR==2')
  if [[ "${FREE_SPACE}" -lt 100000 ]] || [[ "${DISK_SPACE}" -gt "${MAX_EXT_SPACE}" ]]; then
    print_ln "no_log"
    print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
    print_output "[!] $(print_date) - Ending extraction processes" "main"
    pgrep -a -f "binwalk.*${SEARCHER}.*" || true
    pkill -f ".*binwalk.*${SEARCHER}.*" || true
    pkill -f ".*extract\.py.*${SEARCHER}.*" || true
    # PID is from wait_for_extractor
    kill -9 "${PID}" 2>/dev/null || true
    DISK_SPACE_CRIT=1
  fi
}

deep_extractor() {
  sub_module_title "Deep extraction mode"
  local FILES_AFTER_DEEP=0
  local FILES_BEFORE_DEEP=0
  FILES_BEFORE_DEEP=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )

  # if we run into the deep extraction mode we always do at least one extraction round:
  if [[ "${DISK_SPACE_CRIT}" -eq 0 ]]; then
    print_output "[*] Deep extraction - 1st round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 ]]; then
    print_output "[*] Deep extraction - 2nd round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 ]]; then
    print_output "[*] Deep extraction - 3rd round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 ]]; then
    print_output "[*] Deep extraction - 4th round"
    print_output "[*] Walking through all files and try to extract what ever possible with unblob mode"
    print_output "[*] WARNING: This is the last extraction round that is executed."

    # if we are already that far we do a final matryoshka extraction mode
    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  FILES_AFTER_DEEP=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )

  print_output "[*] Before deep extraction we had ${ORANGE}${FILES_BEFORE_DEEP}${NC} files, after deep extraction we have now ${ORANGE}${FILES_AFTER_DEEP}${NC} files extracted."
}

deeper_extractor_helper() {
  local FILE_TMP=""
  local FILE_MD5=""
  local BIN_PID=""
  local WAIT_PIDS_P60=()

  prepare_file_arr_limited "${FIRMWARE_PATH_CP}"

  for FILE_TMP in "${FILE_ARR_LIMITED[@]}"; do

    FILE_MD5="$(md5sum "${FILE_TMP}")"
    # let's check the current md5sum against our array of unique md5sums - if we have a match this is already extracted
    # already extracted stuff is ignored

    [[ "${MD5_DONE_DEEP[*]}" == *"${FILE_MD5/\ *}"* ]] && continue

    print_output "[*] Details of file: ${ORANGE}${FILE_TMP}${NC}"
    print_output "$(indent "$(orange "$(file "${FILE_TMP}")")")"
    print_output "$(indent "$(orange "$(md5sum "${FILE_TMP}")")")"

    # do a quick check if EMBA should handle the file or we give it to unblob:
    # fw_bin_detector is a function from p02
    fw_bin_detector "${FILE_TMP}"

    if [[ "${VMDK_DETECTED}" -eq 1 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        vmdk_extractor "${FILE_TMP}" "${FILE_TMP}_vmdk_extracted" &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        vmdk_extractor "${FILE_TMP}" "${FILE_TMP}_vmdk_extracted"
      fi
    elif [[ "${UBI_IMAGE}" -eq 1 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        ubi_extractor "${FILE_TMP}" "${FILE_TMP}_ubi_extracted" &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        ubi_extractor "${FILE_TMP}" "${FILE_TMP}_ubi_extracted"
      fi
    # now handled via unblob
    # elif [[ "${DLINK_ENC_DETECTED}" -eq 1 ]]; then
    #  if [[ "${THREADED}" -eq 1 ]]; then
    #    dlink_SHRS_enc_extractor "${FILE_TMP}" "${FILE_TMP}_shrs_extracted" &
    #    BIN_PID="$!"
    #    store_kill_pids "${BIN_PID}"
    #    disown "${BIN_PID}" 2> /dev/null || true
    #    WAIT_PIDS_P60+=( "${BIN_PID}" )
    #  else
    #    dlink_SHRS_enc_extractor "${FILE_TMP}" "${FILE_TMP}_shrs_extracted"
    #  fi
    # now handled via unblob
    # elif [[ "${DLINK_ENC_DETECTED}" -eq 2 ]]; then
    #  if [[ "${THREADED}" -eq 1 ]]; then
    #    dlink_enc_img_extractor "${FILE_TMP}" "${FILE_TMP}_enc_img_extracted" &
    #    BIN_PID="$!"
    #    store_kill_pids "${BIN_PID}"
    #    disown "${BIN_PID}" 2> /dev/null || true
    #    WAIT_PIDS_P60+=( "${BIN_PID}" )
    #  else
    #    dlink_enc_img_extractor "${FILE_TMP}" "${FILE_TMP}_enc_img_extracted"
    #  fi
    elif [[ "${EXT_IMAGE}" -eq 1 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        ext_extractor "${FILE_TMP}" "${FILE_TMP}_ext_extracted" &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        ext_extractor "${FILE_TMP}" "${FILE_TMP}_ext_extracted"
      fi
    # now handled via unblob
    # elif [[ "${ENGENIUS_ENC_DETECTED}" -ne 0 ]]; then
    #  if [[ "${THREADED}" -eq 1 ]]; then
    #    engenius_enc_extractor "${FILE_TMP}" "${FILE_TMP}_engenius_extracted" &
    #    BIN_PID="$!"
    #    store_kill_pids "${BIN_PID}"
    #    disown "${BIN_PID}" 2> /dev/null || true
    #    WAIT_PIDS_P60+=( "${BIN_PID}" )
    #  else
    #    engenius_enc_extractor "${FILE_TMP}" "${FILE_TMP}_engenius_extracted"
    #  fi
    elif [[ "${BSD_UFS}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        ufs_extractor "${FILE_TMP}" "${FILE_TMP}_bsd_ufs_extracted" &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        ufs_extractor "${FILE_TMP}" "${FILE_TMP}_bsd_ufs_extracted"
      fi
    elif [[ "${ANDROID_OTA}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        android_ota_extractor "${FILE_TMP}" "${FILE_TMP}_android_ota_extracted" &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        android_ota_extractor "${FILE_TMP}" "${FILE_TMP}_android_ota_extracted"
      fi
    elif [[ "${OPENSSL_ENC_DETECTED}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        foscam_enc_extractor "${FILE_TMP}" "${FILE_TMP}_foscam_enc_extracted" &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        foscam_enc_extractor "${FILE_TMP}" "${FILE_TMP}_foscam_enc_extracted"
      fi
    elif [[ "${BUFFALO_ENC_DETECTED}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        buffalo_enc_extractor "${FILE_TMP}" "${FILE_TMP}_buffalo_enc_extracted" &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        buffalo_enc_extractor "${FILE_TMP}" "${FILE_TMP}_buffalo_enc_extracted"
      fi
    elif [[ "${ZYXEL_ZIP}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        zyxel_zip_extractor "${FILE_TMP}" "${FILE_TMP}_zyxel_enc_extracted" &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        zyxel_zip_extractor "${FILE_TMP}" "${FILE_TMP}_zyxel_enc_extracted"
      fi
    elif [[ "${QCOW_DETECTED}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        qcow_extractor "${FILE_TMP}" "${FILE_TMP}_qemu_qcow_extracted" &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        qcow_extractor "${FILE_TMP}" "${FILE_TMP}_qemu_qcow_extracted"
      fi
    elif [[ "${BMC_ENC_DETECTED}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        bmc_extractor "${FILE_TMP}" "${FILE_TMP}_bmc_decrypted" &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        bmc_extractor "${FILE_TMP}" "${FILE_TMP}_qemu_bmc_decrypted"
      fi
    else
      # default case to Unblob
      if [[ "${THREADED}" -eq 1 ]]; then
        unblobber "${FILE_TMP}" "${FILE_TMP}_unblob_extracted" 1 &
        BIN_PID="$!"
        store_kill_pids "${BIN_PID}"
        disown "${BIN_PID}" 2> /dev/null || true
        WAIT_PIDS_P60+=( "${BIN_PID}" )
      else
        unblobber "${FILE_TMP}" "${FILE_TMP}_unblob_extracted" 1
      fi
    fi

    MD5_DONE_DEEP+=( "${FILE_MD5/\ *}" )
    max_pids_protection "${MAX_MOD_THREADS}" "${WAIT_PIDS_P60[@]}"

    check_disk_space

    FREE_SPACE=$(df --output=avail "${LOG_DIR}" | awk 'NR==2')
    if [[ "${FREE_SPACE}" -lt 100000 ]]; then
      # this should stop the complete EMBA test in the future - currenlty it is work in progress
      print_output "[!] $(print_date) - The system is running out of disk space ${ORANGE}${FREE_SPACE}${NC}" "main"
      print_output "[!] $(print_date) - Ending EMBA firmware analysis processes" "main"
      cleaner 1
      exit
    elif [[ "${DISK_SPACE}" -gt "${MAX_EXT_SPACE}" ]]; then
      # this stops the deep extractor but not EMBA
      print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
      print_output "[!] $(print_date) - Ending extraction processes" "main"
      DISK_SPACE_CRIT=1
      break
    fi
  done

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${WAIT_PIDS_P60[@]}"
}

linux_basic_identification_helper() {
  local FIRMWARE_PATH_CHECK="${1:-}"
  if ! [[ -d "${FIRMWARE_PATH_CHECK}" ]]; then
    LINUX_PATH_COUNTER=0
    return
  fi
  LINUX_PATH_COUNTER="$(find "${FIRMWARE_PATH_CHECK}" "${EXCL_FIND[@]}" -xdev -type d -iname bin -o -type f -iname busybox -o -type f -name shadow -o -type f -name passwd -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"
  backup_var "LINUX_PATH_COUNTER" "${LINUX_PATH_COUNTER}"
}

wait_for_extractor() {
  export OUTPUT_DIR="${FIRMWARE_PATH_CP}"
  local SEARCHER=""
  SEARCHER=$(basename "${FIRMWARE_PATH}")

  # this is not solid and we probably have to adjust it in the future
  # but for now it works
  SEARCHER="$(safe_echo "${SEARCHER}" | tr "(" "." | tr ")" ".")"

  for PID in "${WAIT_PIDS[@]}"; do
    local running=1
    while [[ ${running} -eq 1 ]]; do
      print_dot
      if ! pgrep -v grep | grep -q "${PID}"; then
        running=0
      fi
      disk_space_protection "${SEARCHER}"
      sleep 1
    done
  done
}
