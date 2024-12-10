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

  export DISK_SPACE_CRIT=0
  local lFILES_EXT=0
  local lUNIQUE_FILES=0
  local lDIRS_EXT=0
  local lBINS=0
  local lR_PATH=""

  # If we have not found a linux filesystem we try to do an extraction round on every file multiple times
  # If we already know it is a linux (RTOS -> 0) or it is UEFI (UEFI_VERIFIED -> 1) we do not need to run
  # the deep extractor
  if [[ "${RTOS}" -eq 0 ]] || [[ "${UEFI_VERIFIED}" -eq 1 ]] || [[ "${DJI_DETECTED}" -eq 1 ]] || [[ "${DISABLE_DEEP:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  module_title "Binary firmware deep extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  check_disk_space
  if ! [[ "${DISK_SPACE}" -gt "${MAX_EXT_SPACE}" ]]; then
    deep_extractor
  else
    print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
    print_output "[!] $(print_date) - Ending extraction processes - no deep extraction performed" "main"
    DISK_SPACE_CRIT=1
  fi

  if [[ "${SBOM_MINIMAL:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 1
    return
  fi

  sub_module_title "Extraction results"

  lUNIQUE_FILES=$(find "${FIRMWARE_PATH_CP}" "${EXCL_FIND[@]}" -xdev -type f -print0|xargs -r -0 -P 16 -I % sh -c 'md5sum "%" || true' 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
  lBINS=$(find "${FIRMWARE_PATH_CP}" "${EXCL_FIND[@]}" -xdev -type f -print0|xargs -r -0 -P 16 -I % sh -c 'file "%" | grep -c "ELF"' || true)
  lFILES_EXT=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )

  if [[ "${lBINS}" -gt 0 || "${lUNIQUE_FILES}" -gt 0 ]]; then
    lDIRS_EXT=$(find "${FIRMWARE_PATH_CP}" -xdev -type d | wc -l )
    export LINUX_PATH_COUNTER=0
    linux_basic_identification_helper "${FIRMWARE_PATH_CP}"
    print_ln
    print_output "[*] Found ${ORANGE}${lFILES_EXT}${NC} files (${ORANGE}${lUNIQUE_FILES}${NC} unique files) and ${ORANGE}${lDIRS_EXT}${NC} directories at all."
    print_output "[*] Found ${ORANGE}${lBINS}${NC} binaries."
    print_output "[*] Additionally the Linux path counter is ${ORANGE}${LINUX_PATH_COUNTER}${NC}."

    tree -csh "${FIRMWARE_PATH_CP}" | tee -a "${LOG_FILE}"

    # now it should be fine to also set the FIRMWARE_PATH ot the FIRMWARE_PATH_CP
    export FIRMWARE_PATH="${FIRMWARE_PATH_CP}"

    if [[ "${#ROOT_PATH[@]}" -gt 0 ]] ; then
      write_csv_log "FILES" "UNIQUE_FILES" "DIRS" "Binaries" "LINUX_PATH_COUNTER" "Root PATH detected"
      for lR_PATH in "${ROOT_PATH[@]}"; do
        write_csv_log "${lFILES_EXT}" "${lUNIQUE_FILES}" "${lDIRS_EXT}" "${lBINS}" "${LINUX_PATH_COUNTER}" "${lR_PATH}"
      done
    fi
    backup_var "FILES_EXT" "${lFILES_EXT}"
  fi

  module_end_log "${FUNCNAME[0]}" "${lFILES_EXT}"
}

check_disk_space() {
  export DISK_SPACE=0
  DISK_SPACE=$(du -hm "${FIRMWARE_PATH_CP}" --max-depth=1 --exclude="proc" 2>/dev/null | awk '{ print $1 }' | sort -hr | head -1 || true)
}

disk_space_protection() {
  local lSEARCHER="${1:-}"
  local lDDISK="${LOG_DIR}"
  local lFREE_SPACE=""

  check_disk_space
  lFREE_SPACE=$(df --output=avail "${lDDISK}" | awk 'NR==2')
  if [[ "${lFREE_SPACE}" -lt 100000 ]] || [[ "${DISK_SPACE}" -gt "${MAX_EXT_SPACE}" ]]; then
    print_ln "no_log"
    print_output "[!] $(print_date) - Extractor needs too much disk space ${DISK_SPACE}" "main"
    print_output "[!] $(print_date) - Ending extraction processes" "main"
    pgrep -a -f "binwalk.*${lSEARCHER}.*" || true
    pkill -f ".*binwalk.*${lSEARCHER}.*" || true
    pkill -f ".*extract\.py.*${lSEARCHER}.*" || true
    # PID is from wait_for_extractor
    kill -9 "${PID}" 2>/dev/null || true
    DISK_SPACE_CRIT=1
  fi
}

deep_extractor() {
  sub_module_title "Deep extraction mode"
  local lFILES_AFTER_DEEP=0
  local lFILES_BEFORE_DEEP=0
  lFILES_BEFORE_DEEP=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )

  # if we run into the deep extraction mode we always do at least one extraction round:
  if [[ "${DISK_SPACE_CRIT}" -eq 0 ]] && [[ "${DEEP_EXT_DEPTH:-4}" -gt 0 ]]; then
    print_output "[*] Deep extraction - 1st round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 && "${DEEP_EXT_DEPTH:-4}" -gt 1 ]]; then
    print_output "[*] Deep extraction - 2nd round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 && "${DEEP_EXT_DEPTH:-4}" -gt 2 ]]; then
    print_output "[*] Deep extraction - 3rd round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 && "${DEEP_EXT_DEPTH:-4}" -gt 3 ]]; then
    print_output "[*] Deep extraction - 4th round"
    print_output "[*] Walking through all files and try to extract what ever possible with unblob mode"
    print_output "[*] WARNING: This is the last extraction round that is executed."

    # if we are already that far we do a final matryoshka extraction mode
    deeper_extractor_helper
    detect_root_dir_helper "${FIRMWARE_PATH_CP}"
  fi

  lFILES_AFTER_DEEP=$(find "${FIRMWARE_PATH_CP}" -xdev -type f | wc -l )

  print_output "[*] Before deep extraction we had ${ORANGE}${lFILES_BEFORE_DEEP}${NC} files, after deep extraction we have now ${ORANGE}${lFILES_AFTER_DEEP}${NC} files extracted."
}

deeper_extractor_helper() {
  local lFILE_TMP=""
  local lFILE_MD5=""
  local lFILE_DETAILS=""
  local lBIN_PID=""
  local lWAIT_PIDS_P60=()
  local lFREE_SPACE=""

  prepare_file_arr_limited "${FIRMWARE_PATH_CP}"

  for lFILE_TMP in "${FILE_ARR_LIMITED[@]}"; do
    lFILE_DETAILS=$(file -b "${lFILE_TMP}")
    if [[ "${lFILE_DETAILS}" == *"text"* ]]; then
      continue
    fi

    lFILE_MD5="$(md5sum "${lFILE_TMP}")"
    # let's check the current md5sum against our array of unique md5sums - if we have a match this is already extracted
    # already extracted stuff is ignored

    [[ "${MD5_DONE_DEEP[*]}" == *"${lFILE_MD5/\ *}"* ]] && continue

    print_output "[*] Details of file: ${ORANGE}${lFILE_TMP}${NC}"
    print_output "$(indent "$(orange "${lFILE_DETAILS}")")"
    print_output "$(indent "$(orange "$(md5sum "${lFILE_TMP}")")")"

    # do a quick check if EMBA should handle the file or we give it to unblob:
    # fw_bin_detector is a function from p02
    fw_bin_detector "${lFILE_TMP}"

    if [[ "${VMDK_DETECTED}" -eq 1 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        vmdk_extractor "${lFILE_TMP}" "${lFILE_TMP}_vmdk_extracted" &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        vmdk_extractor "${lFILE_TMP}" "${lFILE_TMP}_vmdk_extracted"
      fi
    elif [[ "${UBI_IMAGE}" -eq 1 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        ubi_extractor "${lFILE_TMP}" "${lFILE_TMP}_ubi_extracted" &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        ubi_extractor "${lFILE_TMP}" "${lFILE_TMP}_ubi_extracted"
      fi
    # now handled via unblob
    # elif [[ "${DLINK_ENC_DETECTED}" -eq 1 ]]; then
    #  if [[ "${THREADED}" -eq 1 ]]; then
    #    dlink_SHRS_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_shrs_extracted" &
    #    lBIN_PID="$!"
    #    store_kill_pids "${lBIN_PID}"
    #    disown "${lBIN_PID}" 2> /dev/null || true
    #    lWAIT_PIDS_P60+=( "${lBIN_PID}" )
    #  else
    #    dlink_SHRS_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_shrs_extracted"
    #  fi
    # now handled via unblob
    # elif [[ "${DLINK_ENC_DETECTED}" -eq 2 ]]; then
    #  if [[ "${THREADED}" -eq 1 ]]; then
    #    dlink_enc_img_extractor "${lFILE_TMP}" "${lFILE_TMP}_enc_img_extracted" &
    #    lBIN_PID="$!"
    #    store_kill_pids "${lBIN_PID}"
    #    disown "${lBIN_PID}" 2> /dev/null || true
    #    lWAIT_PIDS_P60+=( "${lBIN_PID}" )
    #  else
    #    dlink_enc_img_extractor "${lFILE_TMP}" "${lFILE_TMP}_enc_img_extracted"
    #  fi
    elif [[ "${EXT_IMAGE}" -eq 1 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        ext_extractor "${lFILE_TMP}" "${lFILE_TMP}_ext_extracted" &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        ext_extractor "${lFILE_TMP}" "${lFILE_TMP}_ext_extracted"
      fi
    # now handled via unblob
    # elif [[ "${ENGENIUS_ENC_DETECTED}" -ne 0 ]]; then
    #  if [[ "${THREADED}" -eq 1 ]]; then
    #    engenius_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_engenius_extracted" &
    #    lBIN_PID="$!"
    #    store_kill_pids "${lBIN_PID}"
    #    disown "${lBIN_PID}" 2> /dev/null || true
    #    lWAIT_PIDS_P60+=( "${lBIN_PID}" )
    #  else
    #    engenius_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_engenius_extracted"
    #  fi
    elif [[ "${BSD_UFS}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        ufs_extractor "${lFILE_TMP}" "${lFILE_TMP}_bsd_ufs_extracted" &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        ufs_extractor "${lFILE_TMP}" "${lFILE_TMP}_bsd_ufs_extracted"
      fi
    elif [[ "${ANDROID_OTA}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        android_ota_extractor "${lFILE_TMP}" "${lFILE_TMP}_android_ota_extracted" &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        android_ota_extractor "${lFILE_TMP}" "${lFILE_TMP}_android_ota_extracted"
      fi
    elif [[ "${OPENSSL_ENC_DETECTED}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        foscam_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_foscam_enc_extracted" &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        foscam_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_foscam_enc_extracted"
      fi
    elif [[ "${BUFFALO_ENC_DETECTED}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        buffalo_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_buffalo_enc_extracted" &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        buffalo_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_buffalo_enc_extracted"
      fi
    elif [[ "${ZYXEL_ZIP}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        zyxel_zip_extractor "${lFILE_TMP}" "${lFILE_TMP}_zyxel_enc_extracted" &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        zyxel_zip_extractor "${lFILE_TMP}" "${lFILE_TMP}_zyxel_enc_extracted"
      fi
    elif [[ "${QCOW_DETECTED}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        qcow_extractor "${lFILE_TMP}" "${lFILE_TMP}_qemu_qcow_extracted" &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        qcow_extractor "${lFILE_TMP}" "${lFILE_TMP}_qemu_qcow_extracted"
      fi
    elif [[ "${BMC_ENC_DETECTED}" -ne 0 ]]; then
      if [[ "${THREADED}" -eq 1 ]]; then
        bmc_extractor "${lFILE_TMP}" "${lFILE_TMP}_bmc_decrypted" &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        bmc_extractor "${lFILE_TMP}" "${lFILE_TMP}_qemu_bmc_decrypted"
      fi
    else
      # default case to Unblob
      if [[ "${THREADED}" -eq 1 ]]; then
        unblobber "${lFILE_TMP}" "${lFILE_TMP}_unblob_extracted" 1 &
        lBIN_PID="$!"
        store_kill_pids "${lBIN_PID}"
        disown "${lBIN_PID}" 2> /dev/null || true
        lWAIT_PIDS_P60+=( "${lBIN_PID}" )
      else
        unblobber "${lFILE_TMP}" "${lFILE_TMP}_unblob_extracted" 1
      fi
    fi

    MD5_DONE_DEEP+=( "${lFILE_MD5/\ *}" )
    max_pids_protection "${MAX_MOD_THREADS}" "${lWAIT_PIDS_P60[@]}"

    check_disk_space

    lFREE_SPACE=$(df --output=avail "${LOG_DIR}" | awk 'NR==2')
    if [[ "${lFREE_SPACE}" -lt 100000 ]]; then
      # this should stop the complete EMBA test in the future - currenlty it is work in progress
      print_output "[!] $(print_date) - The system is running out of disk space ${ORANGE}${lFREE_SPACE}${NC}" "main"
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

  [[ "${THREADED}" -eq 1 ]] && wait_for_pid "${lWAIT_PIDS_P60[@]}"
}

linux_basic_identification_helper() {
  local lFIRMWARE_PATH_CHECK="${1:-}"
  if ! [[ -d "${lFIRMWARE_PATH_CHECK}" ]]; then
    LINUX_PATH_COUNTER=0
    return
  fi
  LINUX_PATH_COUNTER="$(find "${lFIRMWARE_PATH_CHECK}" "${EXCL_FIND[@]}" -xdev -type d -iname bin -o -type f -iname busybox -o -type f -name shadow -o -type f -name passwd -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"
  backup_var "LINUX_PATH_COUNTER" "${LINUX_PATH_COUNTER}"
}

wait_for_extractor() {
  export OUTPUT_DIR="${FIRMWARE_PATH_CP}"
  local lSEARCHER=""
  lSEARCHER=$(basename "${FIRMWARE_PATH}")

  # this is not solid and we probably have to adjust it in the future
  # but for now it works
  lSEARCHER="$(safe_echo "${lSEARCHER}" | tr "(" "." | tr ")" ".")"

  for PID in "${WAIT_PIDS[@]}"; do
    local lrunning=1
    while [[ ${lrunning} -eq 1 ]]; do
      print_dot
      if ! pgrep -v grep | grep -q "${PID}"; then
        lrunning=0
      fi
      disk_space_protection "${lSEARCHER}"
      sleep 1
    done
  done
}
