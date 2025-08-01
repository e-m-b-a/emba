#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
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
  local lR_PATH=""
  # dirty solution to know if have not run the extractor and we just re-created the P99 log
  export NO_EXTRACTED=0

  # If we have not found a linux filesystem we try to do an extraction round on every file multiple times
  # If we already know it is a linux (RTOS -> 0) or it is UEFI (UEFI_VERIFIED -> 1) we do not need to run
  # the deep extractor
  if [[ "${RTOS:-1}" -eq 0 ]] || [[ "${UEFI_VERIFIED:-0}" -eq 1 ]] || [[ "${DJI_DETECTED:-0}" -eq 1 ]] || [[ "${DISABLE_DEEP:-0}" -eq 1 ]]; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  module_title "Binary firmware deep extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  local lFILES_P99_BEFORE=0
  if [[ -f "${P99_CSV_LOG}" ]]; then
    lFILES_P99_BEFORE=$(wc -l "${P99_CSV_LOG}")
    lFILES_P99_BEFORE="${lFILES_P99_BEFORE/\ *}"
  fi

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

  mapfile -t lFILES_EXT_ARR < <(find "${FIRMWARE_PATH_CP}" -type f ! -name "*.raw")
  local lFILES_P99=0
  if [[ -f "${P99_CSV_LOG}" ]]; then
    lFILES_P99=$(wc -l "${P99_CSV_LOG}")
    lFILES_P99="${lFILES_P99/\ *}"
  fi

  # we only do the P99 populating if we have done something with the deep extractor
  # and we have now more files found as already known in P99
  if [[ "${NO_EXTRACTED}" -eq 0 ]] && [[ "${#lFILES_EXT_ARR[@]}" -gt "${lFILES_P99}" ]]; then
    sub_module_title "Extraction results"

    print_output "[*] Extracted ${ORANGE}${#lFILES_EXT_ARR[@]}${NC} files."

    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_EXT_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_EXT_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done

    local lLINUX_PATH_COUNTER=0
    lLINUX_PATH_COUNTER=$(linux_basic_identification "${FIRMWARE_PATH_CP}")
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    print_ln
    print_output "[*] Found ${ORANGE}${#lFILES_EXT_ARR[@]}${NC} files at all."
    print_output "[*] Additionally the Linux path counter is ${ORANGE}${lLINUX_PATH_COUNTER}${NC}."
    print_output "[*] Before deep extraction we had ${ORANGE}${lFILES_P99_BEFORE}${NC} files, after deep extraction we have now ${ORANGE}${#lFILES_EXT_ARR[@]}${NC} files extracted."

    tree -csh "${FIRMWARE_PATH_CP}" | tee -a "${LOG_FILE}"

    # now it should be fine to also set the FIRMWARE_PATH ot the FIRMWARE_PATH_CP
    export FIRMWARE_PATH="${FIRMWARE_PATH_CP}"

    if [[ "${#ROOT_PATH[@]}" -gt 0 ]] ; then
      write_csv_log "FILES" "LINUX_PATH_COUNTER" "Root PATH detected"
      for lR_PATH in "${ROOT_PATH[@]}"; do
        write_csv_log "${#lFILES_EXT_ARR[@]}" "${lLINUX_PATH_COUNTER}" "${lR_PATH}"
      done
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "${#lFILES_EXT_ARR[@]}"
}

check_disk_space() {
  export DISK_SPACE=0
  DISK_SPACE=$(du -hm "${FIRMWARE_PATH_CP}" --max-depth=1 --exclude="proc" 2>/dev/null | awk '{ print $1 }' | sort -hr | head -1 || true)
}

deep_extractor() {
  sub_module_title "Deep extraction mode"

  local lFILES_DEEP_PRE_ARR=()
  local lBINARY=""
  if [[ ! -f "${P99_CSV_LOG}" ]]; then
    print_output "[-] No ${P99_CSV_LOG} log file available ... trying to create it now"
    mapfile -t lFILES_DEEP_PRE_ARR < <(find "${LOG_DIR}/firmware" -type f)
    if [[ -f "${FIRMWARE_PATH}" ]]; then
      lFILES_DEEP_PRE_ARR+=("${FIRMWARE_PATH}")
    fi
    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_DEEP_PRE_ARR[@]}${NC} files ... could take some time" "no_log"

    for lBINARY in "${lFILES_DEEP_PRE_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "${FUNCNAME[0]}" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_P60_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P60_ARR[@]}"
    detect_root_dir_helper "${LOG_DIR}/firmware"
    if [[ ${RTOS} -eq 0 ]]; then
      export NO_EXTRACTED=1
      return
    fi
  fi

  # if we run into the deep extraction mode we always do at least one extraction round:
  if [[ ${RTOS} -eq 1 && "${DISK_SPACE_CRIT}" -eq 0 && "${DEEP_EXT_DEPTH:-4}" -gt 0 ]]; then
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
}

deeper_extractor_helper() {
  local lFILE_TMP=""
  local lFILE_MD5=""
  local lFILE_DETAILS=""
  local lBIN_PID=""

  prepare_file_arr_limited "${FIRMWARE_PATH_CP}"
  for lFILE_TMP in "${FILE_ARR_LIMITED[@]}"; do
    lFILE_MD5="$(md5sum "${lFILE_TMP}")"
    [[ "${MD5_DONE_DEEP[*]}" == *"${lFILE_MD5/\ *}"* ]] && continue
    MD5_DONE_DEEP+=( "${lFILE_MD5/\ *}" )
    # deeper_extractor_threader "${lFILE_TMP}" >> "${LOG_PATH_MODULE}/tmp_out_${MD5_DONE_DEEP}" &
    deeper_extractor_threader "${lFILE_TMP}" &
    lBIN_PID="$!"
    lWAIT_PIDS_P60_init+=( "${lBIN_PID}" )
    max_pids_protection $((2*"${MAX_MOD_THREADS}")) lWAIT_PIDS_P60_init
  done
  wait_for_pid "${lWAIT_PIDS_P60_init[@]}"
}

deeper_extractor_threader() {
  local lFILE_TMP="${1:-}"

  local lFILE_DETAILS=""
  lFILE_DETAILS=$(file -b "${lFILE_TMP}")
  if [[ "${lFILE_DETAILS}" == *"text"* ]]; then
    return
  fi

  print_output "[*] Details of file: ${ORANGE}${lFILE_TMP}${NC}"
  print_output "$(indent "$(orange "${lFILE_DETAILS}")")"
  print_output "$(indent "$(orange "$(md5sum "${lFILE_TMP}")")")"

  # do a quick check if EMBA should handle the file or we give it to the default extractor (binwalk or unblob):
  # fw_bin_detector is a function from p02
  fw_bin_detector "${lFILE_TMP}"

  if [[ "${VMDK_DETECTED}" -eq 1 ]]; then
    vmdk_extractor "${lFILE_TMP}" "${lFILE_TMP}_vmdk_extracted"
    # now handled via unblob
    # elif [[ "${UBI_IMAGE}" -eq 1 ]]; then
    #   ubi_extractor "${lFILE_TMP}" "${lFILE_TMP}_ubi_extracted"
    # now handled via unblob
    # elif [[ "${DLINK_ENC_DETECTED}" -eq 1 ]]; then
    #   dlink_SHRS_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_shrs_extracted"
    # now handled via unblob
    # elif [[ "${DLINK_ENC_DETECTED}" -eq 2 ]]; then
    #   dlink_enc_img_extractor "${lFILE_TMP}" "${lFILE_TMP}_enc_img_extracted"
  elif [[ "${EXT_IMAGE}" -eq 1 ]]; then
    ext_extractor "${lFILE_TMP}" "${lFILE_TMP}_ext_extracted"
    # now handled via unblob
    # elif [[ "${ENGENIUS_ENC_DETECTED}" -ne 0 ]]; then
    #   engenius_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_engenius_extracted"
    # fi
  elif [[ "${BSD_UFS}" -ne 0 ]]; then
    ufs_extractor "${lFILE_TMP}" "${lFILE_TMP}_bsd_ufs_extracted"
  elif [[ "${ANDROID_OTA}" -ne 0 ]]; then
    android_ota_extractor "${lFILE_TMP}" "${lFILE_TMP}_android_ota_extracted"
  elif [[ "${OPENSSL_ENC_DETECTED}" -ne 0 ]]; then
    foscam_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_foscam_enc_extracted"
  elif [[ "${BUFFALO_ENC_DETECTED}" -ne 0 ]]; then
    buffalo_enc_extractor "${lFILE_TMP}" "${lFILE_TMP}_buffalo_enc_extracted"
  elif [[ "${ZYXEL_ZIP}" -ne 0 ]]; then
    zyxel_zip_extractor "${lFILE_TMP}" "${lFILE_TMP}_zyxel_enc_extracted"
  elif [[ "${QCOW_DETECTED}" -ne 0 ]]; then
    qcow_extractor "${lFILE_TMP}" "${lFILE_TMP}_qemu_qcow_extracted"
  elif [[ "${BMC_ENC_DETECTED}" -ne 0 ]]; then
    bmc_extractor "${lFILE_TMP}" "${lFILE_TMP}_bmc_decrypted"
  else
    # configure the extractor to use in the default configuration file
    # or via scanning profile
    # EMBA usually uses unblob as default for the deep extractor
    if [[ "${DEEP_EXTRACTOR}" == "binwalk" ]]; then
      binwalker_matryoshka "${lFILE_TMP}" "${lFILE_TMP}_binwalk_extracted"
    else
      # default case to Unblob
      unblobber "${lFILE_TMP}" "${lFILE_TMP}_unblob_extracted" 0
    fi
  fi
}

