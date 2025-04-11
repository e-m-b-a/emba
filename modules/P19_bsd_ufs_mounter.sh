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

# Description: Mounts and extracts BSD UFS images
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P19_bsd_ufs_mounter() {
  local lNEG_LOG=0

  if [[ "${BSD_UFS}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "BSD UFS filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    print_output "[*] Connect to device ${ORANGE}${FIRMWARE_PATH}${NC}"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/ufs_mount_filesystem/

    ufs_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

ufs_extractor() {
  local lUFS_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lTMP_UFS_MOUNT="${TMP_DIR}""/ufs_mount_${RANDOM}"
  local lFILES_UFS_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  if ! [[ -f "${lUFS_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "UFS filesystem extractor"

  mkdir -p "${lTMP_UFS_MOUNT}" 2>/dev/null || true
  print_output "[*] Trying to mount ${ORANGE}${lUFS_PATH_}${NC} to ${ORANGE}${lTMP_UFS_MOUNT}${NC} directory"
  # modprobe ufs
  if ! lsmod | grep -q "^ufs[[:space:]]"; then
    print_output "[-] WARNING: Ufs kernel module probably not loaded - trying to proceed"
  fi
  mount -r -t ufs -o ufstype=ufs2 "${lUFS_PATH_}" "${lTMP_UFS_MOUNT}"

  if mount | grep -q ufs_mount; then
    print_output "[*] Copying ${ORANGE}${lTMP_UFS_MOUNT}${NC} to firmware tmp directory (${ORANGE}${lEXTRACTION_DIR_}${NC})"
    mkdir -p "${lEXTRACTION_DIR_}" 2>/dev/null || true
    cp -pri "${lTMP_UFS_MOUNT}"/* "${lEXTRACTION_DIR_}" 2>/dev/null || true
    print_ln
    print_output "[*] Using the following firmware directory (${ORANGE}${lEXTRACTION_DIR_}${NC}) as base directory:"
    find "${lEXTRACTION_DIR_}" -xdev -maxdepth 1 -ls | tee -a "${LOG_FILE}"
    print_ln
    print_output "[*] Unmounting ${ORANGE}${lTMP_UFS_MOUNT}${NC} directory"

    mapfile -t lFILES_UFS_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")
    print_output "[*] Extracted ${ORANGE}${#lFILES_UFS_ARR[@]}${NC} files from the firmware image."
    print_output "[*] Populating backend data for ${ORANGE}${#lFILES_UFS_ARR[@]}${NC} files ... could take some time" "no_log"
    for lBINARY in "${lFILES_UFS_ARR[@]}" ; do
      binary_architecture_threader "${lBINARY}" "P07_windows_exe_extract" &
      local lTMP_PID="$!"
      store_kill_pids "${lTMP_PID}"
      lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
    done
    wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

    write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
    write_csv_log "UFS filesystem extractor" "${lUFS_PATH_}" "${lEXTRACTION_DIR_}" "${#lFILES_UFS_ARR[@]}" "NA"
    umount "${lTMP_UFS_MOUNT}" 2>/dev/null || true

    detect_root_dir_helper "${lEXTRACTION_DIR_}"
  fi
  rm -r "${lTMP_UFS_MOUNT}"
}
