#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Analyzes firmware with binwalk, checks entropy and extracts firmware to the log directory.

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# This module extracts the firmware and is blocking modules that needs executed before the following modules can run
export PRE_THREAD_ENA=0

P59_binwalk_extractor() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binwalk firmware extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  export LINUX_PATH_COUNTER=0

  if [[ -d "${FIRMWARE_PATH}" ]] && [[ "$RTOS" -eq 1 ]]; then
    detect_root_dir_helper "$FIRMWARE_PATH"
  fi

  # we already found a linux root directory
  if [[ $RTOS -eq 0 ]] ; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  if [[ -d "$FIRMWARE_PATH" ]]; then
    print_output "[-] Binwalk module only deals with firmware files - directories are handled via deep extractor"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  # we need to check if sasquatch is the correct one for binwalk:
  if ! [[ "$(readlink -q -f "$UNBLOB_PATH"/sasquatch)" == "/usr/local/bin/sasquatch_binwalk" ]]; then
    if [[ -L "$UNBLOB_PATH"/sasquatch ]]; then
      rm "$UNBLOB_PATH"/sasquatch
    fi
    ln -s /usr/local/bin/sasquatch_binwalk "$UNBLOB_PATH"/sasquatch || true
  fi

  # typically FIRMWARE_PATH is only a file if none of the EMBA extractors were able to extract something
  # This means we are using binwalk in Matryoshka mode here
  # if we have a directory with multiple files in it we automatically pass here and run into the deep extractor
  if [[ -f "$FIRMWARE_PATH" ]]; then
    binwalking "$FIRMWARE_PATH"
  fi

  # FIRMWARE_PATH_CP is typically /log/firmware - shellcheck is probably confused here
  # shellcheck disable=SC2153
  detect_root_dir_helper "$FIRMWARE_PATH_CP"

  print_ln

  FILES_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
  UNIQUE_FILES=$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
  DIRS_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type d | wc -l )
  BINS=$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type f -exec file {} \; | grep -c "ELF" || true)

  if [[ "$BINS" -gt 0 || "$UNIQUE_FILES" -gt 0 ]]; then
    sub_module_title "Firmware extraction details"
    linux_basic_identification_helper "$FIRMWARE_PATH_CP"
    print_ln
    print_output "[*] Found $ORANGE$FILES_EXT$NC files ($ORANGE$UNIQUE_FILES$NC unique files) and $ORANGE$DIRS_EXT$NC directories at all."
    print_output "[*] Found $ORANGE$BINS$NC binaries."
    print_output "[*] Additionally the Linux path counter is $ORANGE$LINUX_PATH_COUNTER$NC."
    print_ln
    tree -csh "$FIRMWARE_PATH_CP" | tee -a "$LOG_FILE"

    # now it should be fine to also set the FIRMWARE_PATH ot the FIRMWARE_PATH_CP
    export FIRMWARE_PATH="$FIRMWARE_PATH_CP"

    if [[ "${#ROOT_PATH[@]}" -gt 0 ]] ; then
      write_csv_log "FILES" "UNIQUE_FILES" "DIRS" "Binaries" "LINUX_PATH_COUNTER" "Root PATH detected"
      for R_PATH in "${ROOT_PATH[@]}"; do
        write_csv_log "$FILES_EXT" "$UNIQUE_FILES" "$DIRS_EXT" "$BINS" "$LINUX_PATH_COUNTER" "$R_PATH"
      done
    fi
    backup_var "FILES_EXT" "$FILES_EXT"
    backup_var "FILES_EXT" "$UNIQUE_FILES"
    backup_var "FILES_EXT" "$DIRS_EXT"
  fi

  module_end_log "${FUNCNAME[0]}" "$FILES_EXT"
}

wait_for_extractor() {
  export OUTPUT_DIR="$FIRMWARE_PATH_CP"
  local SEARCHER=""
  SEARCHER=$(basename "$FIRMWARE_PATH")

  # this is not solid and we probably have to adjust it in the future
  # but for now it works
  SEARCHER="$(safe_echo "$SEARCHER" | tr "(" "." | tr ")" ".")"

  for PID in "${WAIT_PIDS[@]}"; do
    local running=1
    while [[ $running -eq 1 ]]; do
      print_dot
      if ! pgrep -v grep | grep -q "$PID"; then
        running=0
      fi
      disk_space_protection "$SEARCHER"
      sleep 1
    done
  done
}

# this function is for the first round of binwalk
# in case no other EMBA extractor did something and the
# current firmware file is a file and not multiple files
binwalking() {
  local FIRMWARE_PATH_="${1:-}"
  export OUTPUT_DIR_BINWALK=""

  if ! [[ -f "$FIRMWARE_PATH_" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "Analyze binary firmware blob with binwalk"

  print_output "[*] Basic analysis with binwalk"
  # just a quick fix for ignoring the warnings. As binwalk is nearly not used anymore this does not affect EMBA
  "${BINWALK_BIN[@]}" "$FIRMWARE_PATH_" | tee -a "$LOG_FILE"

  print_ln "no_log"

  OUTPUT_DIR_BINWALK=$(basename "$FIRMWARE_PATH_")
  OUTPUT_DIR_BINWALK="$FIRMWARE_PATH_CP""/""$OUTPUT_DIR_BINWALK"_binwalk_emba

  print_ln
  print_output "[*] Extracting firmware to directory $ORANGE$OUTPUT_DIR_BINWALK$NC"
  # this is not working in background. I have created a new function that gets executed in the background
  # probably there is a more elegant way
  # binwalk is executed in Matryoshka mode
  binwalk_deep_extract_helper 1 "$FIRMWARE_PATH_" "$OUTPUT_DIR_BINWALK" &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  WAIT_PIDS=( )

  MD5_DONE_DEEP+=( "$(md5sum "$FIRMWARE_PATH_" | awk '{print $1}')" )
}

linux_basic_identification_helper() {
  local FIRMWARE_PATH_CHECK="${1:-}"
  if ! [[ -d "$FIRMWARE_PATH_CHECK" ]]; then
    LINUX_PATH_COUNTER=0
    return
  fi
  LINUX_PATH_COUNTER="$(find "$FIRMWARE_PATH_CHECK" "${EXCL_FIND[@]}" -xdev -type d -iname bin -o -type f -iname busybox -o -type f -name shadow -o -type f -name passwd -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"
  backup_var "LINUX_PATH_COUNTER" "$LINUX_PATH_COUNTER"
}

binwalk_deep_extract_helper() {
  # Matryoshka mode is first parameter: 1 - enable, 0 - disable
  local MATRYOSHKA_="${1:-0}"
  local FILE_TO_EXTRACT_="${2:-}"
  local DEST_FILE_="${3:-}"

  if ! [[ -f "$FILE_TO_EXTRACT_" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  # we need to check if sasquatch is the correct one for binwalk:
  if ! [[ "$(readlink -q -f "$UNBLOB_PATH"/sasquatch)" == "/usr/local/bin/sasquatch_binwalk" ]]; then
    if [[ -L "$UNBLOB_PATH"/sasquatch ]]; then
      rm "$UNBLOB_PATH"/sasquatch
    fi
    ln -s /usr/local/bin/sasquatch_binwalk "$UNBLOB_PATH"/sasquatch || true
  fi

  if [[ "$BINWALK_VER_CHECK" == 1 ]]; then
    if [[ "$MATRYOSHKA_" -eq 1 ]]; then
      "${BINWALK_BIN[@]}" --run-as=root --preserve-symlinks --dd='.*' -e -M -C "$DEST_FILE_" "$FILE_TO_EXTRACT_" | tee -a "$LOG_FILE" || true
    else
      # no more Matryoshka mode ... we are doing it manually and check the files every round via MD5
      "${BINWALK_BIN[@]}" --run-as=root --preserve-symlinks --dd='.*' -e -C "$DEST_FILE_" "$FILE_TO_EXTRACT_" | tee -a "$LOG_FILE" || true
    fi
  else
    if [[ "$MATRYOSHKA_" -eq 1 ]]; then
      "${BINWALK_BIN[@]}" --dd='.*' -e -M -C "$DEST_FILE_" "$FILE_TO_EXTRACT_" | tee -a "$LOG_FILE" || true
    else
      "${BINWALK_BIN[@]}" --dd='.*' -e -C "$DEST_FILE_" "$FILE_TO_EXTRACT_" | tee -a "$LOG_FILE" || true
    fi
  fi
}
