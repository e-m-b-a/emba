#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner

# Description:  Extracts firmware with unblob to the module log directory.
#               IMPORTANT: The results are currently not used for further analysis.
#               This module is currently only for evaluation purposes.

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# This module extracts the firmware and is blocking modules that needs executed before the following modules can run
export PRE_THREAD_ENA=0

P61_unblob_eval() {
  module_log_init "${FUNCNAME[0]}"

  if [[ "$UNBLOB" -eq 0 ]]; then
    print_output "[-] Unblob module currently disabled - enable it in emba.sh setting the UNBLOB variable to 1"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  local FW_PATH_UNBLOB="$FIRMWARE_PATH_BAK"

  if ! [[ -f "$FW_PATH_UNBLOB" ]]; then
    print_output "[-] Unblob module currently only deals with firmware files - not with directories"
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  module_title "Unblob binary firmware extractor"
  pre_module_reporter "${FUNCNAME[0]}"
  print_output "[*] Unblob module currently enabled - disable it in emba.sh setting the UNBLOB variable to 0"

  print_output "[!] INFO: This is an evaluation module for the extractor ${ORANGE}unblob - https://unblob.org/$MAGENTA."
  print_output "[!] INFO: The results are currently not further used in the EMBA firmware analysis process (this will probably change in the future)."

  export LINUX_PATH_COUNTER_UNBLOB=0
  local OUTPUT_DIR_UNBLOB="$LOG_PATH_MODULE"/unblob_extracted

  if [[ -f "$FW_PATH_UNBLOB" ]]; then
    unblobber "$FW_PATH_UNBLOB" "$OUTPUT_DIR_UNBLOB"
  fi

  linux_basic_identification_unblobber "$OUTPUT_DIR_UNBLOB"

  print_ln

  FILES_EXT_UB=$(find "$OUTPUT_DIR_UNBLOB" -xdev -type f | wc -l )
  UNIQUE_FILES_UB=$(find "$OUTPUT_DIR_UNBLOB" "${EXCL_FIND[@]}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
  DIRS_EXT_UB=$(find "$OUTPUT_DIR_UNBLOB" -xdev -type d | wc -l )
  BINS_UB=$(find "$OUTPUT_DIR_UNBLOB" "${EXCL_FIND[@]}" -xdev -type f -exec file {} \; | grep -c "ELF" || true)

  if [[ "$BINS_UB" -gt 0 ]] || [[ "$FILES_EXT_UB" -gt 0 ]]; then
    print_bar
    print_output "[*] ${ORANGE}Unblob$NC results:"
    print_output "[*] Found $ORANGE$FILES_EXT_UB$NC files ($ORANGE$UNIQUE_FILES_UB$NC unique files) and $ORANGE$DIRS_EXT_UB$NC directories at all."
    print_output "[*] Found $ORANGE$BINS_UB$NC binaries."
    print_output "[*] Additionally the Linux path counter is $ORANGE$LINUX_PATH_COUNTER_UNBLOB$NC."
    print_ln
    print_output "[*] ${ORANGE}EMBA/binwalk$NC results:$NC"
    print_output "[*] Found $ORANGE$FILES_EXT$NC files ($ORANGE$UNIQUE_FILES$NC unique files) and $ORANGE$DIRS_EXT$NC directories at all."
    print_output "[*] Found $ORANGE$BINS$NC binaries."
    print_output "[*] Additionally the Linux path counter is $ORANGE$LINUX_PATH_COUNTER$NC."
    print_bar
    tree -sh "$OUTPUT_DIR_UNBLOB" | tee -a "$LOG_FILE"
    print_ln
  fi

  module_end_log "${FUNCNAME[0]}" "$FILES_EXT_UB"
}

unblobber() {
  local FIRMWARE_PATH_="${1:-}"
  local OUTPUT_DIR_UNBLOB="${2:-}"
  local UNBLOB_BIN="unblob"

  # find unblob installation - we move this later to the dependency checker
  if ! command -v unblob && [[ -f "$EXT_DIR"/unblob/unblob_path.cfg ]]; then
    # recover unblob installation - usually we are in the docker container
    if ! [[ -d "$HOME"/.cache ]]; then
      mkdir "$HOME"/.cache
    fi
    cp -pr "$EXT_DIR"/unblob/root_cache/* "$HOME"/.cache/
    if [[ -e $(cat "$EXT_DIR"/unblob/unblob_path.cfg)/bin/"$UNBLOB_BIN" ]]; then
      UNBLOB_PATH="$(cat "$EXT_DIR"/unblob/unblob_path.cfg)""/bin/"
      export PATH=$PATH:"$UNBLOB_PATH"
    else
      print_output "[-] Cant find unblob installation - check your installation"
      return
    fi
  else
    print_output "[-] Cant find unblob installation - check your installation"
    return
  fi

  sub_module_title "Analyze binary firmware blob with unblob"

  print_output "[*] Extracting firmware to directory $ORANGE$OUTPUT_DIR_UNBLOB$NC"

  if ! [[ -d "$OUTPUT_DIR_UNBLOB" ]]; then
    mkdir -p "$OUTPUT_DIR_UNBLOB"
  fi

  "$UNBLOB_BIN" -e "$OUTPUT_DIR_UNBLOB" "$FIRMWARE_PATH_" | tee -a "$LOG_FILE"

  print_ln
}

linux_basic_identification_unblobber() {
  local FIRMWARE_PATH_CHECK="${1:-}"
  if ! [[ -d "$FIRMWARE_PATH_CHECK" ]]; then
    return
  fi
  LINUX_PATH_COUNTER_UNBLOB="$(find "$FIRMWARE_PATH_CHECK" "${EXCL_FIND[@]}" -xdev -type d -iname bin -o -type f -iname busybox -o -type f -name shadow -o -type f -name passwd -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"
}
