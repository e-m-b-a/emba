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

# Description: Extracts AVM firmware images with Freetz-NG (see https://github.com/Freetz-NG/freetz-ng.git)
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P12_avm_freetz_ng_extract() {
  local NEG_LOG=0

  if [[ "$AVM_DETECTED" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "AVM freetz-ng firmware extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    EXTRACTION_DIR="$LOG_DIR"/firmware/freetz_ng_extractor

    avm_extractor "$FIRMWARE_PATH" "$EXTRACTION_DIR"

    if [[ "$FRITZ_FILES" -gt 0 ]]; then
      MD5_DONE_DEEP+=( "$(md5sum "$FIRMWARE_PATH" | awk '{print $1}')" )
      export FIRMWARE_PATH="$LOG_DIR"/firmware/
      backup_var "FIRMWARE_PATH" "$FIRMWARE_PATH"
    fi

    NEG_LOG=1
    module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
  fi
}

avm_extractor() {
  local AVM_FW_PATH_="${1:-}"
  local EXTRACTION_DIR_="${2:-}"
  if ! [[ -f "$AVM_FW_PATH_" ]]; then
    return
  fi
  local FRITZ_DIRS=0
  local FIT_IMAGES=()
  local FIT_IMAGE=""
  local RAM_DISKS=()
  local RAM_DISK=""
  local RAM_DISK_NAME=""
  export FRITZ_FILE=0
  export FRITZ_VERSION=""

  sub_module_title "AVM freetz-ng firmware extractor"

  # read only filesystem bypass:
  cp "$EXT_DIR"/freetz-ng/.config "$TMP_DIR"/.config

  "$EXT_DIR"/freetz-ng/fwmod -u -i "$TMP_DIR"/.config -d "$EXTRACTION_DIR_" "$AVM_FW_PATH_" | tee -a "$LOG_FILE" || true

  if [[ -d "$EXTRACTION_DIR_" ]]; then
    FRITZ_FILES=$(find "$EXTRACTION_DIR_" -type f | wc -l)
    FRITZ_DIRS=$(find "$EXTRACTION_DIR_" -type d | wc -l)

    FRITZ_VERSION=$(grep "detected firmware version:" "$LOG_FILE" | cut -d ":" -f2- || true)
    if [[ -z "$FRITZ_VERSION" ]]; then
      FRITZ_VERSION="NA"
    else
      print_output "[+] Detected Fritz version: $ORANGE$FRITZ_VERSION$NC"
    fi

    # fitimages are handled here with fitimg - binwalk and unblob are also able to handle these images
    # but it is currently more beautiful doing the AVM extraction in one place here
    mapfile -t FIT_IMAGES < <(find "$EXTRACTION_DIR_" -type f -name "fit-image")

    if [[ "${#FIT_IMAGES[@]}" -gt 0 ]]; then
      if [[ -f "$EXT_DIR"/fitimg-0.8/fitimg ]]; then
        for FIT_IMAGE in "${FIT_IMAGES[@]}"; do
          print_output "[*] Detected fit-image: $ORANGE$FIT_IMAGE$NC"
          print_output "[*] Extracting fit-image with fitimg to $ORANGE$EXTRACTION_DIR/fit-image-extraction$NC"
          mkdir -p "$EXTRACTION_DIR/fit-image-extraction"
          "$EXT_DIR"/fitimg-0.8/fitimg -x "$FIT_IMAGE" -d "$EXTRACTION_DIR"/fit-image-extraction || true
          mapfile -t RAM_DISKS < <(find "$EXTRACTION_DIR_"/fit-image-extraction -type f -name "*ramdisk")
          print_ln
        done
      else
        print_output "[-] Fitimg installation not available - check your installation"
      fi
    fi
    if [[ "${#RAM_DISKS[@]}" -gt 0 ]]; then
      for RAM_DISK in "${RAM_DISKS[@]}"; do
        print_output "[*] Detected AVM ramdisk: $ORANGE$RAM_DISK$NC"
        RAM_DISK_NAME="$(basename "$RAM_DISK")"
        binwalk_deep_extract_helper 1 "$RAM_DISK" "$EXTRACTION_DIR_"/fit-image-extraction/"$RAM_DISK_NAME"_binwalk
        print_ln
      done
    fi

    if [[ "$FRITZ_FILES" -gt 0 ]]; then
      print_ln
      print_output "[*] Extracted $ORANGE$FRITZ_FILES$NC files and $ORANGE$FRITZ_DIRS$NC directories from the firmware image."
      write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "directory counter" "further details"
      write_csv_log "AVM extractor" "$AVM_FW_PATH_" "$EXTRACTION_DIR_" "$FRITZ_FILES" "$FRITZ_DIRS" "$FRITZ_VERSION"
      export DEEP_EXTRACTOR=1
      MD5_DONE_DEEP+=( "$(md5sum "$AVM_FW_PATH_" | awk '{print $1}')" )

      if [[ -z "${FW_VENDOR:-}" ]]; then
        FW_VENDOR="AVM"
        backup_var "FW_VENDOR" "$FW_VENDOR"
      fi
      if [[ -z "${FW_VERSION:-}" && "$FRITZ_VERSION" != "NA" ]]; then
        FW_VERSION="$FRITZ_VERSION"
      fi
    fi
  fi
}
