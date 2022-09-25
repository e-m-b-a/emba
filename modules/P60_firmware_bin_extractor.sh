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

# Description:  Analyzes firmware with binwalk, checks entropy and extracts firmware to the log directory.

# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# This module extracts the firmware and is blocking modules that needs executed before the following modules can run
export PRE_THREAD_ENA=0

P60_firmware_bin_extractor() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware deep extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  export DISK_SPACE_CRIT=0
  export LINUX_PATH_COUNTER=0

  # If we have not found a linux filesystem we try to do an extraction round on every file multiple times
  if [[ $RTOS -eq 0 ]] ; then
    module_end_log "${FUNCNAME[0]}" 0
    return
  fi

  check_disk_space
  if ! [[ "$DISK_SPACE" -gt "$MAX_EXT_SPACE" ]]; then
    deep_extractor
  else
    print_output "[!] $(date) - Extractor needs too much disk space $DISK_SPACE" "main"
    print_output "[!] $(date) - Ending extraction processes - no deep extraction performed" "main"
    DISK_SPACE_CRIT=1
  fi

  print_ln

  FILES_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
  UNIQUE_FILES=$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
  DIRS_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type d | wc -l )
  BINS=$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type f -exec file {} \; | grep -c "ELF" || true)

  if [[ "$BINS" -gt 0 || "$UNIQUE_FILES" -gt 0 ]]; then
    linux_basic_identification_helper "$FIRMWARE_PATH_CP"
    print_ln
    print_output "[*] Found $ORANGE$FILES_EXT$NC files ($ORANGE$UNIQUE_FILES$NC unique files) and $ORANGE$DIRS_EXT$NC directories at all."
    print_output "[*] Found $ORANGE$BINS$NC binaries."
    print_output "[*] Additionally the Linux path counter is $ORANGE$LINUX_PATH_COUNTER$NC."
    print_ln
    tree -csh "$FIRMWARE_PATH_CP" | tee -a "$LOG_FILE"

    # now it should be fine to also set the FIRMWARE_PATH ot the FIRMWARE_PATH_CP
    export FIRMWARE_PATH="$FIRMWARE_PATH_CP"
  fi

  module_end_log "${FUNCNAME[0]}" "$FILES_EXT"
}

check_disk_space() {
  export DISK_SPACE
  DISK_SPACE=$(du -hm "$FIRMWARE_PATH_CP" --max-depth=1 --exclude="proc" 2>/dev/null | awk '{ print $1 }' | sort -hr | head -1 || true)
}

disk_space_protection() {
  local SEARCHER="${1:-}"

  check_disk_space
  if [[ "$DISK_SPACE" -gt "$MAX_EXT_SPACE" ]]; then
    print_ln "no_log"
    print_output "[!] $(date) - Extractor needs too much disk space $DISK_SPACE" "main"
    print_output "[!] $(date) - Ending extraction processes" "main"
    pgrep -a -f "binwalk.*$SEARCHER.*" || true
    pkill -f ".*binwalk.*$SEARCHER.*" || true
    pkill -f ".*extract\.py.*$SEARCHER.*" || true
    kill -9 "$PID" 2>/dev/null || true
    DISK_SPACE_CRIT=1
  fi
}

deep_extractor() {
  sub_module_title "Deep extraction mode"

  FILE_ARR_TMP=()
  FILE_MD5=""

  FILES_BEFORE_DEEP=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )

  # if we run into the deep extraction mode we always do at least one extraction round:
  if [[ "$DISK_SPACE_CRIT" -eq 0 ]]; then
    print_output "[*] Deep extraction - 1st round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "$FIRMWARE_PATH_CP"
  fi

  if [[ $RTOS -eq 1 && "$DISK_SPACE_CRIT" -eq 0 ]]; then
    print_output "[*] Deep extraction - 2nd round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "$FIRMWARE_PATH_CP"
  fi

  if [[ $RTOS -eq 1 && "$DISK_SPACE_CRIT" -eq 0 ]]; then
    print_output "[*] Deep extraction - 3rd round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
    detect_root_dir_helper "$FIRMWARE_PATH_CP"
  fi

  if [[ $RTOS -eq 1 && "$DISK_SPACE_CRIT" -eq 0 ]]; then
    print_output "[*] Deep extraction - 4th round"
    print_output "[*] Walking through all files and try to extract what ever possible with binwalk matryoshka mode"
    print_output "[*] WARNING: This is the last extraction round that is executed."

    # if we are already that far we do a final matryoshka extraction mode
    deeper_extractor_helper "M"
    detect_root_dir_helper "$FIRMWARE_PATH_CP"
  fi

  FILES_AFTER_DEEP=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )

  print_output "[*] Before deep extraction we had $ORANGE$FILES_BEFORE_DEEP$NC files, after deep extraction we have now $ORANGE$FILES_AFTER_DEEP$NC files extracted."
}

deeper_extractor_helper() {

  if [[ -v 1 ]] && [[ "$1" == "M" ]]; then
    local MATRYOSHKA=1
  else
    local MATRYOSHKA=0
  fi
  local FILE_ARR_TMP=()
  local FILE_TMP=""
  local FILE_MD5=""

  readarray -t FILE_ARR_TMP < <(find "$FIRMWARE_PATH_CP" -xdev "${EXCL_FIND[@]}" -type f ! \( -iname "*.udeb" -o -iname "*.deb" \
    -o -iname "*.ipk" -o -iname "*.pdf" -o -iname "*.php" -o -iname "*.txt" -o -iname "*.doc" -o -iname "*.rtf" -o -iname "*.docx" \
    -o -iname "*.htm" -o -iname "*.html" -o -iname "*.md5" -o -iname "*.sha1" -o -iname "*.torrent" -o -iname "*.png" -o -iname "*.svg" \
    -o -iname "*.js" \) \
    -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3- )

  for FILE_TMP in "${FILE_ARR_TMP[@]}"; do

    FILE_MD5="$(md5sum "$FILE_TMP" | awk '{print $1}')"
    # let's check the current md5sum against our array of unique md5sums - if we have a match this is already extracted
    # already extracted stuff is now ignored

    if [[ ! " ${MD5_DONE_DEEP[*]} " =~ ${FILE_MD5} ]]; then

      print_output "[*] Details of file: $ORANGE$FILE_TMP$NC"
      print_output "$(indent "$(file "$FILE_TMP")")"

      # do a quick check if EMBA should handle the file or we give it to binwalk:
      # fw_bin_detector is a function from p02
      fw_bin_detector "$FILE_TMP"

      if [[ "$VMDK_DETECTED" -eq 1 ]]; then
        if [[ "$THREADED" -eq 1 ]]; then
          vmdk_extractor "$FILE_TMP" "${FILE_TMP}_vmdk_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          vmdk_extractor "$FILE_TMP" "${FILE_TMP}_vmdk_extracted"
        fi
      elif [[ "$UBI_IMAGE" -eq 1 ]]; then
        if [[ "$THREADED" -eq 1 ]]; then
          ubi_extractor "$FILE_TMP" "${FILE_TMP}_ubi_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          ubi_extractor "$FILE_TMP" "${FILE_TMP}_ubi_extracted"
        fi
      elif [[ "$DLINK_ENC_DETECTED" -eq 1 ]]; then
        if [[ "$THREADED" -eq 1 ]]; then
          dlink_SHRS_enc_extractor "$FILE_TMP" "${FILE_TMP}_shrs_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          dlink_SHRS_enc_extractor "$FILE_TMP" "${FILE_TMP}_shrs_extracted"
        fi
      elif [[ "$DLINK_ENC_DETECTED" -eq 2 ]]; then
        if [[ "$THREADED" -eq 1 ]]; then
          dlink_enc_img_extractor "$FILE_TMP" "${FILE_TMP}_enc_img_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          dlink_enc_img_extractor "$FILE_TMP" "${FILE_TMP}_enc_img_extracted"
        fi
      elif [[ "$EXT_IMAGE" -eq 1 ]]; then
        if [[ "$THREADED" -eq 1 ]]; then
          ext_extractor "$FILE_TMP" "${FILE_TMP}_ext_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          ext_extractor "$FILE_TMP" "${FILE_TMP}_ext_extracted"
        fi
      elif [[ "$ENGENIUS_ENC_DETECTED" -ne 0 ]]; then
        if [[ "$THREADED" -eq 1 ]]; then
          engenius_enc_extractor "$FILE_TMP" "${FILE_TMP}_engenius_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          engenius_enc_extractor "$FILE_TMP" "${FILE_TMP}_engenius_extracted"
        fi
      elif [[ "$BSD_UFS" -ne 0 ]]; then
        if [[ "$THREADED" -eq 1 ]]; then
          ufs_extractor "$FILE_TMP" "${FILE_TMP}_bsd_ufs_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          ufs_extractor "$FILE_TMP" "${FILE_TMP}_bsd_ufs_extracted"
        fi
      elif [[ "$ANDROID_OTA" -ne 0 ]]; then
        if [[ "$THREADED" -eq 1 ]]; then
          android_ota_extractor "$FILE_TMP" "${FILE_TMP}_android_ota_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          android_ota_extractor "$FILE_TMP" "${FILE_TMP}_android_ota_extracted"
        fi
      elif [[ "$OPENSSL_ENC_DETECTED" -ne 0 ]]; then
        if [[ "$THREADED" -eq 1 ]]; then
          foscam_enc_extractor "$FILE_TMP" "${FILE_TMP}_foscam_enc_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          foscam_enc_extractor "$FILE_TMP" "${FILE_TMP}_foscam_enc_extracted"
        fi
      elif [[ "$BUFFALO_ENC_DETECTED" -ne 0 ]]; then
        if [[ "$THREADED" -eq 1 ]]; then
          buffalo_enc_extractor "$FILE_TMP" "${FILE_TMP}_buffalo_enc_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          buffalo_enc_extractor "$FILE_TMP" "${FILE_TMP}_buffalo_enc_extracted"
        fi

      else
        # default case to binwalk
        if [[ "$THREADED" -eq 1 ]]; then
          binwalk_deep_extract_helper "$MATRYOSHKA" "$FILE_TMP" "${FILE_TMP}_binwalk_extracted" &
          WAIT_PIDS_P20+=( "$!" )
        else
          binwalk_deep_extract_helper "$MATRYOSHKA" "$FILE_TMP" "${FILE_TMP}_binwalk_extracted"
        fi
      fi

      MD5_DONE_DEEP+=( "$FILE_MD5" )
      max_pids_protection "$MAX_MOD_THREADS" "${WAIT_PIDS_P20[@]}"
    fi

    check_disk_space

    if [[ "$DISK_SPACE" -gt "$MAX_EXT_SPACE" ]]; then
      print_output "[!] $(date) - Extractor needs too much disk space $DISK_SPACE" "main"
      print_output "[!] $(date) - Ending extraction processes" "main"
      DISK_SPACE_CRIT=1
      break
    fi
  done

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_P20[@]}"
  fi
}

binwalk_deep_extract_helper() {
  # Matryoshka mode is first parameter: 1 - enable, 0 - disable
  local MATRYOSHKA_="${1:-0}"
  local FILE_TO_EXTRACT_="${2:-}"
  local DEST_FILE_="${3:-$FIRMWARE_PATH_CP}"

  if ! [[ -f "$FILE_TO_EXTRACT_" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  if [[ "$BINWALK_VER_CHECK" == 1 ]]; then
    if [[ "$MATRYOSHKA_" -eq 1 ]]; then
      binwalk --run-as=root --preserve-symlinks --dd='.*' -e -M -C "$DEST_FILE_" "$FILE_TO_EXTRACT_" | tee -a "$LOG_FILE" || true
    else
      # no more Matryoshka mode ... we are doing it manually and check the files every round via MD5
      binwalk --run-as=root --preserve-symlinks --dd='.*' -e -C "$DEST_FILE_" "$FILE_TO_EXTRACT_" | tee -a "$LOG_FILE" || true
    fi
  else
    if [[ "$MATRYOSHKA_" -eq 1 ]]; then
      binwalk --dd='.*' -e -M -C "$DEST_FILE_" "$FILE_TO_EXTRACT_" | tee -a "$LOG_FILE" || true
    else
      binwalk --dd='.*' -e -C "$DEST_FILE_" "$FILE_TO_EXTRACT_" | tee -a "$LOG_FILE" || true
    fi
  fi
}
