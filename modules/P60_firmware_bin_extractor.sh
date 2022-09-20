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
  module_title "Binary firmware extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  export DISK_SPACE_CRIT=0
  export LINUX_PATH_COUNTER=0

  # typically FIRMWARE_PATH is only a file if none of the EMBA extractors were able to extract something
  # This means we are using binwalk in Matryoshka mode here
  # if we have a directory with multiple files in it we automatically pass here and run into the deep extractor
  if [[ -f "$FIRMWARE_PATH" ]]; then
    # we love binwalk ... this is our first chance for extracting everything
    binwalking "$FIRMWARE_PATH"
  fi

  # FIRMWARE_PATH_CP is typically /log/firmware - shellcheck is probably confused here
  # shellcheck disable=SC2153
  linux_basic_identification_helper "$FIRMWARE_PATH_CP"

  # If we have not found a linux filesystem we try to do an extraction round on every file multiple times
  # Manual activation via -x switch:
  # print_output "[*] LINUX_PATH_COUNTER: $LINUX_PATH_COUNTER"
  if [[ $LINUX_PATH_COUNTER -lt 2 || $DEEP_EXTRACTOR -eq 1 ]] ; then
    check_disk_space
    if ! [[ "$DISK_SPACE" -gt "$MAX_EXT_SPACE" ]]; then
      deep_extractor
    else
      print_output "[!] $(date) - Extractor needs too much disk space $DISK_SPACE" "main"
      print_output "[!] $(date) - Ending extraction processes - no deep extraction performed" "main"
      DISK_SPACE_CRIT=1
    fi
  fi

  # we need it after deep extraction:
  # shellcheck disable=SC2153
  linux_basic_identification_helper "$FIRMWARE_PATH_CP"

  # FIRMWARE_PATH_CP is typically /log/firmware - shellcheck is probably confused here
  # shellcheck disable=SC2153
  detect_root_dir_helper "$FIRMWARE_PATH_CP" "$LOG_FILE"
  print_ln

  FILES_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
  UNIQUE_FILES=$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
  DIRS_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type d | wc -l )
  BINS=$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type f -exec file {} \; | grep -c "ELF" || true)

  if [[ "$BINS" -gt 0 || "$UNIQUE_FILES" -gt 0 ]]; then
    print_ln
    print_output "[*] Found $ORANGE$FILES_EXT$NC files ($ORANGE$UNIQUE_FILES$NC unique files) and $ORANGE$DIRS_EXT$NC directories at all."
    print_output "[*] Found $ORANGE$BINS$NC binaries."
    print_output "[*] Additionally the Linux path counter is $ORANGE$LINUX_PATH_COUNTER$NC."
    print_ln
    tree -sh "$FIRMWARE_PATH_CP" | tee -a "$LOG_FILE"

    # now it should be fine to also set the FIRMWARE_PATH ot the FIRMWARE_PATH_CP
    export FIRMWARE_PATH="$FIRMWARE_PATH_CP"
  fi

  module_end_log "${FUNCNAME[0]}" "$FILES_EXT"
}

wait_for_extractor() {
  export OUTPUT_DIR="$FIRMWARE_PATH_CP"
  local SEARCHER=""
  SEARCHER=$(basename "$FIRMWARE_PATH")

  # this is not solid and we probably have to adjust it in the future
  # but for now it works
  SEARCHER="$(echo "$SEARCHER" | tr "(" "." | tr ")" ".")"

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

  if [[ "$DISK_SPACE_CRIT" -eq 0 ]]; then
    print_output "[*] Deep extraction - 1st round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
  fi

  linux_basic_identification_helper

  if [[ $LINUX_PATH_COUNTER -lt 5 && "$DISK_SPACE_CRIT" -eq 0 ]]; then
    print_output "[*] Deep extraction - 2nd round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
  fi

  linux_basic_identification_helper

  if [[ $LINUX_PATH_COUNTER -lt 5 && "$DISK_SPACE_CRIT" -eq 0 ]]; then
    print_output "[*] Deep extraction - 3rd round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
  fi

  linux_basic_identification_helper

  if [[ $LINUX_PATH_COUNTER -lt 5 && "$DISK_SPACE_CRIT" -eq 0 ]]; then
    print_output "[*] Deep extraction - 4th round"
    print_output "[*] Walking through all files and try to extract what ever possible with binwalk matryoshka mode"
    print_output "[*] This is the last extraction round that is executed."

    deeper_extractor_helper "M"
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
          binwalk_deep_extract_helper "$MATRYOSHKA" "$FILE_TMP" "$FIRMWARE_PATH_CP" &
          WAIT_PIDS_P20+=( "$!" )
        else
          binwalk_deep_extract_helper "$MATRYOSHKA" "$FILE_TMP" "$FIRMWARE_PATH_CP"
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

binwalking() {
  local FIRMWARE_PATH_="${1:-}"
  export OUTPUT_DIR_BINWALK=""

  if ! [[ -f "$FIRMWARE_PATH_" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "Analyze binary firmware blob with binwalk"

  print_output "[*] Basic analysis with binwalk"
  binwalk "$FIRMWARE_PATH_" | tee -a "$LOG_FILE"

  print_ln "no_log"
  # we use the original FIRMWARE_PATH for entropy testing, just if it is a file
  if [[ -f $FIRMWARE_PATH_BAK ]] && ! [[ -f "$LOG_DIR"/firmware_entropy.png ]]; then
    print_output "[*] Entropy testing with binwalk ... "
    # we have to change the working directory for binwalk, because everything except the log directory is read-only in
    # Docker container and binwalk fails to save the entropy picture there
    if [[ $IN_DOCKER -eq 1 ]] ; then
      cd "$LOG_DIR" || return
      print_output "$(binwalk -E -F -J "$FIRMWARE_PATH_BAK")"
      mv "$(basename "$FIRMWARE_PATH_".png)" "$LOG_DIR"/firmware_entropy.png 2> /dev/null || true
      cd /emba || return
    else
      print_output "$(binwalk -E -F -J "$FIRMWARE_PATH_BAK")"
      mv "$(basename "$FIRMWARE_PATH_".png)" "$LOG_DIR"/firmware_entropy.png 2> /dev/null || true
    fi
  fi

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
      #binwalk --run-as=root --preserve-symlinks -e -M -C "$DEST_FILE_" "$FILE_TO_EXTRACT_" | tee -a "$LOG_FILE" || true
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

linux_basic_identification_helper() {
  local FIRMWARE_PATH_CHECK="${1:-}"
  if ! [[ -d "$FIRMWARE_PATH_CHECK" ]]; then
    return
  fi
  LINUX_PATH_COUNTER="$(find "$FIRMWARE_PATH_CHECK" "${EXCL_FIND[@]}" -xdev -type d -iname bin -o -type f -iname busybox -o -type f -name shadow -o -type f -name passwd -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"
  backup_var "LINUX_PATH_COUNTER" "$LINUX_PATH_COUNTER"
}
