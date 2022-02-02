#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Analyzes firmware with binwalk, checks entropy and extracts firmware in the log directory. 
#               If binwalk fails to extract the firmware, it will be extracted with FACT-extractor.
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# This module extracts the firmware and is blocking modules that needs executed before the following modules can run
export PRE_THREAD_ENA=0


P60_firmware_bin_extractor() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware extractor"
  pre_module_reporter "${FUNCNAME[0]}"

  DISK_SPACE_CRIT=0
  FILES_FACT=0
  FILES_BINWALK=0
  LINUX_PATH_COUNTER=0

  if [[ -f "$FIRMWARE_PATH" ]]; then
    # we love binwalk ... this is our first chance for extracting everything
    binwalking
  fi

  linux_basic_identification_helper

  if [[ -f "$FIRMWARE_PATH" ]]; then
    # if we have not found a linux filesystem we try to extract the firmware again with FACT-extractor
    # shellcheck disable=SC2153
    if [[ $FACT_EXTRACTOR -eq 1 && $LINUX_PATH_COUNTER -lt 2 ]]; then
      fact_extractor
      linux_basic_identification_helper
    fi

    FILES_BINWALK=$(find "$OUTPUT_DIR_binwalk" -xdev -type f | wc -l )
    if [[ -n "${OUTPUT_DIR_fact:-}" && -d "$OUTPUT_DIR_fact" ]]; then
      FILES_FACT=$(find "$OUTPUT_DIR_fact" -xdev -type f | wc -l )
    fi
    print_output ""
    print_output "[*] Default binwalk extractor extracted $ORANGE$FILES_BINWALK$NC files."
  fi

  if [[ -n ${FILES_FACT} ]]; then
    print_output "[*] Default FACT-extractor extracted $ORANGE$FILES_FACT$NC files."
  fi

  # If we have not found a linux filesystem we try to do a binwalk -e -M on every file for two times
  # Manual activation via -x switch:
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

  detect_root_dir_helper "$FIRMWARE_PATH_CP" "$LOG_FILE"

  FILES_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )

  if [[ "${#ROOT_PATH[@]}" -gt 0 ]]; then
    print_output ""
    if [[ "$DISK_SPACE_CRIT" -ne 1 ]]; then
      deb_extractor
    else
      print_output "[!] $(date) - Extractor needs too much disk space $DISK_SPACE" "main"
      print_output "[!] $(date) - Ending extraction processes - no deb extraction performed" "main"
      DISK_SPACE_CRIT=1
    fi
    if [[ "$DISK_SPACE_CRIT" -ne 1 ]]; then
      ipk_extractor
    else
      print_output "[!] $(date) - Extractor needs too much disk space $DISK_SPACE" "main"
      print_output "[!] $(date) - Ending extraction processes - no ipk extraction performed" "main"
      DISK_SPACE_CRIT=1
    fi
    if [[ "$DISK_SPACE_CRIT" -ne 1 ]]; then
      apk_extractor
    else
      print_output "[!] $(date) - Extractor needs too much disk space $DISK_SPACE" "main"
      print_output "[!] $(date) - Ending extraction processes - apk extraction performed" "main"
      DISK_SPACE_CRIT=1
    fi
  fi

  BINS=$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type f | wc -l )
  UNIQUE_BINS=$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
  if [[ "$BINS" -gt 0 || "$UNIQUE_BINS" -gt 0 ]]; then
    print_output ""
    print_output "[*] Found $ORANGE$UNIQUE_BINS$NC unique files and $ORANGE$BINS$NC files at all."
  fi

  if [[ "$FILES_EXT" -eq 0 ]]; then
    FILES_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
  fi
  module_end_log "${FUNCNAME[0]}" "$FILES_EXT"
}

wait_for_extractor() {
  export OUTPUT_DIR="$FIRMWARE_PATH_CP"
  SEARCHER=$(basename "$FIRMWARE_PATH")

  # this is not solid and we probably have to adjust it in the future
  # but for now it works
  SEARCHER="$(echo "$SEARCHER" | tr "(" "." | tr ")" ".")"

  for PID in "${WAIT_PIDS[@]}"; do
    running=1
    while [[ $running -eq 1 ]]; do
      echo "." | tr -d "\n"
      if ! pgrep -v grep | grep -q "$PID"; then
        running=0
      fi
      disk_space_protection
      sleep 1
    done
  done
}

check_disk_space() {
  DISK_SPACE=$(du -hm "$FIRMWARE_PATH_CP" --max-depth=1 --exclude="proc" 2>/dev/null | awk '{ print $1 }' | sort -hr | head -1)
}

disk_space_protection() {
  check_disk_space
  if [[ "$DISK_SPACE" -gt "$MAX_EXT_SPACE" ]]; then
    echo ""
    print_output "[!] $(date) - Extractor needs too much disk space $DISK_SPACE" "main"
    print_output "[!] $(date) - Ending extraction processes" "main"
    pgrep -a -f "binwalk.*$SEARCHER.*"
    pkill -f ".*binwalk.*$SEARCHER.*"
    pkill -f ".*extract\.py.*$SEARCHER.*"
    kill -9 "$PID" 2>/dev/null
    DISK_SPACE_CRIT=1
  fi
}

apk_extractor() {
  sub_module_title "APK archive extraction mode"
  print_output "[*] Identify apk archives and extracting it to the root directories ..."
  extract_apk_helper &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  WAIT_PIDS=( )
  if [[ -f "$TMP_DIR"/apk_db.txt ]] ; then
    APK_ARCHIVES=$(wc -l "$TMP_DIR"/apk_db.txt | awk '{print $1}')
    if [[ "$APK_ARCHIVES" -gt 0 ]]; then
      print_output "[*] Found $ORANGE$APK_ARCHIVES$NC APK archives - extracting them to the root directories ..."
      for R_PATH in "${ROOT_PATH[@]}"; do
        while read -r APK; do
          APK_NAME=$(basename "$APK")
          print_output "[*] Extracting $ORANGE$APK_NAME$NC package to the root directory $ORANGE$R_PATH$NC."
          tar xpf "$APK" --directory "$R_PATH" 
        done < "$TMP_DIR"/apk_db.txt
      done

      FILES_AFTER_APK=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
      echo ""
      print_output "[*] Before apk extraction we had $ORANGE$FILES_EXT$NC files, after deep extraction we have $ORANGE$FILES_AFTER_APK$NC files extracted."
    fi
    check_disk_space
  else
    print_output "[-] No apk packages extracted."
  fi
}

ipk_extractor() {
  sub_module_title "IPK archive extraction mode"
  print_output "[*] Identify ipk archives and extracting it to the root directories ..."
  extract_ipk_helper &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  WAIT_PIDS=( )

  if [[ -f "$TMP_DIR"/ipk_db.txt ]] ; then
    IPK_ARCHIVES=$(wc -l "$TMP_DIR"/ipk_db.txt | awk '{print $1}')
    if [[ "$IPK_ARCHIVES" -gt 0 ]]; then
      print_output "[*] Found $ORANGE$IPK_ARCHIVES$NC IPK archives - extracting them to the root directories ..."
      mkdir "$LOG_DIR"/ipk_tmp
      for R_PATH in "${ROOT_PATH[@]}"; do
        while read -r IPK; do
          IPK_NAME=$(basename "$IPK")
          print_output "[*] Extracting $ORANGE$IPK_NAME$NC package to the root directory $ORANGE$R_PATH$NC."
          tar zxpf "$IPK" --directory "$LOG_DIR"/ipk_tmp
          tar xzf "$LOG_DIR"/ipk_tmp/data.tar.gz --directory "$R_PATH"
          rm -r "$LOG_DIR"/ipk_tmp/*
        done < "$TMP_DIR"/ipk_db.txt
      done

      FILES_AFTER_IPK=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
      echo ""
      print_output "[*] Before ipk extraction we had $ORANGE$FILES_EXT$NC files, after deep extraction we have $ORANGE$FILES_AFTER_IPK$NC files extracted."
      rm -r "$LOG_DIR"/ipk_tmp
    fi
    check_disk_space
  else
    print_output "[-] No ipk packages extracted."
  fi
}

deb_extractor() {
  sub_module_title "Debian archive extraction mode"
  print_output "[*] Identify debian archives and extracting it to the root directories ..."
  extract_deb_helper &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  WAIT_PIDS=( )

  if [[ -f "$TMP_DIR"/deb_db.txt ]] ; then
    DEB_ARCHIVES=$(wc -l "$TMP_DIR"/deb_db.txt | awk '{print $1}')
    if [[ "$DEB_ARCHIVES" -gt 0 ]]; then
      print_output "[*] Found $ORANGE$DEB_ARCHIVES$NC debian archives - extracting them to the root directories ..."
      for R_PATH in "${ROOT_PATH[@]}"; do
        while read -r DEB; do
          if [[ "$THREADED" -eq 1 ]]; then
            extract_deb_extractor_helper &
            WAIT_PIDS_P20+=( "$!" )
          else
            extract_deb_extractor_helper
          fi
        done < "$TMP_DIR"/deb_db.txt
      done

      if [[ "$THREADED" -eq 1 ]]; then
        wait_for_pid "${WAIT_PIDS_P20[@]}"
      fi

      FILES_AFTER_DEB=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
      echo ""
      print_output "[*] Before deb extraction we had $ORANGE$FILES_EXT$NC files, after deep extraction we have $ORANGE$FILES_AFTER_DEB$NC files extracted."
    fi
    check_disk_space
  else
    print_output "[-] No deb packages extracted."
  fi
}

deep_extractor() {
  sub_module_title "Deep extraction mode"
  MAX_THREADS_P20=$((2*"$(grep -c ^processor /proc/cpuinfo)"))

  local FILE_ARR_TMP
  local FILE_MD5
  local MD5_DONE_DEEP

  FILES_BEFORE_DEEP=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )

  if [[ "$DISK_SPACE_CRIT" -eq 0 ]]; then
    print_output "[*] Deep extraction - 1st round"
    print_output "[*] Walking through all files and try to extract what ever possible"

    deeper_extractor_helper
  fi

  linux_basic_identification_helper

  if [[ $LINUX_PATH_COUNTER -lt 5 && "$DISK_SPACE_CRIT" -eq 0 ]]; then
  #if [[ "$DISK_SPACE_CRIT" -eq 0 ]]; then
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

  FILES_AFTER_DEEP=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )

  print_output "[*] Before deep extraction we had $ORANGE$FILES_BEFORE_DEEP$NC files, after deep extraction we have now $ORANGE$FILES_AFTER_DEEP$NC files extracted."
}

deeper_extractor_helper() {

  readarray -t FILE_ARR_TMP < <(find "$FIRMWARE_PATH_CP" -xdev "${EXCL_FIND[@]}" -type f ! \( -iname "*.udeb" -o -iname "*.deb" \
    -o -iname "*.ipk" -o -iname "*.pdf" -o -iname "*.php" -o -iname "*.txt" -o -iname "*.doc" -o -iname "*.rtf" -o -iname "*.docx" \
    -o -iname "*.htm" -o -iname "*.html" -o -iname "*.md5" -o -iname "*.sha1" -o -iname "*.torrent" -o -iname "*.png" -o -iname "*.svg" \) \
    -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  for FILE_TMP in "${FILE_ARR_TMP[@]}"; do

    FILE_MD5=$(md5sum "$FILE_TMP" | cut -d\  -f1)
    # let's check the current md5sum against our array of unique md5sums - if we have a match this is already extracted
    # already extracted stuff is now ignored

    if [[ ! " ${MD5_DONE_DEEP[*]} " =~ ${FILE_MD5} ]]; then

      # do a quick check if EMBA should handle the file or we give it to binwalk:
      fw_bin_detector "$FILE_TMP"

      if [[ "$VMDK_DETECTED" -eq 1 ]]; then
        vmdk_extractor "$FILE_TMP" "${FILE_TMP}_vmdk_extracted" &
        WAIT_PIDS_P20+=( "$!" )
      elif [[ "$UBI_IMAGE" -eq 1 ]]; then
        ubi_extractor "$FILE_TMP" "${FILE_TMP}_ubi_extracted" &
        WAIT_PIDS_P20+=( "$!" )
      elif [[ "$DLINK_ENC_DETECTED" -eq 1 ]]; then
        dlink_SHRS_enc_extractor "$FILE_TMP" "${FILE_TMP}_shrs_extracted" &
        WAIT_PIDS_P20+=( "$!" )
      elif [[ "$EXT_IMAGE" -eq 1 ]]; then
        ext2_extractor "$FILE_TMP" "${FILE_TMP}_ext_extracted" &
        WAIT_PIDS_P20+=( "$!" )
      elif [[ "$ENGENIUS_ENC_DETECTED" -ne 0 ]]; then
        engenius_enc_extractor "$FILE_TMP" "${FILE_TMP}_engenius_extracted" &
        WAIT_PIDS_P20+=( "$!" )
      else
        # default case to binwalk
        binwalk_deep_extract_helper &
        WAIT_PIDS_P20+=( "$!" )
      fi

      if [[ "$THREADED" -eq 1 ]]; then
        binwalk_deep_extract_helper &
        WAIT_PIDS_P20+=( "$!" )
      else
        binwalk_deep_extract_helper
      fi
      MD5_DONE_DEEP+=( "$FILE_MD5" )
      max_pids_protection "$MAX_THREADS_P20" "${WAIT_PIDS_P20[@]}"
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

fact_extractor() {
  sub_module_title "Extracting binary firmware blob with FACT-extractor"

  export OUTPUT_DIR_fact
  OUTPUT_DIR_fact=$(basename "$FIRMWARE_PATH")
  OUTPUT_DIR_fact="$FIRMWARE_PATH_CP""/""$OUTPUT_DIR_fact"_fact_emba

  print_output "[*] Extracting firmware to directory $OUTPUT_DIR_fact"

  # this is not working in background. I have created a new function that gets executed in the background
  # probably there is a more elegant way
  #mapfile -t FACT_EXTRACT < <(./external/extract.py -o "$OUTPUT_DIR_fact" "$FIRMWARE_PATH" 2>/dev/null &)
  extract_fact_helper &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  WAIT_PIDS=( )

  # as we probably kill FACT and to not loose the results we need to execute FACT in a function 
  # and read the results from the caller
  if [[ -f "$TMP_DIR"/FACTer.txt ]] ; then
    tee -a "$LOG_FILE" < "$TMP_DIR"/FACTer.txt 
  fi
}

binwalking() {
  sub_module_title "Analyze binary firmware blob with binwalk"

  print_output "[*] Basic analysis with binwalk"
  mapfile -t BINWALK_OUTPUT < <(binwalk "$FIRMWARE_PATH")
  if [[ ${#BINWALK_OUTPUT[@]} -ne 0 ]] ; then
    for LINE in "${BINWALK_OUTPUT[@]}" ; do
      print_output "$LINE"
    done
  fi

  echo
  # we use the original FIRMWARE_PATH for entropy testing, just if it is a file
  if [[ -f $FIRMWARE_PATH_BAK ]] ; then
    print_output "[*] Entropy testing with binwalk ... "
    # we have to change the working directory for binwalk, because /emba is read-only in the Docker container and binwalk fails to save the entropy picture there
    if [[ $IN_DOCKER -eq 1 ]] ; then
      cd / || return
      print_output "$(binwalk -E -F -J "$FIRMWARE_PATH_BAK")"
      mv "$(basename "$FIRMWARE_PATH".png)" "$LOG_DIR"/firmware_entropy.png 2> /dev/null
      cd /emba || return
    else
      print_output "$(binwalk -E -F -J "$FIRMWARE_PATH_BAK")"
      mv "$(basename "$FIRMWARE_PATH".png)" "$LOG_DIR"/firmware_entropy.png 2> /dev/null
    fi
  fi

  export OUTPUT_DIR_binwalk
  OUTPUT_DIR_binwalk=$(basename "$FIRMWARE_PATH")
  OUTPUT_DIR_binwalk="$FIRMWARE_PATH_CP""/""$OUTPUT_DIR_binwalk"_binwalk_emba

  echo
  print_output "[*] Extracting firmware to directory $OUTPUT_DIR_binwalk"
  # this is not working in background. I have created a new function that gets executed in the background
  # probably there is a more elegant way
  extract_binwalk_helper &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  WAIT_PIDS=( )

  # as we probably kill binwalk and to not loose the results we need to execute binwalk in a function 
  # and read the results from the caller
  if [[ -f "$TMP_DIR"/binwalker.txt ]] ; then
    tee -a "$LOG_FILE" < "$TMP_DIR"/binwalker.txt 
  fi
}

extract_binwalk_helper() {
  if [[ "$BINWALK_VER_CHECK" == 1 ]]; then
    binwalk --run-as=root --preserve-symlinks -e -M -C "$OUTPUT_DIR_binwalk" "$FIRMWARE_PATH" >> "$TMP_DIR"/binwalker.txt
  else
    binwalk -e -M -C "$OUTPUT_DIR_binwalk" "$FIRMWARE_PATH" >> "$TMP_DIR"/binwalker.txt
  fi
}
extract_fact_helper() {
  if [[ -d /tmp/extractor ]]; then
    # This directory is currently hard coded in FACT-extractor
    rm -rf /tmp/extractor
  fi

  "$EXT_DIR"/fact_extractor/fact_extractor/fact_extract.py -d "$FIRMWARE_PATH" >> "$TMP_DIR"/FACTer.txt

  if [[ -d /tmp/extractor/files ]]; then
    cat /tmp/extractor/reports/meta.json >> "$TMP_DIR"/FACTer.txt
    cp -r /tmp/extractor/files "$OUTPUT_DIR_fact"
    rm -rf /tmp/extractor
  fi
}
extract_ipk_helper() {
  find "$FIRMWARE_PATH_CP" -xdev -type f -name "*.ipk" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 >> "$TMP_DIR"/ipk_db.txt
}
extract_apk_helper() {
  find "$FIRMWARE_PATH_CP" -xdev -type f -name "*.apk" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 >> "$TMP_DIR"/apk_db.txt
}
extract_deb_helper() {
  find "$FIRMWARE_PATH_CP" -xdev -type f \( -name "*.deb" -o -name "*.udeb" \) -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 >> "$TMP_DIR"/deb_db.txt
}
binwalk_deep_extract_helper() {
  if [[ "$BINWALK_VER_CHECK" == 1 ]]; then
    binwalk --run-as=root --preserve-symlinks -e -M -C "$FIRMWARE_PATH_CP" "$FILE_TMP" | tee -a "$LOG_FILE"
  else
    binwalk -e -M -C "$FIRMWARE_PATH_CP" "$FILE_TMP" | tee -a "$LOG_FILE"
  fi
}
extract_deb_extractor_helper(){
  DEB_NAME=$(basename "$DEB")
  print_output "[*] Extracting $ORANGE$DEB_NAME$NC package to the root directory $ORANGE$R_PATH$NC."
  dpkg-deb --extract "$DEB" "$R_PATH"
}
linux_basic_identification_helper() {
  LINUX_PATH_COUNTER="$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type d -iname bin -o -type f -iname busybox -o -type f -name shadow -o -type f -name passwd -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"
}
