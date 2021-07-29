#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Analyzes firmware with binwalk, checks entropy and extracts firmware in the log directory. 
#               If binwalk fails to extract the firmware, it will be extracted with FACT-extractor.
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
# This module extracts the firmware and is blocking modules that needs executed before the following modules can run
export PRE_THREAD_ENA=0


P20_firmware_bin_extractor() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware extractor"

  # we love binwalk ... this is our first chance for extracting everything
  binwalking

  linux_basic_identification_helper

  # if we have not found a linux filesystem we try to extract the firmware again with FACT-extractor
  # shellcheck disable=SC2153
  if [[ $FACT_EXTRACTOR -eq 1 && $LINUX_PATH_COUNTER -lt 2 ]]; then
    fact_extractor
    linux_basic_identification_helper
  fi

  FILES_BINWALK=$(find "$OUTPUT_DIR_binwalk" -xdev -type f | wc -l )
  if [[ -n "$OUTPUT_DIR_fact" ]]; then
    FILES_FACT=$(find "$OUTPUT_DIR_fact" -xdev -type f | wc -l )
  fi

  print_output ""
  print_output "[*] Default binwalk extractor extracted $ORANGE$FILES_BINWALK$NC files."

  if [[ -n $FILES_FACT ]]; then
    print_output "[*] Default FACT-extractor extracted $ORANGE$FILES_FACT$NC files."
  fi

  # If we have not found a linux filesystem we try to do a binwalk -e -M on every file for two times
  # Manual activation via -x switch:
  if [[ $LINUX_PATH_COUNTER -lt 2 || $DEEP_EXTRACTOR -eq 1 ]] ; then
    deep_extractor
  fi

  detect_root_dir_helper "$FIRMWARE_PATH_CP" "$LOG_FILE"

  FILES_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )

  if [[ "${#ROOT_PATH[@]}" -gt 0 ]]; then
    print_output ""
    deb_extractor
    ipk_extractor
    apk_extractor
  fi

  BINS=$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type f -executable | wc -l )
  UNIQUE_BINS=$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type f -executable -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 | wc -l )
  if [[ "$BINS" -gt 0 || "$UNIQUE_BINS" -gt 0 ]]; then
    print_output ""
    print_output "[*] Found $ORANGE$UNIQUE_BINS$NC unique executables and $ORANGE$BINS$NC executables at all."
  fi

  if [[ "$FILES_EXT" -eq 0 ]]; then
    FILES_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
  fi
  module_end_log "${FUNCNAME[0]}" "$FILES_EXT"
}

wait_for_extractor() {
  OUTPUT_DIR="$FIRMWARE_PATH_CP"
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
      DISK_SPACE=$(du -hm "$OUTPUT_DIR"/ --max-depth=1 --exclude="proc" 2>/dev/null | awk '{ print $1 }' | sort -hr | head -1)
      if [[ "$DISK_SPACE" -gt "$MAX_EXT_SPACE" ]]; then
        echo ""
    	  print_output "[!] $(date) - Extractor needs too much disk space $DISK_SPACE" "main"
        print_output "[!] $(date) - Ending extraction processes" "main"
        pgrep -a -f "binwalk.*$SEARCHER.*"
        pkill -f ".*binwalk.*$SEARCHER.*"
        pkill -f ".*extract\.py.*$SEARCHER.*"
        kill -9 "$PID" 2>/dev/null
      fi
      sleep 1
    done
  done
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
  else
    print_output "[-] No apk packages extracted."
  fi
}

ipk_extractor() {
  sub_module_title "IPK archive extraction mode"
  print_output "[*] Identify ipk archives and extracting it to the root directories ..."
  extract_ipk_helper &
  # this does not work as expected -> we have to check it again
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
  else
    print_output "[-] No ipk packages extracted."
  fi
}

deb_extractor() {
  sub_module_title "Debian archive extraction mode"
  print_output "[*] Identify debian archives and extracting it to the root directories ..."
  extract_deb_helper &
  # this does not work as expected -> we have to check it again
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
  else
    print_output "[-] No deb packages extracted."
  fi
}

deep_extractor() {
  sub_module_title "Deep extraction mode"
  print_output "[*] Deep extraction with binwalk - 1st round"
  print_output "[*] Walking through all files and try to extract what ever possible"

  local FILE_ARR_TMP
  local FILE_MD5
  local MD5_DONE_DEEP

  FILES_BEFORE_DEEP=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
  readarray -t FILE_ARR_TMP < <(find "$FIRMWARE_PATH_CP" -xdev "${EXCL_FIND[@]}" -type f ! \( -name "*.udeb" -o -name "*.deb" -o -name "*.ipk" \) -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  for FILE_TMP in "${FILE_ARR_TMP[@]}"; do
    if [[ "$THREADED" -eq 1 ]]; then
      binwalk_deep_extract_helper &
      WAIT_PIDS_P20+=( "$!" )
    else
      binwalk_deep_extract_helper
    fi
    #let's build an array with all our unique md5 checksums of our files
    FILE_MD5=$(md5sum "$FILE_TMP" | cut -d\  -f1)
    MD5_DONE_DEEP+=( "$FILE_MD5" )
  done

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_P20[@]}"
  fi

  print_output "[*] Deep extraction with binwalk - 2nd round"
  print_output "[*] Walking through all files and try to extract what ever possible"

  readarray -t FILE_ARR_TMP < <(find "$FIRMWARE_PATH_CP" -xdev "${EXCL_FIND[@]}" -type f ! \( -name "*.udeb" -o -name "*.deb" -o -name "*.ipk" \) -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  for FILE_TMP in "${FILE_ARR_TMP[@]}"; do
    FILE_MD5=$(md5sum "$FILE_TMP" | cut -d\  -f1)
    # let's check the current md5sum against our array of unique md5sums - if we have a match this is already extracted
    # already extracted stuff is now ignored
    if [[ ! " ${MD5_DONE_DEEP[*]} " =~ ${FILE_MD5} ]]; then
      if [[ "$THREADED" -eq 1 ]]; then
        binwalk_deep_extract_helper &
        WAIT_PIDS_P20+=( "$!" )
      else
        binwalk_deep_extract_helper
      fi
      MD5_DONE_DEEP+=( "$FILE_MD5" )
    fi
  done

  if [[ "$THREADED" -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_P20[@]}"
  fi

  FILES_AFTER_DEEP=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )

  print_output "[*] Before deep extraction we had $ORANGE$FILES_BEFORE_DEEP$NC files, after deep extraction we have now $ORANGE$FILES_AFTER_DEEP$NC files extracted."
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
  print_output "[*] Entropy testing with binwalk ... "
  # we have to change the working directory for binwalk, because /emba is read-only in the Docker container and binwalk fails to save the entropy picture there
  if [[ $IN_DOCKER -eq 1 ]] ; then
    cd / || return
    print_output "$(binwalk -E -F -J "$FIRMWARE_PATH")"
    mv "$(basename "$FIRMWARE_PATH".png)" "$LOG_DIR"/"$(basename "$FIRMWARE_PATH"_entropy.png)" 2> /dev/null
    cd /emba || return
  else
    print_output "$(binwalk -E -F -J "$FIRMWARE_PATH")"
    mv "$(basename "$FIRMWARE_PATH".png)" "$LOG_DIR"/"$(basename "$FIRMWARE_PATH"_entropy.png)" 2> /dev/null
  fi
  # we have to think about this thing. I like it for testing only one firmware but it drives me crazy in massive testing
  #if command -v xdg-open > /dev/null; then
  #  xdg-open "$LOG_DIR"/"$(basename "$FIRMWARE_PATH"_entropy.png)" 2> /dev/null
  #fi

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
  binwalk -e -M -C "$OUTPUT_DIR_binwalk" "$FIRMWARE_PATH" >> "$TMP_DIR"/binwalker.txt
}
extract_fact_helper() {
  ./external/extract.py -o "$OUTPUT_DIR_fact" "$FIRMWARE_PATH" >> "$TMP_DIR"/FACTer.txt
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
  binwalk -e -M -C "$FIRMWARE_PATH_CP" "$FILE_TMP" | tee -a "$LOG_FILE"
}
extract_deb_extractor_helper(){
  DEB_NAME=$(basename "$DEB")
  print_output "[*] Extracting $ORANGE$DEB_NAME$NC package to the root directory $ORANGE$R_PATH$NC."
  dpkg-deb --extract "$DEB" "$R_PATH"
}
linux_basic_identification_helper() {
  LINUX_PATH_COUNTER="$(find "$FIRMWARE_PATH_CP" "${EXCL_FIND[@]}" -xdev -type d -iname bin -o -type f -iname busybox -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"
}
