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

P05_firmware_bin_extractor() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Binary firmware extractor"

  # we love binwalk ... this is our first chance for extracting everything
  binwalking

  LINUX_PATH_COUNTER="$(find "$OUTPUT_DIR_binwalk" "${EXCL_FIND[@]}" -xdev -type d -iname bin -o -type f -iname busybox -o -type d -iname sbin -o -type d -iname etc 2> /dev/null | wc -l)"

  # if we have not found a linux filesystem we try to extract the firmware again with FACT-extractor
  # shellcheck disable=SC2153
  if [[ $FACT_EXTRACTOR -eq 1 && $LINUX_PATH_COUNTER -lt 2 ]]; then
    fact_extractor
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

  # if we have not found a linux filesystem we try to do a binwalk -e -M on every file
  if [[ $DEEP_EXTRACTOR -eq 1 ]] ; then
    deep_extractor
  fi

  detect_root_dir_helper "$FIRMWARE_PATH_CP"

  FILES_EXT=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
  deb_extractor
  ipk_extractor

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

  # this is not solid and we have to probably adjust it in the future
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

ipk_extractor() {
  print_output ""
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
    fi
  fi
}

deb_extractor() {
  print_output ""
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
          DEB_NAME=$(basename "$DEB")
          print_output "[*] Extracting $ORANGE$DEB_NAME$NC package to the root directory $ORANGE$R_PATH$NC."
          dpkg-deb --extract "$DEB" "$R_PATH"
        done < "$TMP_DIR"/deb_db.txt
      done
      FILES_AFTER_DEB=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
      echo ""
      print_output "[*] Before deb extraction we had $ORANGE$FILES_EXT$NC files, after deep extraction we have $ORANGE$FILES_AFTER_DEB$NC files extracted."
    fi
  fi
}

deep_extractor() {
  sub_module_title "Walking through all files and try to extract what ever possible"
  print_output "[*] Deep extraction with binwalk - 1st round"

  FILES_BEFORE_DEEP=$(find "$FIRMWARE_PATH_CP" -xdev -type f | wc -l )
  find "$FIRMWARE_PATH_CP" -xdev -type f ! -name "*.deb" ! -name "*.ipk" -exec binwalk -e -M {} \; &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  WAIT_PIDS=( )

  print_output "[*] Deep extraction with binwalk - 2nd round"
  find "$FIRMWARE_PATH_CP" -xdev -type f ! -name "*.deb" ! -name "*.ipk" -exec binwalk -e -M {} \; &
  WAIT_PIDS+=( "$!" )
  wait_for_extractor
  WAIT_PIDS=( )

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
    while read -r LINE; do 
      print_output "$LINE"
    done < "$TMP_DIR"/FACTer.txt
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
  print_output "$(binwalk -E -F -J "$FIRMWARE_PATH")"
  mv "$(basename "$FIRMWARE_PATH".png)" "$LOG_DIR"/"$(basename "$FIRMWARE_PATH"_entropy.png)" 2> /dev/null
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
    while read -r LINE; do 
      print_output "$LINE"
    done < "$TMP_DIR"/binwalker.txt
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
extract_deb_helper() {
  find "$FIRMWARE_PATH_CP" -xdev -type f -name "*.deb" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 >> "$TMP_DIR"/deb_db.txt
}
