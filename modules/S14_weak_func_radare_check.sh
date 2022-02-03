#!/bin/bash
# shellcheck disable=SC2016

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

# Description:  This module identifies binaries that are using weak functions and creates a ranking of areas to look first.
#               It iterates through all executables and searches with radare for interesting functions like strcpy (defined in helpers.cfg). 
#               As the module runs quite long with high CPU load it only gets executed when the objdump module fails.

# Threading priority - if set to 1, these modules will be executed first
# do not prio s13 and s14 as the dependency check during runtime will fail!
export THREAD_PRIO=0

S14_weak_func_radare_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries for weak functions (radare mode)"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ -n "$ARCH" ]] ; then
    # as this module is slow we only run it in case the objdump method from s13 was not working as expected
    if [[ -f "$MAIN_LOG" ]]; then
      while [[ $(grep -c S13_weak "$MAIN_LOG") -eq 1 ]]; do
        sleep 1
      done
    fi

    # This module waits for S12 - binary protections
    # check emba.log for S12_binary_protection starting
    if [[ -f "$MAIN_LOG" ]]; then
      while [[ $(grep -c S12_binary "$MAIN_LOG") -eq 1 ]]; do
        sleep 1
      done
    fi

    VULNERABLE_FUNCTIONS="$(config_list "$CONFIG_DIR""/functions.cfg")"
    print_output "[*] Vulnerable functions: ""$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
    IFS=" " read -r -a VULNERABLE_FUNCTIONS <<<"$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ /g' )"

    STRCPY_CNT=0
    write_csv_log "binary" "function" "function count" "common linux file" "networking"
    for LINE in "${BINARIES[@]}" ; do
      # we run throught the bins and check if the bin was already analysed via objdump:
      if [[ "$(find "$LOG_DIR"/s13_weak_func_check/vul_func_*"$(basename "$LINE")".txt 2>/dev/null | wc -l)" -gt 0 ]]; then
        continue
      fi
      if ( file "$LINE" | grep -q ELF ) ; then
        NAME=$(basename "$LINE" 2> /dev/null)

        if ( file "$LINE" | grep -q "x86-64" ) ; then
          if [[ "$THREADED" -eq 1 ]]; then
            radare_function_check_x86_64 &
            WAIT_PIDS_S14+=( "$!" )
          else
            radare_function_check_x86_64
          fi
        elif ( file "$LINE" | grep -q "Intel 80386" ) ; then
          if [[ "$THREADED" -eq 1 ]]; then
            radare_function_check_x86 &
            WAIT_PIDS_S14+=( "$!" )
          else
            radare_function_check_x86
          fi
        elif ( file "$LINE" | grep -q "32-bit.*ARM" ) ; then
          if [[ "$THREADED" -eq 1 ]]; then
            radare_function_check_ARM32 &
            WAIT_PIDS_S14+=( "$!" )
          else
            radare_function_check_ARM32
          fi
        elif ( file "$LINE" | grep -q "64-bit.*ARM" ) ; then
          # ARM 64 code is in alpha state and nearly not tested!
          if [[ "$THREADED" -eq 1 ]]; then
            radare_function_check_ARM64 &
            WAIT_PIDS_S14+=( "$!" )
          else
            radare_function_check_ARM64
          fi
        elif ( file "$LINE" | grep -q "MIPS" ) ; then
          if [[ "$THREADED" -eq 1 ]]; then
            radare_function_check_MIPS32 &
            WAIT_PIDS_S14+=( "$!" )
          else
            radare_function_check_MIPS32
          fi
        elif ( file "$LINE" | grep -q "PowerPC" ) ; then
          if [[ "$THREADED" -eq 1 ]]; then
            radare_function_check_PPC32 &
            WAIT_PIDS_S14+=( "$!" )
          else
            radare_function_check_PPC32
          fi
        else
          print_output "[-] Something went wrong ... no supported architecture available"
        fi
      fi
    done

    if [[ "$THREADED" -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS_S14[@]}"
    fi

    radare_print_top10_statistics

    if [[ -f "$TMP_DIR"/S14_STRCPY_CNT.tmp ]]; then
      while read -r STRCPY; do
        STRCPY_CNT=$((STRCPY_CNT+STRCPY))
      done < "$TMP_DIR"/S14_STRCPY_CNT.tmp
    fi

    # shellcheck disable=SC2129
    write_log ""
    write_log "[*] Statistics:$STRCPY_CNT"
    write_log ""
    write_log "[*] Statistics1:$ARCH"
  fi

  module_end_log "${FUNCNAME[0]}" "${#RESULTS[@]}"
}

radare_function_check_PPC32(){
  NETWORKING=$(readelf -a "$LINE" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    if ( readelf -r "$LINE" | awk '{print $5}' | grep -E -q "^$FUNCTION" 2> /dev/null ) ; then
      NAME=$(basename "$LINE" 2> /dev/null)
      if [[ "$FUNCTION" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $s' "$LINE" | grep -E -A 20 "bl.*$FUNCTION" 2> /dev/null || true)
      else
        mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $s' "$LINE" | grep -E -A 2 -B 20 "bl.*$FUNCTION" 2> /dev/null || true)
      fi
      if [[ "${#R2_DUMPS_ARR[@]}" -gt 0 ]] ; then
        radare_write_log_header

        COUNT_FUNC="$(grep -c "bl.*""$FUNCTION" "$FUNC_LOG"  2> /dev/null || true)"
        if [[ "$FUNCTION" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "bl.*strlen" "$FUNC_LOG"  2> /dev/null || true)
          STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
        elif [[ "$FUNCTION" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          COUNT_MMAP_OK=$(grep -c "cmpwi.*,r.*,-1" "$FUNC_LOG"  2> /dev/null || true)
        fi
        radare_log_func_footer
        radare_output_function_details
      fi
    fi
  done
  echo "$STRCPY_CNT" >> "$TMP_DIR"/S14_STRCPY_CNT.tmp
}

radare_function_check_MIPS32() {
  NETWORKING=$(readelf -a "$LINE" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null || true)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    NAME=$(basename "$LINE" 2> /dev/null)
    if [[ "$FUNCTION" == "mmap" ]] ; then
      # For the mmap check we need the disasm after the call
      mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $ss' "$LINE" 2>/dev/null | grep -A 20 "^lw .*$FUNCTION""(gp)" || true)
    else
      mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $ss' "$LINE" 2>/dev/null | grep -A 20 -B 25 "^lw .*$FUNCTION""(gp)" || true)
    fi
    if [[ "${#R2_DUMPS_ARR[@]}" -gt 0 ]] ; then
      radare_write_log_header

      COUNT_FUNC="$(grep -c "lw.*""$FUNCTION" "$FUNC_LOG" 2> /dev/null || true)"
      if [[ "$FUNCTION" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "lw.*strlen" "$FUNC_LOG" 2> /dev/null || true)
        STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
      elif [[ "$FUNCTION" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Check this. This test is very rough:
        # TODO: check this in radare2
        #COUNT_MMAP_OK=$(grep -c ",-1$" "$FUNC_LOG"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      radare_log_func_footer
      radare_output_function_details
    fi
  done
  echo "$STRCPY_CNT" >> "$TMP_DIR"/S14_STRCPY_CNT.tmp
}

radare_function_check_ARM64() {
  NETWORKING=$(readelf -a "$LINE" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    NAME=$(basename "$LINE" 2> /dev/null)
    if [[ "$FUNCTION" == "mmap" ]] ; then
      mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $s' "$LINE" | grep -A 20 "bl.*$FUNCTION" 2> /dev/null || true)
    else
      mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $s' "$LINE" | grep -A 2 -B 20 "bl.*$FUNCTION" 2> /dev/null || true)
    fi
    if [[ "${#R2_DUMPS_ARR[@]}" -gt 0 ]] ; then
      radare_write_log_header

      COUNT_FUNC="$(grep -c "bl.*$FUNCTION" "$FUNC_LOG"  2> /dev/null || true)"
      if [[ "$FUNCTION" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "bl.*strlen" "$FUNC_LOG"  2> /dev/null || true)
        STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
      elif [[ "$FUNCTION" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Test not implemented on ARM64
        # TODO: check this in radare2
        #COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "$FUNC_LOG"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      radare_log_func_footer
      radare_output_function_details
    fi
  done
  echo "$STRCPY_CNT" >> "$TMP_DIR"/S14_STRCPY_CNT.tmp
}

radare_function_check_ARM32() {
  NETWORKING=$(readelf -a "$LINE" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    NAME=$(basename "$LINE" 2> /dev/null)
    if [[ "$FUNCTION" == "mmap" ]] ; then
      mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $s' "$LINE" | grep -A 20 "bl.*$FUNCTION" 2> /dev/null || true)
    else
      mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $s' "$LINE" | grep -A 2 -B 20 "bl.*$FUNCTION" 2> /dev/null || true)
    fi
    if [[ "${#R2_DUMPS_ARR[@]}" -gt 0 ]] ; then
      radare_write_log_header

      COUNT_FUNC="$(grep -c "bl.*$FUNCTION" "$FUNC_LOG"  2> /dev/null || true)"
      if [[ "$FUNCTION" == "strcpy" ]] ; then
        COUNT_STRLEN=$(grep -c "bl.*strlen" "$FUNC_LOG"  2> /dev/null || true)
        STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
      elif [[ "$FUNCTION" == "mmap" ]] ; then
        # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
        # Check this testcase. Not sure if it works in all cases! 
        # TODO: check this in radare2
        # COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "$FUNC_LOG"  2> /dev/null)
        COUNT_MMAP_OK="NA"
      fi
      radare_log_func_footer
      radare_output_function_details
    fi
  done
  echo "$STRCPY_CNT" >> "$TMP_DIR"/S14_STRCPY_CNT.tmp
}

radare_function_check_x86() {
  NETWORKING=$(readelf -a "$LINE" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    if ( readelf -r --use-dynamic "$LINE" | awk '{print $5}' | grep -E -q "^$FUNCTION" 2> /dev/null ) ; then
      if [[ "$FUNCTION" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $s' "$LINE" | grep -E -A 20 "call.*$FUNCTION" 2> /dev/null || true)
      else
        mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $s' "$LINE" | grep -E -A 2 -B 20 "call.*$FUNCTION" 2> /dev/null || true)
      fi
      if [[ "${#R2_DUMPS_ARR[@]}" -gt 0 ]] ; then
        radare_write_log_header

        COUNT_FUNC="$(grep -c -e "call.*$FUNCTION" "$FUNC_LOG"  2> /dev/null || true)"
        if [[ "$FUNCTION" == "strcpy" ]] ; then
          COUNT_STRLEN=$(grep -c "call.*strlen" "$FUNC_LOG"  2> /dev/null || true)
          STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
        elif [[ "$FUNCTION" == "mmap" ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          # TODO: check this in radare2
          COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffff" "$FUNC_LOG"  2> /dev/null || true)
        fi
        radare_log_func_footer
        radare_output_function_details
      fi
    fi
  done
  echo "$STRCPY_CNT" >> "$TMP_DIR"/S14_STRCPY_CNT.tmp
}

radare_function_check_x86_64() {
  NETWORKING=$(readelf -a "$LINE" --use-dynamic 2> /dev/null | grep -E "FUNC[[:space:]]+UND" | grep -c "\ bind\|\ socket\|\ accept\|\ recvfrom\|\ listen" 2> /dev/null)
  for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
    if ( readelf -r --use-dynamic "$LINE" | awk '{print $5}' | grep -E -q "^$FUNCTION" 2> /dev/null ) ; then
      if [[ "$FUNCTION" == "mmap" ]] ; then
        # For the mmap check we need the disasm after the call
        mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $s' "$LINE" | grep -E -A 20 "call.*$FUNCTION" 2> /dev/null || true)
      else
        mapfile -t R2_DUMPS_ARR < <(r2 -e io.cache=true -e scr.color=false -q -c 'pI $s' "$LINE" | grep -E -A 2 -B 20 "call.*$FUNCTION" 2> /dev/null || true)
      fi
      if [[ "${#R2_DUMPS_ARR[@]}" -gt 0 ]] ; then
        radare_write_log_header

        COUNT_FUNC="$(grep -c -e "call.*$FUNCTION" "$FUNC_LOG"  2> /dev/null || true)"
        if [[ "$FUNCTION" == "strcpy"  ]] ; then
          COUNT_STRLEN=$(grep -c "call.*strlen" "$FUNC_LOG"  2> /dev/null || true)
          STRCPY_CNT=$((STRCPY_CNT+COUNT_FUNC))
        elif [[ "$FUNCTION" == "mmap"  ]] ; then
          # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
          COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffffffffffff" "$FUNC_LOG"  2> /dev/null)
        fi
        radare_output_function_details
        radare_log_func_footer
      fi
    fi
  done
  echo "$STRCPY_CNT" >> "$TMP_DIR"/S14_STRCPY_CNT.tmp
}

radare_print_top10_statistics() {
  if [[ "$(find "$LOG_PATH_MODULE" -xdev -iname "vul_func_*_*-*.txt" | wc -l)" -gt 0 ]]; then
    for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
      local SEARCH_TERM
      local F_COUNTER
      readarray -t RESULTS < <( find "$LOG_PATH_MODULE" -xdev -iname "vul_func_*_""$FUNCTION""-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_""$FUNCTION""-/  /" | sed "s/\.txt//" 2> /dev/null)
  
      if [[ "${#RESULTS[@]}" -gt 0 ]]; then
        print_output ""
        print_output "[+] ""$FUNCTION"" - top 10 results:"
        if [[ "$FUNCTION" == "strcpy" ]] ; then
          write_anchor "strcpysummary"
        fi
        for LINE in "${RESULTS[@]}" ; do
          SEARCH_TERM="$(echo "$LINE" | cut -d\  -f3)"
          F_COUNTER="$(echo "$LINE" | cut -d\  -f1)"
          if [[ -f "$BASE_LINUX_FILES" ]]; then
            # if we have the base linux config file we are checking it:
            if grep -E -q "^$SEARCH_TERM$" "$BASE_LINUX_FILES" 2>/dev/null; then
              printf "${GREEN}\t%-5.5s : %-15.15s : common linux file: yes${NC}\n" "$F_COUNTER" "$SEARCH_TERM" | tee -a "$LOG_FILE"
            else
              printf "${ORANGE}\t%-5.5s : %-15.15s : common linux file: no${NC}\n" "$F_COUNTER" "$SEARCH_TERM" | tee -a "$LOG_FILE"
            fi  
          else
            print_output "$(indent "$(orange "$F_COUNTER""\t:\t""$SEARCH_TERM")")"
          fi  
        done
      fi  
    done
  else
    print_output "$(indent "$(orange "No weak binary functions found - check it manually with readelf and objdump -D")")"
  fi
} 

radare_write_log_header() {
  FUNC_LOG="$LOG_PATH_MODULE""/vul_func_""$FUNCTION""-""$NAME"".txt"
  radare_log_bin_hardening
  radare_log_func_header
  for E in "${R2_DUMPS_ARR[@]}" ; do
    if [[ "$E" == *"$FUNCTION"* ]]; then
      # we need the hex codes for sed here -> red output of the important line:
      E="$(echo "$E" | sed -r "s/^(.*)($FUNCTION)(.*)/\x1b[31m&\x1b[0m/")"
    fi
    write_log "$E" "$FUNC_LOG"
  done
}

radare_log_bin_hardening() {
  if [[ -f "$LOG_DIR"/s12_binary_protection.txt ]]; then
    write_log "[*] Binary protection state of $ORANGE$NAME$NC" "$FUNC_LOG"
    write_log "" "$FUNC_LOG"
    # get headline:
    HEAD_BIN_PROT=$(grep "FORTIFY Fortified" "$LOG_DIR"/s12_binary_protection.txt | sed 's/FORTIFY.*//'| sort -u)
    write_log "  $HEAD_BIN_PROT" "$FUNC_LOG"
    # get binary entry
    BIN_PROT=$(grep '/'"$NAME"' ' "$LOG_DIR"/s12_binary_protection.txt | sed 's/Symbols.*/Symbols/' | sort -u)
    write_log "  $BIN_PROT" "$FUNC_LOG"
    write_log "" "$FUNC_LOG"
  fi
}

radare_log_func_header() {
  write_log "" "$FUNC_LOG"
  write_log "[*] Function $ORANGE$FUNCTION$NC tear down of $ORANGE$NAME$NC" "$FUNC_LOG"
  write_log "" "$FUNC_LOG"
}

radare_log_func_footer() {
  write_log "" "$FUNC_LOG"
  write_log "[*] Function $ORANGE$FUNCTION$NC used $ORANGE$COUNT_FUNC$NC times $ORANGE$NAME$NC" "$FUNC_LOG"
  write_log "" "$FUNC_LOG"
}

radare_output_function_details()
{
  write_s14_log()
  {
    OLD_LOG_FILE="$LOG_FILE"
    LOG_FILE="$3"
    print_output "$1"
    write_link "$2"
    cat "$LOG_FILE" >> "$OLD_LOG_FILE"
    rm "$LOG_FILE" 2> /dev/null
    LOG_FILE="$OLD_LOG_FILE"
  }

  local LOG_FILE_LOC
  LOG_FILE_LOC="$LOG_PATH_MODULE"/vul_func_"$FUNCTION"-"$NAME".txt

  #check if this is common linux file:
  local COMMON_FILES_FOUND
  local SEARCH_TERM
  if [[ -f "$BASE_LINUX_FILES" ]]; then
    SEARCH_TERM=$(basename "$LINE")
    if grep -q "^$SEARCH_TERM\$" "$BASE_LINUX_FILES" 2>/dev/null; then
      COMMON_FILES_FOUND="${CYAN}"" - common linux file: yes - "
      write_log "[+] File $(print_path "$LINE") found in default Linux file dictionary" "$SUPPL_PATH/common_linux_files.txt"
      CFF_CSV="true"
    else
      write_log "[+] File $(print_path "$LINE") not found in default Linux file dictionary" "$SUPPL_PATH/common_linux_files.txt"
      COMMON_FILES_FOUND="${RED}"" - common linux file: no -"
      CFF_CSV="false"
    fi
  else
    COMMON_FILES_FOUND=" -"
  fi

  LOG_FILE_LOC_OLD="$LOG_FILE_LOC"
  LOG_FILE_LOC="$LOG_PATH_MODULE"/vul_func_"$COUNT_FUNC"_"$FUNCTION"-"$NAME".txt

  mv "$LOG_FILE_LOC_OLD" "$LOG_FILE_LOC" 2> /dev/null
  
  if [[ "$NETWORKING" -gt 1 ]]; then
    NETWORKING_="${ORANGE}networking: yes${NC}"
    NW_CSV="yes"
  else
    NETWORKING_="${GREEN}networking: no${NC}"
    NW_CSV="no"
  fi

  if [[ $COUNT_FUNC -ne 0 ]] ; then
    if [[ "$FUNCTION" == "strcpy" ]] ; then
      OUTPUT="[+] ""$(print_path "$LINE")""$COMMON_FILES_FOUND""${NC}"" Vulnerable function: ""${CYAN}""$FUNCTION"" ""${NC}""/ ""${RED}""Function count: ""$COUNT_FUNC"" ""${NC}""/ ""${ORANGE}""strlen: ""$COUNT_STRLEN"" ""${NC}""/ ""$NETWORKING_""${NC}""\\n"
    elif [[ "$FUNCTION" == "mmap" ]] ; then
      OUTPUT="[+] ""$(print_path "$LINE")""$COMMON_FILES_FOUND""${NC}"" Vulnerable function: ""${CYAN}""$FUNCTION"" ""${NC}""/ ""${RED}""Function count: ""$COUNT_FUNC"" ""${NC}""/ ""${ORANGE}""Correct error handling: ""$COUNT_MMAP_OK"" ""${NC}""\\n"
    else
      OUTPUT="[+] ""$(print_path "$LINE")""$COMMON_FILES_FOUND""${NC}"" Vulnerable function: ""${CYAN}""$FUNCTION"" ""${NC}""/ ""${RED}""Function count: ""$COUNT_FUNC"" ""${NC}""/ ""$NETWORKING_""${NC}""\\n"
    fi
    write_s14_log "$OUTPUT" "$LOG_FILE_LOC" "$LOG_PATH_MODULE""/vul_func_tmp_""$FUNCTION"-"$NAME"".txt"
    write_csv_log "$(print_path "$LINE")" "$FUNCTION" "$COUNT_FUNC" "$CFF_CSV" "$NW_CSV"
  fi
}

