#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann, Stefan Haböck

# Description:  Check for vulnerable functions in binary array, dump objdump output in log and look for binary
#               protection with checksec.sh
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}


S10_binaries_check()
{
  module_log_init "s10_check_binaries"
  module_title "Check binaries"
  CONTENT_AVAILABLE=0

  vul_func_basic_check
  objdump_disassembly
  binary_protection
  
  if [[ $HTML == 1 ]]; then
     generate_html_file $LOG_FILE $CONTENT_AVAILABLE
  fi
}

vul_func_basic_check()
{
  sub_module_title "Searching vulnerable functions"

  local COUNTER=0
  local BIN_COUNT=0
  local VULNERABLE_FUNCTIONS
  VULNERABLE_FUNCTIONS="$(config_list "$CONFIG_DIR""/functions.cfg")"
  print_output "[*] Vulnerable functions: ""$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
  IFS=" " read -r -a VUL_FUNC_GREP <<<"$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ -e /g' )"

  if [[ "$VULNERABLE_FUNCTIONS" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$VULNERABLE_FUNCTIONS" ]] ; then
    for LINE in "${BINARIES[@]}" ; do
      if ( file "$LINE" | grep -q "ELF" ) ; then
        local VUL_FUNC_RESULT
        BIN_COUNT=$((BIN_COUNT+1))
        VUL_FUNC_RESULT="$("$OBJDUMP" -T "$LINE" 2> /dev/null | grep -e "${VUL_FUNC_GREP[@]}")"
        if [[ -n "$VUL_FUNC_RESULT" ]] ; then
          print_output "[+] Vulnerable function in ""$(print_path "$LINE")"":"
          print_output "$(indent "$VUL_FUNC_RESULT")""\\n"
          COUNTER=$((COUNTER+1))
        #else
        #  print_output "[-] No vulnerable function in ""$(print_path "$LINE")""\\n"
        fi
      fi
    done
    print_output "[*] Found ""$COUNTER"" binaries with weak functions in ""$BIN_COUNT"" files (vulnerable functions: ""$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ /g' )"")"
    CONTENT_AVAILABLE=1
  fi
}

objdump_disassembly()
{
  # OBJDMP_ARCH, READELF are set in dependency check

  # Test source: https://security.web.cern.ch/security/recommendations/en/codetools/c.shtml

  sub_module_title "Generating objdump disassembly"

  VULNERABLE_FUNCTIONS="$(config_list "$CONFIG_DIR""/functions.cfg")"
  print_output "[*] Vulnerable functions: ""$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
  IFS=" " read -r -a VULNERABLE_FUNCTIONS <<<"$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ /g' )"

  for LINE in "${BINARIES[@]}" ; do
    if ( file "$LINE" | grep -q ELF ) ; then
      NAME=$(basename "$LINE" 2> /dev/null)
      local OBJDUMP_LOG="$LOG_DIR""/objdumps/objdump_""$NAME".txt
      #"$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" > "$OBJDUMP_LOG"
      "$OBJDUMP" -d "$LINE" > "$OBJDUMP_LOG"

        if ( file "$LINE" | grep -q "x86-64" ) ; then
          for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
            if ( "$READELF" -r "$LINE" | awk '{print $5}' | grep -E -q "^$FUNCTION" 2> /dev/null ) ; then
              local OBJ_DUMPS_OUT
              if [[ "$FUNCTION" == "mmap" ]] ; then
                # For the mmap check we need the disasm after the call
                #OBJ_DUMPS_OUT=$("$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" | grep -E -A 20 "call.*<$FUNCTION" 2> /dev/null)
                OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -E -A 20 "call.*<$FUNCTION" 2> /dev/null)
              else
                #OBJ_DUMPS_OUT=$("$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" | grep -E -A 2 -B 20 "call.*<$FUNCTION" 2> /dev/null)
                OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -E -A 2 -B 20 "call.*<$FUNCTION" 2> /dev/null)
              fi
              if [[ "$OBJ_DUMPS_OUT" != *"file format not recognized"*  ]] ; then
                readarray -t OBJ_DUMPS_ARR <<<"$OBJ_DUMPS_OUT"
                unset OBJ_DUMPS_OUT
                FUNC_LOG="$LOG_DIR""/vul_func_checker/vul_func_""$FUNCTION""-""$NAME"".txt"
                for E in "${OBJ_DUMPS_ARR[@]}" ; do
                  echo "$E" >> "$FUNC_LOG"
                done
                COUNT_FUNC="$(grep -c -e "call.*$FUNCTION" "$FUNC_LOG"  2> /dev/null)"
                if [[ "$FUNCTION" == "strcpy"  ]] ; then
                  COUNT_STRLEN=$(grep -c "call.*strlen" "$FUNC_LOG"  2> /dev/null)
                elif [[ "$FUNCTION" == "mmap"  ]] ; then
                  # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                  COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffffffffffff" "$FUNC_LOG"  2> /dev/null)
                fi
                output_function_details
              fi
            fi
          done
          CONTENT_AVAILABLE=1
         elif ( file "$LINE" | grep -q "Intel 80386" ) ; then
            for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
              if ( "$READELF" -r "$LINE" | awk '{print $5}' | grep -E -q "^$FUNCTION" 2> /dev/null ) ; then
                local OBJ_DUMPS_OUT
                if [[ "$FUNCTION" == "mmap" ]] ; then
                  # For the mmap check we need the disasm after the call
                  #OBJ_DUMPS_OUT=$("$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" | grep -E -A 20 "call.*<$FUNCTION" 2> /dev/null)
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -E -A 20 "call.*<$FUNCTION" 2> /dev/null)
                else
                  #OBJ_DUMPS_OUT=$("$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" | grep -E -A 2 -B 20 "call.*<$FUNCTION" 2> /dev/null)
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -E -A 2 -B 20 "call.*<$FUNCTION" 2> /dev/null)
                fi
                if [[ "$OBJ_DUMPS_OUT" != *"file format not recognized"*  ]] ; then
                  readarray -t OBJ_DUMPS_ARR <<<"$OBJ_DUMPS_OUT"
                  unset OBJ_DUMPS_OUT
                  FUNC_LOG="$LOG_DIR""/vul_func_checker/vul_func_""$FUNCTION""-""$NAME"".txt"
                  for E in "${OBJ_DUMPS_ARR[@]}" ; do
                    echo "$E" >> "$FUNC_LOG"
                  done
                  COUNT_FUNC="$(grep -c -e "call.*$FUNCTION" "$FUNC_LOG"  2> /dev/null)"
                  if [[ "$FUNCTION" == "strcpy" ]] ; then
                    COUNT_STRLEN=$(grep -c "call.*strlen" "$FUNC_LOG"  2> /dev/null)
                  elif [[ "$FUNCTION" == "mmap" ]] ; then
                    # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                    COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffff" "$FUNC_LOG"  2> /dev/null)
                  fi
                  output_function_details
                fi
              fi
            done
            CONTENT_AVAILABLE=1
          elif ( file "$LINE" | grep -q "32-bit.*ARM" ) ; then
            for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
              FUNC_ADDR=$("$READELF" -r "$LINE" 2>/dev/null| grep -E -m1 \ "$FUNCTION" | awk '{print $4}' | sed s/^0*//  2> /dev/null)
              STRLEN_ADDR=$("$READELF" -r "$LINE" 2>/dev/null | grep -E \ "strlen" | awk '{print $4}' | sed s/^0*//  2> /dev/null)
              if [[ -n "$FUNC_ADDR" ]] && ! [[ "$FUNC_ADDR" =~ ^0000.*  ]] && [[ "$FUNC_ADDR" != "00000000"*  ]] ; then
                NAME=$(basename "$LINE" 2> /dev/null)
                local OBJ_DUMPS_OUT
                if [[ "$FUNCTION" == "mmap" ]] ; then
                  # For the mmap check we need the disasm after the call
                  #OBJ_DUMPS_OUT=$("$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" | grep -A 20 "[[:blank:]]bl[[:blank:]]$FUNC_ADDR <" | sed s/"$FUNC_ADDR"\ \</"$FUNCTION"" <"/ 2> /dev/null)
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -A 20 "[[:blank:]]bl[[:blank:]]$FUNC_ADDR <" | sed s/"$FUNC_ADDR"\ \</"$FUNCTION"" <"/ 2> /dev/null)
                else
                  #OBJ_DUMPS_OUT=$("$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" | grep -A 2 -B 20 "[[:blank:]]bl[[:blank:]]$FUNC_ADDR <" | sed s/"$FUNC_ADDR"\ \</"$FUNCTION"" <"/ 2> /dev/null)
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -A 2 -B 20 "[[:blank:]]bl[[:blank:]]$FUNC_ADDR <" | sed s/"$FUNC_ADDR"\ \</"$FUNCTION"" <"/ 2> /dev/null)
                fi
                if [[ "$OBJ_DUMPS_OUT" != *"file format not recognized"*  ]] ; then
                  readarray -t OBJ_DUMPS_ARR <<<"${OBJ_DUMPS_OUT//$STRLEN_ADDR\ \</strlen\ \<}"
                  unset OBJ_DUMPS_OUT
                  FUNC_LOG="$LOG_DIR""/vul_func_checker/vul_func_""$FUNCTION""-""$NAME"".txt"
                  for E in "${OBJ_DUMPS_ARR[@]}" ; do
                    echo "$E" >> "$FUNC_LOG"
                  done
                  COUNT_FUNC="$(grep -c "[[:blank:]]bl[[:blank:]]$FUNCTION" "$FUNC_LOG"  2> /dev/null)"
                  if [[ "$FUNCTION" == "strcpy" ]] ; then
                    COUNT_STRLEN=$(grep -c "[[:blank:]]bl[[:blank:]]strlen" "$FUNC_LOG"  2> /dev/null)
                  elif [[ "$FUNCTION" == "mmap" ]] ; then
                    # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                    # Check this testcase. Not sure if it works in all cases! 
                    COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "$FUNC_LOG"  2> /dev/null)
                  fi
                  output_function_details
                fi
              fi
            done
            CONTENT_AVAILABLE=1
          # ARM 64 code is in alpha state and nearly not tested!
          elif ( file "$LINE" | grep -q "64-bit.*ARM" ) ; then
            for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
              NAME=$(basename "$LINE" 2> /dev/null)
              local OBJ_DUMPS_OUT
              if [[ "$FUNCTION" == "mmap" ]] ; then
                OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -A 20 "[[:blank:]]bl[[:blank:]].*<$FUNCTION" 2> /dev/null)
              else
                OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -A 2 -B 20 "[[:blank:]]bl[[:blank:]].*<$FUNCTION" 2> /dev/null)
              fi
              if [[ "$OBJ_DUMPS_OUT" != *"file format not recognized"*  ]] ; then
                readarray -t OBJ_DUMPS_ARR <<<"${OBJ_DUMPS_OUT}"
                unset OBJ_DUMPS_OUT
                FUNC_LOG="$LOG_DIR""/vul_func_checker/vul_func_""$FUNCTION""-""$NAME"".txt"
                for E in "${OBJ_DUMPS_ARR[@]}" ; do
                  echo "$E" >> "$FUNC_LOG"
                done
                COUNT_FUNC="$(grep -c "[[:blank:]]bl[[:blank:]].*<$FUNCTION" "$FUNC_LOG"  2> /dev/null)"
                if [[ "$FUNCTION" == "strcpy" ]] ; then
                  COUNT_STRLEN=$(grep -c "[[:blank:]]bl[[:blank:]].*<strlen" "$FUNC_LOG"  2> /dev/null)
                elif [[ "$FUNCTION" == "mmap" ]] ; then
                  # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                  # Test not implemented on ARM64
                  #COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "$FUNC_LOG"  2> /dev/null)
                  COUNT_MMAP_OK="NA"
                fi
                output_function_details
              fi
            done
            CONTENT_AVAILABLE=1
          elif ( file "$LINE" | grep -q "MIPS" ) ; then
            for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
              FUNC_ADDR=$("$READELF" -A "$LINE" 2> /dev/null | grep -E \ "$FUNCTION" | grep gp | grep -m1 UND | cut -d\  -f4 | sed s/\(gp\)// | sed s/-// 2> /dev/null)
              STRLEN_ADDR=$("$READELF" -A "$LINE" 2> /dev/null | grep -E \ "strlen" | grep gp | grep -m1 UND | cut -d\  -f4 | sed s/\(gp\)// | sed s/-// 2> /dev/null)
              if [[ -n "$FUNC_ADDR" ]] ; then
                NAME=$(basename "$LINE" 2> /dev/null)
                local OBJ_DUMPS_OUT
                if [[ "$FUNCTION" == "mmap" ]] ; then
                  # For the mmap check we need the disasm after the call
                  #OBJ_DUMPS_OUT=$("$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" | grep -A 20 "$FUNC_ADDR""(gp)" | sed s/-"$FUNC_ADDR"\(gp\)/"$FUNCTION"/ )
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -A 20 "$FUNC_ADDR""(gp)" | sed s/-"$FUNC_ADDR"\(gp\)/"$FUNCTION"/ )
                else
                  #OBJ_DUMPS_OUT=$("$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" | grep -A 2 -B 25 "$FUNC_ADDR""(gp)" | sed s/-"$FUNC_ADDR"\(gp\)/"$FUNCTION"/ | sed s/-"$STRLEN_ADDR"\(gp\)/strlen/ )
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -A 2 -B 25 "$FUNC_ADDR""(gp)" | sed s/-"$FUNC_ADDR"\(gp\)/"$FUNCTION"/ | sed s/-"$STRLEN_ADDR"\(gp\)/strlen/ )
                fi
                if [[ "$OBJ_DUMPS_OUT" != *"file format not recognized"* ]] ; then
                  readarray -t OBJ_DUMPS_ARR <<<"$OBJ_DUMPS_OUT"
                  unset OBJ_DUMPS_OUT
                  FUNC_LOG="$LOG_DIR""/vul_func_checker/vul_func_""$FUNCTION""-""$NAME"".txt"
                  for E in "${OBJ_DUMPS_ARR[@]}" ; do
                    echo "$E" >> "$FUNC_LOG"
                  done
                  COUNT_FUNC="$(grep -c "lw.*""$FUNCTION" "$FUNC_LOG"  2> /dev/null)"
                  if [[ "$FUNCTION" == "strcpy" ]] ; then
                    COUNT_STRLEN=$(grep -c "lw.*strlen" "$FUNC_LOG"  2> /dev/null)
                  elif [[ "$FUNCTION" == "mmap" ]] ; then
                    # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                    # Check this. This test is very rough:
                    COUNT_MMAP_OK=$(grep -c ",-1$" "$FUNC_LOG"  2> /dev/null)
                  fi
                  output_function_details
                fi
              fi
            done
            CONTENT_AVAILABLE=1
          elif ( file "$LINE" | grep -q "PowerPC" ) ; then
            for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
              if ( "$READELF" -r "$LINE" | awk '{print $5}' | grep -E -q "^$FUNCTION" 2> /dev/null ) ; then
                NAME=$(basename "$LINE" 2> /dev/null)
                local OBJ_DUMPS_OUT
                if [[ "$FUNCTION" == "mmap" ]] ; then
                  # For the mmap check we need the disasm after the call
                  #OBJ_DUMPS_OUT=$("$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" | grep -E -A 20 "bl.*<$FUNCTION" 2> /dev/null)
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -E -A 20 "bl.*<$FUNCTION" 2> /dev/null)
                else
                  #OBJ_DUMPS_OUT=$("$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" | grep -E -A 2 -B 20 "bl.*<$FUNCTION" 2> /dev/null)
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -E -A 2 -B 20 "bl.*<$FUNCTION" 2> /dev/null)
                fi
                if [[ "$OBJ_DUMPS_OUT" != *"file format not recognized"* ]] ; then
                  readarray -t OBJ_DUMPS_ARR <<<"$OBJ_DUMPS_OUT"
                  unset OBJ_DUMPS_OUT
                  FUNC_LOG="$LOG_DIR""/vul_func_checker/vul_func_""$FUNCTION""-""$NAME"".txt"
                  for E in "${OBJ_DUMPS_ARR[@]}" ; do
                    echo "$E" >> "$FUNC_LOG"
                  done
                  COUNT_FUNC="$(grep -c "bl.*""$FUNCTION" "$FUNC_LOG"  2> /dev/null)"
                  if [[ "$FUNCTION" == "strcpy" ]] ; then
                    COUNT_STRLEN=$(grep -c "bl.*strlen" "$FUNC_LOG"  2> /dev/null)
                  elif [[ "$FUNCTION" == "mmap" ]] ; then
                    # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                    COUNT_MMAP_OK=$(grep -c "cmpwi.*,r.*,-1" "$FUNC_LOG"  2> /dev/null)
                  fi
                  output_function_details
                fi
              fi
            done
	    CONTENT_AVAILABLE=1
          else
            print_output "[-] Something went wrong ... no usable architecture available"
          fi
        fi
      done
  
      for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
        print_output "\\n"
        print_output "[*] ""$FUNCTION"" - top 10 results:"
        local SEARCH_TERM
        local RESULTS
        readarray -t RESULTS < <( find "$LOG_DIR""/vul_func_checker/" -iname "vul_func_*_""$FUNCTION""-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_""$FUNCTION""-/  /" | sed     "s/\.txt//" 2> /dev/null)

        for LINE in "${RESULTS[@]}" ; do
          SEARCH_TERM=$(echo "$LINE" | cut -d\  -f3)
          if [[ -f "$BASE_LINUX_FILES" ]]; then
            if grep -q "^$SEARCH_TERM\$" "$BASE_LINUX_FILES" 2>/dev/null; then
              print_output "$(indent "$(green "$LINE"" - common linux file: yes")")"
            else
              print_output "$(indent "$(orange "$LINE"" - common linux file: no")")"
            fi
          else
            print_output "$(indent "$(orange "$LINE")")"
          fi
        done
      done
      echo
}

output_function_details()
{
  local LOG_FILE_LOC
  LOG_FILE_LOC="$LOG_DIR""/vul_func_checker/vul_func_""$FUNCTION""-""$NAME"".txt"

  #check if this is common linux file:
  local COMMON_FILES_FOUND
  local SEARCH_TERM
  if [[ -f "$BASE_LINUX_FILES" ]]; then
    COMMON_FILES_FOUND="${RED}"" - common linux file: no -"
    SEARCH_TERM=$(basename "$LINE")
    if grep -q "^$SEARCH_TERM\$" "$BASE_LINUX_FILES" 2>/dev/null; then
      COMMON_FILES_FOUND="${CYAN}"" - common linux file: yes - "
    fi
  else
    COMMON_FILES_FOUND=" -"
  fi
  
  if [[ $COUNT_FUNC -ne 0 ]] ; then
    if [[ "$FUNCTION" == "strcpy" ]] ; then
      OUTPUT="[+] ""$(print_path "$LINE")""$COMMON_FILES_FOUND""${NC}"" Vulnerable function: ""${CYAN}""$FUNCTION"" ""${NC}""/ ""${RED}""Function Count: ""$COUNT_FUNC"" ""${NC}""/ ""${ORANGE}""strlen: ""$COUNT_STRLEN"" ""${NC}""\\n"
      print_output "$OUTPUT"
      LOG_FILE_O="$LOG_FILE"
      LOG_FILE="$LOG_FILE_LOC"
      write_log "$OUTPUT"
      LOG_FILE="$LOG_FILE_O"
    elif [[ "$FUNCTION" == "mmap" ]] ; then
      OUTPUT="[+] ""$(print_path "$LINE")""$COMMON_FILES_FOUND""${NC}"" Vulnerable function: ""${CYAN}""$FUNCTION"" ""${NC}""/ ""${RED}""Function Count: ""$COUNT_FUNC"" ""${NC}""/ ""${ORANGE}""Correct error handling: ""$COUNT_MMAP_OK"" ""${NC}""\\n"
      print_output "$OUTPUT"
      LOG_FILE_O="$LOG_FILE"
      LOG_FILE="$LOG_FILE_LOC"
      write_log "$OUTPUT"
      LOG_FILE="$LOG_FILE_O"
    else
      OUTPUT="[+] ""$(print_path "$LINE")""$COMMON_FILES_FOUND""${NC}"" Vulnerable function: ""${CYAN}""$FUNCTION"" ""${NC}""/ ""${RED}""Function count: ""$COUNT_FUNC"" ""${NC}""\\n"
      print_output "$OUTPUT"
      LOG_FILE_O="$LOG_FILE"
      LOG_FILE="$LOG_FILE_LOC"
      write_log "$OUTPUT"
      LOG_FILE="$LOG_FILE_O"
    fi
#  else
#    OUTPUT="[*] ""$(print_path "$LINE")"": Vulnerable function: ""$FUNCTION"" / Function count: ""$COUNT_FUNC""\\n"
#    print_output "$OUTPUT"
#    LOG_FILE_O="$LOG_FILE"
#    LOG_FILE="$LOG_FILE_LOC"
#    write_log "$OUTPUT"
#    LOG_FILE="$LOG_FILE_O"  
    CONTENT_AVAILABLE=1
  fi

  mv "$LOG_FILE_LOC" "$LOG_DIR""/vul_func_checker/vul_func_""$COUNT_FUNC""_""$FUNCTION""-""$NAME"".txt" 2> /dev/null
}

binary_protection()
{
  sub_module_title "Binary check for mechanisms via checksec.sh"

  print_output "RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified  Fortifiable  FILE"
  for LINE in "${BINARIES[@]}" ; do
    if ( file "$LINE" | grep -q ELF ) ; then
      if [[ -f "$EXT_DIR"/checksec ]] ; then
        CONTENT_AVAILABLE=1
        print_output "$( "$EXT_DIR"/checksec --file="$LINE" | grep -v "CANARY" )"
      fi
    fi
  done
}



