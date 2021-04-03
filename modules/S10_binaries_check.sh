#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  This module was the first module that existed in emba. The main idea was to identify the binaries that were using weak 
#               functions and to establish a ranking of areas to look at first.
#               It iterates through all executables and searches with objdump for interesting functions like strcpy (defined in helpers.cfg). 
#               It also looks for protection mechanisms in the binaries via checksec.

S10_binaries_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Check binaries"

  LOG_FILE="$( get_log_file )"

  vul_func_basic_check
  objdump_disassembly
  binary_protection

  # shellcheck disable=SC2129
  echo -e "\\n[*] Statistics:$STRCPY_CNT" >> "$LOG_FILE"
  echo -e "\\n[*] Statistics1:$ARCH" >> "$LOG_FILE"

  if [[ "$COUNTER" -gt 0 || "${#RESULTS[@]}" -gt 0 ]] ; then
    NEG_LOG=1
  fi

  module_end_log "${FUNCNAME[0]}" "$NEG_LOG"
}

vul_func_basic_check()
{
  sub_module_title "Searching interesting functions"

  COUNTER=0
  local BIN_COUNT=0
  local VULNERABLE_FUNCTIONS
  VULNERABLE_FUNCTIONS="$(config_list "$CONFIG_DIR""/functions.cfg")"
  print_output "[*] Interesting functions: ""$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ /g' )""\\n"
  IFS=" " read -r -a VUL_FUNC_GREP <<<"$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ -e /g')"

  if [[ "$VULNERABLE_FUNCTIONS" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ -n "$VULNERABLE_FUNCTIONS" ]] ; then
    for LINE in "${BINARIES[@]}" ; do
      if ( file "$LINE" | grep -q "ELF" ) ; then
        local VUL_FUNC_RESULT
        BIN_COUNT=$((BIN_COUNT+1))
        #VUL_FUNC_RESULT="$("$OBJDUMP" -T "$LINE" 2> /dev/null | grep -e "${VUL_FUNC_GREP[@]}" | grep -v "file format")"
        mapfile -t VUL_FUNC_RESULT < <("$OBJDUMP" -T "$LINE" 2> /dev/null | grep -we "${VUL_FUNC_GREP[@]}" | grep -v "file format")
        if [[ "${#VUL_FUNC_RESULT[@]}" -ne 0 ]] ; then
          print_output "[+] Interesting function in ""$(print_path "$LINE")"" found:"
          for VUL_FUNC in "${VUL_FUNC_RESULT[@]}" ; do
            # shellcheck disable=SC2001
            VUL_FUNC="$(echo "$VUL_FUNC" | sed -e 's/[[:space:]]\+/\t/g')"
            print_output "$(indent "$VUL_FUNC")"
          done
          COUNTER=$((COUNTER+1))
        fi
      fi
    done
    print_output "[*] Found ""$COUNTER"" binaries with interesting functions in ""$BIN_COUNT"" files (vulnerable functions: ""$( echo -e "$VULNERABLE_FUNCTIONS" | sed ':a;N;$!ba;s/\n/ /g' )"")"
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

  STRCPY_CNT=0
  for LINE in "${BINARIES[@]}" ; do
    if ( file "$LINE" | grep -q ELF ) ; then
      NAME=$(basename "$LINE" 2> /dev/null)
      local OBJDUMP_LOG="$LOG_DIR""/objdumps/objdump_""$NAME".txt
      #"$OBJDUMP" "$OBJDMP_ARCH" -d "$LINE" > "$OBJDUMP_LOG"
      "$OBJDUMP" -d "$LINE" > "$OBJDUMP_LOG"

        if ( file "$LINE" | grep -q "x86-64" ) ; then
          for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
            if ( readelf -r "$LINE" | awk '{print $5}' | grep -E -q "^$FUNCTION" 2> /dev/null ) ; then
              local OBJ_DUMPS_OUT
              if [[ "$FUNCTION" == "mmap" ]] ; then
                # For the mmap check we need the disasm after the call
                OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -E -A 20 "call.*<$FUNCTION" 2> /dev/null)
              else
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
                  (( STRCPY_CNT="$STRCPY_CNT"+"$COUNT_FUNC" ))
                elif [[ "$FUNCTION" == "mmap"  ]] ; then
                  # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                  COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffffffffffff" "$FUNC_LOG"  2> /dev/null)
                fi
                output_function_details
              fi
            fi
          done

          elif ( file "$LINE" | grep -q "Intel 80386" ) ; then
            for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
              if ( readelf -r "$LINE" | awk '{print $5}' | grep -E -q "^$FUNCTION" 2> /dev/null ) ; then
                local OBJ_DUMPS_OUT
                if [[ "$FUNCTION" == "mmap" ]] ; then
                  # For the mmap check we need the disasm after the call
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -E -A 20 "call.*<$FUNCTION" 2> /dev/null)
                else
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
                    (( STRCPY_CNT="$STRCPY_CNT"+"$COUNT_FUNC" ))
                  elif [[ "$FUNCTION" == "mmap" ]] ; then
                    # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                    COUNT_MMAP_OK=$(grep -c "cmp.*0xffffffff" "$FUNC_LOG"  2> /dev/null)
                  fi
                  output_function_details
                fi
              fi
            done

          elif ( file "$LINE" | grep -q "32-bit.*ARM" ) ; then
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
                  (( STRCPY_CNT="$STRCPY_CNT"+"$COUNT_FUNC" ))
                elif [[ "$FUNCTION" == "mmap" ]] ; then
                  # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                  # Check this testcase. Not sure if it works in all cases! 
                  COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "$FUNC_LOG"  2> /dev/null)
                fi
                output_function_details
              fi
 

            done

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
                  (( STRCPY_CNT="$STRCPY_CNT"+"$COUNT_FUNC" ))
                elif [[ "$FUNCTION" == "mmap" ]] ; then
                  # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                  # Test not implemented on ARM64
                  #COUNT_MMAP_OK=$(grep -c "cm.*r.*,\ \#[01]" "$FUNC_LOG"  2> /dev/null)
                  COUNT_MMAP_OK="NA"
                fi
                output_function_details
              fi
            done

          elif ( file "$LINE" | grep -q "MIPS" ) ; then
            for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
              FUNC_ADDR=$(readelf -A "$LINE" 2> /dev/null | grep -E \ "$FUNCTION" | grep gp | grep -m1 UND | cut -d\  -f4 | sed s/\(gp\)// | sed s/-// 2> /dev/null)
              STRLEN_ADDR=$(readelf -A "$LINE" 2> /dev/null | grep -E \ "strlen" | grep gp | grep -m1 UND | cut -d\  -f4 | sed s/\(gp\)// | sed s/-// 2> /dev/null)
              if [[ -n "$FUNC_ADDR" ]] ; then
                NAME=$(basename "$LINE" 2> /dev/null)
                local OBJ_DUMPS_OUT
                if [[ "$FUNCTION" == "mmap" ]] ; then
                  # For the mmap check we need the disasm after the call
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -A 20 "$FUNC_ADDR""(gp)" | sed s/-"$FUNC_ADDR"\(gp\)/"$FUNCTION"/ )
                else
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
                    (( STRCPY_CNT="$STRCPY_CNT"+"$COUNT_FUNC" ))
                  elif [[ "$FUNCTION" == "mmap" ]] ; then
                    # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                    # Check this. This test is very rough:
                    COUNT_MMAP_OK=$(grep -c ",-1$" "$FUNC_LOG"  2> /dev/null)
                  fi
                  output_function_details
                fi
              fi
            done

          elif ( file "$LINE" | grep -q "PowerPC" ) ; then
            for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
              if ( readelf -r "$LINE" | awk '{print $5}' | grep -E -q "^$FUNCTION" 2> /dev/null ) ; then
                NAME=$(basename "$LINE" 2> /dev/null)
                local OBJ_DUMPS_OUT
                if [[ "$FUNCTION" == "mmap" ]] ; then
                  # For the mmap check we need the disasm after the call
                  OBJ_DUMPS_OUT=$("$OBJDUMP" -d "$LINE" | grep -E -A 20 "bl.*<$FUNCTION" 2> /dev/null)
                else
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
                    (( STRCPY_CNT="$STRCPY_CNT"+"$COUNT_FUNC" ))
                  elif [[ "$FUNCTION" == "mmap" ]] ; then
                    # Test source: https://www.golem.de/news/mmap-codeanalyse-mit-sechs-zeilen-bash-2006-148878-2.html
                    COUNT_MMAP_OK=$(grep -c "cmpwi.*,r.*,-1" "$FUNC_LOG"  2> /dev/null)
                  fi
                  output_function_details
                fi
              fi
            done

          else
            print_output "[-] Something went wrong ... no usable architecture available"
          fi
        fi
      done

      if [[ "$(find "$LOG_DIR""/vul_func_checker/" -xdev -iname "vul_func_*_""$FUNCTION""-*.txt" | wc -l)" -gt 0 ]]; then
        for FUNCTION in "${VULNERABLE_FUNCTIONS[@]}" ; do
          local SEARCH_TERM
          local RESULTS
          local F_COUNTER
          readarray -t RESULTS < <( find "$LOG_DIR""/vul_func_checker/" -xdev -iname "vul_func_*_""$FUNCTION""-*.txt" 2> /dev/null | sed "s/.*vul_func_//" | sort -g -r | head -10 | sed "s/_""$FUNCTION""-/  /" | sed "s/\.txt//" 2> /dev/null)
  
          if [[ "${#RESULTS[@]}" -gt 0 ]]; then
            print_output ""
            print_output "[+] ""$FUNCTION"" - top 10 results:"
            for LINE in "${RESULTS[@]}" ; do
              SEARCH_TERM="$(echo "$LINE" | cut -d\  -f3)"
              F_COUNTER="$(echo "$LINE" | cut -d\  -f1)"
              if [[ -f "$BASE_LINUX_FILES" ]]; then
                # if we have the base linux config file we are checking it:
                if grep -q "^$SEARCH_TERM\$" "$BASE_LINUX_FILES" 2>/dev/null; then
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
      OUTPUT="[+] ""$(print_path "$LINE")""$COMMON_FILES_FOUND""${NC}"" Vulnerable function: ""${CYAN}""$FUNCTION"" ""${NC}""/ ""${RED}""Function count: ""$COUNT_FUNC"" ""${NC}""/ ""${ORANGE}""strlen: ""$COUNT_STRLEN"" ""${NC}""\\n"
      print_output "$OUTPUT"
      write_log "$OUTPUT" "$LOG_FILE_LOC"
    elif [[ "$FUNCTION" == "mmap" ]] ; then
      OUTPUT="[+] ""$(print_path "$LINE")""$COMMON_FILES_FOUND""${NC}"" Vulnerable function: ""${CYAN}""$FUNCTION"" ""${NC}""/ ""${RED}""Function count: ""$COUNT_FUNC"" ""${NC}""/ ""${ORANGE}""Correct error handling: ""$COUNT_MMAP_OK"" ""${NC}""\\n"
      print_output "$OUTPUT"
      write_log "$OUTPUT" "$LOG_FILE_LOC"
    else
      OUTPUT="[+] ""$(print_path "$LINE")""$COMMON_FILES_FOUND""${NC}"" Vulnerable function: ""${CYAN}""$FUNCTION"" ""${NC}""/ ""${RED}""Function count: ""$COUNT_FUNC"" ""${NC}""\\n"
      print_output "$OUTPUT"
      write_log "$OUTPUT" "$LOG_FILE_LOC"
    fi
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
        print_output "$( "$EXT_DIR"/checksec --file="$LINE" | grep -v "CANARY" | rev | cut -f 2- | rev )""\\t""$NC""$(print_path "$LINE")"
        NEG_LOG=1
      fi
    fi
  done
}

