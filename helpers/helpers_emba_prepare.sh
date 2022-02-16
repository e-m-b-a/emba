#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Preparation for testing firmware:
#                 Check log directory
#                 Excluding paths
#                 Check architecture
#                 Binary array
#                 etc path handling
#                 Check firmware
#               Access:
#                 firmware root path via $FIRMWARE_PATH

log_folder()
{
  if [[ $ONLY_DEP -eq 0 ]] && [[ -d "$LOG_DIR" ]] ; then
    echo -e "\\n[${RED}!${NC}] ${ORANGE}Warning${NC}\\n"
    echo -e "    There are files in the specified directory: ""$LOG_DIR""\\n    You can now delete the content here or start the tool again and specify a different directory."
    echo -e "\\n${ORANGE}Delete content of log directory: $LOG_DIR ?${NC}\\n"
    read -p "(Y/n)  " -r ANSWER
    case ${ANSWER:0:1} in
        y|Y|"" )
          if mount | grep "$LOG_DIR" | grep -e "proc\|sys\|run" > /dev/null; then
            echo
            print_output "[!] We found unmounted areas from a former emulation process in your log directory $LOG_DIR." "no_log"
            print_output "[!] You should unmount this stuff manually:\\n" "no_log"
            print_output "$(indent "$(mount | grep "$LOG_DIR")")" "no_log"
            echo -e "\\n${RED}Terminate EMBA${NC}\\n"
            exit 1
          elif mount | grep "$LOG_DIR" > /dev/null; then
            echo
            print_output "[!] We found unmounted areas in your log directory $LOG_DIR." "no_log"
            print_output "[!] If EMBA is failing check this manually:\\n" "no_log"
            print_output "$(indent "$(mount | grep "$LOG_DIR")")" "no_log"
          else
            rm -R "${LOG_DIR:?}/"* 2>/dev/null || true
            echo -e "\\n${GREEN}Sucessfully deleted: $LOG_DIR ${NC}\\n"
          fi
        ;;
        * )
          echo -e "\\n${RED}Terminate EMBA${NC}\\n"
          exit 1
        ;;
    esac
  fi

  readarray -t D_LOG_FILES < <( find . \( -path ./external -o -path ./config -o -path ./report_templates \) -prune -false -o \( -name "*.txt" -o -name "*.log" \) -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  if [[ $USE_DOCKER -eq 1 && ${#D_LOG_FILES[@]} -gt 0 ]] ; then
    echo -e "\\n[${RED}!${NC}] ${ORANGE}Warning${NC}\\n"
    echo -e "    It appears that there are log files in the EMBA directory.\\n    You should move these files to another location where they won't be exposed to the Docker container."
    for D_LOG_FILE in "${D_LOG_FILES[@]}" ; do
      echo -e "        ""$(print_path "$D_LOG_FILE")"
    done
    echo -e "\\n${ORANGE}Continue to run EMBA and ignore this warning?${NC}\\n"
    read -p "(Y/n)  " -r ANSWER
    case ${ANSWER:0:1} in
        y|Y|"" )
          echo
        ;;
        * )
          echo -e "\\n${RED}Terminate EMBA${NC}\\n"
          exit 1
        ;;
    esac
  fi
}

set_exclude()
{
  export EXCLUDE_PATHS

  if [[ "$FIRMWARE_PATH" == "/" ]]; then
    EXCLUDE=("${EXCLUDE[@]}" "/proc" "/sys" "$(pwd)")
    print_output "[!] Apparently you want to test your live system. This can lead to errors. Please report the bugs so the software can be fixed." "no_log"
  fi

  echo

  # exclude paths from testing and set EXCL_FIND for find command (prune paths dynamicially)
  EXCLUDE_PATHS="$(set_excluded_path)"
  export EXCL_FIND
  IFS=" " read -r -a EXCL_FIND <<< "$( echo -e "$(get_excluded_find "$EXCLUDE_PATHS")" | tr '\r\n' ' ' | tr -d '\n' 2>/dev/null)"
  print_excluded
}

architecture_check()
{
  if [[ $ARCH_CHECK -eq 1 ]] ; then
    print_output "[*] Architecture auto detection (could take some time)\\n"
    local ARCH_MIPS=0 ARCH_ARM=0 ARCH_X64=0 ARCH_X86=0 ARCH_PPC=0
    local D_END_LE=0 D_END_BE=0

    # we use the binaries array which is already unique
    for D_ARCH in "${BINARIES[@]}" ; do
      D_ARCH=$(file "$D_ARCH")

      if [[ "$D_ARCH" == *"MSB"* ]] ; then
        D_END_BE=$((D_END_BE+1))
      elif [[ "$D_ARCH" == *"LSB"* ]] ; then
        D_END_LE=$((D_END_LE+1))
      fi

      if [[ "$D_ARCH" == *"MIPS"* ]] ; then
        ARCH_MIPS=$((ARCH_MIPS+1))
        continue
      elif [[ "$D_ARCH" == *"ARM"* ]] ; then
        ARCH_ARM=$((ARCH_ARM+1))
        continue
      elif [[ "$D_ARCH" == *"x86-64"* ]] ; then
        ARCH_X64=$((ARCH_X64+1))
        continue
      elif [[ "$D_ARCH" == *"80386"* ]] ; then
        ARCH_X86=$((ARCH_X86+1))
        continue
      elif [[ "$D_ARCH" == *"PowerPC"* ]] ; then
        ARCH_PPC=$((ARCH_PPC+1))
        continue
      fi
    done

    if [[ $((ARCH_MIPS+ARCH_ARM+ARCH_X64+ARCH_X86+ARCH_PPC)) -gt 0 ]] ; then
      print_output "$(indent "$(orange "Architecture  Count")")"
      if [[ $ARCH_MIPS -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS          ""$ARCH_MIPS")")" ; fi
      if [[ $ARCH_ARM -gt 0 ]] ; then print_output "$(indent "$(orange "ARM           ""$ARCH_ARM")")" ; fi
      if [[ $ARCH_X64 -gt 0 ]] ; then print_output "$(indent "$(orange "x64           ""$ARCH_X64")")" ; fi
      if [[ $ARCH_X86 -gt 0 ]] ; then print_output "$(indent "$(orange "x86           ""$ARCH_X86")")" ; fi
      if [[ $ARCH_PPC -gt 0 ]] ; then print_output "$(indent "$(orange "PPC           ""$ARCH_PPC")")" ; fi
      if [[ $ARCH_MIPS -gt $ARCH_ARM ]] && [[ $ARCH_MIPS -gt $ARCH_X64 ]] && [[ $ARCH_MIPS -gt $ARCH_X86 ]] && [[ $ARCH_MIPS -gt $ARCH_PPC ]] ; then
        D_ARCH="MIPS"
      elif [[ $ARCH_ARM -gt $ARCH_MIPS ]] && [[ $ARCH_ARM -gt $ARCH_X64 ]] && [[ $ARCH_ARM -gt $ARCH_X86 ]] && [[ $ARCH_ARM -gt $ARCH_PPC ]] ; then
        D_ARCH="ARM"
      elif [[ $ARCH_X64 -gt $ARCH_MIPS ]] && [[ $ARCH_X64 -gt $ARCH_ARM ]] && [[ $ARCH_X64 -gt $ARCH_X86 ]] && [[ $ARCH_X64 -gt $ARCH_PPC ]] ; then
        D_ARCH="x64"
      elif [[ $ARCH_X86 -gt $ARCH_MIPS ]] && [[ $ARCH_X86 -gt $ARCH_X64 ]] && [[ $ARCH_X86 -gt $ARCH_ARM ]] && [[ $ARCH_X86 -gt $ARCH_PPC ]] ; then
        D_ARCH="x86"
      elif [[ $ARCH_PPC -gt $ARCH_MIPS ]] && [[ $ARCH_PPC -gt $ARCH_ARM ]] && [[ $ARCH_PPC -gt $ARCH_X64 ]] && [[ $ARCH_PPC -gt $ARCH_X86 ]] ; then
        D_ARCH="PPC"
      fi

      if [[ $((D_END_BE+D_END_LE)) -gt 0 ]] ; then
        print_output ""
        print_output "$(indent "$(orange "Endianness  Count")")"
        if [[ $D_END_BE -gt 0 ]] ; then print_output "$(indent "$(orange "Big endian          ""$D_END_BE")")" ; fi
        if [[ $D_END_LE -gt 0 ]] ; then print_output "$(indent "$(orange "Little endian          ""$D_END_LE")")" ; fi
      fi

      if [[ $D_END_LE -gt $D_END_BE ]] ; then
        D_END="EL"
      elif [[ $D_END_BE -gt $D_END_LE ]] ; then
        D_END="EB"
      else
        D_END="NA"
      fi

      print_output ""

      if [[ $((D_END_BE+D_END_LE)) -gt 0 ]] ; then
        print_output "$(indent "Detected architecture and endianness of the firmware: ""$ORANGE""$D_ARCH"" / ""$D_END""$NC")""\\n"
        export D_END
      else
        print_output "$(indent "Detected architecture of the firmware: ""$ORANGE""$D_ARCH""$NC")""\\n"
      fi

      if [[ -n "${ARCH:-}" ]] ; then
        if [[ "$ARCH" != "$D_ARCH" ]] ; then
          print_output "[!] Your set architecture (""$ARCH"") is different from the automatically detected one. The set architecture will be used."
        fi
      else
        print_output "[*] No architecture was enforced, so the automatically detected one is used."
        ARCH="$D_ARCH"
        export ARCH
      fi
    else
      print_output "$(indent "$(red "No architecture in firmware found")")"
      if [[ -n "$ARCH" ]] ; then
        print_output "[*] Your set architecture (""$ARCH"") will be used."
      else
        print_output "[!] Since no architecture could be detected, you should set one."
      fi
    fi

  else
    print_output "[*] Architecture auto detection disabled\\n"
    if [[ -n "$ARCH" ]] ; then
      print_output "[*] Your set architecture (""$ARCH"") will be used."
    else
      print_output "[!] Since no architecture could be detected, you should set one."
    fi
  fi
}

prepare_file_arr()
{
  echo ""
  print_output "[*] Unique files auto detection (could take some time)\\n"

  export FILE_ARR
  readarray -t FILE_ARR < <(find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  # RTOS handling:
  if [[ -f $FIRMWARE_PATH && $RTOS -eq 1 ]]; then
    readarray -t FILE_ARR < <(find "$OUTPUT_DIR" -xdev -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
    FILE_ARR+=( "$FIRMWARE_PATH" )
  fi
  print_output "[*] Found $ORANGE${#FILE_ARR[@]}$NC unique files."

  # xdev will do the trick for us:
  # remove ./proc/* executables (for live testing)
  #rm_proc_binary "${FILE_ARR[@]}"
}

prepare_binary_arr()
{
  echo ""
  print_output "[*] Unique binary auto detection (could take some time)\\n"

  # lets try to get an unique binary array
  # Necessary for providing BINARIES array (usable in every module)
  export BINARIES=()
  #readarray -t BINARIES < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -executable -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  # In some firmwares we miss the exec permissions in the complete firmware. In such a case we try to find ELF files and unique it
  readarray -t BINARIES_TMP < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -exec file {} \; 2>/dev/null | grep ELF | cut -d: -f1)
  if [[ -v BINARIES_TMP[@] ]]; then
    for BINARY in "${BINARIES_TMP[@]}"; do
      if [[ -f "$BINARY" ]]; then
        BIN_MD5=$(md5sum "$BINARY" | cut -d\  -f1)
        if [[ ! " ${MD5_DONE_INT[*]} " =~ ${BIN_MD5} ]]; then
          BINARIES+=( "$BINARY" )
          MD5_DONE_INT+=( "$BIN_MD5" )
        fi
      fi
    done
    print_output "[*] Found $ORANGE${#BINARIES[@]}$NC unique executables."
  fi

  # remove ./proc/* executables (for live testing)
  #rm_proc_binary "${BINARIES[@]}"
}

set_etc_paths()
{
  # For the case if ./etc isn't in root of provided firmware or is renamed like e.g. ./etc-ro:
  # search etc paths
  # set them in ETC_PATHS variable
  # If another variable needs a "Extrawurst", you only need to copy 'set_etc_path' function, modify it and change
  # 'mod_path' for project wide path modification
  export ETC_PATHS
  set_etc_path
  print_etc
}

check_firmware()
{
  # Check if firmware got normal linux directory structure and warn if not
  # as we already have done some root directory detection we are going to use it now
  local DIR_COUNT=0
  local LINUX_PATHS=( "bin" "boot" "dev" "etc" "home" "lib" "mnt" "opt" "proc" "root" "sbin" "srv" "tmp" "usr" "var" )
  if [[ ${#ROOT_PATH[@]} -gt 0 ]]; then
    for R_PATH in "${ROOT_PATH[@]}"; do
      for L_PATH in "${LINUX_PATHS[@]}"; do
        if [[ -d "$R_PATH"/"$L_PATH" ]] ; then
          ((DIR_COUNT+=1))
        fi
      done
    done
  else
    # this is needed for directories we are testing
    # in such a case the pre-checking modules are not executed and no RPATH is available
    for L_PATH in "${LINUX_PATHS[@]}"; do
      if [[ -d "$FIRMWARE_PATH"/"$L_PATH" ]] ; then
        ((DIR_COUNT+=1))
      fi
    done
  fi

  if [[ $DIR_COUNT -lt 5 ]] ; then
    echo
    print_output "[!] Your firmware looks not like a regular Linux system, sure that you have entered the correct path?"
  else
    print_output "[+] Your firmware looks like a regular Linux system."
  fi
}

detect_root_dir_helper() {
  SEARCH_PATH="${1:-}"
  #if [[ -n "$2" ]];then
  #  LOGGER="$2"
  #else
  #  LOGGER="no_log"
  #fi

  #print_output "[*] Root directory auto detection (could take some time)\\n" "$LOGGER"
  print_output "[*] Root directory auto detection (could take some time)\\n"
  ROOT_PATH=()
  export ROOT_PATH
  local R_PATH

  mapfile -t INTERPRETER_FULL_PATH < <(find "$SEARCH_PATH" -ignore_readdir_race -type f -exec file {} \; 2>/dev/null | grep "ELF" | grep "interpreter" | sed s/.*interpreter\ // | sed s/,\ .*$// | sort -u 2>/dev/null || true)

  if [[ "${#INTERPRETER_FULL_PATH[@]}" -gt 0 ]]; then
    for INTERPRETER_PATH in "${INTERPRETER_FULL_PATH[@]}"; do
      # now we have a result like this "/lib/ld-uClibc.so.0"
      # lets escape it
      INTERPRETER_ESCAPED=$(echo "$INTERPRETER_PATH" | sed -e 's/\//\\\//g')
      mapfile -t INTERPRETER_FULL_RPATH < <(find "$SEARCH_PATH" -ignore_readdir_race -wholename "*$INTERPRETER_PATH" 2>/dev/null | sort -u)
      for R_PATH in "${INTERPRETER_FULL_RPATH[@]}"; do
        # remove the interpreter path from the full path:
        R_PATH="${R_PATH//$INTERPRETER_ESCAPED/}"
        ROOT_PATH+=( "$R_PATH" )
      done
    done
  else
    # if we can't find the interpreter we fall back to a search for something like "*root/bin/* and take this:
    mapfile -t ROOT_PATH < <(find "$SEARCH_PATH" -path "*root/bin" -exec dirname {} \; 2>/dev/null)
  fi

  if [[ ${#ROOT_PATH[@]} -eq 0 ]]; then
    print_output "[*] Root directory set to firmware path ... last resort"
    ROOT_PATH+=( "$SEARCH_PATH" )
  fi

  eval "ROOT_PATH=($(for i in "${ROOT_PATH[@]}" ; do echo "\"$i\"" ; done | sort -u))"
  if [[ ${#ROOT_PATH[@]} -gt 1 ]]; then
    #print_output "[*] Found $ORANGE${#ROOT_PATH[@]}$NC different root directories:" "$LOGGER"
    print_output "[*] Found $ORANGE${#ROOT_PATH[@]}$NC different root directories:"
    write_link "s05#file_dirs"
  fi
  for R_PATH in "${ROOT_PATH[@]}"; do
    #print_output "[+] Found the following root directory: $R_PATH" "$LOGGER"
    print_output "[+] Found the following root directory: $R_PATH"
    write_link "s05#file_dirs"
  done
}

check_init_size() {
  SIZE=$(du -b --max-depth=0 "$FIRMWARE_PATH"| awk '{print $1}' || true)
  if [[ $SIZE -gt 400000000 ]]; then
    print_output "" "no_log"
    print_output "[!] WARNING: Your firmware is very big!" "no_log"
    print_output "[!] WARNING: Analysing huge firmwares will take a lot of disk space, RAM and time!" "no_log"
    print_output "" "no_log"
  fi

}

generate_msf_db() {
  # only running on host in full installation (with metapsloit installed)
  print_output "[*] Building the Metasploit exploit database" "no_log"
  # search all ruby files in the metasploit directory and create a temporary file with the module path and CVE:
  find "$MSF_PATH" -type f -iname "*.rb" -exec grep -H -E -o "CVE', '[0-9]{4}-[0-9]+" {} \; | sed "s/', '/-/g" | sort > "$MSF_DB_PATH"
  print_output "[*] Metasploit exploit database now has $ORANGE$(wc -l "$MSF_DB_PATH")$NC exploit entries." "no_log"
}

generate_trickest_db() {
  # only running on host in full installation (with trickest database installed)
  print_output "[*] Update and build the Trickest CVE/exploit database" "no_log"
  # search all markdown files in the trickest directory and create a temporary file with the module path (including CVE) and github URL to exploit:

  cd "$EXT_DIR"/trickest-cve || true
  git pull || true
  cd ../.. || true

  find "$EXT_DIR"/trickest-cve -type f -iname "*.md" -exec grep -o -H "\-\ https://github.com/.*" {} \; | sed 's/:-\ /:/g' | sort > "$TRICKEST_DB_PATH"
  print_output "[*] Trickest CVE database now has $ORANGE$(wc -l "$TRICKEST_DB_PATH")$NC exploit entries." "no_log"
}

