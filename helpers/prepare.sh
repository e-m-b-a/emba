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

# Description:  Preparation for testing firmware:
#                 Excluding paths
#                 Check architecture
#                 Binary array
#                 etc path handling
#                 Check firmware
#               Access:
#                 firmware root path via $FIRMWARE_PATH

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
    print_output "[*] Architecture auto detection (could take some time)\\n" "no_log"
    local DETECT_ARCH ARCH_MIPS=0 ARCH_ARM=0 ARCH_X64=0 ARCH_X86=0 ARCH_PPC=0
    # do not use -executable here. Not all firmware updates have exec permissions set
    IFS=" " read -r -a DETECT_ARCH < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -xdev -exec file {} \; 2>/dev/null | grep ELF | tr '\r\n' ' ' | tr -d '\n' 2>/dev/null)
    for D_ARCH in "${DETECT_ARCH[@]}" ; do
      if [[ "$D_ARCH" == *"MIPS"* ]] ; then
        ARCH_MIPS=$((ARCH_MIPS+1))
      elif [[ "$D_ARCH" == *"ARM"* ]] ; then
        ARCH_ARM=$((ARCH_ARM+1))
      elif [[ "$D_ARCH" == *"x86-64"* ]] ; then
        ARCH_X64=$((ARCH_X64+1))
      elif [[ "$D_ARCH" == *"80386"* ]] ; then
        ARCH_X86=$((ARCH_X86+1))
      elif [[ "$D_ARCH" == *"PowerPC"* ]] ; then
        ARCH_PPC=$((ARCH_PPC+1))
      fi
    done
    if [[ $((ARCH_MIPS+ARCH_ARM+ARCH_X64+ARCH_X86+ARCH_PPC)) -gt 0 ]] ; then
      print_output "$(indent "$(orange "Architecture  Count")")" "no_log"
      if [[ $ARCH_MIPS -gt 0 ]] ; then print_output "$(indent "$(orange "MIPS          ""$ARCH_MIPS")")" "no_log" ; fi
      if [[ $ARCH_ARM -gt 0 ]] ; then print_output "$(indent "$(orange "ARM           ""$ARCH_ARM")")" "no_log" ; fi
      if [[ $ARCH_X64 -gt 0 ]] ; then print_output "$(indent "$(orange "x64           ""$ARCH_X64")")" "no_log" ; fi
      if [[ $ARCH_X86 -gt 0 ]] ; then print_output "$(indent "$(orange "x86           ""$ARCH_X86")")" "no_log" ; fi
      if [[ $ARCH_PPC -gt 0 ]] ; then print_output "$(indent "$(orange "PPC           ""$ARCH_PPC")")" "no_log" ; fi
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
      echo
      print_output "$(indent "Detected architecture of the firmware: ""$ORANGE""$D_ARCH""$NC")""\\n" "no_log"
      if [[ -n "$ARCH" ]] ; then
        if [[ "$ARCH" != "$D_ARCH" ]] ; then
          print_output "[!] Your set architecture (""$ARCH"") is different from the automatically detected one. The set architecture will be used." "no_log"
        fi
      else
        print_output "[*] No architecture was enforced, so the automatically detected one is used." "no_log"
        ARCH="$D_ARCH"
        export ARCH
      fi
    else
      print_output "$(indent "$(red "No architecture in firmware found")")" "no_log"
      if [[ -n "$ARCH" ]] ; then
        print_output "[*] Your set architecture (""$ARCH"") will be used." "no_log"
      else
        print_output "[!] Since no architecture could be detected, you have to set one." "no_log"
        print_help
        exit 1
      fi
    fi
  else
    print_output "[*] Architecture auto detection disabled\\n" "no_log"
    if [[ -n "$ARCH" ]] ; then
      print_output "[*] Your set architecture (""$ARCH"") will be used." "no_log"
    else
      print_output "[!] Since no architecture could be detected, you have to set one." "no_log"
      print_help
      exit 1
    fi
  fi
}

prepare_file_arr()
{
  echo ""
  print_output "[*] Unique files auto detection (could take some time)\\n" "main"

  export FILE_ARR
  readarray -t FILE_ARR < <(find "$FIRMWARE_PATH" -xdev "${EXCL_FIND[@]}" -type f -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )
  print_output "[*] Found $ORANGE${#FILE_ARR[@]}$NC unique files." "main"

  # xdev will do the trick for us:
  # remove ./proc/* executables (for live testing)
  #rm_proc_binary "${FILE_ARR[@]}"
}

prepare_binary_arr()
{
  echo ""
  print_output "[*] Unique binary auto detection (could take some time)\\n" "main"

  # lets try to get an unique binary array
  # Necessary for providing BINARIES array (usable in every module)
  export BINARIES
  readarray -t BINARIES < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -executable -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 )

  # in some firmwares we miss the exec permissions in the complete firmware. In such a case we try to find ELF files and unique it
  # this is a slow fallback solution just to have something we can work with
  if [[ "${#BINARIES[@]}" -eq 0 ]]; then
    readarray -t BINARIES_TMP < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -exec file {} \; 2>/dev/null | grep ELF | cut -d: -f1)
    for BINARY in "${BINARIES_TMP[@]}"; do
      BIN_MD5=$(md5sum "$BINARY" | cut -d\  -f1)
      if [[ ! " ${MD5_DONE_INT[*]} " =~ ${BIN_MD5} ]]; then
        BINARIES+=( "$BINARY" )
        MD5_DONE_INT+=( "$BIN_MD5" )
      fi
    done
  fi
  print_output "[*] Found $ORANGE${#BINARIES[@]}$NC unique executables." "main"

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
  for R_PATH in "${ROOT_PATH[@]}"; do
    for L_PATH in "${LINUX_PATHS[@]}"; do
      if [[ -d "$R_PATH"/"$L_PATH" ]] ; then
        ((DIR_COUNT++))
      fi
    done
  done

  if [[ $DIR_COUNT -lt 5 ]] ; then
    echo
    print_output "[!] Your firmware looks not like a regular Linux system, sure that you have entered the correct path?" "no_log"
  fi
}

detect_root_dir_helper() {
  SEARCH_PATH="$1"
  print_output "[*] Root directory auto detection (could take some time)\\n" "no_log"
  ROOT_PATH=()
  export ROOT_PATH
  local R_PATH

  mapfile -t INTERPRETER_FULL_PATH < <(find "$SEARCH_PATH" -ignore_readdir_race -type f -exec file {} \; 2>/dev/null | grep "ELF" | grep "interpreter" | sed s/.*interpreter\ // | sed s/,\ .*$// | sort -u 2>/dev/null)

  if [[ "${#INTERPRETER_FULL_PATH[@]}" -ne 0 ]]; then
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
    print_output "[*] Root directory set to firmware path ... last resort" "no_log"
    ROOT_PATH+=( "$SEARCH_PATH" )
  fi

  eval "ROOT_PATH=($(for i in "${ROOT_PATH[@]}" ; do echo "\"$i\"" ; done | sort -u))"
  if [[ ${#ROOT_PATH[@]} -gt 1 ]]; then
    print_output "[*] Found $ORANGE${#ROOT_PATH[@]}$NC different root directories:" "no_log"
  fi
  for R_PATH in "${ROOT_PATH[@]}"; do
    print_output "[+] Found the following root directory: $R_PATH" "no_log"
  done
}

