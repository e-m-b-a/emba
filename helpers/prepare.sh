#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
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
    IFS=" " read -r -a DETECT_ARCH < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -executable -exec file {} \; | grep "executable\|shared\ object" | tr '\r\n' ' ' | tr -d '\n' 2>/dev/null)
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
        print_output "[*] No architecture was set, so the automatically detected one is used." "no_log"
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

prepare_binary_arr()
{
  # Necessary for providing BINARIES array (usable in every module)
  export BINARIES
  readarray -t BINARIES < <( find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -type f -executable -iname "*" )

  # remove ./proc/* executables (for live testing)
  rm_proc_binary "${BINARIES[@]}"
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
  local DIR_COUNT=0
  if [[ -d "$FIRMWARE_PATH""/bin" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/boot" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/dev" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/etc" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/home" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/lib" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/media" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/mnt" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/opt" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/proc" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/root" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/run" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/sbin" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/srv" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/tmp" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/usr" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi
  if [[ -d "$FIRMWARE_PATH""/var" ]] ; then
    DIR_COUNT=$((DIR_COUNT + 1))
  fi

  if [[ $DIR_COUNT -lt 5 ]] ; then
    echo
    print_output "[!] Your firmware looks strange, sure that you have entered the correct path?" "no_log"
  fi
}
