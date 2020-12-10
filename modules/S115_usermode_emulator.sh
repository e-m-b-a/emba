#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Module with all available functions and patterns to use
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}

S115_usermode_emulator() {
  module_log_init "usermode_emulator"
  module_title "Trying to emulate binaries via qemu usermode emulator"

  print_output "[!] This module is experimental and could harm your host environment."
  print_output "[!] This module creates a working copy of the firmware filesystem in the log directory $LOG_DIR.\\n"

  print_output "[*] Should we proceed?\\n"
  read -p "(y/N)  " -r ANSWER
  case ${ANSWER:0:1} in
    n|N|"" )
      echo -e "\\n${RED}Terminating emba${NC}\\n"
      exit 1
    ;;
  esac

  if [[ "$QEMULATION" -eq 1 ]]; then
    SHORT_PATH_BAK=$SHORT_PATH
    SHORT_PATH=1

    # as we modify the firmware we copy it to the log directory and do stuff in this area
    copy_firmware

    for LINE in "${BINARIES[@]}" ; do
      if ( file "$LINE" | grep -q ELF ) && [[ "$LINE" != './qemu-'*'-static' ]]; then
        if ( file "$LINE" | grep -q "x86-64" ) ; then
          EMULATOR="qemu-x86_64-static"
        elif ( file "$LINE" | grep -q "Intel 80386" ) ; then
          EMULATOR="qemu-i386-static"
        elif ( file "$LINE" | grep -q "32-bit LSB.*ARM" ) ; then
          EMULATOR="qemu-arm-static"
        elif ( file "$LINE" | grep -q "32-bit MSB.*ARM" ) ; then
          EMULATOR="qemu-armeb-static"
        elif ( file "$LINE" | grep -q "32-bit LSB.*MIPS" ) ; then
          EMULATOR="qemu-mipsel-static"
        elif ( file "$LINE" | grep -q "32-bit MSB.*MIPS" ) ; then
          EMULATOR="qemu-mips-static"
        elif ( file "$LINE" | grep -q "32-bit MSB.*PowerPC" ) ; then
          EMULATOR="qemu-ppc-static"
        else
          print_output "[-] No working emulator found for ""$LINE"
          EMULATOR="NA"
        fi

        if [[ "$EMULATOR" != "NA" ]]; then
          prepare_emulator
          emulate_binary
        fi
        running_jobs
      fi
    done

    cleanup
    running_jobs
    version_detection

  else
    print_output "[!] Automated emulation is disabled."
    print_output "$(indent "Enable it with the parameter -E.")"
  fi
}

version_detection() {
  sub_module_title "Version detection started"

  while read -r VERSION_LINE; do 
    BINARY=$(echo "$VERSION_LINE" | cut -d: -f1)
    VERSION_IDENTIFIER=$(echo "$VERSION_LINE" | cut -d: -f2 | sed s/^\"// | sed s/\"$//)
    readarray -t VERSIONS_DETECTED < <(grep -e "$VERSION_IDENTIFIER" "$LOG_DIR"/qemu_emulator/*)

    if [[ ${#VERSIONS_DETECTED[@]} -ne 0 ]]; then
      for VERSION_DETECTED in "${VERSIONS_DETECTED[@]}"; do
        # if we have multiple detection of the same version details:
        if [ "$VERSION_DETECTED" != "$VERS_DET_OLD" ]; then
          VERS_DET_OLD=$VERSION_DETECTED
          VERSIONS_BIN=$(basename "$(echo "$VERSION_DETECTED" | cut -d: -f1)")
          VERSION_DETECTED=$(echo "$VERSION_DETECTED" | cut -d: -f2-)
          print_output "[+] Version information found ${RED}""$VERSION_DETECTED""${NC}${GREEN} (from binary $BINARY) used in $VERSIONS_BIN."
        fi
      done
    fi
  done < "$CONFIG_DIR"/bin_version_strings.cfg 
  echo
}

copy_firmware() {
  print_output "[*] Create a firmware backup for emulation ..."
  cp -pri "$FIRMWARE_PATH" "$LOG_DIR"/
  EMULATION_DIR=$(basename "$FIRMWARE_PATH")
  EMULATION_PATH="$LOG_DIR"/"$EMULATION_DIR"
}

running_jobs() {
  CJOBS=$(pgrep -a "$EMULATOR")
  if [[ -n "$CJOBS" ]] ; then
    echo
    print_output "[*] Currently running emulation jobs: $(echo "$CJOBS" | wc -l)"
    print_output "$(indent "$CJOBS")""\\n"
  else
    CJOBS="NA"
  fi
}

cleanup() {
  # reset the terminal after all the uncontrolled emulation it is typically broken!
  reset

  print_output "[*] Terminating qemu processes - check it with ps"
  mapfile -t CJOBS < <(pgrep -f "$EMULATOR")
  for PID in "${CJOBS[@]}"; do
    print_output "[*] Terminating process ""$PID"
    kill "$PID" 2> /dev/null
  done

  CJOBS_=$(pgrep qemu-)
  if [[ -n "$CJOBS_" ]] ; then
    print_output "[*] More emulation jobs are running ... we kill it with fire\\n"
    killall -9 "$EMULATOR" 2> /dev/null
  fi

  EMULATORS_=( qemu*static )
  if (( ${#EMULATORS_[@]} )) ; then
    print_output "[*] Cleaning the emulation environment\\n"
    rm "$EMULATION_PATH"/qemu*static 2> /dev/null
  fi

  echo
  print_output "[*] Umounting proc, sys and run"
  umount -l "$EMULATION_PATH""/proc"
  umount "$EMULATION_PATH""/sys"
  umount "$EMULATION_PATH""/run"

  FILES=$(find "$LOG_DIR""/qemu_emulator/" -type f -name "qemu_*")
  if [[ -n "$FILES" ]] ; then
    print_output "[*] Cleanup empty log files.\\n"
    for FILE in $FILES ; do
      if [[ ! -s "$FILE" ]] ; then
        rm "$FILE" 2> /dev/null
      else
        BIN=$(basename "$FILE")
        BIN=$(echo "$BIN" | cut -d_ -f2 | sed 's/.txt$//')
        print_output "[+]""${NC}"" Emulated binary ""${GREEN}""$BIN""${NC}"" generated output in ""${GREEN}""$FILE""${NC}"". Please check this manually."
      fi
    done
  fi
  SHORT_PATH=$SHORT_PATH_BAK
}

prepare_emulator() {

  if [[ ! -f "$EMULATION_PATH""/""$EMULATOR" ]]; then
    print_output "[*] Preparing the environment for usermode emulation"
    cp "$(which $EMULATOR)" "$EMULATION_PATH"/

    if ! [[ -d "$EMULATION_PATH""/proc" ]] ; then
      mkdir "$EMULATION_PATH""/proc" 2> /dev/null
    fi

    if ! [[ -d "$EMULATION_PATH""/sys" ]] ; then
      mkdir "$EMULATION_PATH""/sys" 2> /dev/null
    fi

    if ! [[ -d "$EMULATION_PATH""/run" ]] ; then
      mkdir "$EMULATION_PATH""/run" 2> /dev/null
    fi

    if ! [[ -d "$EMULATION_PATH""/dev/" ]] ; then
      mkdir "$EMULATION_PATH""/dev/" 2> /dev/null
    fi

    mount proc "$EMULATION_PATH""/proc" -t proc 2> /dev/null
    mount -o bind /run "$EMULATION_PATH""/run" 2> /dev/null
    mount -o bind /sys "$EMULATION_PATH""/sys" 2> /dev/null

    if [[ -e "$EMULATION_PATH""/dev/console" ]] ; then
      rm "$EMULATION_PATH""/dev/console" 2> /dev/null
    fi
    mknod -m 622 "$EMULATION_PATH""/dev/console" c 5 1 2> /dev/null

    if [[ -e "$EMULATION_PATH""/dev/null" ]] ; then
      rm "$EMULATION_PATH""/dev/null" 2> /dev/null
    fi
    mknod -m 666 "$EMULATION_PATH""/dev/null" c 1 3 2> /dev/null

    if [[ -e "$EMULATION_PATH""/dev/zero" ]] ; then
      rm "$EMULATION_PATH""/dev/zero" 2> /dev/null
    fi
    mknod -m 666 "$EMULATION_PATH""/dev/zero" c 1 5 2> /dev/null

    if [[ -e "$EMULATION_PATH""/dev/ptmx" ]] ; then
      rm "$EMULATION_PATH""/dev/ptmx" 2> /dev/null
    fi
    mknod -m 666 "$EMULATION_PATH""/dev/ptmx" c 5 2 2> /dev/null

    if [[ -e "$EMULATION_PATH""/dev/tty" ]] ; then
      rm "$EMULATION_PATH""/dev/tty" 2> /dev/null
    fi
    mknod -m 666 "$EMULATION_PATH""/dev/tty" c 5 0 2> /dev/null

    if [[ -e "$EMULATION_PATH""/dev/random" ]] ; then
      rm "$EMULATION_PATH""/dev/random" 2> /dev/null
    fi
    mknod -m 444 "$EMULATION_PATH""/dev/random" c 1 8 2> /dev/null

    if [[ -e "$EMULATION_PATH""/dev/urandom" ]] ; then
      rm "$EMULATION_PATH""/dev/urandom" 2> /dev/null
    fi
    mknod -m 444 "$EMULATION_PATH""/dev/urandom" c 1 9 2> /dev/null

    chown -v root:tty "$EMULATION_PATH""/dev/"{console,ptmx,tty} > /dev/null 2>&1

    print_output ""
    print_output "[*] Currently mounted areas:"
    print_output "$(indent "$(mount | grep "$EMULATION_PATH" 2> /dev/null )")""\\n"

  fi
  if ! [[ -d "$LOG_DIR""/qemu_emulator" ]] ; then
    mkdir "$LOG_DIR""/qemu_emulator" 2> /dev/null
  fi
}

emulate_binary() {
  BIN_EMU="$(cut_path "$LINE")"
  BIN_EMU_NAME="$(basename "$LINE")"
  
  # emulate binary with different command line parameters:
  EMULATION_PARAMS=("" "-v" "-V" "-h" "-help" "--help" "--version")
  for PARAM in "${EMULATION_PARAMS[@]}"; do
    print_output "[*] Trying to emulate binary ""$(print_path "$BIN_EMU")"" with parameter ""$PARAM"""

    chroot "$EMULATION_PATH" ./"$EMULATOR" "$BIN_EMU" "$PARAM" | tee -a "$LOG_DIR""/qemu_emulator/qemu_""$BIN_EMU_NAME"".txt" 2>&1 &
    print_output ""
  done
  # reset the terminal after all the uncontrolled emulation it is typically broken!
  reset
}

