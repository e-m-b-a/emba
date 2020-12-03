#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020 Siemens Energy AG
#
# Emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# Emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Module with all available functions and patterns to use
#               Access:
#                 firmware root path via $FIRMWARE_PATH
#                 binary array via ${BINARIES[@]}

S115_usermode_emulator() {
  module_log_init "usermode_emulator"
  module_title "Trying to emulate binaries via qemu usermode emulator"

  print_output "[-] This module is experimental and could harm your host environment."

  if [[ "$QEMULATION" -eq 1 ]]; then
    SHORT_PATH_BAK=$SHORT_PATH
    SHORT_PATH=1

    for LINE in "${BINARIES[@]}" ; do
      if ( file "$LINE" | grep -q ELF ) ; then
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
          print_output "[-] no working emulator found for $LINE"
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

  else
    print_output "[-] Automated emulation is disabled."
    print_output "[-] Enable it with the parameter -E."
  fi
}

running_jobs() {
  CJOBS=$(pgrep -a "$EMULATOR")
  if [[ -n "$CJOBS" ]]; then
    print_output "\n[*] Currently running emulation jobs: $(echo "$CJOBS" | wc -l)"
    print_output "$CJOBS"
  else
    CJOBS="NA"
  fi
}

cleanup() {
  print_output "\n[*] Terminating qemu processes - check it with ps"
  mapfile -t CJOBS < <(pgrep qemu-)
  for PID in "${CJOBS[@]}"; do
    print_output "[*] terminating process $PID"
    kill "$PID" 2> /dev/null
  done

  CJOBS_=$(pgrep qemu-)
  if [[ -n "$CJOBS_" ]]; then
    print_output "[*] more emulation jobs are running ... we kill it with fire"
    killall -9 "$EMULATOR" 2> /dev/null
  fi

  EMULATORS_=( qemu*static )
  if (( ${#EMULATORS_[@]} )); then
    print_output "[*] cleaning the emulation environment"
    rm "$FIRMWARE_PATH"/qemu*static 2> /dev/null
  fi

  print_output "\n[*] Umounting proc, sys and run"
  umount -l "$FIRMWARE_PATH"/proc 
  umount "$FIRMWARE_PATH"/sys 
  umount "$FIRMWARE_PATH"/run

  FILES=$(find "$LOG_DIR""/qemu_emulator/" -type f -name "qemu_*")
  if [[ -n "$FILES" ]]; then
    print_output "\n[*] Cleanup empty log files.\n"
    for FILE in $FILES; do
      if [[ ! -s "$FILE" ]] ; then
        #print_output "[*] removing empty log file $FILE"
        rm "$FILE" 2> /dev/null
      else
        BIN=$(basename "$FILE")
        BIN=$(echo "$BIN" | cut -d_ -f2 | sed 's/.txt$//')
        print_output "[+]${NC} Emulated binary ${GREEN}$BIN${NC} generated output in ${GREEN}$FILE${NC}. Please check this manually."
      fi
    done
  fi
  SHORT_PATH=$SHORT_PATH_BAK
}

prepare_emulator() {
  if [[ ! -f "$FIRMWARE_PATH"/"$EMULATOR" ]]; then
    print_output "\n[*] preparing the environment for usermode emulation"
    cp "$(which $EMULATOR)" "$FIRMWARE_PATH"

    if ! [[ -d "$FIRMWARE_PATH"/proc ]] ; then
      mkdir "$FIRMWARE_PATH"/proc 2> /dev/null
    fi

    if ! [[ -d "$FIRMWARE_PATH"/sys ]] ; then
      mkdir "$FIRMWARE_PATH"/sys 2> /dev/null
    fi

    if ! [[ -d "$FIRMWARE_PATH"/run ]] ; then
      mkdir "$FIRMWARE_PATH"/run 2> /dev/null
    fi

    if ! [[ -d "$FIRMWARE_PATH"/dev/ ]] ; then
      mkdir "$FIRMWARE_PATH"/dev/ 2> /dev/null
    fi

    mount proc "$FIRMWARE_PATH"/proc -t proc 2> /dev/null
    mount -o bind /run "$FIRMWARE_PATH"/run 2> /dev/null
    mount -o bind /sys "$FIRMWARE_PATH"/sys 2> /dev/null

    if [[ -f "$FIRMWARE_PATH"/dev/console ]] ; then
      rm "$FIRMWARE_PATH"/dev/console
      mknod -m 622 "$FIRMWARE_PATH"/dev/console c 5 1
    fi

    if [[ -f "$FIRMWARE_PATH"/dev/null ]] ; then
      rm "$FIRMWARE_PATH"/dev/null
      mknod -m 666 "$FIRMWARE_PATH"/dev/null c 1 3
    fi

    if [[ -f "$FIRMWARE_PATH"/dev/zero ]] ; then
      rm "$FIRMWARE_PATH"/dev/zero
      mknod -m 666 "$FIRMWARE_PATH"/dev/zero c 1 5
    fi

    if [[ -f "$FIRMWARE_PATH"/dev/ptmx ]] ; then
      rm "$FIRMWARE_PATH"/dev/ptmx
      mknod -m 666 "$FIRMWARE_PATH"/dev/ptmx c 5 2
    fi

    if [[ -f "$FIRMWARE_PATH"/dev/tty ]] ; then
      rm "$FIRMWARE_PATH"/dev/tty
      mknod -m 666 "$FIRMWARE_PATH"/dev/tty c 5 0
    fi

    if [[ -f "$FIRMWARE_PATH"/dev/random ]] ; then
      rm "$FIRMWARE_PATH"/dev/random
      mknod -m 444 "$FIRMWARE_PATH"/dev/random c 1 8
    fi

    if [[ -f "$FIRMWARE_PATH"/dev/urandom ]] ; then
      rm "$FIRMWARE_PATH"/dev/urandom
      mknod -m 444 "$FIRMWARE_PATH"/dev/urandom c 1 9
    fi

    chown -v root:tty "$FIRMWARE_PATH"/dev/{console,ptmx,tty}

    print_output "\n[*] Currently mounted areas:"
    mount | grep "$FIRMWARE_PATH" 2> /dev/null

    if ! [[ -d "$LOG_DIR"/qemu_emulator/ ]] ; then
      mkdir "$LOG_DIR"/qemu_emulator/ 2> /dev/null
    fi
  fi
}

emulate_binary() {
  print_output "\n[*] trying to emulate binary $LINE"
  BIN_EMU="$(cut_path "$LINE")"
  BIN_EMU_NAME="$(basename "$LINE")"
  chroot "$FIRMWARE_PATH" ./"$EMULATOR" "$BIN_EMU" | tee -a "$LOG_DIR"/qemu_emulator/qemu_"$BIN_EMU_NAME".txt &
  print_output "\n[*] Emulating $BIN_EMU ... "
}
