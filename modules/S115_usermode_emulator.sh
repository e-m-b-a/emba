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

  if [[ "$EMULATION" -eq 1 ]]; then
    SHORT_PATH_BAK=$SHORT_PATH
    SHORT_PATH=1
    declare -a PIDs

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
        elif ( file "$LINE" | grep -q "32-bit LSB.*MIPS32" ) ; then
          EMULATOR="qemu-mipsel-static"
        elif ( file "$LINE" | grep -q "32-bit MSB.*MIPS32" ) ; then
          EMULATOR="qemu-mips-static"
        elif ( file "$LINE" | grep -q "32-bit MSB.*PowerPC" ) ; then
          EMULATOR="qemu-ppc-static"
        else
          print_output "[-] no working emulator found for $LINE"
          EMULATOR="NA"
        fi

        if [[ $EMULATOR != "NA" ]]; then
          prepare_emulator
          emulate_binary
        fi
      fi
    done

    cleanup

    print_output "[*] Checking running processes for qemu processes:"
    ps aux | grep qemu
  else
    print_output "[-] Automated emulation is disabled."
    print_output "[-] Enable it with the parameter -E."
  fi
}

cleanup() {
  print_output "[*] Terminating qemu processes - check it with ps"
  for PID in "${PIDs[@]}"; do
    print_output "[*] terminating process $PID"
    kill "$PID" 2> /dev/null
  done

  EMULATORS_=( qemu*static )
  if (( ${#EMULATORS_[@]} )); then
    print_output "[*] cleaning the emulation environment"
    rm "$FIRMWARE_PATH"/qemu*static
  fi

  print_output "[*] Umounting proc, sys, run and dev"
  umount "$FIRMWARE_PATH"/proc
  umount "$FIRMWARE_PATH"/sys
  umount "$FIRMWARE_PATH"/run
  umount "$FIRMWARE_PATH"/dev

  SHORT_PATH=$SHORT_PATH_BAK
}

prepare_emulator() {
  if [[ ! -f $FIRMWARE_PATH/$EMULATOR ]]; then
    print_output "[*] preparing the environment for usermode emulation"
    cp "$(which $EMULATOR)" "$FIRMWARE_PATH"

    if ! [[ -d "$FIRMWARE_PATH"/proc ]] ; then
      mkdir "$FIRMWARE_PATH"/proc
    fi

    if ! [[ -d "$FIRMWARE_PATH"/sys ]] ; then
      mkdir "$FIRMWARE_PATH"/sys
    fi

    if ! [[ -d "$FIRMWARE_PATH"/run ]] ; then
      mkdir "$FIRMWARE_PATH"/run
    fi

    if ! [[ -d "$FIRMWARE_PATH"/dev/pts ]] ; then
      mkdir -p "$FIRMWARE_PATH"/dev/pts
    fi

    mount proc "$FIRMWARE_PATH"/proc -t proc
    mount -o bind /run "$FIRMWARE_PATH"/run
    mount -o bind /dev "$FIRMWARE_PATH"/dev
    mount -o bind /sys "$FIRMWARE_PATH"/sys
    mount
  fi
}

emulate_binary() {
  print_output "\n[*] trying to emulate binary $LINE"
  BIN_EMU="$(cut_path "$LINE")"
  chroot "$FIRMWARE_PATH" ./"$EMULATOR" "$BIN_EMU" &
  PID=$!
  echo $PID
  PIDs+=("$PID")
  print_output "\n[*] Emulating $BIN_EMU with PID $PID"
}
