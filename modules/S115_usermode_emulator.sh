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
}

cleanup() {
  print_output "[*] killall qemu processes - check it with ps"
  for PID in "${PIDs[@]}"; do
    #print_output "[*] terminating process $PID"
    kill "$PID" 2> /dev/null
  done

  EMULATORS_=( qemu*static )
  if (( ${#EMULATORS_[@]} )); then
    print_output "[*] cleaning the emulation environment"
    rm "$FIRMWARE_PATH"/qemu*static
  fi

  SHORT_PATH=$SHORT_PATH_BAK
}

prepare_emulator() {
  if [[ ! -f $FIRMWARE_PATH/$EMULATOR ]]; then
    print_output "[*] preparing the environment for usermode emulation"
    cp "$(which $EMULATOR)" "$FIRMWARE_PATH"
  fi
}

emulate_binary() {
  print_output "\n[*] trying to emulate binary $LINE"
  BIN_EMU="$(cut_path "$LINE")"
  chroot "$FIRMWARE_PATH" ./"$EMULATOR" "$BIN_EMU" 2> /dev/null &
  echo "1"
  PID=$! 2> /dev/null
  echo "2"
  PIDs+=("$PID")
  echo "3"
  #echo "pid: $PID"
  #print_output "\n[*] emulating $BIN_EMU with PID $PID"
  #print_output "\n[*] emulating $BIN_EMU."
  echo "4"
}
