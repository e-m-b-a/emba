#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
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
  module_log_init "${FUNCNAME[0]}"
  module_title "Software component and version detection started via emulation with qemu usermode emulation"

  if [[ "$QEMULATION" -eq 1 ]]; then

    print_output "[!] This module is experimental and could harm your host environment."
    print_output "[!] This module creates a working copy of the firmware filesystem in the log directory $LOG_DIR.\\n"

    SHORT_PATH_BAK=$SHORT_PATH
    SHORT_PATH=1
    # some processes are running long and logging a lot
    # to protect the host we are going to kill them on a KILL_SIZE limit
    KILL_SIZE="100M"
    # to get rid of all the running stuff we are going to kill it after RUNTIME
    RUNTIME="10m"
    declare -a MISSING

    ## load blacklist of binaries that could cause troubles during emulation:
    readarray -t BIN_BLACKLIST < "$CONFIG_DIR"/emulation_blacklist.cfg

    # as we modify the firmware we copy it to the log directory and do the modifications in this area
    copy_firmware

    for LINE in "${BINARIES[@]}" ; do
      if ( file "$LINE" | grep -q ELF ) && [[ "$LINE" != './qemu-'*'-static' ]]; then
        if ! [[ "${BIN_BLACKLIST[*]}" == *"$(basename "$LINE")"* ]]; then
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
            print_output "[*] Emulator used: $EMULATOR"
            prepare_emulator
            emulate_binary
          fi
        else
          print_output "[!] Blacklist triggered ... $LINE"
        fi
        running_jobs
      fi
    done

    cleanup
    running_jobs
    filesystem_fixes
    version_detection

  else
    echo
    print_output "[!] Automated emulation is disabled."
    print_output "[!] Enable it with the -E switch."
  fi
}

filesystem_fixes() {
  if [[ "${#MISSING[@]}" -ne 0 ]]; then
    sub_module_title "Filesystem fixes"
    print_output "[*] Emba has auto-generated the files during runtime."
    print_output "[*] For persistence you could generate it manually in your filesystem.\\n"
    for MISSING_FILE in "${MISSING[@]}"; do
      print_output "[*] Missing file: $MISSING_FILE"
    done
  fi
}

version_detection() {
  sub_module_title "Software component and version detection started"

  while read -r VERSION_LINE; do 
    BINARY="$(echo "$VERSION_LINE" | cut -d: -f1)"
    STRICT="$(echo "$VERSION_LINE" | cut -d: -f2)"
    VERSION_IDENTIFIER="$(echo "$VERSION_LINE" | cut -d: -f3- | sed s/^\"// | sed s/\"$//)"

    # if we have the key strict this version identifier only works for the defined binary and is not generic!
    if [[ $STRICT == "strict" ]]; then
      if [[ -f "$LOG_DIR"/qemu_emulator/qemu_"$BINARY".txt ]]; then
        VERSION_STRICT=$(grep -o -e "$VERSION_IDENTIFIER" "$LOG_DIR"/qemu_emulator/qemu_"$BINARY".txt | sort -u | head -1 2>/dev/null)
        if [[ -n "$VERSION_STRICT" ]]; then
          if [[ "$BINARY" == "smbd" ]]; then
            # we log it as the original binary and the samba binary name
            VERSION_="$BINARY $VERSION_STRICT"
            VERSIONS_DETECTED+=("$VERSION_")
            BINARY="samba"
          fi
          VERSION_="$BINARY:$BINARY $VERSION_STRICT"
          VERSIONS_DETECTED+=("$VERSION_")
        fi
      fi
    else
      readarray -t VERSIONS_DETECTED < <(grep -o -e "$VERSION_IDENTIFIER" "$LOG_DIR"/qemu_emulator/* 2>/dev/null)
    fi

    if [[ ${#VERSIONS_DETECTED[@]} -ne 0 ]]; then
      for VERSION_DETECTED in "${VERSIONS_DETECTED[@]}"; do
        # if we have multiple detection of the same version details:
        if [ "$VERSION_DETECTED" != "$VERS_DET_OLD" ]; then
          VERS_DET_OLD="$VERSION_DETECTED"
          VERSIONS_BIN="$(basename "$(echo "$VERSION_DETECTED" | cut -d: -f1)")"
          VERSION_DETECTED="$(echo "$VERSION_DETECTED" | cut -d: -f2-)"
          # we do not deal with output formatting the usual way -> it destroys our current aggregator
          # we have to deal with it in the future
          FORMAT_LOG_BAK="$FORMAT_LOG"
          FORMAT_LOG=0
          print_output "[+] Version information found ${RED}""$VERSION_DETECTED""${NC}${GREEN} (from binary $BINARY) found in $VERSIONS_BIN."
          FORMAT_LOG="$FORMAT_LOG_BAK"
        fi
      done
    fi
  done < "$CONFIG_DIR"/bin_version_strings.cfg 
  echo
}

detect_root_dir() {
  EMULATION_PATH=()

  INTERPRETER_FULL_PATH=$(find "$EMULATION_PATH_BASE" -ignore_readdir_race -type f -executable -name "$BIN_EMU_NAME" -exec file {} \; 2>/dev/null | grep "ELF" | grep "interpreter" | sed s/.*interpreter\ // | sed s/,\ .*$// | sort -u | head -1 2>/dev/null)

  # sometimes it is complicated to debug the chosen root directory. Lets output some helpers
  print_output "[*] Emulation_path_base: $EMULATION_PATH_BASE"
  print_output "[*] Bin_emu_name: $BIN_EMU_NAME"
  print_output "[*] Interpreter: $INTERPRETER_FULL_PATH"

  PATH_OK=0
  if [[ -n "$INTERPRETER_FULL_PATH" ]]; then
    # now we have a result like this "/lib/ld-uClibc.so.0"
    INTERPRETER=$(echo "$INTERPRETER_FULL_PATH" | sed -e 's/\//\\\//g')
    # in some cases we have multiple extracted root directories and currently we do not know in which sits our binary for emulation
    # quick and dirty: just try to emulate our binary in every detected root directory
    mapfile -t EMULATION_PATH_TMP < <(find "$EMULATION_PATH_BASE" -ignore_readdir_race -wholename "*$INTERPRETER_FULL_PATH" 2>/dev/null | sort -u)
    #EMULATION_PATH="${EMULATION_PATH//$INTERPRETER/}"
    for E_PATH in "${EMULATION_PATH_TMP[@]}"; do
      E_PATH="${E_PATH//$INTERPRETER/}"
      EMULATION_PATH+=( "$E_PATH" )
      print_output "[*] Root directory detection via interpreter ... $E_PATH"
    done
  else
    # if we can't find the interpreter we fall back to a search for something like "*root/bin/* and take this:
    print_output "[*] Root directory detection via path pattern ... "
    mapfile -t EMULATION_PATH < <(find "$EMULATION_PATH_BASE" -path "*root/bin" -exec dirname {} \; 2>/dev/null)
  fi

  # if the new root directory does not include the current working directory we fall back to the search for something like "*root/bin/* and take this:
  for E_PATH in "${EMULATION_PATH[@]}"; do
    if [[ "$E_PATH" == *"$EMULATION_PATH_BASE"* ]]; then
      PATH_OK=1
    fi
  done

  # this could happen if the interpreter path from the first check is broken and results in something like this: "/" or "."
  # if this happens we have to handle this and try to fix the path:
  if [[ "$PATH_OK" -ne 1 ]]; then
    print_output "[*] Root directory detection via path pattern ... failed interpreter detection"
    mapfile -t EMULATION_PATH < <(find "$EMULATION_PATH_BASE" -path "*root/bin" -exec dirname {} \; 2>/dev/null)
  fi

  for E_PATH in "${EMULATION_PATH[@]}"; do
    # now we have to include a final check and fix the root path to the firmware path (as last resort)
    if [[ "$E_PATH" == *"$EMULATION_PATH_BASE"* ]]; then
      PATH_OK=1
    fi
  done

  if [[ $PATH_OK -ne 1 ]]; then
    print_output "[*] Root directory set to firmware path ... last resort"
    EMULATION_PATH+=( "$EMULATION_PATH_BASE" )
  fi

  # This is for quick testing here - if emba fails to detect the root directory you can poke with it here (we have to find a better way for the future):
  #EMULATION_PATH="$EMULATION_PATH_BASE"

  for E_PATH in "${EMULATION_PATH[@]}"; do
    print_output "[*] Using the following path as emulation root path: $E_PATH"
  done
}

copy_firmware() {
  print_output "[*] Create a firmware backup for emulation ..."
  cp -pri "$FIRMWARE_PATH" "$LOG_DIR"/ 2> /dev/null
  EMULATION_DIR=$(basename "$FIRMWARE_PATH")
  EMULATION_PATH_BASE="$LOG_DIR"/"$EMULATION_DIR"
}

running_jobs() {
  # if no emulation at all was possible the $EMULATOR variable is not defined
  if [[ -n "$EMULATOR" ]]; then
    CJOBS=$(pgrep -a "$EMULATOR")
    if [[ -n "$CJOBS" ]] ; then
      echo
      print_output "[*] Currently running emulation jobs: $(echo "$CJOBS" | wc -l)"
      print_output "$(indent "$CJOBS")""\\n"
    else
      CJOBS="NA"
    fi
  fi
}

cleanup() {
  # reset the terminal - after all the uncontrolled emulation it is typically broken!
  reset

  # if no emulation at all was possible the $EMULATOR variable is not defined
  if [[ -n "$EMULATOR" ]]; then
    print_output "[*] Terminating qemu processes - check it with ps"
    mapfile -t CJOBS < <(pgrep -f "$EMULATOR")
    for PID in "${CJOBS[@]}"; do
      print_output "[*] Terminating process ""$PID"
      kill "$PID" 2> /dev/null
    done
  fi

  CJOBS_=$(pgrep qemu-)
  if [[ -n "$CJOBS_" ]] ; then
    print_output "[*] More emulation jobs are running ... we kill it with fire\\n"
    killall -9 "$EMULATOR" 2> /dev/null
  fi

  print_output "[*] Cleaning the emulation environment\\n"
  find "$EMULATION_PATH_BASE" -iname "qemu*static" -exec rm {} \;

  print_output ""
  print_output "[*] Umounting proc, sys and run"
  mapfile -t CHECK_MOUNTS < <(mount | grep "$EMULATION_PATH_BASE")
  for MOUNT in "${CHECK_MOUNTS[@]}"; do
    print_output "[*] Unmounting $MOUNT"
    MOUNT=$(echo "$MOUNT" | cut -d\  -f3)
    umount -l "$MOUNT"
  done

  mapfile -t FILES < <(find "$LOG_DIR""/qemu_emulator/" -type f -name "qemu_*" 2>/dev/null)
  if [[ "${#FILES[@]}" -gt 0 ]] ; then
    print_output "[*] Cleanup empty log files.\\n\\n"
    for FILE in "${FILES[@]}" ; do
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

  if [[ ! -e "$E_PATH""/""$EMULATOR" ]]; then
    print_output "[*] Preparing the environment for usermode emulation"
    if ! command -v "$EMULATOR" > /dev/null ; then
      echo
      print_output "[!] Is the qemu package installed?"
      print_output "$(indent "We can't find it!")"
      print_output "$(indent "$(red "Terminating emba now.\\n")")"
      exit 1
    else
      cp "$(which $EMULATOR)" "$E_PATH"/
    fi

    if ! [[ -d "$E_PATH""/proc" ]] ; then
      mkdir "$E_PATH""/proc" 2> /dev/null
    fi

    if ! [[ -d "$E_PATH""/sys" ]] ; then
      mkdir "$E_PATH""/sys" 2> /dev/null
    fi

    if ! [[ -d "$E_PATH""/run" ]] ; then
      mkdir "$E_PATH""/run" 2> /dev/null
    fi

    if ! [[ -d "$E_PATH""/dev/" ]] ; then
      mkdir "$E_PATH""/dev/" 2> /dev/null
    fi

    if ! mount | grep "$E_PATH"/proc > /dev/null ; then
      mount proc "$E_PATH""/proc" -t proc 2> /dev/null
    fi
    if ! mount | grep "$E_PATH/run" > /dev/null ; then
      mount -o bind /run "$E_PATH""/run" 2> /dev/null
    fi
    if ! mount | grep "$E_PATH/sys" > /dev/null ; then
      mount -o bind /sys "$E_PATH""/sys" 2> /dev/null
    fi

    if ! [[ -e "$E_PATH""/dev/console" ]] ; then
      mknod -m 622 "$E_PATH""/dev/console" c 5 1 2> /dev/null
    fi

    if ! [[ -e "$E_PATH""/dev/null" ]] ; then
      mknod -m 666 "$E_PATH""/dev/null" c 1 3 2> /dev/null
    fi

    if ! [[ -e "$E_PATH""/dev/zero" ]] ; then
      mknod -m 666 "$E_PATH""/dev/zero" c 1 5 2> /dev/null
    fi

    if ! [[ -e "$E_PATH""/dev/ptmx" ]] ; then
      mknod -m 666 "$E_PATH""/dev/ptmx" c 5 2 2> /dev/null
    fi

    if ! [[ -e "$E_PATH""/dev/tty" ]] ; then
      mknod -m 666 "$E_PATH""/dev/tty" c 5 0 2> /dev/null
    fi

    if ! [[ -e "$E_PATH""/dev/random" ]] ; then
      mknod -m 444 "$E_PATH""/dev/random" c 1 8 2> /dev/null
    fi

    if ! [[ -e "$E_PATH""/dev/urandom" ]] ; then
      mknod -m 444 "$E_PATH""/dev/urandom" c 1 9 2> /dev/null
    fi

    chown -v root:tty "$E_PATH""/dev/"{console,ptmx,tty} > /dev/null 2>&1

    print_output ""
    print_output "[*] Currently mounted areas:"
    print_output "$(indent "$(mount | grep "$E_PATH" 2> /dev/null )")""\\n"

  fi
  if ! [[ -d "$LOG_DIR""/qemu_emulator" ]] ; then
    mkdir "$LOG_DIR""/qemu_emulator" 2> /dev/null
  fi
}

emulate_strace_run() {
    echo
    print_output "[*] Initial strace run on the command ${GREEN}$BIN_EMU_NAME / $BIN_EMU${NC} to identify missing areas"

    # currently we only look for file errors (errno=2) and try to fix this
    chroot "$E_PATH" ./"$EMULATOR" --strace "$BIN_EMU" > "$LOG_DIR""/qemu_emulator/stracer_""$BIN_EMU_NAME"".txt" 2>&1 &
    PID=$!

    # wait a second and then kill it
    sleep 1
    kill -0 -9 "$PID" 2> /dev/null

    # extract missing files, exclude *.so files:
    mapfile -t MISSING_AREAS < <(grep -a "open" "$LOG_DIR""/qemu_emulator/stracer_""$BIN_EMU_NAME"".txt" | grep -a "errno=2\ " 2>&1 | cut -d\" -f2 2>&1 | sort -u | grep -v ".*\.so")

    for MISSING_AREA in "${MISSING_AREAS[@]}"; do
      MISSING+=("$MISSING_AREA")
      if [[ "$MISSING_AREA" != */proc/* || "$MISSING_AREA" != */sys/* ]]; then
        print_output "[*] Found missing area: $MISSING_AREA"
  
        FILENAME_MISSING=$(basename "$MISSING_AREA")
        print_output "[*] Trying to create this missing file: $FILENAME_MISSING"
        PATH_MISSING=$(dirname "$MISSING_AREA")

        FILENAME_FOUND=$(find "$E_PATH" -ignore_readdir_race -path "$E_PATH"/sys -prune -false -o -path "$E_PATH"/proc -prune -false -o -type f -name "$FILENAME_MISSING")
        if [[ -n "$FILENAME_FOUND" ]]; then
          print_output "[*] Possible matching file found: $FILENAME_FOUND"
        fi
    
        if [[ ! -d "$E_PATH""$PATH_MISSING" ]]; then
          print_output "[*] Creating directory $E_PATH$PATH_MISSING"
          mkdir -p "$E_PATH""$PATH_MISSING" 2> /dev/null
        fi
        if [[ -n "$FILENAME_FOUND" ]]; then
          print_output "[*] Copy file $FILENAME_FOUND to $E_PATH$PATH_MISSING/"
          cp "$FILENAME_FOUND" "$E_PATH""$PATH_MISSING"/ 2> /dev/null
        else
          print_output "[*] Creating empty file $E_PATH$PATH_MISSING/$FILENAME_MISSING"
          touch "$E_PATH""$PATH_MISSING"/"$FILENAME_MISSING" 2> /dev/null
        fi
      fi
    done
    rm "$LOG_DIR""/qemu_emulator/stracer_""$BIN_EMU_NAME"".txt"
}

check_disk_space() {

  mapfile -t CRITICAL_FILES < <(find "$LOG_DIR"/qemu_emulator/ -type f -size +"$KILL_SIZE" -exec basename {} \; | cut -d\. -f1 | cut -d_ -f2)
  for KILLER in "${CRITICAL_FILES[@]}"; do
    if pgrep -f "$EMULATOR.*$KILLER" > /dev/null; then
      print_output "[!] Qemu processes are wasting disk space ... we try to kill it"
      print_output "[*] Killing process ${ORANGE}$EMULATOR.*$KILLER.*${NC}"
        pkill -f "$EMULATOR.*$KILLER.*"
    fi
  done
}

emulate_binary() {
  BIN_EMU_NAME="$(basename "$LINE")"
  print_output "[*] Binary LINE: $LINE"

  ## as we currently do not have the right path of our binary we have to find it now:
  DIR=$(pwd)
  # if we find multiple binaries with the same name we have to take care of it
  mapfile -t BIN_EMU < <(cd "$EMULATION_PATH_BASE" && find . -ignore_readdir_race -type f -executable -name "$BIN_EMU_NAME" 2>/dev/null && cd "$DIR" || exit)

  # if we find multiple binaries with the same name we have to take care of it
  for BINARY_EMU in "${BIN_EMU[@]}"; do
    print_output "[*] BINARY_EMU: $BINARY_EMU"
    detect_root_dir

    # use every root directory we found for the binary name and try to emulate it
    # possibility for improvement!
    for E_PATH in "${EMULATION_PATH[@]}"; do
      # just use this path if it includes the base path
      if [[ "$E_PATH" == *"$EMULATION_PATH_BASE"* ]]; then
  
        # now we know the root directory and so we can search the file we would like to emulate
        # if we find multiple binaries with the same name we have to care about it ...
        mapfile -t BINS < <(cd "$E_PATH" && find . -ignore_readdir_race -type f -executable -name "$BIN_EMU_NAME" 2>/dev/null | sort -u | head -1 && cd "$DIR" || exit)
  
        prepare_emulator
        for BIN_EMU in "${BINS[@]}"; do
          emulate_strace_run
    
          # emulate binary with different command line parameters:
          if [[ "$BIN_EMU_NAME" == *"bash"* ]]; then
            EMULATION_PARAMS=("--help" "--version")
          else
            EMULATION_PARAMS=("" "-v" "-V" "-h" "-help" "--help" "--version" "version")
          fi
    
          for PARAM in "${EMULATION_PARAMS[@]}"; do
            #print_output "[*] Trying to emulate binary ${GREEN}""$BINARY_EMU""${NC} with parameter ""$PARAM"""
            print_output "[*] Trying to emulate binary ${GREEN}""$BIN_EMU""${NC} with parameter ""$PARAM"""
            print_output "[*] Using root directory: $E_PATH"
            chroot "$E_PATH" ./"$EMULATOR" "$BIN_EMU" "$PARAM" 2>&1 | tee -a "$LOG_DIR""/qemu_emulator/qemu_""$BIN_EMU_NAME"".txt" &
            print_output ""
            check_disk_space
          done
        done
      else
        print_output "[!] We found a path that should not be handled! $E_PATH"
      fi
    done
  
    # now we kill all older qemu-processes:
    # if we use the correct identifier $EMULATOR it will not work ...
    killall --quiet --older-than "$RUNTIME" -r .*qemu.*sta.*
  
    # reset the terminal - after all the uncontrolled emulation it is typically broken!
    reset
  done
}
