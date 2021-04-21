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

# Description:  Emulates executables from the firmware with qemu to get version information. 
#               Currently this is an experimental module and needs to be activated separately via the -E switch. 
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=1

S115_usermode_emulator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Software component and version detection via emulation started"

  if [[ "$QEMULATION" -eq 1 ]]; then

    print_output "[!] This module is experimental and could harm your host environment."
    print_output "[!] This module creates a working copy of the firmware filesystem in the log directory $LOG_DIR.\\n"

    # some processes are running long and logging a lot
    # to protect the host we are going to kill them on a KILL_SIZE limit
    KILL_SIZE="100M"
    # to get rid of all the running stuff we are going to kill it after RUNTIME
    RUNTIME="2m"

    declare -a MISSING
    declare -a MD5_DONE

    ## load blacklist of binaries that could cause troubles during emulation:
    readarray -t BIN_BLACKLIST < "$CONFIG_DIR"/emulation_blacklist.cfg

    # as we modify the firmware area, we copy it to the log directory and do the modifications in this area
    # Note: only for firmware directories - if we have already extracted the firmware we do not copy it again
    copy_firmware

    # we only need to detect the root directory again if we have copied it before
    if [[ -d "$FIRMWARE_PATH_BAK" ]]; then
      detect_root_dir_helper "$EMULATION_PATH_BASE"
    fi

    print_output "[*] Detected ${#ROOT_PATH[@]} root directories:"
    for R_PATH in "${ROOT_PATH[@]}" ; do
      print_output "[*] Detected root path: $R_PATH"
    done

    for R_PATH in "${ROOT_PATH[@]}" ; do
      print_output "[*] Running emulation processes in $R_PATH root path ..."

      DIR=$(pwd)
      mapfile -t BIN_EMU < <(cd "$R_PATH" && find . -xdev -ignore_readdir_race -type f ! -name "*.ko" -exec md5sum {} \; 2>/dev/null | sort -u -k1,1 | cut -d\  -f3 2>/dev/null && cd "$DIR" || exit)

      print_output "[*] Found ${#BIN_EMU[@]} unique executables in root dirctory: $R_PATH."

      for BIN_ in "${BIN_EMU[@]}" ; do
        FULL_BIN_PATH="$R_PATH"/"$BIN_"
        if ( file "$FULL_BIN_PATH" | grep -q ELF ) && [[ "$BIN_" != './qemu-'*'-static' ]]; then
          if ! [[ "${BIN_BLACKLIST[*]}" == *"$(basename "$FULL_BIN_PATH")"* ]]; then
            if ( file "$FULL_BIN_PATH" | grep -q "version\ .\ (FreeBSD)" ) ; then
              # https://superuser.com/questions/1404806/running-a-freebsd-binary-on-linux-using-qemu-user
              print_output "[-] No working emulator found for FreeBSD binary $BIN_"
              EMULATOR="NA"
            elif ( file "$FULL_BIN_PATH" | grep -q "x86-64" ) ; then
              EMULATOR="qemu-x86_64-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "Intel 80386" ) ; then
              EMULATOR="qemu-i386-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "32-bit LSB.*ARM" ) ; then
              EMULATOR="qemu-arm-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "32-bit MSB.*ARM" ) ; then
              EMULATOR="qemu-armeb-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "32-bit LSB.*MIPS" ) ; then
              EMULATOR="qemu-mipsel-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "32-bit MSB.*MIPS" ) ; then
              EMULATOR="qemu-mips-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "32-bit MSB.*PowerPC" ) ; then
              EMULATOR="qemu-ppc-static"
            else
              print_output "[-] No working emulator found for $BIN_"
              EMULATOR="NA"
            fi
    
            if [[ "$EMULATOR" != "NA" ]]; then
              print_output "[*] Emulator used: $ORANGE$EMULATOR$NC"
              prepare_emulator
              emulate_binary
            fi
          else
            print_output "[!] Blacklist triggered ... $BIN_"
          fi
          running_jobs
        fi
      done
    done

    s115_cleanup
    running_jobs
    print_filesystem_fixes
    version_detection

  else
    echo
    print_output "[!] Automated emulation is disabled."
    print_output "[!] Enable it with the -E switch."
  fi

  module_end_log "${FUNCNAME[0]}" "$QEMULATION"
}

print_filesystem_fixes() {
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
    if [[ $THREADING -eq 1 ]]; then
      version_detection_thread &
      WAIT_PIDS_S115+=( "$!" )
    else
      version_detection_thread
    fi
  done < "$CONFIG_DIR"/bin_version_strings.cfg
  echo
  if [[ $THREADED -eq 1 ]]; then
    wait_for_pid "${WAIT_PIDS_S115[@]}"
  fi
}

version_detection_thread() {
    BINARY="$(echo "$VERSION_LINE" | cut -d: -f1)"
    STRICT="$(echo "$VERSION_LINE" | cut -d: -f2)"
    VERSION_IDENTIFIER="$(echo "$VERSION_LINE" | cut -d: -f3- | sed s/^\"// | sed s/\"$//)"
    if [[ -f "$LOG_DIR"/qemu_emulator/qemu_"$BINARY".txt ]]; then
      mapfile -t BINARY_PATHS < <(grep -a "Emulating binary:" "$LOG_DIR"/qemu_emulator/qemu_"$BINARY".txt | cut -d: -f2 | sed -e 's/^\ //' | sort -u 2>/dev/null)
    fi

    # if we have the key strict this version identifier only works for the defined binary and is not generic!
    if [[ $STRICT == "strict" ]]; then
      if [[ -f "$LOG_DIR"/qemu_emulator/qemu_"$BINARY".txt ]]; then
        VERSION_STRICT=$(grep -a -o -E "$VERSION_IDENTIFIER" "$LOG_DIR"/qemu_emulator/qemu_"$BINARY".txt | sort -u | head -1 2>/dev/null)
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
      readarray -t VERSIONS_DETECTED < <(grep -a -o -E "$VERSION_IDENTIFIER" "$LOG_DIR"/qemu_emulator/* 2>/dev/null)
    fi

    if [[ ${#VERSIONS_DETECTED[@]} -ne 0 ]]; then
      for VERSION_DETECTED in "${VERSIONS_DETECTED[@]}"; do
        # if we have multiple detection of the same version details:
        if [ "$VERSION_DETECTED" != "$VERS_DET_OLD" ]; then
          VERS_DET_OLD="$VERSION_DETECTED"
          #VERSIONS_BIN="$(basename "$(echo "$VERSION_DETECTED" | cut -d: -f1)")"
          VERSION_DETECTED="$(echo "$VERSION_DETECTED" | cut -d: -f2-)"
          for BINARY_PATH in "${BINARY_PATHS[@]}"; do
            print_output "[+] Version information found ${RED}""$VERSION_DETECTED""${NC}${GREEN} in binary $ORANGE$(print_path "$BINARY_PATH")$GREEN (emulation)."
          done
        fi
      done
    fi
}

copy_firmware() {
  # we just create a backup if the original firmware path was a root directory
  # if it was a binary file we already have extracted it and it is already messed up
  # so we can mess it up a bit more ;)
  # shellcheck disable=SC2154
  if [[ -d "$FIRMWARE_PATH_BAK" ]]; then
    print_output "[*] Create a firmware backup for emulation ..."
    mkdir "$LOG_DIR""/qemu_emulator" 2>/dev/null
    cp -pri "$FIRMWARE_PATH" "$LOG_DIR"/qemu_emulator/ 2> /dev/null
    EMULATION_DIR=$(basename "$FIRMWARE_PATH")
    EMULATION_PATH_BASE="$LOG_DIR"/qemu_emulator/"$EMULATION_DIR"
    print_output "[*] Firmware backup for emulation created in $EMULATION_PATH_BASE"
  else
    EMULATION_DIR=$(basename "$FIRMWARE_PATH")
    EMULATION_PATH_BASE="$LOG_DIR"/"$EMULATION_DIR"
    print_output "[*] Firmware used for emulation in $EMULATION_PATH_BASE"
  fi
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

s115_cleanup() {
  # reset the terminal - after all the uncontrolled emulation it is typically messed up!
  reset

  # if no emulation at all was possible the $EMULATOR variable is not defined
  if [[ -n "$EMULATOR" ]]; then
    print_output "[*] Terminating qemu processes - check it with ps"
    killall -9 --quiet -r .*qemu.*sta.*
    #mapfile -t CJOBS < <(pgrep -f "$EMULATOR")
    #for PID in "${CJOBS[@]}"; do
    #  print_output "[*] Terminating process ""$PID"
    #  kill "$PID" 2> /dev/null
    #done
  fi

  CJOBS_=$(pgrep qemu-)
  if [[ -n "$CJOBS_" ]] ; then
    print_output "[*] More emulation jobs are running ... we kill it with fire\\n"
    killall -9 "$EMULATOR" 2> /dev/null
  fi

  print_output "[*] Cleaning the emulation environment\\n"
  find "$EMULATION_PATH_BASE" -xdev -iname "qemu*static" -exec rm {} \; 2>/dev/null

  print_output ""
  print_output "[*] Umounting proc, sys and run"
  mapfile -t CHECK_MOUNTS < <(mount | grep "$EMULATION_PATH_BASE")
  for MOUNT in "${CHECK_MOUNTS[@]}"; do
    print_output "[*] Unmounting $MOUNT"
    MOUNT=$(echo "$MOUNT" | cut -d\  -f3)
    umount -l "$MOUNT"
  done

  mapfile -t FILES < <(find "$LOG_DIR""/qemu_emulator/" -xdev -type f -name "qemu_*" 2>/dev/null)
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
  # if we got a firmware directory then we have created a backup for emulation
  # lets delete it now
  if [[ -d "$FIRMWARE_PATH_BAK" ]]; then
    print_output "[*] Remove firmware copy from emulation directory.\\n\\n"
    rm -r "$EMULATION_PATH_BASE"
  fi
}

prepare_emulator() {

  if [[ ! -e "$R_PATH""/""$EMULATOR" ]]; then
    print_output "[*] Preparing the environment for usermode emulation"
    if ! command -v "$EMULATOR" > /dev/null ; then
      echo
      print_output "[!] Is the qemu package installed?"
      print_output "$(indent "We can't find it!")"
      print_output "$(indent "$(red "Terminating emba now.\\n")")"
      exit 1
    else
      cp "$(which $EMULATOR)" "$R_PATH"/
    fi

    if ! [[ -d "$R_PATH""/proc" ]] ; then
      mkdir "$R_PATH""/proc" 2> /dev/null
    fi

    if ! [[ -d "$R_PATH""/sys" ]] ; then
      mkdir "$R_PATH""/sys" 2> /dev/null
    fi

    if ! [[ -d "$R_PATH""/run" ]] ; then
      mkdir "$R_PATH""/run" 2> /dev/null
    fi

    if ! [[ -d "$R_PATH""/dev/" ]] ; then
      mkdir "$R_PATH""/dev/" 2> /dev/null
    fi

    if ! mount | grep "$R_PATH"/proc > /dev/null ; then
      mount proc "$R_PATH""/proc" -t proc 2> /dev/null
    fi
    if ! mount | grep "$R_PATH/run" > /dev/null ; then
      mount -o bind /run "$R_PATH""/run" 2> /dev/null
    fi
    if ! mount | grep "$R_PATH/sys" > /dev/null ; then
      mount -o bind /sys "$R_PATH""/sys" 2> /dev/null
    fi

    if ! [[ -e "$R_PATH""/dev/console" ]] ; then
      mknod -m 622 "$R_PATH""/dev/console" c 5 1 2> /dev/null
    fi

    if ! [[ -e "$R_PATH""/dev/null" ]] ; then
      mknod -m 666 "$R_PATH""/dev/null" c 1 3 2> /dev/null
    fi

    if ! [[ -e "$R_PATH""/dev/zero" ]] ; then
      mknod -m 666 "$R_PATH""/dev/zero" c 1 5 2> /dev/null
    fi

    if ! [[ -e "$R_PATH""/dev/ptmx" ]] ; then
      mknod -m 666 "$R_PATH""/dev/ptmx" c 5 2 2> /dev/null
    fi

    if ! [[ -e "$R_PATH""/dev/tty" ]] ; then
      mknod -m 666 "$R_PATH""/dev/tty" c 5 0 2> /dev/null
    fi

    if ! [[ -e "$R_PATH""/dev/random" ]] ; then
      mknod -m 444 "$R_PATH""/dev/random" c 1 8 2> /dev/null
    fi

    if ! [[ -e "$R_PATH""/dev/urandom" ]] ; then
      mknod -m 444 "$R_PATH""/dev/urandom" c 1 9 2> /dev/null
    fi

    chown -v root:tty "$R_PATH""/dev/"{console,ptmx,tty} > /dev/null 2>&1

    print_output ""
    print_output "[*] Currently mounted areas:"
    print_output "$(indent "$(mount | grep "$R_PATH" 2> /dev/null )")""\\n"

  fi
  if ! [[ -d "$LOG_DIR""/qemu_emulator" ]] ; then
    mkdir "$LOG_DIR""/qemu_emulator" 2> /dev/null
  fi
}

emulate_strace_run() {
    echo
    print_output "[*] Initial strace run on the command ${GREEN}$BIN_${NC} to identify missing areas"

    # currently we only look for file errors (errno=2) and try to fix this
    chroot "$R_PATH" ./"$EMULATOR" --strace "$BIN_" > "$LOG_DIR""/qemu_emulator/stracer_""$BIN_EMU_NAME"".txt" 2>&1 &
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

        FILENAME_FOUND=$(find "$R_PATH" -xdev -ignore_readdir_race -path "$R_PATH"/sys -prune -false -o -path "$R_PATH"/proc -prune -false -o -type f -name "$FILENAME_MISSING" 2>/dev/null)
        if [[ -n "$FILENAME_FOUND" ]]; then
          print_output "[*] Possible matching file found: $FILENAME_FOUND"
        fi
    
        if [[ ! -d "$R_PATH""$PATH_MISSING" ]]; then
          print_output "[*] Creating directory $R_PATH$PATH_MISSING"
          mkdir -p "$R_PATH""$PATH_MISSING" 2> /dev/null
        fi
        if [[ -n "$FILENAME_FOUND" ]]; then
          print_output "[*] Copy file $FILENAME_FOUND to $R_PATH$PATH_MISSING/"
          cp "$FILENAME_FOUND" "$R_PATH""$PATH_MISSING"/ 2> /dev/null
        else
          print_output "[*] Creating empty file $R_PATH$PATH_MISSING/$FILENAME_MISSING"
          touch "$R_PATH""$PATH_MISSING"/"$FILENAME_MISSING" 2> /dev/null
        fi
      fi
    done
    rm "$LOG_DIR""/qemu_emulator/stracer_""$BIN_EMU_NAME"".txt"
}

check_disk_space() {

  mapfile -t CRITICAL_FILES < <(find "$LOG_DIR"/qemu_emulator/ -xdev -type f -size +"$KILL_SIZE" -exec basename {} \; 2>/dev/null| cut -d\. -f1 | cut -d_ -f2)
  for KILLER in "${CRITICAL_FILES[@]}"; do
    if pgrep -f "$EMULATOR.*$KILLER" > /dev/null; then
      print_output "[!] Qemu processes are wasting disk space ... we try to kill it"
      print_output "[*] Killing process ${ORANGE}$EMULATOR.*$KILLER.*${NC}"
      pkill -f "$EMULATOR.*$KILLER.*"
    fi
  done
}

emulate_binary() {
  print_output ""
  print_output "[*] Emulating binary: $ORANGE$BIN_$NC"
  print_output "[*] Using root directory: $ORANGE$R_PATH$NC"
  BIN_EMU_NAME=$(basename "$FULL_BIN_PATH")
  echo -e "[*] Emulating binary: $FULL_BIN_PATH" >> "$LOG_DIR""/qemu_emulator/qemu_""$BIN_EMU_NAME"".txt"
  echo -e "[*] Emulating binary name: $BIN_EMU_NAME" >> "$LOG_DIR""/qemu_emulator/qemu_""$BIN_EMU_NAME"".txt"

  # we check every binary only once. So calculate the checksum and store it for checking
  BIN_MD5=$(md5sum "$FULL_BIN_PATH" | cut -d\  -f1)
  if [[ ! " ${MD5_DONE[*]} " =~ ${BIN_MD5} ]]; then
    # letz assume we now have only ELF files. Sometimes the permissions of firmware updates are completely weird
    # we are going to give all ELF files exec permissions to execute it in the emulator
    if ! [[ -x "$FULL_BIN_PATH" ]]; then
      print_output "[*] Change permissions +x to $FULL_BIN_PATH"
      chmod +x "$FULL_BIN_PATH"
    fi
    emulate_strace_run
  
    # emulate binary with different command line parameters:
    if [[ "$BIN_" == *"bash"* ]]; then
      EMULATION_PARAMS=("--help" "--version")
    else
      EMULATION_PARAMS=("" "-v" "-V" "-h" "-help" "--help" "--version" "version")
    fi
  
    for PARAM in "${EMULATION_PARAMS[@]}"; do
      print_output "[*] Trying to emulate binary ${GREEN}""$BIN_""${NC} with parameter ""$PARAM"
      echo -e "[*] Trying to emulate binary $BIN_ with parameter $PARAM" >> "$LOG_DIR""/qemu_emulator/qemu_""$BIN_EMU_NAME"".txt"
      chroot "$R_PATH" ./"$EMULATOR" "$BIN_" "$PARAM" 2>&1 | tee -a "$LOG_DIR""/qemu_emulator/qemu_""$BIN_EMU_NAME"".txt" &
      print_output ""
      check_disk_space
    done
    MD5_DONE+=( "$BIN_MD5" )
  else
    print_output "[*] Binary $BIN_ was already tested."
  fi
  
  # now we kill all older qemu-processes:
  # if we use the correct identifier $EMULATOR it will not work ...
  killall -9 --quiet --older-than "$RUNTIME" -r .*qemu.*sta.*
  
  # reset the terminal - after all the uncontrolled emulation it is typically broken!
  reset
}
