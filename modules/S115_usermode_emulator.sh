#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Emulates executables from the firmware with qemu to get version information. 
#               Currently this is an experimental module and needs to be activated separately via the -E switch. 
#               It is also recommended to only use this technique in a dockerized or virtualized environment.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=1

S115_usermode_emulator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Usermode emulation"
  pre_module_reporter "${FUNCNAME[0]}"

  if [[ "$QEMULATION" -eq 1 && "$RTOS" -eq 0 ]]; then

    if [[ $IN_DOCKER -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi
    EMULATOR="NA"

    print_output "[*] This module creates a working copy of the firmware filesystem in the log directory $LOG_DIR.\\n"
    # get the local interface ip address for later verification
    # ensure that the emulator does not reconfigure the interface
    get_local_ip

    # some processes are running long and logging a lot
    # to protect the host we are going to kill them on a KILL_SIZE limit
    KILL_SIZE="50M"

    #declare -a MISSING
    export MISSING=()
    ROOT_CNT=0

    # load blacklist of binaries that could cause troubles during emulation:
    readarray -t BIN_BLACKLIST < "$CONFIG_DIR"/emulation_blacklist.cfg

    # as we modify the firmware area, we copy it to the log directory and do the modifications in this area
    # Note: only for firmware directories - if we have already extracted the firmware we do not copy it again
    copy_firmware

    # we only need to detect the root directory again if we have copied it before
    if [[ -d "$FIRMWARE_PATH_BAK" ]]; then
      detect_root_dir_helper "$EMULATION_PATH_BASE" "$LOG_FILE"
    fi
    kill_qemu_threader &
    PID_killer+="$!"

    print_output "[*] Detected $ORANGE${#ROOT_PATH[@]}$NC root directories:"
    for R_PATH in "${ROOT_PATH[@]}" ; do
      print_output "[*] Detected root path: $ORANGE$R_PATH$NC"
      # MD5_DONE_INT is the array of all MD5 checksums for all root paths -> this is needed to ensure that we do not test bins twice
      MD5_DONE_INT=()
      BIN_CNT=0
      ((ROOT_CNT=ROOT_CNT+1))
      print_output "[*] Running emulation processes in $ORANGE$R_PATH$NC root path ($ORANGE$ROOT_CNT/${#ROOT_PATH[@]}$NC)."

      DIR=$(pwd)
      mapfile -t BIN_EMU_TMP < <(cd "$R_PATH" && find . -xdev -ignore_readdir_race -type f ! \( -name "*.ko" -o -name "*.so" \) -exec file {} \; 2>/dev/null | grep "ELF.*executable\|ELF.*shared\ object" | grep -v "version\ .\ (FreeBSD)" | cut -d: -f1 2>/dev/null && cd "$DIR" || exit)
      # we re-create the BIN_EMU array with all unique binaries for every root directory
      # as we have all tested MD5s in MD5_DONE_INT (for all root dirs) we test every bin only once
      BIN_EMU=()

      print_output "[*] Create unique binary array for $ORANGE$R_PATH$NC root path ($ORANGE$ROOT_CNT/${#ROOT_PATH[@]}$NC)."

      for BINARY in "${BIN_EMU_TMP[@]}"; do
        # we emulate every binary only once. So calculate the checksum and store it for checking
        BIN_MD5_=$(md5sum "$R_PATH"/"$BINARY" | cut -d\  -f1)
        if [[ ! " ${MD5_DONE_INT[*]} " =~ ${BIN_MD5_} ]]; then
          BIN_EMU+=( "$BINARY" )
          MD5_DONE_INT+=( "$BIN_MD5_" )
        fi
      done

      print_output "[*] Testing $ORANGE${#BIN_EMU[@]}$NC unique executables in root dirctory: $ORANGE$R_PATH$NC ($ORANGE$ROOT_CNT/${#ROOT_PATH[@]}$NC)."

      for BIN_ in "${BIN_EMU[@]}" ; do
        ((BIN_CNT=BIN_CNT+1))
        FULL_BIN_PATH="$R_PATH"/"$BIN_"

        local BIN_EMU_NAME_
        BIN_EMU_NAME_=$(basename "$FULL_BIN_PATH")

        THOLD=$(( 25*"$ROOT_CNT" ))
        # if we have already a log file with a lot of content we assume this binary was already emulated correct
        if [[ $(sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" "$LOG_DIR"/s115_usermode_emulator/qemu_init_"$BIN_EMU_NAME_".txt 2>/dev/null | grep -c -v -E "\[\*\]\ " || true) -gt "$THOLD" ]]; then
          print_output "[!] BIN $BIN_EMU_NAME_ was already emulated ... skipping"
          continue
        fi

        if [[ "${BIN_BLACKLIST[*]}" == *"$(basename "$FULL_BIN_PATH")"* ]]; then
          print_output "[!] Blacklist triggered ... $ORANGE$BIN_$NC ($ORANGE$BIN_CNT/${#BIN_EMU[@]}$NC)"
          continue
        else
          if [[ "$THREADED" -eq 1 ]]; then
            # we adjust the max threads regularly. S115 respects the consumption of S09 and adjusts the threads
            MAX_THREADS_S115=$((7*"$(grep -c ^processor /proc/cpuinfo || true)"))
            if [[ $(grep -c S09_ "$LOG_DIR"/"$MAIN_LOG_FILE" || true) -eq 1 ]]; then
              # if only one result for S09_ is found in emba.log means the S09 module is started and currently running
              MAX_THREADS_S115=$((3*"$(grep -c ^processor /proc/cpuinfo || true)"))
            fi
          fi
          if [[ "$BIN_" != './qemu-'*'-static' ]]; then
            if ( file "$FULL_BIN_PATH" | grep -q "version\ .\ (FreeBSD)" ) ; then
              # https://superuser.com/questions/1404806/running-a-freebsd-binary-on-linux-using-qemu-user
              print_output "[-] No working emulator found for FreeBSD binary $ORANGE$BIN_$NC."
              EMULATOR="NA"
              continue
            elif ( file "$FULL_BIN_PATH" | grep -q "x86-64" ) ; then
              EMULATOR="qemu-x86_64-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "Intel 80386" ) ; then
              EMULATOR="qemu-i386-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "32-bit LSB.*ARM" ) ; then
              EMULATOR="qemu-arm-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "32-bit MSB.*ARM" ) ; then
              EMULATOR="qemu-armeb-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "64-bit LSB.*ARM aarch64" ) ; then
              EMULATOR="qemu-aarch64-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "64-bit MSB.*ARM aarch64" ) ; then
              EMULATOR="qemu-aarch64_be-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "32-bit LSB.*MIPS" ) ; then
              EMULATOR="qemu-mipsel-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "32-bit MSB.*MIPS" ) ; then
              EMULATOR="qemu-mips-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "64-bit LSB.*MIPS" ) ; then
              EMULATOR="qemu-mips64el-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "64-bit MSB.*MIPS" ) ; then
              EMULATOR="qemu-mips64-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "32-bit MSB.*PowerPC" ) ; then
              EMULATOR="qemu-ppc-static"
            elif ( file "$FULL_BIN_PATH" | grep -q "64-bit MSB.*PowerPC" ) ; then
              EMULATOR="qemu-ppc64-static"
            else
              print_output "[-] No working emulator found for $BIN_"
              EMULATOR="NA"
              continue
            fi

            if [[ "$EMULATOR" != "NA" ]]; then
              prepare_emulator
              if [[ "$THREADED" -eq 1 ]]; then
                emulate_binary &
                WAIT_PIDS_S115_x+=( "$!" )
                max_pids_protection "$MAX_THREADS_S115" "${WAIT_PIDS_S115_x[@]}"
              else
                emulate_binary
              fi
            fi
          fi
          running_jobs
        fi
      done
    done

    if [[ "$THREADED" -eq 1 ]]; then
      wait_for_pid "${WAIT_PIDS_S115_x[@]}"
    fi

    s115_cleanup
    running_jobs
    print_filesystem_fixes
    recover_local_ip "$IP_ETH0"

  else
    print_output ""
    print_output "[!] Automated emulation is disabled."
    print_output "[!] Enable it with the $ORANGE-E$MAGENTA switch.$NC"
  fi

  module_end_log "${FUNCNAME[0]}" "$QEMULATION"
}

get_local_ip() {
  IP_ETH0=$(ifconfig eth0 2>/dev/null|awk '/inet / {print $2}')
}

recover_local_ip() {
  # some firmware images (e.g. OpenWRT) reconfigure the network interface.
  # We try to recover it now to access the CVE database
  local IP_TO_CHECK_="$1"

  if ! ifconfig eth0 | grep -q "$IP_TO_CHECK_"; then
    print_output "[!] Warning: The emulation process of S115 has reconfigured your network interface."
    print_output "[*] We try to recover the interface eth0 with address $IP_TO_CHECK_"
    ifconfig eth0 "$IP_TO_CHECK_" up
  fi
}

print_filesystem_fixes() {
  if [[ "${#MISSING[@]}" -ne 0 ]]; then
    sub_module_title "Filesystem fixes"
    print_output "[*] Emba has auto-generated the files during runtime."
    print_output "[*] For persistence you could generate it manually in your filesystem.\\n"
    for MISSING_FILE in "${MISSING[@]}"; do
      print_output "[*] Missing file: $ORANGE$MISSING_FILE$NC"
    done
  fi
}

copy_firmware() {
  EMULATION_PATH_BASE="$LOG_DIR"/firmware
  # we just create a backup if the original firmware path was a root directory
  # if it was a binary file we already have extracted it and it is already messed up
  # so we can mess it up a bit more ;)
  # shellcheck disable=SC2154
  if [[ -d "$FIRMWARE_PATH_BAK" ]]; then
    print_output "[*] Create a firmware backup for emulation ..."
    cp -pri "$FIRMWARE_PATH" "$LOG_PATH_MODULE"/ 2> /dev/null
    EMULATION_DIR=$(basename "$FIRMWARE_PATH")
    EMULATION_PATH_BASE="$LOG_PATH_MODULE"/"$EMULATION_DIR"
    print_output "[*] Firmware backup for emulation created in $ORANGE$EMULATION_PATH_BASE$NC"
  else
    EMULATION_DIR=$(basename "$FIRMWARE_PATH")
    EMULATION_PATH_BASE="$LOG_DIR"/"$EMULATION_DIR"
    print_output "[*] Firmware used for emulation in $ORANGE$EMULATION_PATH_BASE$NC"
  fi
}

running_jobs() {
  # if no emulation at all was possible the $EMULATOR variable is not defined
  if [[ -n "$EMULATOR" ]]; then
    CJOBS=$(pgrep -a "$EMULATOR" || true)
    if [[ -n "$CJOBS" ]] ; then
      echo
      print_output "[*] Currently running emulation jobs: $(echo "$CJOBS" | wc -l)"
      print_output "$(indent "$CJOBS")""\\n"
    else
      CJOBS="NA"
    fi
  fi
  # sometimes it is quite hard to get rid of all the qemu processes:
}

kill_qemu_threader() {
  while true; do
    pkill -9 -O 240 -f .*qemu.* || true
    sleep 20
  done
}

s115_cleanup() {
  print_output ""
  sub_module_title "Cleanup phase"
  CHECK_MOUNTS=()

  # reset the terminal - after all the uncontrolled emulation it is typically messed up!
  reset

  rm "$LOG_PATH_MODULE""/stracer_*.txt" 2>/dev/null || true

  # if no emulation at all was possible the $EMULATOR variable is not defined
  if [[ -n "$EMULATOR" ]]; then
    print_output "[*] Terminating qemu processes - check it with ps"
    killall -9 --quiet -r .*qemu.*sta.* || true
  fi

  CJOBS_=$(pgrep qemu- || true)
  if [[ -n "$CJOBS_" ]] ; then
    print_output "[*] More emulation jobs are running ... we kill it with fire\\n"
    killall -9 "$EMULATOR" 2> /dev/null || true
  fi
  kill "$PID_killer" || true

  print_output "[*] Cleaning the emulation environment\\n"
  find "$EMULATION_PATH_BASE" -xdev -iname "qemu*static" -exec rm {} \; 2>/dev/null || true

  print_output ""
  print_output "[*] Umounting proc, sys and run"
  mapfile -t CHECK_MOUNTS < <(mount | grep "$EMULATION_PATH_BASE")
  if [[ -v CHECK_MOUNTS[@] ]]; then
    for MOUNT in "${CHECK_MOUNTS[@]}"; do
      print_output "[*] Unmounting $MOUNT"
      MOUNT=$(echo "$MOUNT" | cut -d\  -f3)
      umount -l "$MOUNT" || true
    done
  fi

  mapfile -t FILES < <(find "$LOG_PATH_MODULE""/" -xdev -type f -name "qemu_tmp*" 2>/dev/null)
  if [[ "${#FILES[@]}" -gt 0 ]] ; then
    print_output "[*] Cleanup empty log files.\\n"
    print_bar
    sub_module_title "Reporting phase"
    for FILE in "${FILES[@]}" ; do
      if [[ ! -s "$FILE" ]] ; then
        rm "$FILE" 2> /dev/null || true
      else
        BIN=$(basename "$FILE")
        BIN=$(echo "$BIN" | cut -d_ -f3 | sed 's/.txt$//')
        print_output "[+]""${NC}"" Emulated binary ""${GREEN}""$BIN""${NC}"" generated output in ""${GREEN}""$FILE""${NC}""." "" "$FILE"
      fi
    done
  fi
  # if we got a firmware directory then we have created a backup for emulation
  # lets delete it now
  if [[ -d "$FIRMWARE_PATH_BAK" ]]; then
    print_output "[*] Remove firmware copy from emulation directory.\\n\\n"
    rm -r "$EMULATION_PATH_BASE" || true
  fi
}

prepare_emulator() {

  if [[ ! -e "$R_PATH""/""$EMULATOR" ]]; then

    sub_module_title "Preparation phase"

    print_output "[*] Preparing the environment for usermode emulation"
    if ! command -v "$EMULATOR" > /dev/null ; then
      echo
      print_output "[!] Is the qemu package installed?"
      print_output "$(indent "We can't find it!")"
      print_output "$(indent "$(red "Terminating EMBA now.\\n")")"
      exit 1
    else
      cp "$(which $EMULATOR)" "$R_PATH"/
    fi

    if ! [[ -d "$R_PATH""/proc" ]] ; then
      mkdir "$R_PATH""/proc" 2> /dev/null || true
    fi

    if ! [[ -d "$R_PATH""/sys" ]] ; then
      mkdir "$R_PATH""/sys" 2> /dev/null || true
    fi

    if ! [[ -d "$R_PATH""/run" ]] ; then
      mkdir "$R_PATH""/run" 2> /dev/null || true
    fi

    if ! [[ -d "$R_PATH""/dev/" ]] ; then
      mkdir "$R_PATH""/dev/" 2> /dev/null || true
    fi

    if ! mount | grep "$R_PATH"/proc > /dev/null ; then
      mount proc "$R_PATH""/proc" -t proc 2> /dev/null || true
    fi
    if ! mount | grep "$R_PATH/run" > /dev/null ; then
      mount -o bind /run "$R_PATH""/run" 2> /dev/null || true
    fi
    if ! mount | grep "$R_PATH/sys" > /dev/null ; then
      mount -o bind /sys "$R_PATH""/sys" 2> /dev/null || true
    fi

    creating_dev_area

    print_output ""
    print_output "[*] Currently mounted areas:"
    print_output "$(indent "$(mount | grep "$R_PATH" 2> /dev/null )")""\\n"

    # we disable core dumps in our docker environment. If running on the host without docker
    # the user is responsible for useful settings
    if [[ $IN_DOCKER -eq 1 ]] ; then
      print_output ""
      print_output "[*] We disable core dumps to prevent wasting our disk space."
      ulimit -c 0
    fi

    print_output "[*] Final fixes of the root filesytem in a chroot environment"
    cp ./helpers/fixImage_user_mode_emulation.sh "$R_PATH"/
    chmod +x "$R_PATH"/fixImage_user_mode_emulation.sh
    cp "$(which busybox)" "$R_PATH"/
    chmod +x "$R_PATH"/busybox
    chroot "$R_PATH" /busybox ash /fixImage_user_mode_emulation.sh | tee -a "$LOG_PATH_MODULE"/chroot_fixes.txt
    rm "$R_PATH"/fixImage_user_mode_emulation.sh || true
    rm "$R_PATH"/busybox || true
    print_bar
  fi
}

creating_dev_area() {
  print_output "[*] Creating dev area for user mode emulation"

  if ! [[ -e "$R_PATH""/dev/console" ]] ; then
    print_output "[*] Creating /dev/console"
    mknod -m 622 "$R_PATH""/dev/console" c 5 1 2> /dev/null || true
  fi

  if ! [[ -e "$R_PATH""/dev/null" ]] ; then
    print_output "[*] Creating /dev/null"
    mknod -m 666 "$R_PATH""/dev/null" c 1 3 2> /dev/null || true
  fi

  if ! [[ -e "$R_PATH""/dev/zero" ]] ; then
    print_output "[*] Creating /dev/zero"
    mknod -m 666 "$R_PATH""/dev/zero" c 1 5 2> /dev/null || true
  fi

  if ! [[ -e "$R_PATH""/dev/ptmx" ]] ; then
    print_output "[*] Creating /dev/ptmx"
    mknod -m 666 "$R_PATH""/dev/ptmx" c 5 2 2> /dev/null || true
  fi

  if ! [[ -e "$R_PATH""/dev/tty" ]] ; then
    print_output "[*] Creating /dev/tty"
    mknod -m 666 "$R_PATH""/dev/tty" c 5 0 2> /dev/null || true
  fi

  if ! [[ -e "$R_PATH""/dev/random" ]] ; then
    print_output "[*] Creating /dev/random"
    mknod -m 444 "$R_PATH""/dev/random" c 1 8 2> /dev/null || true
  fi

  if ! [[ -e "$R_PATH""/dev/urandom" ]] ; then
    print_output "[*] Creating /dev/urandom"
    mknod -m 444 "$R_PATH""/dev/urandom" c 1 9 2> /dev/null || true
  fi

  if ! [[ -e "$R_PATH""/dev/mem" ]] ; then
    print_output "[*] Creating /dev/mem"
    mknod -m 660 "$R_PATH"/dev/mem c 1 1 2> /dev/null || true
  fi
  if ! [[ -e "$R_PATH""/dev/kmem" ]] ; then
    print_output "[*] Creating /dev/kmem"
    mknod -m 640 "$R_PATH"/dev/kmem c 1 2 2> /dev/null || true
  fi
  if ! [[ -e "$R_PATH""/dev/armem" ]] ; then
    print_output "[*] Creating /dev/armem"
    mknod -m 666 "$R_PATH"/dev/armem c 1 13 2> /dev/null || true
  fi
  
  if ! [[ -e "$R_PATH""/dev/tty0" ]] ; then
    print_output "[*] Creating /dev/tty0"
    mknod -m 622 "$R_PATH"/dev/tty0 c 4 0 2> /dev/null || true
  fi
  if ! [[ -e "$R_PATH""/dev/ttyS0" ]] ; then
    print_output "[*] Creating /dev/ttyS0 - ttyS3"
    mknod -m 660 "$R_PATH"/dev/ttyS0 c 4 64 2> /dev/null || true
    mknod -m 660 "$R_PATH"/dev/ttyS1 c 4 65 2> /dev/null || true
    mknod -m 660 "$R_PATH"/dev/ttyS2 c 4 66 2> /dev/null || true
    mknod -m 660 "$R_PATH"/dev/ttyS3 c 4 67 2> /dev/null || true
  fi

  if ! [[ -e "$R_PATH""/dev/adsl0" ]] ; then
    print_output "[*] Creating /dev/adsl0"
    mknod -m 644 "$R_PATH"/dev/adsl0 c 100 0 2> /dev/null || true
  fi
  if ! [[ -e "$R_PATH""/dev/ppp" ]] ; then
    print_output "[*] Creating /dev/ppp"
    mknod -m 644 "$R_PATH"/dev/ppp c 108 0 2> /dev/null || true
  fi
  if ! [[ -e "$R_PATH""/dev/hidraw0" ]] ; then
    print_output "[*] Creating /dev/hidraw0"
    mknod -m 666 "$R_PATH"/dev/hidraw0 c 251 0 2> /dev/null || true
  fi

  if ! [[ -d "$R_PATH"/dev/mtd ]]; then
    print_output "[*] Creating and populating /dev/mtd"
    mkdir -p "$R_PATH"/dev/mtd 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/0 c 90 0 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/1 c 90 2 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/2 c 90 4 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/3 c 90 6 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/4 c 90 8 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/5 c 90 10 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/6 c 90 12 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/7 c 90 14 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/8 c 90 16 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/9 c 90 18 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtd/10 c 90 20 2> /dev/null || true
  fi

  mknod -m 644 "$R_PATH"/dev/mtd0 c 90 0 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr0 c 90 1 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtd1 c 90 2 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr1 c 90 3 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtd2 c 90 4 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr2 c 90 5 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtd3 c 90 6 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr3 c 90 7 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtd4 c 90 8 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr4 c 90 9 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtd5 c 90 10 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr5 c 90 11 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtd6 c 90 12 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr6 c 90 13 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtd7 c 90 14 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr7 c 90 15 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtd8 c 90 16 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr8 c 90 17 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtd9 c 90 18 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr9 c 90 19 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtd10 c 90 20 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdr10 c 90 21 2> /dev/null || true

  if ! [[ -d "$R_PATH"/dev/mtdblock ]]; then
    print_output "[*] Creating and populating /dev/mtdblock"
    mkdir -p "$R_PATH"/dev/mtdblock 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/0 b 31 0 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/1 b 31 1 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/2 b 31 2 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/3 b 31 3 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/4 b 31 4 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/5 b 31 5 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/6 b 31 6 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/7 b 31 7 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/8 b 31 8 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/9 b 31 9 2> /dev/null || true
    mknod -m 644 "$R_PATH"/dev/mtdblock/10 b 31 10 2> /dev/null || true
  fi

  mknod -m 644 "$R_PATH"/dev/mtdblock0 b 31 0 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdblock1 b 31 1 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdblock2 b 31 2 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdblock3 b 31 3 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdblock4 b 31 4 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdblock5 b 31 5 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdblock6 b 31 6 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdblock7 b 31 7 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdblock8 b 31 8 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdblock9 b 31 9 2> /dev/null || true
  mknod -m 644 "$R_PATH"/dev/mtdblock10 b 31 10 2> /dev/null || true

  if ! [[ -d "$R_PATH"/dev/tts ]]; then
    print_output "[*] Creating and populating /dev/tts"
    mkdir -p "$R_PATH"/dev/tts 2> /dev/null || true
    mknod -m 660 "$R_PATH"/dev/tts/0 c 4 64 2> /dev/null || true
    mknod -m 660 "$R_PATH"/dev/tts/1 c 4 65 2> /dev/null || true
    mknod -m 660 "$R_PATH"/dev/tts/2 c 4 66 2> /dev/null || true
    mknod -m 660 "$R_PATH"/dev/tts/3 c 4 67 2> /dev/null || true
  fi

  chown -v root:tty "$R_PATH""/dev/"{console,ptmx,tty} > /dev/null 2>&1 || true
}

run_init_test() {

  local BIN_EMU_NAME_
  BIN_EMU_NAME_=$(basename "$FULL_BIN_PATH")
  local LOG_FILE_INIT
  LOG_FILE_INIT="$LOG_PATH_MODULE""/qemu_init_""$BIN_EMU_NAME_"".txt"
  local CPU_CONFIG_
  CPU_CONFIG_=""
  # get the most used cpu configuration for the initial check:
  if [[ -f "$LOG_PATH_MODULE""/qemu_init_cpu.txt" ]]; then
    CPU_CONFIG_=$(grep -a CPU_CONFIG "$LOG_PATH_MODULE""/qemu_init_cpu.txt" | cut -d\; -f2 | uniq -c | sort -nr | head -1 | awk '{print $2}' || true)
  fi

  print_output "[*] Initial emulation process of binary $ORANGE$BIN_EMU_NAME_$NC with CPU configuration $ORANGE$CPU_CONFIG_$NC." "$LOG_FILE_INIT" "$LOG_FILE_INIT"

  run_init_qemu "$CPU_CONFIG_" "$BIN_EMU_NAME_" "$LOG_FILE_INIT"

  if [[ ! -f "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" || $(grep -a -c "Illegal instruction\|cpu_init.*failed" "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" 2> /dev/null) -gt 0 || $(wc -l "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" | awk '{print $1}') -lt 6 ]]; then

    write_log "[-] Emulation process of binary $ORANGE$BIN_EMU_NAME_$NC with CPU configuration $ORANGE$CPU_CONFIG_$NC failed" "$LOG_FILE_INIT"

    mapfile -t CPU_CONFIGS < <(chroot "$R_PATH" ./"$EMULATOR" -cpu help | grep -v alias | awk '{print $2}' | tr -d "'" || true)

    for CPU_CONFIG_ in "${CPU_CONFIGS[@]}"; do
      if [[ -f "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" ]]; then
        rm "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" || true
      fi

      run_init_qemu "$CPU_CONFIG_" "$BIN_EMU_NAME_" "$LOG_FILE_INIT"

      if [[ -z "$CPU_CONFIG_" ]]; then
        CPU_CONFIG_="NONE"
      fi

      if [[ ! -f "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" || $(grep -a -c "Illegal instruction\|cpu_init.*failed" "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" 2> /dev/null) -gt 0 || $(wc -l "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" | awk '{print $1}') -lt 6 ]]; then
        write_log "[-] Emulation process of binary $ORANGE$BIN_EMU_NAME_$NC with CPU configuration $ORANGE$CPU_CONFIG_$NC failed" "$LOG_FILE_INIT"
        continue
      fi

      write_log "[+] CPU configuration used for $ORANGE$BIN_EMU_NAME_$GREEN: $ORANGE$CPU_CONFIG_$GREEN" "$LOG_FILE_INIT"
      write_log "CPU_CONFIG_det\;$CPU_CONFIG_" "$LOG_PATH_MODULE""/qemu_init_cpu.txt"
      write_log "CPU_CONFIG_det\;$CPU_CONFIG_" "$LOG_FILE_INIT"
      break

    done
  else
    if [[ -z "$CPU_CONFIG_" ]]; then
      CPU_CONFIG_="NONE"
    fi

    write_log "[+] CPU configuration used for $ORANGE$BIN_EMU_NAME_$GREEN: $ORANGE$CPU_CONFIG_$GREEN" "$LOG_FILE_INIT"
    write_log "CPU_CONFIG_det\;$CPU_CONFIG_" "$LOG_PATH_MODULE""/qemu_init_cpu.txt"
    write_log "CPU_CONFIG_det\;$CPU_CONFIG_" "$LOG_FILE_INIT"
  fi

  # fallback solution - we use the most working configuration:
  if ! grep -q "CPU_CONFIG_det" "$LOG_PATH_MODULE""/qemu_init_cpu.txt"; then
    CPU_CONFIG_=$(grep -a CPU_CONFIG "$LOG_PATH_MODULE""/qemu_init_cpu.txt" | cut -d\; -f2 | uniq -c | sort -nr | head -1 | awk '{print $2}' || true)
    write_log "[+] CPU configuration used for $ORANGE$BIN_EMU_NAME_$GREEN: $ORANGE$CPU_CONFIG_$GREEN" "$LOG_FILE_INIT"
    write_log "CPU_CONFIG_det\;$CPU_CONFIG_" "$LOG_PATH_MODULE""/qemu_init_cpu.txt"
    write_log "CPU_CONFIG_det\;$CPU_CONFIG_" "$LOG_FILE_INIT"
    write_log "[*] Fallback to most found CPU configuration" "$LOG_FILE_INIT"
  fi
}

run_init_qemu() {

  local CPU_CONFIG_="${1:-}"
  local BIN_EMU_NAME_="${2:-}"
  local LOG_FILE_INIT="${3:-}"

  # Enable the following echo output for debugging
  echo "BIN: $BIN_" | tee -a "$LOG_FILE_INIT"
  echo "EMULATOR: $EMULATOR" | tee -a "$LOG_FILE_INIT"
  echo "R_PATH: $R_PATH" | tee -a "$LOG_FILE_INIT"
  echo "CPU_CONFIG: $CPU_CONFIG_" | tee -a "$LOG_FILE_INIT"

  if [[ "$STRICT_MODE" -eq 1 ]]; then
    set +e
  fi
  run_init_qemu_runner "$CPU_CONFIG_" "$BIN_EMU_NAME_" "$LOG_FILE_INIT" &
  PID=$!
  if [[ "$STRICT_MODE" -eq 1 ]]; then
    set -e
  fi

  # wait a bit and then kill it
  sleep 1
  kill -0 -9 "$PID" 2> /dev/null || true
  if [[ -f "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" ]]; then
    cat "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" >> "$LOG_FILE_INIT"
  fi

}

run_init_qemu_runner() {

  local CPU_CONFIG_="$1"
  local BIN_EMU_NAME_="$2"
  local LOG_FILE_INIT="$3"

  if [[ -z "$CPU_CONFIG_" || "$CPU_CONFIG_" == "NONE" ]]; then
    write_log "[*] Trying to emulate binary $ORANGE$BIN_$NC with cpu config ${ORANGE}NONE$NC" "$LOG_FILE_INIT"
    timeout --preserve-status --signal SIGINT 2 chroot "$R_PATH" ./"$EMULATOR" --strace "$BIN_" >> "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" 2>&1 || true
  else
    write_log "[*] Trying to emulate binary $ORANGE$BIN_$NC with cpu config $ORANGE$CPU_CONFIG_$NC" "$LOG_FILE_INIT"
    timeout --preserve-status --signal SIGINT 2 chroot "$R_PATH" ./"$EMULATOR" --strace -cpu "$CPU_CONFIG_" "$BIN_" >> "$LOG_PATH_MODULE""/qemu_initx_""$BIN_EMU_NAME_"".txt" 2>&1 || true
  fi
}

emulate_strace_run() {
  local CPU_CONFIG_="$1"
  LOG_FILE_STRACER="$LOG_PATH_MODULE""/stracer_""$BIN_EMU_NAME"".txt"

  print_output "[*] Initial strace run on the command ${ORANGE}$BIN_${NC} to identify missing areas" "$LOG_FILE_STRACER" "$LOG_FILE_STRACER"

  # currently we only look for file errors (errno=2) and try to fix this
  if [[ "$STRICT_MODE" -eq 1 ]]; then
    set +e
  fi
  if [[ -z "$CPU_CONFIG_" || "$CPU_CONFIG_" == *"NONE"* ]]; then
    timeout --preserve-status --signal SIGINT 2 chroot "$R_PATH" ./"$EMULATOR" --strace "$BIN_" > "$LOG_FILE_STRACER" 2>&1 &
    PID=$!
  else
    timeout --preserve-status --signal SIGINT 2 chroot "$R_PATH" ./"$EMULATOR" -cpu "$CPU_CONFIG_" --strace "$BIN_" > "$LOG_FILE_STRACER" 2>&1 &
    PID=$!
  fi
  if [[ "$STRICT_MODE" -eq 1 ]]; then
    set -e
  fi

  # wait a second and then kill it
  sleep 1
  kill -0 -9 "$PID" 2> /dev/null || true

  # extract missing files, exclude *.so files:
  mapfile -t MISSING_AREAS < <(grep -a "open.*errno=2\ " "$LOG_FILE_STRACER" 2>&1 | cut -d\" -f2 2>&1 | sort -u || true)
  mapfile -t MISSING_AREAS_ < <(grep -a "^qemu.*: Could not open" "$LOG_FILE_STRACER" | cut -d\' -f2 2>&1 | sort -u || true)
  MISSING_AREAS+=("${MISSING_AREAS_[@]}" )

  for MISSING_AREA in "${MISSING_AREAS[@]}"; do
    MISSING+=("$MISSING_AREA")
    if [[ "$MISSING_AREA" != */proc/* || "$MISSING_AREA" != */sys/* ]]; then
      write_log "[*] Found missing area: $ORANGE$MISSING_AREA$NC" "$LOG_FILE_STRACER"
  
      FILENAME_MISSING=$(basename "$MISSING_AREA")
      write_log "[*] Trying to identify this missing file: $ORANGE$FILENAME_MISSING$NC" "$LOG_FILE_STRACER"
      PATH_MISSING=$(dirname "$MISSING_AREA")

      FILENAME_FOUND=$(find "$LOG_DIR"/firmware -xdev -ignore_readdir_race -name "$FILENAME_MISSING" 2>/dev/null | sort -u | head -1 || true)
      if [[ -n "$FILENAME_FOUND" ]]; then
        write_log "[*] Possible matching file found: $ORANGE$FILENAME_FOUND$NC" "$LOG_FILE_STRACER"
      fi
    
      if [[ ! -d "$R_PATH""$PATH_MISSING" ]]; then
        write_log "[*] Creating directory $ORANGE$R_PATH$PATH_MISSING$NC" "$LOG_FILE_STRACER"
        mkdir -p "$R_PATH""$PATH_MISSING" 2> /dev/null || true
        #continue
      fi
      if [[ -n "$FILENAME_FOUND" ]]; then
        write_log "[*] Copy file $ORANGE$FILENAME_FOUND$NC to $ORANGE$R_PATH$PATH_MISSING/$NC" "$LOG_FILE_STRACER"
        cp -L "$FILENAME_FOUND" "$R_PATH""$PATH_MISSING"/ 2> /dev/null || true
        continue
      else
      #  # disable this for now - have to rethink this
      #  # This can only be used on non library and non elf files. How can we identify them without knowing them?
      #  write_log "[*] Creating empty file $ORANGE$R_PATH$PATH_MISSING/$FILENAME_MISSING$NC" "$LOG_FILE_STRACER"
        write_log "[*] Missing file $ORANGE$R_PATH$PATH_MISSING/$FILENAME_MISSING$NC" "$LOG_FILE_STRACER"
      #  touch "$R_PATH""$PATH_MISSING"/"$FILENAME_MISSING" 2> /dev/null
        continue
      fi
    fi
  done
  cat "$LOG_FILE_STRACER"
}

check_disk_space_emu() {

  mapfile -t CRITICAL_FILES < <(find "$LOG_PATH_MODULE"/ -xdev -type f -size +"$KILL_SIZE" -exec basename {} \; 2>/dev/null| cut -d\. -f1 | cut -d_ -f2 || true)
  for KILLER in "${CRITICAL_FILES[@]}"; do
    if pgrep -f "$EMULATOR.*$KILLER" > /dev/null; then
      print_output "[!] Qemu processes are wasting disk space ... we try to kill it"
      print_output "[*] Killing process ${ORANGE}$EMULATOR.*$KILLER.*${NC}"
      pkill -f "$EMULATOR.*$KILLER.*" || true
      #rm "$LOG_DIR"/qemu_emulator/*"$KILLER"*
    fi
  done
}

emulate_binary() {

  BIN_EMU_NAME=$(basename "$FULL_BIN_PATH")
  LOG_FILE_BIN="$LOG_PATH_MODULE""/qemu_tmp_""$BIN_EMU_NAME"".txt"

  run_init_test
  # now we should have CPU_CONFIG in log file from Binary

  local CPU_CONFIG_
  CPU_CONFIG_="$(grep "CPU_CONFIG_det" "$LOG_PATH_MODULE""/qemu_init_""$BIN_EMU_NAME"".txt" | cut -d\; -f2 | sort -u | head -1 || true)"

  write_log "\\n-----------------------------------------------------------------\\n" "$LOG_FILE_BIN"
  print_output "[*] Emulating binary: $ORANGE$BIN_$NC ($ORANGE$BIN_CNT/${#BIN_EMU[@]}$NC)" "" "$LOG_FILE_BIN"
  write_log "[*] Emulating binary name: $ORANGE$BIN_EMU_NAME$NC" "$LOG_FILE_BIN"
  write_log "[*] Emulator used: $ORANGE$EMULATOR$NC" "$LOG_FILE_BIN"
  write_log "[*] Using root directory: $ORANGE$R_PATH$NC ($ORANGE$ROOT_CNT/${#ROOT_PATH[@]}$NC)" "$LOG_FILE_BIN"
  write_log "[*] Using CPU config: $ORANGE$CPU_CONFIG_$NC" "$LOG_FILE_BIN"
  #write_log "[*] Root path used: $ORANGE$R_PATH$NC" "$LOG_FILE_BIN"
  #shellcheck disable=SC2001
  write_log "[*] Emulating binary: $ORANGE$(echo "$BIN_" | sed 's/^\.//')$NC" "$LOG_FILE_BIN"

  # lets assume we now have only ELF files. Sometimes the permissions of firmware updates are completely weird
  # we are going to give all ELF files exec permissions to execute it in the emulator
  if ! [[ -x "$FULL_BIN_PATH" ]]; then
    write_log "[*] Change permissions +x to $ORANGE$FULL_BIN_PATH$NC." "$LOG_FILE_BIN"
    chmod +x "$FULL_BIN_PATH"
  fi
  emulate_strace_run "$CPU_CONFIG_"
  
  # emulate binary with different command line parameters:
  if [[ "$BIN_" == *"bash"* ]]; then
    EMULATION_PARAMS=("--help" "--version")
  else
    EMULATION_PARAMS=("" "-v" "-V" "-h" "-help" "--help" "--version" "version")
  fi
  
  if [[ "$CPU_CONFIG_" == "NONE" ]]; then
    CPU_CONFIG_=""
  fi

  for PARAM in "${EMULATION_PARAMS[@]}"; do
    if [[ -z "$PARAM" ]]; then
      PARAM="NONE"
    fi

    if [[ "$STRICT_MODE" -eq 1 ]]; then
      set +e
    fi
    if [[ -z "$CPU_CONFIG_" ]]; then
      write_log "[*] Emulating binary $ORANGE$BIN_$NC with parameter $ORANGE$PARAM$NC" "$LOG_FILE_BIN"
      #chroot "$R_PATH" ./"$EMULATOR" "$BIN_" "$PARAM" 2>&1 | tee -a "$LOG_FILE_BIN"
      timeout --preserve-status --signal SIGINT "$QRUNTIME" chroot "$R_PATH" ./"$EMULATOR" "$BIN_" "$PARAM" 2>&1 | tee -a "$LOG_FILE_BIN" || true &
    else
      write_log "[*] Emulating binary $ORANGE$BIN_$NC with parameter $ORANGE$PARAM$NC and cpu configuration $ORANGE$CPU_CONFIG_$NC" "$LOG_FILE_BIN"
      #chroot "$R_PATH" ./"$EMULATOR" -cpu "$CPU_CONFIG_" "$BIN_" "$PARAM" 2>&1 | tee -a "$LOG_FILE_BIN" &
      timeout --preserve-status --signal SIGINT "$QRUNTIME" chroot "$R_PATH" ./"$EMULATOR" -cpu "$CPU_CONFIG_" "$BIN_" "$PARAM" 2>&1 | tee -a "$LOG_FILE_BIN" || true &
    fi
    if [[ "$STRICT_MODE" -eq 1 ]]; then
      set -e
    fi
    check_disk_space_emu
  done

  # now we kill all older qemu-processes:
  # if we use the correct identifier $EMULATOR it will not work ...
  killall -9 --quiet --older-than "$QRUNTIME" -r .*qemu.*sta.* || true
  killall -9 --quiet --older-than "$QRUNTIME" -r .*qemu-.* || true
  write_log "\\n-----------------------------------------------------------------\\n" "$LOG_FILE_BIN"
  
  # reset the terminal - after all the uncontrolled emulation it is typically broken!
  reset
}
