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

# Description:  Builds and emulates Linux firmware - this module is based on the great work of firmadyne
#               Check out the original firmadyne project at https://github.com/firmadyne
#               Currently this is an experimental module and needs to be activated separately via the -Q switch. 
# Warning:      This module changes your network configuration and it could happen that your system looses
#               network connectivity.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

L10_system_emulator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "System emulation of Linux based embedded devices with firmadyne."

  SYS_ONLINE=0
  BOOTED=0
  IPS=()

  if [[ "$FULL_EMULATION" -eq 1 && "$RTOS" -eq 0 ]]; then
    pre_module_reporter "${FUNCNAME[0]}"

    export FIRMADYNE_DIR="$EXT_DIR""/firmadyne"

    print_output "[*] This module creates a full copy of the firmware filesystem in the log directory $LOG_DIR.\\n"

    if [[ "$ARCH" == "MIPS" || "$ARCH" == "ARM" ]]; then

      export BINARY_DIR="$FIRMADYNE_DIR/binaries"

      for R_PATH in "${ROOT_PATH[@]}" ; do
        KPANIC=0

        print_output "[*] Detected root path: $ORANGE$R_PATH$NC"

        if [[ -n "$D_END" ]]; then
          D_END="$(echo "$D_END" | tr '[:upper:]' '[:lower:]')"
          ARCH_END="$(echo "$ARCH" | tr '[:upper:]' '[:lower:]')$(echo "$D_END" | tr '[:upper:]' '[:lower:]')"
          CONSOLE=$(get_console "$ARCH_END")
          LIBNVRAM=$(get_nvram "$ARCH_END")

          pre_cleanup

          create_emulation_filesystem "$R_PATH" "$ARCH_END"
          if [[ "$FS_CREATED" -eq 1 ]]; then
            identify_networking "$IMAGE_NAME" "$ARCH_END"
            get_networking_details

            if [[ "$KPANIC" -eq 0 && "${#IPS[@]}" -gt 0 ]]; then
              setup_network
              run_emulated_system
              check_online_stat
              EXECUTE=1
              if [[ "$SYS_ONLINE" -eq 1 ]]; then
                print_output "[+] System emulation was successful."
                print_output "[+] System should be available via IP $IP."
                EXECUTE=0
              fi
              reset_network "$EXECUTE"
              if [[ "$SYS_ONLINE" -eq 1 ]]; then
                create_emulation_archive
              fi
              # if the emulation was successful, we stop here - no emulation of other detected rootfs
              break
            else
              print_output "[!] No further emulation steps are performed"
            fi
          else
            print_output "[!] No further emulation steps are performed"
          fi
        else
          print_output "[!] No supported architecture detected"
        fi
      done
      MODULE_END=1
    else
      print_output "[!] No supported architecture found.\\n"
      print_output "[!] Curently supported: ARM, MIPS.\\n"
      MODULE_END=0
    fi

  fi

  write_log ""
  write_log "[*] Statistics:$SYS_ONLINE:${#IPS[@]}:$BOOTED"
  module_end_log "${FUNCNAME[0]}" "$MODULE_END"

}

pre_cleanup() {
  # this cleanup function is to ensure that we have no mounts from previous tests mounted
  print_output "[*] Checking for not unmounted proc, sys and run in log directory"
  mapfile -t CHECK_MOUNTS < <(mount | grep "$LOG_DIR" | grep "proc\|sys\|run" || true)
  for MOUNT in "${CHECK_MOUNTS[@]}"; do
    print_output "[*] Unmounting $MOUNT"
    MOUNT=$(echo "$MOUNT" | cut -d\  -f3)
    umount -l "$MOUNT" || true
  done
}

create_emulation_filesystem() {
  # based on the original firmadyne script:
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/makeImage.sh

  sub_module_title "Create Qemu filesystem"
  ROOT_PATH="${1:-}"
  ARCH_END="${2:-}"
  export IMAGE_NAME
  FS_CREATED=1
  IMAGE_NAME="$(basename "$ROOT_PATH")_$ARCH_END-$RANDOM"
  MNT_POINT="$LOG_PATH_MODULE/emulation_tmp_fs"
  if [[ -d "$MNT_POINT" ]]; then
    MNT_POINT="$MNT_POINT"-"$RANDOM"
  fi
  mkdir "$MNT_POINT" || true

  print_output "[*] Create filesystem for emulation - $ROOT_PATH.\\n"
  IMAGE_SIZE="$(du -b --max-depth=0 "$ROOT_PATH" | awk '{print $1}')"
  IMAGE_SIZE=$((IMAGE_SIZE + 150 * 1024 * 1024))

  print_output "[*] Size of filesystem for emulation - $IMAGE_SIZE.\\n"
  print_output "[*] Name of filesystem for emulation - $IMAGE_NAME.\\n"
  qemu-img create -f raw "$LOG_PATH_MODULE/$IMAGE_NAME" "$IMAGE_SIZE"
  chmod a+rw "$LOG_PATH_MODULE/$IMAGE_NAME"

  print_output "[*] Creating Partition Table"
  echo -e "o\nn\np\n1\n\n\nw" | /sbin/fdisk "$LOG_PATH_MODULE/$IMAGE_NAME"

  print_output "[*] Mounting QEMU Image"
  DEVICE=$(get_device "$(kpartx -a -s -v "$LOG_PATH_MODULE/$IMAGE_NAME")")
  sleep 1
  print_output "[*] Device mapper created at ${DEVICE}"

  print_output "[*] Creating Filesystem"
  sync
  mkfs.ext2 "${DEVICE}" || true

  print_output "[*] Mounting QEMU Image Partition 1 to $MNT_POINT"
  mount "${DEVICE}" "$MNT_POINT"
  if mount | grep -q "$MNT_POINT"; then
    print_output "[*] Copy root filesystem to QEMU image"
    #rm -rf "${MNT_POINT:?}/"*
    cp -prf "$ROOT_PATH"/* "$MNT_POINT"/ || true

    print_output "[*] Creating FIRMADYNE Directories"
    mkdir -p "$MNT_POINT/firmadyne/libnvram/" || true
    mkdir -p "$MNT_POINT/firmadyne/libnvram.override/" || true

    print_output "[*] Patching Filesystem (chroot)"
    cp "$(which busybox)" "$MNT_POINT" || true

    cp "$FIRMADYNE_DIR/scripts/fixImage_firmadyne.sh" "$MNT_POINT"/fixImage.sh || true
    chroot "$MNT_POINT" /busybox ash /fixImage.sh || true

    rm "$MNT_POINT/fixImage.sh" || true
    rm "$MNT_POINT/busybox" || true

    print_output "[*] Setting up FIRMADYNE"
    cp "${CONSOLE}" "$MNT_POINT/firmadyne/console" || true
    chmod a+x "$MNT_POINT/firmadyne/console"
    mknod -m 666 "$MNT_POINT/firmadyne/ttyS1" c 4 65

    cp "${LIBNVRAM}" "$MNT_POINT/firmadyne/libnvram.so" || true
    chmod a+x "$MNT_POINT/firmadyne/libnvram.so"

    cp "$FIRMADYNE_DIR/scripts/preInit_firmadyne.sh" "$MNT_POINT/firmadyne/preInit.sh" || true
    chmod a+x "$MNT_POINT/firmadyne/preInit.sh"

    print_output "[*] Unmounting QEMU Image"
    sync
    umount "${DEVICE}" || true

  else
    print_output "[!] Filesystem mount failed"
    FS_CREATED=0
  fi
  print_output "[*] Deleting device mapper"
  kpartx -v -d "$LOG_PATH_MODULE/$IMAGE_NAME"
  losetup -d "${DEVICE}" &>/dev/null || true
  # just in case we check the output and remove our device:
  if losetup | grep -q "$(basename "$IMAGE_NAME")"; then
    losetup -d "$(losetup | grep "$(basename "$IMAGE_NAME")" | awk '{print $1}' || true)"
  fi
  dmsetup remove "$(basename "$DEVICE")" &>/dev/null || true
  rm -rf "${MNT_POINT:?}/"* || true
}

identify_networking() {
  # based on the original firmadyne script:
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/inferNetwork.sh
  
  sub_module_title "Network identification"
  IMAGE_NAME="${1:-}"
  IMAGE=$(abs_path "$LOG_PATH_MODULE/$IMAGE_NAME")

  ARCH_END="${2:-}"

  print_output "[*] Test basic emulation and identify network settings.\\n"
  print_output "[*] Running firmware $IMAGE_NAME: terminating after 60 secs..."

  QEMU_PARAMS=""
  if [[ "$ARCH_END" == "mipsel" ]]; then
    KERNEL_="vmlinux"
    QEMU="qemu-system-mipsel"
    MACHINE="malta"
    DRIVE="if=ide,format=raw,file=$IMAGE"
    ROOT_DEV="/dev/sda1"
    NETWORK="-netdev socket,id=s0,listen=:2000 -device e1000,netdev=s0 -netdev socket,id=s1,listen=:2001 -device e1000,netdev=s1 -netdev socket,id=s2,listen=:2002 -device e1000,netdev=s2 -netdev socket,id=s3,listen=:2003 -device e1000,netdev=s3"
  elif [[ "$ARCH_END" == "mipseb" ]]; then
    KERNEL_="vmlinux"
    QEMU="qemu-system-mips"
    MACHINE="malta"
    #DRIVE="if=ide,format=raw,file=\"$IMAGE\""
    DRIVE="if=ide,format=raw,file=$IMAGE"
    ROOT_DEV="/dev/sda1"
    NETWORK="-netdev socket,id=s0,listen=:2000 -device e1000,netdev=s0 -netdev socket,id=s1,listen=:2001 -device e1000,netdev=s1 -netdev socket,id=s2,listen=:2002 -device e1000,netdev=s2 -netdev socket,id=s3,listen=:2003 -device e1000,netdev=s3"
  elif [[ "$ARCH_END" == "armel" ]]; then
    QEMU="qemu-system-arm"
    KERNEL_="zImage"
    MACHINE="virt"
    DRIVE="if=none,file=$IMAGE,format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
    ROOT_DEV="/dev/vda1"
    NETWORK="-device virtio-net-device,netdev=net1 -netdev socket,listen=:2000,id=net1 -device virtio-net-device,netdev=net2 -netdev socket,listen=:2001,id=net2 -device virtio-net-device,netdev=net3 -netdev socket,listen=:2002,id=net3 -device virtio-net-device,netdev=net4 -netdev socket,listen=:2003,id=net4"
    QEMU_PARAMS="-audiodev driver=none,id=none"
  fi

  run_network_id &

  tail -F "$LOG_PATH_MODULE/qemu.initial.serial.log" 2>/dev/null&
  sleep 60
  pkill -f "qemu-system-.*$IMAGE_NAME.*" || true
  pkill -f "tail.*$LOG_PATH_MODULE/qemu.initial.serial.log.*" || true

  if [[ -f "$LOG_PATH_MODULE"/qemu.initial.serial.log ]]; then
    cat "$LOG_PATH_MODULE"/qemu.initial.serial.log >> "$LOG_FILE"
  else
    print_output "[-] No $LOG_PATH_MODULE/qemu.initial.serial.log log file generated."
  fi

  print_output "[*] Firmware $IMAGE_NAME finished for identification of the network configuration"
}

run_network_id() {
  # based on the original firmadyne scripts:
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/run.mipsel.sh
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/run.mipseb.sh
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/run.armel.sh

  print_output "[*] Qemu network identification run for $ARCH_END - $IMAGE_NAME"

  KERNEL="$FIRMADYNE_DIR/binaries/$KERNEL_.$ARCH_END"

  # shellcheck disable=SC2086
  $QEMU -m 256 -M $MACHINE -kernel $KERNEL -drive $DRIVE \
    -append "firmadyne.syscall=1 root=$ROOT_DEV console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 rdinit=/firmadyne/preInit.sh rw debug ignore_loglevel print-fatal-signals=1 user_debug=31" \
    -serial file:$LOG_PATH_MODULE/qemu.initial.serial.log -serial unix:/tmp/qemu.$IMAGE_NAME.S1,server,nowait -monitor unix:/tmp/qemu.$IMAGE_NAME,server,nowait -display none \
    $NETWORK $QEMU_PARAMS || true
}

get_networking_details() {
  # based on the original firmadyne script:
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/makeNetwork.py

  sub_module_title "Network identification - $IMAGE_NAME"

  if [[ -f "$LOG_PATH_MODULE"/qemu.initial.serial.log ]]; then
    INT=()
    VLAN=()
  
    mapfile -t MAC_CHANGES < <(grep -a "ioctl_SIOCSIFHWADDR" "$LOG_PATH_MODULE"/qemu.initial.serial.log | cut -d: -f2- | sort -u || true)
    mapfile -t INTERFACE_CANDIDATES < <(grep -a "__inet_insert_ifa" "$LOG_PATH_MODULE"/qemu.initial.serial.log | cut -d: -f2- | sort -u || true)
    mapfile -t BRIDGE_INTERFACES < <(grep -a "br_add_if\|br_dev_ioctl" "$LOG_PATH_MODULE"/qemu.initial.serial.log | cut -d: -f2- | sort -u || true)
    mapfile -t VLAN_INFOS < <(grep -a "register_vlan_dev" "$LOG_PATH_MODULE"/qemu.initial.serial.log | cut -d: -f2- | sort -u || true)
    mapfile -t PANICS < <(grep -a "Kernel panic - " "$LOG_PATH_MODULE"/qemu.initial.serial.log || true)
  
    if [[ "${#MAC_CHANGES[@]}" -gt 0 || "${#INTERFACE_CANDIDATES[@]}" -gt 0 || "${#BRIDGE_INTERFACES[@]}" -gt 0 || "${#VLAN_INFOS[@]}" -gt 0 ]]; then
      BOOTED=1
    fi

    for MAC_CHANGE in "${MAC_CHANGES[@]}"; do
      print_output "[*] MAC change detected: $MAC_CHANGE"
      print_output "[!] No further action implemented"
    done
  
    for INTERFACE_CAND in "${INTERFACE_CANDIDATES[@]}"; do
      print_output "[*] Possible interface candidate detected: $ORANGE$INTERFACE_CAND$NC"
      # INTERFACE_CAND -> __inet_insert_ifa[PID: 139 (ifconfig)]: device:br0 ifa:0xc0a80001
      mapfile -t IP_ADDRESS < <(echo "$INTERFACE_CAND" | grep device | cut -d: -f2- | sed "s/^.*\]:\ //" | awk '{print $2}' | cut -d: -f2 | sed 's/0x//' | sed 's/../0x&\n/g')
      # IP_ADDRESS -> c0a80001
      # as I don't get it to change the hex ip to dec with printf, we do it the poor way:
      IP_=""
      for IPs in "${IP_ADDRESS[@]}"; do
        if [[ "$IPs" == "0x"* ]]; then
          #shellcheck disable=SC2004
          IP_="$IP_.$(($IPs))"
        fi
      done

      #shellcheck disable=SC2001
      IP_="$(echo "$IP_" | sed 's/^\.//')"
  
      if [[ "$D_END" == "eb" ]]; then
        IP_ADDRESS_="$IP_"
      elif [[ "$D_END" == "el" ]]; then
        IP_ADDRESS_=$(echo "$IP_" | tr '.' '\n' | tac | tr '\n' '.' | sed 's/\.$//')
      fi

      if ! [[ "$IP_ADDRESS_" == "127."* ]] && ! [[ "$IP_ADDRESS_" == "0.0.0.0" ]]; then
        IPS+=( "$IP_ADDRESS_" )
        NETWORK_DEVICE="$(echo "$INTERFACE_CAND" | grep device | cut -d: -f2- | sed "s/^.*\]:\ //" | awk '{print $1}' | cut -d: -f2)"
        if [[ -n "$NETWORK_DEVICE" ]]; then
          INT+=( "$NETWORK_DEVICE" )
        fi
      fi
    done
  
    for BRIDGE_INT in "${BRIDGE_INTERFACES[@]}"; do
      print_output "[*] Possible bridge interface candidate detected: $ORANGE$BRIDGE_INT$NC"
      # br_add_if[PID: 138 (brctl)]: br:br0 dev:eth1.1
      BRIDGE_INT_="$(echo "$BRIDGE_INT" | sed "s/^.*\]:\ //" | awk '{print $1}' | cut -d: -f2)"
      NET_DEV="$(echo "$BRIDGE_INT" | sed "s/^.*\]:\ //" | awk '{print $2}' | cut -d: -f2 | cut -d. -f1)"
  
      # check if the dev part is something like eth1.2:
      # br_add_if[PID: 170 (brctl)]: br:br0 dev:eth0
      #if [[ "$(echo "$BRIDGE_INT" | sed "s/^.*\]:\ //" | awk '{print $2}' | cut -d: -f2 | grep -q -E "[0-9]\.[0-9]")" ]]; then
      if echo "$BRIDGE_INT" | sed "s/^.*\]:\ //" | awk '{print $2}' | cut -d: -f2 | grep -q -E "[0-9]\.[0-9]"; then
        VLAN_ID="$(echo "$BRIDGE_INT" | sed "s/^.*\]:\ //" | grep -o "dev:.*" | cut -d. -f2)"
      fi
      if [[ -n "$BRIDGE_INT_" ]]; then
        INT+=( "$BRIDGE_INT_" )
      fi
      if [[ -n "$NET_DEV" ]]; then
        INT+=( "$NET_DEV" )
      fi
    done
  
    for VLAN_INFO in "${VLAN_INFOS[@]}"; do
      print_output "[*] Possible VLAN details detected: $ORANGE$VLAN_INFO$NC"
      # register_vlan_dev[PID: 128 (vconfig)]: dev:eth1.1 vlan_id:1
      NET_DEV="$(echo "$VLAN_INFO" | sed "s/^.*\]:\ //" | awk '{print $1}' | cut -d: -f2 | cut -d. -f1)"
      VLAN_ID="$(echo "$VLAN_INFO" | grep -o "vlan_id:[0-9]" | cut -d: -f2)"
      VLAN+=( "$VLAN_ID" )
      INT+=( "$NET_DEV" )
    done
  
    # make them unique:
    eval "IPS=($(for i in "${IPS[@]}" ; do echo "\"$i\"" ; done | sort -u))"
    eval "INT=($(for i in "${INT[@]}" ; do echo "\"$i\"" ; done | sort -u))"
    eval "VLAN=($(for i in "${VLAN[@]}" ; do echo "\"$i\"" ; done | sort -u))"

    print_output ""
    for IP in "${IPS[@]}"; do
      print_output "[+] Found possible IP address: $ORANGE$IP$NC"
    done
    for INT_ in "${INT[@]}"; do
      if [[ "$INT_" == *"br"* ]]; then
        print_output "[+] Possible bridge interface detected: $ORANGE$INT_$NC"
      else
        print_output "[+] Possible network interface detected: $ORANGE$INT_$NC"
      fi
    done
    for VLAN_ in "${VLAN[@]}"; do
      print_output "[+] Possible VLAN ID detected: $ORANGE$VLAN_$NC"
    done
  
    for PANIC in "${PANICS[@]}"; do
      print_output "[!] WARNING: Kernel Panic detected: $ORANGE$PANIC$NC"
      KPANIC=1
    done

  else
    print_output "[-] No $LOG_PATH_MODULE/qemu.initial.serial.log log file generated."
  fi
  print_output ""
}

setup_network() {
  sub_module_title "Setup networking - $IMAGE_NAME"

  # used for generating startup scripts for offline analysis
  ARCHIVE_PATH="$LOG_PATH_MODULE"/archive-"$IMAGE_NAME"
  if [[ -d "$ARCHIVE_PATH" ]]; then
    ARCHIVE_PATH="$ARCHIVE_PATH-$RANDOM"
  fi

  if ! [[ -d "$ARCHIVE_PATH" ]]; then
    mkdir "$ARCHIVE_PATH"
  fi

  TAP_ID=2 #temp

  # bridge, no vlan, ip address
  TAPDEV_0=tap$TAP_ID"_0"
  HOSTNETDEV_0=$TAPDEV_0
  print_output "[*] Creating TAP device $ORANGE$TAPDEV_0$NC..."
  write_script_exec "tunctl -t $TAPDEV_0" "$ARCHIVE_PATH"/run.sh 1

  if [[ "${#VLAN[@]}" -gt 0 ]]; then
    for VLANID in "${VLAN[@]}"; do
      print_output "[*] Init VLAN $VLAN_ID ..."
      HOSTNETDEV_0x=$TAPDEV_0.$VLANID
      print_output "[*] Bringing up HOSTNETDEV $ORANGE$HOSTNETDEV_0x$NC"
      write_script_exec "ip link add link $TAPDEV_0 name $HOSTNETDEV_0x type vlan id $VLANID" "$ARCHIVE_PATH"/run.sh 1
      write_script_exec "ip link set $TAPDEV_0 up" "$ARCHIVE_PATH"/run.sh 1
    done
  fi

  for IP in "${IPS[@]}"; do
    HOSTIP="$(echo "$IP" | sed 's/\./&\n/g' | sed -E 's/^[0-9]+$/2/' | tr -d '\n')"
    print_output "[*] Using HOSTIP: $ORANGE$HOSTIP$NC"
    print_output "[*] Possible IP address for emulated device: $ORANGE$IP$NC"
    print_output "[*] Bringing up TAP device $ORANGE$TAPDEV_0$NC"

    write_script_exec "ip link set ${HOSTNETDEV_0} up" "$ARCHIVE_PATH"/run.sh 1
    write_script_exec "ip addr add $HOSTIP/24 dev ${HOSTNETDEV_0}" "$ARCHIVE_PATH"/run.sh 1

    print_output "Adding route to $IP..."
    write_script_exec "ip route add $IP via $IP dev ${HOSTNETDEV_0}" "$ARCHIVE_PATH"/run.sh 1
  done
}

run_emulated_system() {
  sub_module_title "Final system emulation."

  IMAGE="$LOG_PATH_MODULE/$IMAGE_NAME"
  # SYS_ONLINE is used to check the network reachability
  SYS_ONLINE=0

  KERNEL_="vmlinux"
  if [[ "$ARCH_END" == "mipsel" ]]; then
    QEMU_BIN="qemu-system-$ARCH_END"
    QEMU_MACHINE="malta"
  elif [[ "$ARCH_END" == "mipseb" ]]; then
    QEMU_BIN="qemu-system-mips"
    QEMU_MACHINE="malta"
  elif [[ "$ARCH_END" == "armel" ]]; then
    KERNEL_="zImage"
    QEMU_BIN="qemu-system-arm"
    QEMU_MACHINE="virt"
  else
    QEMU_BIN="NA"
  fi
  KERNEL="$FIRMADYNE_DIR/binaries/$KERNEL_.$ARCH_END"

  if [[ "$ARCH" == "ARM" ]]; then
    QEMU_DISK="-drive if=none,file=$IMAGE,format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
    QEMU_PARAMS="-audiodev driver=none,id=none"
    QEMU_ROOTFS="/dev/vda1"
    NET_ID=0
    # newer kernels use virtio only
    QEMU_NETWORK="-device virtio-net-device,netdev=net$NET_ID -netdev tap,id=net$NET_ID,ifname=${TAPDEV_0},script=no"
    for NET_ID in 1 2 3; do
      QEMU_NETWORK="$QEMU_NETWORK -device virtio-net-device,netdev=net$NET_ID -netdev socket,id=net$NET_ID,listen=:200$NET_ID"
    done

  elif [[ "$ARCH" == "MIPS" ]]; then
    QEMU_DISK="-drive if=ide,format=raw,file=$IMAGE"
    QEMU_PARAMS=""
    QEMU_ROOTFS="/dev/sda1"
    NET_ID=0
    #QEMU_NETWORK="-netdev socket,id=net$NET_ID,listen=:200$NET_ID -device e1000,netdev=net$NET_ID"
    QEMU_NETWORK="-netdev tap,id=net$NET_ID,ifname=${TAPDEV_0},script=no -device e1000,netdev=net$NET_ID"
    for NET_ID in 1 2 3; do
      QEMU_NETWORK="$QEMU_NETWORK -netdev socket,id=net$NET_ID,listen=:200$NET_ID -device e1000,netdev=net$NET_ID"
    done
  fi

  if [[ "$QEMU_BIN" != "NA" ]]; then
    print_output "[*] Starting firmware emulation $QEMU_BIN / $ARCH / $IMAGE_NAME ... use Ctrl-a + x to exit"
    sleep 1s
    run_qemu_final_emulation &
  else
    print_output "[-] No firmware emulation $ARCH / $IMAGE_NAME possible"
  fi
}

run_qemu_final_emulation() {
  # run this in the background to be able to test the system in parallel
  # kill it afterwards with something like
  # pkill -f "qemu-system-.*$IMAGE_NAME.*"

  echo "echo \"[*] Starting firmware emulation $QEMU_BIN / $ARCH / $IMAGE_NAME ... use Ctrl-a + x to exit\"" >> "$ARCHIVE_PATH"/run.sh
  write_script_exec "$QEMU_BIN -m 256 -M $QEMU_MACHINE -kernel $KERNEL $QEMU_DISK -append \"root=$QEMU_ROOTFS console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 rdinit=/firmadyne/preInit.sh rw debug ignore_loglevel print-fatal-signals=1 user_debug=31 firmadyne.syscall=0\" -nographic $QEMU_NETWORK $QEMU_PARAMS | tee \"$LOG_PATH_MODULE\"/qemu.final.serial.log || true" "$ARCHIVE_PATH"/run.sh 1
}

check_online_stat() {
  # check for a maximum of 60 seconds
  PING_CNT=0
  while [[ "$PING_CNT" -lt 12 ]]; do
    for IP in "${IPS[@]}"; do
      if ping -c 1 "$IP" &> /dev/null; then
        print_output "[+] Host with $IP is reachable via ICMP."
        print_output "[*] Wait 60 seconds until the boot process is completely finished"
        sleep 60
        SYS_ONLINE=1
        break 2
      else
        print_output "[*] Host with $IP is not reachable."
        SYS_ONLINE=0
      fi
    done
    sleep 5
    (( PING_CNT+=1 ))
  done

  print_output ""
  cat "$LOG_PATH_MODULE"/qemu.final.serial.log >> "$LOG_FILE" || true
}

create_emulation_archive() {
  sub_module_title "Create scripts and archive to re-run the emulated system"

  cp "$KERNEL" "$ARCHIVE_PATH" || true
  cp "$IMAGE" "$ARCHIVE_PATH" || true
  if [[ -f "$ARCHIVE_PATH"/run.sh ]];then
    chmod +x "$ARCHIVE_PATH"/run.sh
  else
    print_output "[-] No run script created ..."
  fi
  tar -czvf "$LOG_PATH_MODULE"/archive-"$IMAGE_NAME".tar.gz "$ARCHIVE_PATH"
  if [[ -f "$LOG_PATH_MODULE"/archive-"$IMAGE_NAME".tar.gz ]]; then
    print_output "[*] Qemu emulation archive created in $LOG_PATH_MODULE/archive-$IMAGE_NAME.tar.gz" "" "$LOG_PATH_MODULE/archive-$IMAGE_NAME.tar.gz"
    print_output ""
  fi
}

reset_network() {
  EXECUTE_="${1:0}"

  if [[ "$EXECUTE" -ne 0 ]]; then
    sub_module_title "Reset network environment"
    print_output "[*] Stopping Qemu emulation ..."
    pkill -9 -f "qemu-system-.*$IMAGE_NAME.*" || true
  else
    sub_module_title "Create network environment startup script"
  fi

  if [[ "$EXECUTE" -eq 1 ]]; then
    print_output "[*] Deleting route..."
  fi
  write_script_exec "ip route flush dev \"${HOSTNETDEV_0}\"" "$ARCHIVE_PATH"/run.sh "$EXECUTE_"

  if [[ "$EXECUTE" -eq 1 ]]; then
    print_output "[*] Bringing down TAP device..."
  fi
  write_script_exec "ip link set $TAPDEV_0 down" "$ARCHIVE_PATH"/run.sh "$EXECUTE_"

  if [[ "$EXECUTE" -eq 1 ]]; then
    print_output "Removing VLAN..."
  fi
  write_script_exec "ip link delete ${HOSTNETDEV_0}" "$ARCHIVE_PATH"/run.sh "$EXECUTE_"

  if [[ "$EXECUTE" -eq 1 ]]; then
    print_output "Deleting TAP device ${TAPDEV_0}..."
  fi
  write_script_exec "tunctl -d ${TAPDEV_0}" "$ARCHIVE_PATH"/run.sh "$EXECUTE_"
}

write_script_exec() {
  COMMAND="${1:-}"
  SCRIPT_WRITE="${2:-}"
  # EXECUTE: 0 -> just write script
  # EXECUTE: 1 -> execute and write script
  # EXECUTE: 2 -> just execute
  EXECUTE="${3:0}"

  if [[ "$EXECUTE" -ne 0 ]];then
    eval "$COMMAND" || true &
  fi

  if [[ "$EXECUTE" -ne 2 ]];then
    if ! [[ -f "$SCRIPT_WRITE" ]]; then
      echo "#!/bin/bash" > "$SCRIPT_WRITE"
    fi

    # for the final script we need to adjust the paths:
    if echo "$COMMAND" | grep -q qemu-system-; then
      #shellcheck disable=SC2001
      COMMAND=$(echo "$COMMAND" | sed "s#${KERNEL:-}#\.\/${KERNEL_:-}.${ARCH_END:-}#g")
      #shellcheck disable=SC2001
      COMMAND=$(echo "$COMMAND" | sed "s#${IMAGE:-}#\.\/${IMAGE_NAME:-}#g")
      #shellcheck disable=SC2001
      COMMAND=$(echo "$COMMAND" | sed "s#\"${LOG_PATH_MODULE:-}\"#\.#g")
    fi

    echo "$COMMAND" >> "$SCRIPT_WRITE"
  fi
}

get_nvram () {
  echo "${BINARY_DIR}/libnvram.so.${1}"
}

get_console () {
  echo "${BINARY_DIR}/console.${1}"
}

get_device () {
    # Parses output from kpartx
    echo "/dev/mapper/$(echo "$1" | cut -d ' ' -f 3)"
}
