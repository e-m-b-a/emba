#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens Energy AG
# Copyright 2020-2021 Siemens AG
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
#               Currently this is an experimental module and needs to be activated separately via the -F switch. 
#               It is also recommended to only use this technique in a dockerized or virtualized environment.
# Warning:      This module changes your network configuration and it could happen that your system looses
#               network connectivity.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

L10_system_emulator() {
  module_log_init "${FUNCNAME[0]}"
  module_title "System emulation of Linux based embedded devices."

  if [[ "$FULL_EMULATION" -eq 1 && "$RTOS" -eq 0 ]]; then

    if [[ $IN_DOCKER -eq 0 ]] ; then
      print_output "[!] This module should not be used in developer mode and could harm your host environment."
    fi

    print_output "[!] This module creates a full copy of the firmware filesystem in the log directory $LOG_DIR.\\n"

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

          create_emulation_filesystem "$R_PATH" "$ARCH_END"
          identify_networking "$IMAGE_NAME" "$ARCH_END"
          get_networking_details

          if [[ "$KPANIC" -eq 0 && "${#IPS[@]}" -gt 0 ]]; then
            setup_network
            run_emulated_system
            check_online_stat
            if [[ "$SYS_ONLINE" -eq 0 ]]; then
              reset_network
            else
              print_output "[+] System emulation was successful."
              print_output "[+] System should be available via IP $IP."
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
  write_log "[*] Statistics:$SYS_ONLINE"
  module_end_log "${FUNCNAME[0]}" "$MODULE_END"

}

create_emulation_filesystem() {
  # based on the original firmadyne script:
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/makeImage.sh

  sub_module_title "Create Qemu filesystem"
  ROOT_PATH="$1"
  ARCH_END="$2"
  export IMAGE_NAME
  IMAGE_NAME="$(basename "$ROOT_PATH")_$ARCH_END"
  MNT_POINT="$LOG_PATH_MODULE/emulation_tmp_fs"
  if ! [[ -d "$MNT_POINT" ]]; then
    mkdir "$MNT_POINT"
  fi

  print_output "[*] Create filesystem for emulation - $ROOT_PATH.\\n"
  IMAGE_SIZE="$(du -b --max-depth=0 "$ROOT_PATH" | awk '{print $1}')"
  IMAGE_SIZE=$((IMAGE_SIZE + 10 * 1024 * 1024))

  print_output "[*] Size of filesystem for emulation - $IMAGE_SIZE.\\n"
  print_output "[*] Name of filesystem for emulation - $IMAGE_NAME.\\n"
  qemu-img create -f raw "$LOG_PATH_MODULE/$IMAGE_NAME" "$IMAGE_SIZE"
  chmod a+rw "$LOG_PATH_MODULE/$IMAGE_NAME" | tee -a "$LOG_FILE"

  print_output "[*] Creating Partition Table"
  echo -e "o\nn\np\n1\n\n\nw" | /sbin/fdisk "$LOG_PATH_MODULE/$IMAGE_NAME"

  print_output "[*] Mounting QEMU Image"
  DEVICE=$(get_device "$(kpartx -a -s -v "$LOG_PATH_MODULE/$IMAGE_NAME")")
  sleep 1
  print_output "[*] Device mapper created at ${DEVICE}"

  print_output "[*] Creating Filesystem"
  mkfs.ext2 "${DEVICE}"
  sync

  print_output "[*] Mounting QEMU Image Partition 1"
  mount "${DEVICE}" "$MNT_POINT"

  print_output "[*] Copy root filesystem to QEMU image"
  cp -pri "$ROOT_PATH"/* "$MNT_POINT"/

  print_output "[*] Creating FIRMADYNE Directories"
  mkdir -p "$MNT_POINT/firmadyne/libnvram/"
  mkdir "$MNT_POINT/firmadyne/libnvram.override/"

  print_output "[*] Patching Filesystem (chroot)"
  cp "$(which busybox)" "$MNT_POINT"
  cp "$FIRMADYNE_DIR/scripts/fixImage.sh" "$MNT_POINT"
  chroot "$MNT_POINT" /busybox ash /fixImage.sh
  rm "$MNT_POINT/fixImage.sh"
  rm "$MNT_POINT/busybox"

  print_output "[*] Setting up FIRMADYNE"
  cp "${CONSOLE}" "$MNT_POINT/firmadyne/console"
  chmod a+x "$MNT_POINT/firmadyne/console"
  mknod -m 666 "$MNT_POINT/firmadyne/ttyS1" c 4 65

  cp "${LIBNVRAM}" "$MNT_POINT/firmadyne/libnvram.so"
  chmod a+x "$MNT_POINT/firmadyne/libnvram.so"

  cp "$FIRMADYNE_DIR/scripts/preInit.sh" "$MNT_POINT/firmadyne/preInit.sh"
  chmod a+x "$MNT_POINT/firmadyne/preInit.sh"

  print_output "[*] Unmounting QEMU Image"
  sync
  umount "${DEVICE}"

  print_output "[*] Deleting device mapper"
  kpartx -d "$LOG_PATH_MODULE/$IMAGE_NAME"
  losetup -d "${DEVICE}" &>/dev/null
  dmsetup remove "$(basename "$DEVICE")" &>/dev/null
}

identify_networking() {
  # based on the original firmadyne script:
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/inferNetwork.sh
  
  sub_module_title "Network identification"
  IMAGE_NAME="$1"
  ARCH_END="$2"

  print_output "[*] Test basic emulation and identify network settings.\\n"
  print_output "[*] Running firmware $IMAGE_NAME: terminating after 60 secs..."

  if [[ "$ARCH_END" == "mipsel" ]]; then
    run_mipsel_network_id &
  elif [[ "$ARCH_END" == "mipseb" ]]; then
    run_mipsbe_network_id &
  elif [[ "$ARCH_END" == "armel" ]]; then
    run_armel_network_id &
  fi

  tail -F "$LOG_PATH_MODULE/qemu.initial.serial.log" 2>/dev/null&
  sleep 60
  pkill -f "qemu-system-.*$IMAGE_NAME.*"
  pkill -f "tail.*$LOG_PATH_MODULE/qemu.initial.serial.log.*"

  if [[ -f "$LOG_PATH_MODULE"/qemu.initial.serial.log ]]; then
    cat "$LOG_PATH_MODULE"/qemu.initial.serial.log >> "$LOG_FILE"
  else
    print_output "[-] No $LOG_PATH_MODULE/qemu.initial.serial.log log file generated."
  fi

  print_output "[*] Firmware $IMAGE_NAME finished for identification of the network configuration"
}

run_mipsel_network_id() {
  # based on the original firmadyne script:
  #https://github.com/firmadyne/firmadyne/blob/master/scripts/run.mipsel.sh

  print_output "[*] Qemu run for $ARCH_END - $IMAGE_NAME"
  KERNEL="$FIRMADYNE_DIR/binaries/vmlinux.$ARCH_END"
  IMAGE=$(abs_path "$LOG_PATH_MODULE/$IMAGE_NAME")
  qemu-system-mipsel -m 256 -M malta -kernel "$KERNEL" -drive if=ide,format=raw,file="$IMAGE" -append "firmadyne.syscall=1 root=/dev/sda1 console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 rdinit=/firmadyne/preInit.sh rw debug ignore_loglevel print-fatal-signals=1" -serial file:"$LOG_PATH_MODULE"/qemu.initial.serial.log -serial unix:/tmp/qemu."$IMAGE_NAME".S1,server,nowait -monitor unix:/tmp/qemu."$IMAGE_NAME",server,nowait -display none -netdev socket,id=s0,listen=:2000 -device e1000,netdev=s0 -netdev socket,id=s1,listen=:2001 -device e1000,netdev=s1 -netdev socket,id=s2,listen=:2002 -device e1000,netdev=s2 -netdev socket,id=s3,listen=:2003 -device e1000,netdev=s3

}

run_mipsbe_network_id() {
  # based on the original firmadyne script:
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/run.mipseb.sh

  print_output "[*] Qemu run for $ARCH_END - $IMAGE_NAME"
  KERNEL="$FIRMADYNE_DIR/binaries/vmlinux.$ARCH_END"
  IMAGE=$(abs_path "$LOG_PATH_MODULE/$IMAGE_NAME")
  qemu-system-mips -m 256 -M malta -kernel "$KERNEL" -drive if=ide,format=raw,file="$IMAGE" -append "firmadyne.syscall=1 root=/dev/sda1 console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 rdinit=/firmadyne/preInit.sh rw debug ignore_loglevel print-fatal-signals=1" -serial file:"$LOG_PATH_MODULE"/qemu.initial.serial.log -serial unix:/tmp/qemu."$IMAGE_NAME".S1,server,nowait -monitor unix:/tmp/qemu."$IMAGE_NAME",server,nowait -display none -netdev socket,id=s0,listen=:2000 -device e1000,netdev=s0 -netdev socket,id=s1,listen=:2001 -device e1000,netdev=s1 -netdev socket,id=s2,listen=:2002 -device e1000,netdev=s2 -netdev socket,id=s3,listen=:2003 -device e1000,netdev=s3

}

run_armel_network_id() {
  print_output "[*] Qemu run for $ARCH_END - $IMAGE_NAME"
  print_output "[*] Emulate all the things.\\n"

  print_output "[!] ARM not implemented"
}

get_networking_details() {
  # based on the original firmadyne script:
  # https://github.com/firmadyne/firmadyne/blob/master/scripts/makeNetwork.py

  sub_module_title "Network identification - $IMAGE_NAME"

  if [[ -f "$LOG_PATH_MODULE"/qemu.initial.serial.log ]]; then
    IPS=()
    INT=()
    VLAN=()
  
    mapfile -t MAC_CHANGES < <(grep -a "ioctl_SIOCSIFHWADDR" "$LOG_PATH_MODULE"/qemu.initial.serial.log | cut -d: -f2- | sort -u)
    mapfile -t INTERFACE_CANDIDATES < <(grep -a "__inet_insert_ifa" "$LOG_PATH_MODULE"/qemu.initial.serial.log | cut -d: -f2- | sort -u)
    mapfile -t BRIDGE_INTERFACES < <(grep -a "br_add_if\|br_dev_ioctl" "$LOG_PATH_MODULE"/qemu.initial.serial.log | cut -d: -f2- | sort -u)
    mapfile -t VLAN_INFOS < <(grep -a "register_vlan_dev" "$LOG_PATH_MODULE"/qemu.initial.serial.log | cut -d: -f2- | sort -u)
    mapfile -t PANICS < <(grep -a "Kernel panic" "$LOG_PATH_MODULE"/qemu.initial.serial.log)
  
    for MAC_CHANGE in "${MAC_CHANGES[@]}"; do
      print_output "[*] MAC change detected: $MAC_CHANGE"
      # TODO
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
        VLAN_ID="$(echo "$BRIDGE_INT" | sed "s/^.*\]:\ //" | awk '{print $2}' | cut -d: -f2 | cut -d. -f2)"
      fi
      if [[ -n "$BRIDGE_INT_" ]]; then
        INT+=( "$BRIDGE_INT_" )
      fi
      if [[ -n "$NET_DEV" ]]; then
        INT+=( "$NET_DEV" )
        VLAN+=( "$VLAN_ID" )
      fi
    done
  
    for VLAN_INFO in "${VLAN_INFOS[@]}"; do
      print_output "[*] Possible VLAN details detected: $ORANGE$VLAN_INFO$NC"
      # register_vlan_dev[PID: 128 (vconfig)]: dev:eth1.1 vlan_id:1
      NET_DEV="$(echo "$VLAN_INFO" | sed "s/^.*\]:\ //" | awk '{print $1}' | cut -d: -f2 | cut -d. -f1)"
      VLAN_ID="$(echo "$VLAN_INFO" | sed "s/^.*\]:\ //" | awk '{print $2}' | cut -d: -f2)"
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
      if [[ "$VLAN_" == "[0-9]+" ]]; then
        print_output "[+] Possible VLAN ID detected: $ORANGE$VLAN_$NC"
      fi
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

  TAP_ID=2 #temp

  # bridge, no vlan, ip address
  TAPDEV_0=tap$TAP_ID
  HOSTNETDEV_0=$TAPDEV_0
  print_output "[*] Creating TAP device $ORANGE$TAPDEV_0$NC..."
  tunctl -t $TAPDEV_0

  if [[ "${#VLAN[@]}" -gt 0 ]]; then
    print_output "[*] Init VLAN ..."
    for VLANID in "${VLAN[@]}"; do
      if [[ "$VLANID" == "[0-9]+" ]]; then
        print_output "[*] Init VLAN $VLAN_ID ..."
        HOSTNETDEV_0=$TAPDEV_0.$VLANID
        ip link add link "$TAPDEV_0" name "$HOSTNETDEV_0" type vlan id "$VLANID"
        ip link set "$TAPDEV_0" up
      fi
    done
  fi

  for IP in "${IPS[@]}"; do
    HOSTIP="$(echo "$IP" | sed 's/\./&\n/g' | sed -E 's/^[0-9]+$/2/' | tr -d '\n')"
    print_output "[*] Using HOSTIP: $ORANGE$HOSTIP$NC"
    print_output "[*] Possible IP address for emulated device: $ORANGE$IP$NC"
    print_output "[*] Bringing up TAP device $ORANGE$TAPDEV_0$NC"

    ip link set "${HOSTNETDEV_0}" up
    ip addr add "$HOSTIP"/24 dev "${HOSTNETDEV_0}"

    print_output "Adding route to $IP..."
    ip route add "$IP" via "$IP" dev "${HOSTNETDEV_0}"
  done


}
run_emulated_system() {
  sub_module_title "Final system emulation."

  KERNEL="$FIRMADYNE_DIR/binaries/vmlinux.$ARCH_END"
  IMAGE="$LOG_PATH_MODULE/$IMAGE_NAME"
  # SYS_ONLINE is used to check the network reachability
  SYS_ONLINE=0

  if [[ "$ARCH_END" == "mipsel" ]]; then
    QEMU_BIN="qemu-system-$ARCH_END"
    QEMU_MACHINE="malta"
  elif [[ "$ARCH_END" == "mipseb" ]]; then
    QEMU_BIN="qemu-system-mips"
    QEMU_MACHINE="malta"
  elif [[ "$ARCH_END" == "armel" ]]; then
    QEMU_BIN="qemu-system-arm"
    QEMU_MACHINE="virt"
  else
    QEMU_BIN="NA"
  fi

  if [[ "$ARCH" == "ARM" ]]; then
    QEMU_DISK="-drive if=none,file=$IMAGE,format=raw,id=rootfs -device virtio-blk-device,drive=rootfs"
    QEMU_ENV_VARS="QEMU_AUDIO_DRV=none"
    QEMU_ROOTFS="/dev/vda1"
    NET_ID=0
    # newer kernels use virtio only
    QEMU_NETWORK="-device virtio-net-device,netdev=net$NET_ID -netdev tap,id=net$NET_ID,ifname=${TAPDEV_0},script=no"
    for NET_ID in 1 2 3; do
      QEMU_NETWORK="$QEMU_NETWORK -device virtio-net-device,netdev=net$NET_ID -netdev socket,id=net$NET_ID,listen=:200$NET_ID"
    done

  elif [[ "$ARCH" == "MIPS" ]]; then
    QEMU_DISK="-drive if=ide,format=raw,file=$IMAGE"
    QEMU_ENV_VARS=""
    QEMU_ROOTFS="/dev/sda1"
    NET_ID=0
    #QEMU_NETWORK="-netdev socket,id=net$NET_ID,listen=:200$NET_ID -device e1000,netdev=net$NET_ID"
    # if mac:
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

  #shellcheck disable=SC2086
  $QEMU_ENV_VARS $QEMU_BIN -m 256 -M $QEMU_MACHINE -kernel $KERNEL $QEMU_DISK \
    -append "root=$QEMU_ROOTFS console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 rdinit=/firmadyne/preInit.sh rw debug ignore_loglevel print-fatal-signals=1 user_debug=31 firmadyne.syscall=0" \
    -nographic $QEMU_NETWORK | tee "$LOG_PATH_MODULE"/qemu.final.serial.log

}

check_online_stat() {
  # check for a maximum of 60 seconds
  while [[ "$PING_CNT" -lt 12 ]]; do
    for IP in "${IPS[@]}"; do
      if ping -c 1 "$IP" &> /dev/null; then
        print_output "[*] Host with $IP is not reachable."
        SYS_ONLINE=0
      else
        print_output "[+] Ping to $IP is Ok."
        # wait another 60 seconds to settle everything before proceeding
        print_output "[*] Wait 60 seconds until the boot process is completely finished"
        sleep 60
        SYS_ONLINE=1
        break 2
      fi
    done
    sleep 5
    PING_CNT=("$PING_CNT"+1)
  done

  print_output ""
  cat "$LOG_PATH_MODULE"/qemu.final.serial.log >> "$LOG_FILE"
}

reset_network() {
  sub_module_title "Reset network environment"

  print_output "[*] Deleting route..."
  sudo ip route flush dev "${HOSTNETDEV_0}"

  print_output "[*] Bringing down TAP device..."
  ip link set "$TAPDEV_0" down

  print_output "Removing VLAN..."
  sudo ip link delete "${HOSTNETDEV_0}"

  print_output "Deleting TAP device ${TAPDEV_0}..."
  sudo tunctl -d ${TAPDEV_0}

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
