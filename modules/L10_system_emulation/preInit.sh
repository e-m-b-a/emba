#!/firmadyne/sh

# Copyright 2015 - 2016 Daming Dominic Chen
# Copyright 2017 - 2020 Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright 2022 - 2025 Siemens Energy AG
#
# This script is based on the original scripts from the firmadyne and firmAE project
# Original firmadyne project can be found here: https://github.com/firmadyne/firmadyne
# Original firmAE project can be found here: https://github.com/pr0v3rbs/FirmAE

BUSYBOX=/firmadyne/busybox

get_date() {
  "${BUSYBOX}" date
}

ORANGE="\033[0;33m"
NC="\033[0m"

"${BUSYBOX}" echo -e "${ORANGE}[*] EMBA preInit script starting ...${NC}"
# we create the config state file and track our state in here. This is used from
# the other scripts to track the emulation state and ensure they are not running multiple times
# this file gets removed between automated emulation states. Nevertheless, as we are overwriting
# it from the preInit script here we should be also fine on manual runs via run.sh
"${BUSYBOX}" echo "preInit started" > /tmp/EMBA_config_state

print_keepalive() {
  while(true); do
    "${BUSYBOX}" echo -e "[*] $(get_date) - EMBA emulation system is live"
    "${BUSYBOX}" sleep 5
  done
}

[ -d /dev ] || "${BUSYBOX}" mkdir -p /dev
[ -d /root ] || "${BUSYBOX}" mkdir -p /root
[ -d /sys ] || "${BUSYBOX}" mkdir -p /sys
[ -d /proc ] || "${BUSYBOX}" mkdir -p /proc
[ -d /tmp ] || "${BUSYBOX}" mkdir -p /tmp
[ -d /run ] || "${BUSYBOX}" mkdir -p /run
[ -d /var/lock ] || "${BUSYBOX}" mkdir -p /var/lock

"${BUSYBOX}" mount -t sysfs sysfs /sys
"${BUSYBOX}" mount -t proc proc /proc
"${BUSYBOX}" ln -sf /proc/mounts /etc/mtab

"${BUSYBOX}" mkdir -p /dev/pts
"${BUSYBOX}" mount -t devpts devpts /dev/pts
"${BUSYBOX}" mount -t tmpfs tmpfs /run

"${BUSYBOX}" echo -e "${NC}[*] $(get_date) - Environment details ..."
"${BUSYBOX}" echo -e "\tEMBA_ETC: ${EMBA_ETC}"
"${BUSYBOX}" echo -e "\tEMBA_BOOT: ${EMBA_BOOT}"
"${BUSYBOX}" echo -e "\tEMBA_NET: ${EMBA_NET}"
"${BUSYBOX}" echo -e "\tEMBA_NVRAM: ${EMBA_NVRAM}"
"${BUSYBOX}" echo -e "\tEMBA_KERNEL: ${EMBA_KERNEL}"
"${BUSYBOX}" echo -e "\tEMBA_NC: ${EMBA_NC}"
"${BUSYBOX}" echo -e "\tBINARY_NAME: ${BINARY_NAME}"
"${BUSYBOX}" echo -e "\tKernel details: $("${BUSYBOX}" uname -a)"
"${BUSYBOX}" echo -e "\tKernel cmdline: $("${BUSYBOX}" cat /proc/cmdline)"
"${BUSYBOX}" echo -e "\tSystem uptime: $("${BUSYBOX}" uptime)"
"${BUSYBOX}" echo -e "\tSystem environment: $("${BUSYBOX}" env | "${BUSYBOX}" tr '\n' '/')"

"${BUSYBOX}" echo "[*] Netstat output:"
"${BUSYBOX}" netstat -antu
"${BUSYBOX}" echo "[*] Network configuration:"
"${BUSYBOX}" brctl show
"${BUSYBOX}" ifconfig -a
"${BUSYBOX}" echo "[*] Running processes:"
"${BUSYBOX}" ps
"${BUSYBOX}" echo "[*] /proc filesytem:"
"${BUSYBOX}" ls /proc

"${BUSYBOX}" echo -e "${ORANGE}[*] EMBA preInit script finished ...${NC}"

print_keepalive &
