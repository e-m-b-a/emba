#!/firmadyne/sh

# Copyright (c) 2015 - 2016, Daming Dominic Chen
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright (c) 2022 - 2024 Siemens Energy AG
#
# This script is based on the original scripts from the firmadyne and firmAE project
# Original firmadyne project can be found here: https://github.com/firmadyne/firmadyne
# Original firmAE project can be found here: https://github.com/pr0v3rbs/FirmAE

BUSYBOX=/firmadyne/busybox

ORANGE="\033[0;33m"
NC="\033[0m"

"${BUSYBOX}" echo -e "${ORANGE}[*] EMBA preInit script starting ...${NC}"

[ -d /dev ] || "${BUSYBOX}" mkdir -p /dev
[ -d /root ] || "${BUSYBOX}" mkdir -p /root
[ -d /sys ] || "${BUSYBOX}" mkdir -p /sys
[ -d /proc ] || "${BUSYBOX}" mkdir -p /proc
[ -d /tmp ] || "${BUSYBOX}" mkdir -p /tmp
[ -d /var/lock ] || "${BUSYBOX}" mkdir -p /var/lock

"${BUSYBOX}" mount -t sysfs sysfs /sys
"${BUSYBOX}" mount -t proc proc /proc
"${BUSYBOX}" ln -sf /proc/mounts /etc/mtab

"${BUSYBOX}" mkdir -p /dev/pts
"${BUSYBOX}" mount -t devpts devpts /dev/pts
"${BUSYBOX}" mount -t tmpfs tmpfs /run

"${BUSYBOX}" echo -e "${ORANGE}[*] EMBA preInit script finished ...${NC}"
