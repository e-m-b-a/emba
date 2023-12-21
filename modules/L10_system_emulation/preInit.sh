#!/firmadyne/sh

# Copyright (c) 2015 - 2016, Daming Dominic Chen
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright (c) 2022 - 2023 Siemens Energy AG

BUSYBOX=/firmadyne/busybox

"${BUSYBOX}" echo "[*] EMBA preInit script starting ..."

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

"${BUSYBOX}" echo "[*] EMBA preInit script finished ..."
