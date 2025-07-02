# Copyright 2015 - 2016 Daming Dominic Chen
# Copyright 2017 - 2020 Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright 2022 - 2025 Siemens Energy AG
#
# This script is based on the original scripts from the firmadyne and firmAE project
# Original firmadyne project can be found here: https://github.com/firmadyne/firmadyne
# Original firmAE project can be found here: https://github.com/pr0v3rbs/FirmAE

# use busybox statically-compiled version of all binaries
# shellcheck disable=SC2129,SC2016,SC2148
BUSYBOX="/busybox"

"${BUSYBOX}" echo "[*] EMBA fixImage script starting ..."

# print input if not symlink, otherwise attempt to resolve symlink
resolve_link() {
  TARGET=$("${BUSYBOX}" readlink "${1}")
  if [ -z "${TARGET}" ]; then
    echo "${1}"
  else
    echo "${TARGET}"
  fi
}

if ("${EMBA_BOOT}"); then
  if [ ! -e /bin/sh ]; then
      "${BUSYBOX}" ln -s /firmadyne/busybox /bin/sh
  fi
  "${BUSYBOX}" ln -s /firmadyne/busybox /firmadyne/sh

  mkdir -p "$(resolve_link /proc)"
  mkdir -p "$(resolve_link /dev/pts)"
  mkdir -p "$(resolve_link /etc_ro)"
  mkdir -p "$(resolve_link /tmp)"
  mkdir -p "$(resolve_link /var)"
  mkdir -p "$(resolve_link /run)"
  mkdir -p "$(resolve_link /sys)"
  mkdir -p "$(resolve_link /root)"
  mkdir -p "$(resolve_link /tmp/var)"
  mkdir -p "$(resolve_link /tmp/media)"
  mkdir -p "$(resolve_link /tmp/etc)"
  mkdir -p "$(resolve_link /tmp/var/run)"
  mkdir -p "$(resolve_link /tmp/home/root)"
  mkdir -p "$(resolve_link /tmp/mnt)"
  mkdir -p "$(resolve_link /tmp/opt)"
  mkdir -p "$(resolve_link /tmp/www)"
  mkdir -p "$(resolve_link /var/run)"
  mkdir -p "$(resolve_link /var/lock)"
  mkdir -p "$(resolve_link /usr/bin)"
  mkdir -p "$(resolve_link /usr/sbin)"
  mkdir -p "$(resolve_link /var/tmp)"
  mkdir -p "$(resolve_link /var/sys)"
  mkdir -p "$(resolve_link /var/media)"
  mkdir -p "$(resolve_link /var/wps)"
  mkdir -p "$(resolve_link /var/ppp)"

  for FILE in $("${BUSYBOX}" find /bin /sbin /usr/bin /usr/sbin -type f -perm -u+x -exec "${BUSYBOX}" strings {} \; | "${BUSYBOX}" egrep "^(/var|/etc|/tmp)(.+)\/([^\/]+)$")
  do
    DIR=$("${BUSYBOX}" dirname "${FILE}")
    if (! "${BUSYBOX}" echo "${DIR}" | "${BUSYBOX}" egrep -q "(%s|%c|%d|/tmp/services)");then
      "${BUSYBOX}" echo "${DIR}" >> /firmadyne/dir_log
      mkdir -p "$(resolve_link "${DIR}")"
    fi
  done
fi

# make /etc and add some essential files
mkdir -p "$(resolve_link /etc)"
if [ ! -s /etc/TZ ]; then
  mkdir -p "$(dirname "$(resolve_link /etc/TZ)")"
  echo "EST5EDT" > "$(resolve_link /etc/TZ)"
fi

if [ ! -s /etc/hosts ]; then
  mkdir -p "$(dirname "$(resolve_link /etc/hosts)")"
  echo "127.0.0.1 localhost" > "$(resolve_link /etc/hosts)"
fi

if [ ! -s /etc/passwd ]; then
  mkdir -p "$(dirname "$(resolve_link /etc/passwd)")"
  # nosemgrep
  echo "root::0:0:root:/root:/bin/sh" > "$(resolve_link /etc/passwd)"
fi

# for busybox older v1.3.0 we need an rcS entry
# we also use this rcS as fallback solution
# for this we check different state files and execute the needed scripts
mkdir -p "$(resolve_link /etc/init.d)"

# disabled for now
if [ -s /etc/init.d/rcSX ]; then
  echo '#!/firmadyne/sh' > /etc/init.d/rcS
  echo 'BUSYBOX=/firmadyne/busybox' >> /etc/init.d/rcS
  echo '${BUSYBOX} echo [*] Execute EMBA $0 script sleeping 10 secs ...' >> /etc/init.d/rcS
  echo '${BUSYBOX} echo [*] Filesystem overview:' >> /etc/init.d/rcS
  echo '${BUSYBOX} ls -l /' >> /etc/init.d/rcS
  echo '${BUSYBOX} echo [*] EMBA helpers directory:' >> /etc/init.d/rcS
  echo '${BUSYBOX} ls -l /firmadyne' >> /etc/init.d/rcS
  echo '${BUSYBOX} sleep 10' >> /etc/init.d/rcS
  echo '${BUSYBOX} echo "[*] Execute EMBA preInit.sh script starter .."' >> /etc/init.d/rcS
  echo '/firmadyne/preInit.sh &' >> /etc/init.d/rcS
  echo '${BUSYBOX} sleep 10' >> /etc/init.d/rcS
  echo '${BUSYBOX} echo "[*] Execute EMBA network.sh script starter .."' >> /etc/init.d/rcS
  echo '/firmadyne/network.sh &' >>  /etc/init.d/rcS
  echo '${BUSYBOX} sleep 10' >> /etc/init.d/rcS
  echo '${BUSYBOX} echo "[*] Execute EMBA run_service.sh script starter .."' >> /etc/init.d/rcS
  echo '/firmadyne/run_service.sh &' >> /etc/init.d/rcS
  chmod +x /etc/init.d/rcS
fi

# make /dev and add default device nodes if these are not available
mkdir -p "$(resolve_link /dev)"
echo "[*] Recreating device nodes!"

"${BUSYBOX}" mknod -m 660 /dev/mem c 1 1
"${BUSYBOX}" mknod -m 640 /dev/kmem c 1 2
"${BUSYBOX}" mknod -m 666 /dev/null c 1 3
"${BUSYBOX}" mknod -m 666 /dev/zero c 1 5
"${BUSYBOX}" mknod -m 444 /dev/random c 1 8
"${BUSYBOX}" mknod -m 444 /dev/urandom c 1 9
"${BUSYBOX}" mknod -m 666 /dev/armem c 1 13 2>/dev/null

"${BUSYBOX}" mknod -m 666 /dev/tty c 5 0 2>/dev/null
"${BUSYBOX}" mknod -m 622 /dev/console c 5 1 2>/dev/null
"${BUSYBOX}" mknod -m 666 /dev/ptmx c 5 2 2>/dev/null

"${BUSYBOX}" mknod -m 622 /dev/tty0 c 4 0 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/ttyS0 c 4 64 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/ttyS1 c 4 65 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/ttyS2 c 4 66 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/ttyS3 c 4 67 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/ttyAMA0 c 4 64 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/ttyAMA1 c 4 65 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/ttyAMA2 c 4 66 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/ttyAMA3 c 4 67 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/myttyS0 c 4 64 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/myttyS1 c 4 65 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/myttyS2 c 4 66 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/myttyS3 c 4 67 2>/dev/null

# AVM:
"${BUSYBOX}" mknod -m 600 /dev/ttyMSM0 c 251 0 2>/dev/null

"${BUSYBOX}" mknod -m 644 /dev/adsl0 c 100 0 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/ppp c 108 0 2>/dev/null
"${BUSYBOX}" mknod -m 666 /dev/hidraw0 c 251 0 2>/dev/null

mkdir -p /dev/mtd
"${BUSYBOX}" mknod -m 644 /dev/mtd/0 c 90 0 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd/1 c 90 2 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd/2 c 90 4 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd/3 c 90 6 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd/4 c 90 8 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd/5 c 90 10 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd/6 c 90 12 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd/7 c 90 14 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd/8 c 90 16 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd/9 c 90 18 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd/10 c 90 20 2>/dev/null

"${BUSYBOX}" mknod -m 644 /dev/mtd0 c 90 0 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr0 c 90 1 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd1 c 90 2 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr1 c 90 3 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd2 c 90 4 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr2 c 90 5 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd3 c 90 6 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr3 c 90 7 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd4 c 90 8 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr4 c 90 9 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd5 c 90 10 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr5 c 90 11 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd6 c 90 12 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr6 c 90 13 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd7 c 90 14 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr7 c 90 15 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd8 c 90 16 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr8 c 90 17 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd9 c 90 18 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr9 c 90 19 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtd10 c 90 20 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdr10 c 90 21 2>/dev/null

mkdir -p /dev/mtdblock
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/0 b 31 0 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/1 b 31 1 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/2 b 31 2 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/3 b 31 3 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/4 b 31 4 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/5 b 31 5 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/6 b 31 6 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/7 b 31 7 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/8 b 31 8 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/9 b 31 9 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock/10 b 31 10 2>/dev/null

"${BUSYBOX}" mknod -m 644 /dev/mtdblock0 b 31 0 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock1 b 31 1 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock2 b 31 2 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock3 b 31 3 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock4 b 31 4 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock5 b 31 5 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock6 b 31 6 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock7 b 31 7 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock8 b 31 8 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock9 b 31 9 2>/dev/null
"${BUSYBOX}" mknod -m 644 /dev/mtdblock10 b 31 10 2>/dev/null

mkdir -p /dev/tts
"${BUSYBOX}" mknod -m 660 /dev/tts/0 c 4 64 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/tts/1 c 4 65 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/tts/2 c 4 66 2>/dev/null
"${BUSYBOX}" mknod -m 660 /dev/tts/3 c 4 67 2>/dev/null

ls -l /dev/

# fi

# create a gpio file required for linksys to make the watchdog happy
if ("${BUSYBOX}" grep -sq "/dev/gpio/in" /bin/gpio) ||
  ("${BUSYBOX}" grep -sq "/dev/gpio/in" /usr/lib/libcm.so) ||
  ("${BUSYBOX}" grep -sq "/dev/gpio/in" /usr/lib/libshared.so); then
    echo "Creating /dev/gpio/in!"
    if ("${EMBA_BOOT}"); then
      rm /dev/gpio 2>/dev/null
    fi
    mkdir -p /dev/gpio
    echo -ne "\xff\xff\xff\xff" > /dev/gpio/in
else
  # just create an empty file
  rm -r /dev/gpio 2>/dev/null
  touch /dev/gpio
fi

# prevent system from rebooting
if ("${EMBA_BOOT}"); then
  echo "Removing /sbin/reboot!"
  if [ -s /sbin/reboot ]; then
    rm -f /sbin/reboot
    echo '#!/bin/sh' > /sbin/reboot
    echo 'echo "[*] System tries to reboot - reboot not executed"' >> /sbin/reboot
    chmod +x /sbin/reboot
  fi
fi
echo "Removing /etc/scripts/sys_resetbutton!"
rm -f /etc/scripts/sys_resetbutton

# add some default nvram entries
if "${BUSYBOX}" grep -sq "ipv6_6to4_lan_ip" /sbin/rc; then
  echo "Creating default ipv6_6to4_lan_ip!"
  echo -n "2002:7f00:0001::" > /firmadyne/libnvram.override/ipv6_6to4_lan_ip
fi

if "${BUSYBOX}" grep -sq "time_zone_x" /lib/libacos_shared.so; then
  echo "Creating default time_zone_x!"
  echo -n "0" > /firmadyne/libnvram.override/time_zone_x
fi

if "${BUSYBOX}" grep -sq "rip_multicast" /usr/sbin/httpd; then
  echo "Creating default rip_multicast!"
  echo -n "0" > /firmadyne/libnvram.override/rip_multicast
fi

if "${BUSYBOX}" grep -sq "bs_trustedip_enable" /usr/sbin/httpd; then
  echo "Creating default bs_trustedip_enable!"
  echo -n "0" > /firmadyne/libnvram.override/bs_trustedip_enable
fi

if "${BUSYBOX}" grep -sq "filter_rule_tbl" /usr/sbin/httpd; then
  echo "Creating default filter_rule_tbl!"
  echo -n "" > /firmadyne/libnvram.override/filter_rule_tbl
fi

if "${BUSYBOX}" grep -sq "rip_enable" /sbin/acos_service; then
  echo "Creating default rip_enable!"
  echo -n "0" > /firmadyne/libnvram.override/rip_enable
fi
"${BUSYBOX}" echo "[*] EMBA fixImage script finished ..."
