#!/bin/sh

# This script is based on the firmadyne script:
# https://github.com/firmadyne/firmadyne/blob/master/scripts/fixImage.sh

# use busybox statically-compiled version of all binaries
BUSYBOX="/busybox"

# print input if not symlink, otherwise attempt to resolve symlink
resolve_link() {
  LINK="${1}"
  TARGET=$("${BUSYBOX}" readlink "${LINK}")
  if [ -z "${TARGET}" ]; then
    echo "${LINK}"
    return
  fi
  echo "${TARGET}"
}

backup_file() {
  BACKUP="${1}"
  if [ -f "${BACKUP}" ]; then
    echo "[*] Backing up ${BACKUP} to ${BACKUP}.bak"
    "${BUSYBOX}" cp "${BACKUP}" "${BACKUP}.bak"
  fi
}

rename_file() {
  RENAME="${1}"
  if [ -f "${RENAME}" ]; then
    echo "[*] Renaming ${RENAME} to ${RENAME}.bak"
    "${BUSYBOX}" mv "${RENAME}" "${RENAME}.bak"
  fi
}

remove_file() {
  REMOVE="${1}"
  if [ -f "${REMOVE}" ]; then
    echo "[*] Removing ${REMOVE}"
    "${BUSYBOX}" rm -f "${REMOVE}"
  fi
}

# make /etc and add some essential files
"${BUSYBOX}" mkdir -p "$(resolve_link /etc)"
if [ ! -s /etc/TZ ]; then
  echo "[*] Creating /etc/TZ file"
  "${BUSYBOX}" mkdir -p "$(dirname "$(resolve_link /etc/TZ)")"
  echo "EST5EDT" > "$(resolve_link /etc/TZ)"
fi

if [ ! -s /etc/hosts ]; then
  echo "[*] Creating /etc/hosts file"
  "${BUSYBOX}" mkdir -p "$(dirname "$(resolve_link /etc/hosts)")"
  echo "127.0.0.1 localhost" > "$(resolve_link /etc/hosts)"
fi
"${BUSYBOX}" mkdir -p /var/run

PASSWD=$(resolve_link /etc/passwd)
SHADOW=$(resolve_link /etc/shadow)
if [ ! -s "${PASSWD}" ]; then
  echo "[*] Creating ${PASSWD} file"
  "${BUSYBOX}" mkdir -p "$(dirname "${PASSWD}")"
  # nosemgrep
  echo "root::0:0:root:/root:/bin/sh" > "${PASSWD}"
else
  backup_file "${PASSWD}"
  backup_file "${SHADOW}"
  if ! "${BUSYBOX}" grep -sq "^root:" "${PASSWD}" ; then
    echo "[*] No root user found, creating root user with shell '/bin/sh'"
    # nosemgrep
    echo "root::0:0:root:/root:/bin/sh" > "${PASSWD}"
    "${BUSYBOX}" [ ! -d '/root' ] && "${BUSYBOX}" mkdir /root
  fi

  if [ -z "$(${BUSYBOX} grep -Es '^root:' "${PASSWD}" |${BUSYBOX} grep -Es ':/bin/sh$')" ] ; then
    echo "[*] Fixing shell for root user"
    "${BUSYBOX}" sed -ir 's/^(root:.*):[^:]+$/\1:\/bin\/sh/' "${PASSWD}"
  fi

  if [ -n "$(${BUSYBOX} grep -Es '^root:[^:]+' "${PASSWD}")" ] || [ -n "$(${BUSYBOX} grep -Es '^root:[^:]+' "${SHADOW}")" ]; then
    echo "[*] Unlocking and blanking default root password. (*May not work since some routers reset the password back to default when booting)"
    "${BUSYBOX}" sed -ir 's/^(root:)[^:]+:/\1:/' "${PASSWD}"
    "${BUSYBOX}" sed -ir 's/^(root:)[^:]+:/\1:/' "${SHADOW}"
  fi
fi

# create a gpio file required for linksys to make the watchdog happy
if ("${BUSYBOX}" grep -sq "/dev/gpio/in" /bin/gpio) ||
  ("${BUSYBOX}" grep -sq "/dev/gpio/in" /usr/lib/libcm.so) ||
  ("${BUSYBOX}" grep -sq "/dev/gpio/in" /usr/lib/libshared.so); then
  echo "[*] Creating /dev/gpio/in (required for some linksys devices)"
  "${BUSYBOX}" mkdir -p /dev/gpio
  # shellcheck disable=SC3037,2039
  echo -ne "\xff\xff\xff\xff" > /dev/gpio/in
fi

# prevent system from rebooting
remove_file /etc/scripts/sys_resetbutton
