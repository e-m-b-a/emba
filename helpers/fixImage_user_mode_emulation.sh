#!/bin/sh

###########################################################################
# fixImage_user_mode_emulation.sh
#
# Purpose:
#   This script prepares a firmware image for user-mode emulation by ensuring
#   the presence of essential system files and directories, and by replacing
#   or backing up certain files as needed. It is based on the original
#   firmadyne fixImage.sh script.
#
# Usage:
#   This script is intended to be run inside a chrooted firmware environment or
#   similar environment, typically as part of an automated firmware analysis
#   or emulation setup via EMBA. It should be executed with sufficient privileges
#   to modify system files and directories.
#
# Parameters:
#   None. All actions are hardcoded for standard system locations.
#
# Environment:
#   - Requires a statically-compiled busybox binary at /busybox.
#   - Expects to run in a Linux-compatible filesystem layout.
#
# Modifications:
#   - Creates or modifies /etc/TZ and /etc/hosts if missing.
#   - Ensures /etc and /var/run directories exist.
#   - Provides utility functions for backing up, renaming, and removing files.
#
# Reference:
#   Based on: https://github.com/firmadyne/firmadyne/blob/master/scripts/fixImage.sh
#
# Author: Original: firmadyne authors
#         Modifications: Michael Messner
###########################################################################

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
    if [ ! -d '/root' ]; then
      "${BUSYBOX}" mkdir /root
    fi
  fi

  if ! "${BUSYBOX}" grep -Esq '^root:.*:/bin/sh$' "${PASSWD}"; then
    echo "[*] Fixing shell for root user"
    "${BUSYBOX}" sed -ir 's/^(root:.*):[^:]+$/\1:\/bin\/sh/' "${PASSWD}"
  fi

  if [ -n "$(${BUSYBOX} grep -Es '^root:[^:]+' "${PASSWD}")" ] || [ -n "$(${BUSYBOX} grep -Es '^root:[^:]+' "${SHADOW}")" ]; then
    echo "[*] Unlocking and blanking default root password. (Note: Some routers may reset the password back to default on boot)"
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
