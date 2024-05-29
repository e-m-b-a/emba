# Copyright (c) 2015 - 2016, Daming Dominic Chen
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright (c) 2022 - 2024 Siemens Energy AG
#
# This script is based on the original scripts from the firmadyne and firmAE project
# Original firmadyne project can be found here: https://github.com/firmadyne/firmadyne
# Original firmAE project can be found here: https://github.com/pr0v3rbs/FirmAE

# shellcheck disable=SC2148
BUSYBOX="/busybox"

"${BUSYBOX}" touch /firmadyne/init_tmp
"${BUSYBOX}" touch /firmadyne/init
"${BUSYBOX}" echo "[*] EMBA inferFile script starting ..."

if ("${EMBA_BOOT}"); then
  arr=()
  if [ -e /kernelInit ]; then
    for FILE in $("${BUSYBOX}" strings ./kernelInit)
    do
      # shellcheck disable=SC2016
      FULL_PATH=$("${BUSYBOX}" echo "${FILE}" | "${BUSYBOX}" awk '{split($0,a,"="); print a[2]}')
      "${BUSYBOX}" echo "[*] Found kernelInit ${FULL_PATH}"
      arr+=("${FULL_PATH}")
    done
  fi
  # kernel not handle this program
  if [ -e /init ]; then
    if [ ! -d /init ]; then
      arr+=(/init)
    fi
  fi
  for FILE in $("${BUSYBOX}" find / -name "preinitMT" -o -name "preinit" -o -name "rcS*" -o -name "rc.sysinit" -o -name "rc.local" -o -name "rc.common" -o -name "init" -o -name "linuxrc" -o -name "rc")
  do
    "${BUSYBOX}" echo "[*] Found boot file ${FILE}"
    arr+=("${FILE}")
  done

  # find and parse inittab file
  for FILE in $("${BUSYBOX}" find / -name "inittab" -type f)
  do
    "${BUSYBOX}" echo "[*] Found boot file ${FILE}"
    # sysinit entry is the one to look for
    # shellcheck disable=SC2016
    for STARTUP_FILE in $("${BUSYBOX}" grep "^:.*sysinit:" "${FILE}" | "${BUSYBOX}" rev | "${BUSYBOX}" cut -d: -f1 | "${BUSYBOX}" rev | "${BUSYBOX}" awk '{print $1}' | "${BUSYBOX}" sort -u)
    do
      "${BUSYBOX}" echo "[*] Found possible startup file ${STARTUP_FILE}"
      arr+=("${STARTUP_FILE}")
      #if [ -e "${STARTUP_FILE}" ]; then
      #  arr+=("${STARTUP_FILE}")
      #else
      #  "${BUSYBOX}" echo "[-] Something went wrong with startup file $STARTUP_FILE"
      #fi
    done
  done

  if (( ${#arr[@]} )); then
    # convert to the unique array following the original order
    # shellcheck disable=SC2207,SC2016
    uniq_arr=($("${BUSYBOX}" tr ' ' '\n' <<< "${arr[@]}" | "${BUSYBOX}" awk '!u[$0]++' | "${BUSYBOX}" tr '\n' ' '))
    for FILE in "${uniq_arr[@]}"
    do
      if [ -d "${FILE}" ]; then
        continue
      fi
      if [ "${FILE}" = "/firmadyne/init" ]; then
        # skip our own init
        continue
      fi
      if [ ! -e "${FILE}" ]; then # could not find original file (symbolic link or just file)
        if [ -h "${FILE}" ]; then # remove old symbolic link
          "${BUSYBOX}" rm "${FILE}"
        fi
        # find original program from binary directories
        "${BUSYBOX}" echo "[*] Analysing ${FILE}"
        FILE_NAME=$("${BUSYBOX}" basename "${FILE}")
        if ("${BUSYBOX}" find /bin /sbin /usr/sbin /usr/sbin -type f -exec "${BUSYBOX}" grep -qr "${FILE_NAME}" {} \;); then
          TARGET_FILE=$("${BUSYBOX}" find /bin /sbin /usr/sbin /usr/sbin -type f -exec "${BUSYBOX}" egrep -rl "${FILE_NAME}" {} \; | "${BUSYBOX}" head -1)
          "${BUSYBOX}" echo "[*] Re-creating symlink ${TARGET_FILE} -> ${FILE}"
          "${BUSYBOX}" ln -s "${TARGET_FILE}" "${FILE}"
        else
          continue
        fi
      fi
      if [ -e "${FILE}" ]; then
        "${BUSYBOX}" echo "[*] Writing firmadyne init ${FILE}"
        "${BUSYBOX}" echo "${FILE}" >> /firmadyne/init_tmp
      fi
    done
  fi
fi

"${BUSYBOX}" echo "[*] Re-creating firmadyne/init:"
"${BUSYBOX}" sort /firmadyne/init_tmp > /firmadyne/init
"${BUSYBOX}" echo '/firmadyne/preInit.sh' >> /firmadyne/init
"${BUSYBOX}" cat /firmadyne/init
"${BUSYBOX}" rm /firmadyne/init_tmp

"${BUSYBOX}" echo "[*] EMBA inferFile script finished ..."
