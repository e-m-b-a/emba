# Copyright 2015 - 2016 Daming Dominic Chen
# Copyright 2017 - 2020 Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright 2022 - 2025 Siemens Energy AG
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
  # arr_prio are the entries identified from the kernel (module s24) and get a higher priority
  arr_prio=()
  if [ -e /kernelInit ]; then
    for FILE in $("${BUSYBOX}" strings ./kernelInit); do
      # shellcheck disable=SC2016
      FULL_PATH=$("${BUSYBOX}" echo "${FILE}" | "${BUSYBOX}" awk '{split($0,a,"="); print a[2]}')
      if ! echo "${arr[*]}" | grep -q "${FULL_PATH}"; then
        "${BUSYBOX}" echo "[*] Found kernelInit ${FULL_PATH}"
        arr_prio+=("${FULL_PATH}")
      fi
    done
  fi
  # kernel not handle this program
  if [ -e /init ]; then
    if [ ! -d /init ]; then
      arr+=(/init)
    fi
  fi
  for FILE in $("${BUSYBOX}" find / -name "init" -o -name "preinit" -o -name "rcS*" -o -name "rc.sysinit" -o -name "rc.local" -o -name "rc.common" -o -name "preinitMT" -o -name "linuxrc" -o -name "rc"); do
    "${BUSYBOX}" echo "[*] Found boot file ${FILE}"
    arr+=("${FILE}")
  done

  # find and parse inittab file
  for FILE in $("${BUSYBOX}" find / -name "inittab" -type f); do
    "${BUSYBOX}" echo "[*] Found boot file ${FILE}"
    # sysinit entry is the one to look for
    # shellcheck disable=SC2016
    for STARTUP_FILE in $("${BUSYBOX}" grep "^:.*sysinit:" "${FILE}" | "${BUSYBOX}" rev | "${BUSYBOX}" cut -d: -f1 | "${BUSYBOX}" rev | "${BUSYBOX}" awk '{print $1}' | "${BUSYBOX}" sort -u); do
      if "${BUSYBOX}" echo "${STARTUP_FILE}" | "${BUSYBOX}" grep -q "\.raw$"; then
        # skip binwalk raw files
        continue
      fi
      "${BUSYBOX}" echo "[*] Found possible startup file ${STARTUP_FILE}"
      arr+=("${STARTUP_FILE}")
      # if [ -e "${STARTUP_FILE}" ]; then
      #  arr+=("${STARTUP_FILE}")
      # else
      #  "${BUSYBOX}" echo "[-] Something went wrong with startup file $STARTUP_FILE"
      # fi
    done
  done

  if (( ${#arr[@]} )); then
    # convert to the unique array following the original order
    # shellcheck disable=SC2207,SC2016
    uniq_arr=($("${BUSYBOX}" tr ' ' '\n' <<< "${arr[@]}" | "${BUSYBOX}" awk '!u[$0]++' | "${BUSYBOX}" tr '\n' ' '))
    for FILE in "${uniq_arr[@]}"; do
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
        if ("${BUSYBOX}" find /bin /sbin /usr/bin /usr/sbin -type f -exec "${BUSYBOX}" grep -qr "${FILE_NAME}" {} \;); then
          TARGET_FILE=$("${BUSYBOX}" find /bin /sbin /usr/bin /usr/sbin -type f -exec "${BUSYBOX}" egrep -rl "${FILE_NAME}" {} \; | "${BUSYBOX}" head -1)
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

# ensure we have our kernel entry in the beginning and all the other entries afterwards:
"${BUSYBOX}" echo "[*] Re-creating firmadyne/init:"
for entry in "${arr_prio[@]}"; do
  if [ -z "${entry}" ]; then
    continue
  fi
  "${BUSYBOX}" echo "${entry}" >> /firmadyne/init
done
if [ -s /firmadyne/init_tmp ]; then
  while read -r entry; do
    if [ -z "${entry}" ]; then
      continue
    fi
    if ! "${BUSYBOX}" grep -q "${entry}" /firmadyne/init; then
      "${BUSYBOX}" echo "${entry}" >> /firmadyne/init
    fi
  done < /firmadyne/init_tmp
fi

# finally add the EMBA default/backup entry, print it and remove the temp file
"${BUSYBOX}" echo '/firmadyne/preInit.sh' >> /firmadyne/init
"${BUSYBOX}" cat /firmadyne/init
"${BUSYBOX}" rm /firmadyne/init_tmp

"${BUSYBOX}" echo "[*] EMBA inferFile script finished ..."
