# Copyright (c) 2020 - 2022, Siemens Energy AG
# Copyright (c) 2015 - 2016, Daming Dominic Chen
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim

# shellcheck disable=SC2148
BUSYBOX="/busybox"

${BUSYBOX} touch /firmadyne/init
${BUSYBOX} echo "[*] EMBA inferFile script starting ..."

if (${FIRMAE_BOOT}); then
  arr=()
  if [ -e /kernelInit ]; then
    for FILE in $(${BUSYBOX} strings ./kernelInit)
    do
      # shellcheck disable=SC2016
      FULL_PATH=$(${BUSYBOX} echo "${FILE}" | ${BUSYBOX} awk '{split($0,a,"="); print a[2]}')
      ${BUSYBOX} echo "[*] Found kernelInit $FULL_PATH"
      arr+=("${FULL_PATH}")
    done
  fi
  # kernel not handle this program
  if [ -e /init ]; then
    if [ ! -d /init ]; then
      arr+=(/init)
    fi
  fi
  for FILE in $(${BUSYBOX} find / -name "preinitMT" -o -name "preinit" -o -name "rcS*" -o -name "rc.sysinit" -o -name "rc.local")
  do
    ${BUSYBOX} echo "[*] Found boot file $FILE"
    arr+=("${FILE}")
  done

  # find and parse inittab file
  for FILE in $(${BUSYBOX} find / -name "inittab" -type f)
  do
    ${BUSYBOX} echo "[*] Found boot file $FILE"
    # sysinit entry is the one to look for - we do not handle multiple entries!
    # shellcheck disable=SC2016
    STARTUP_FILE=$(${BUSYBOX} grep ":.*sysinit:" "$FILE" | ${BUSYBOX} rev | ${BUSYBOX} cut -d: -f1 | ${BUSYBOX} rev | ${BUSYBOX} awk '{print $1}')
    ${BUSYBOX} echo "[*] Found possible startup file $STARTUP_FILE"
    if [ -e "${STARTUP_FILE}" ]; then
      arr+=("${STARTUP_FILE}")
    else
      ${BUSYBOX} echo "[-] Something went wrong with startup file $STARTUP_FILE"
    fi
  done

  if (( ${#arr[@]} )); then
    # convert to the unique array following the original order
    # shellcheck disable=SC2207,SC2016
    uniq_arr=($(${BUSYBOX} tr ' ' '\n' <<< "${arr[@]}" | ${BUSYBOX} awk '!u[$0]++' | ${BUSYBOX} tr '\n' ' '))
    for FILE in "${uniq_arr[@]}"
    do
      if [ -d "${FILE}" ]; then
        continue
      fi
      if [ ! -e "${FILE}" ]; then # could not find original file (symbolic link or just file)
        if [ -h "${FILE}" ]; then # remove old symbolic link
          ${BUSYBOX} rm "${FILE}"
        fi
        # find original program from binary directories
        ${BUSYBOX} echo "${FILE}"
        FILE_NAME=$(${BUSYBOX} basename "${FILE}")
        if (${BUSYBOX} find /bin /sbin /usr/sbin /usr/sbin -type f -exec ${BUSYBOX} grep -qr "${FILE_NAME}" {} \;); then
          TARGET_FILE=$(${BUSYBOX} find /bin /sbin /usr/sbin /usr/sbin -type f -exec ${BUSYBOX} egrep -rl "${FILE_NAME}" {} \; | ${BUSYBOX} head -1)
          ${BUSYBOX} echo "[*] Re-creating symlink $TARGET_FILE -> $FILE"
          ${BUSYBOX} ln -s "${TARGET_FILE}" "${FILE}"
        else
          continue
        fi
      fi
      if [ -e "${FILE}" ]; then
        ${BUSYBOX} echo "[*] Writing firmadyne init $FILE"
        ${BUSYBOX} echo "${FILE}" >> /firmadyne/init
      fi
    done
  fi
fi

${BUSYBOX} echo "[*] Re-creating firmadyne/init:"
${BUSYBOX} echo '/firmadyne/preInit.sh' >> /firmadyne/init
${BUSYBOX} cat /firmadyne/init

${BUSYBOX} echo "[*] EMBA inferFile script finished ..."
