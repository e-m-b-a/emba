#!/firmadyne/sh

# Copyright (c) 2020 - 2022, Siemens Energy AG
# Copyright (c) 2015 - 2016, Daming Dominic Chen
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim

BUSYBOX=/firmadyne/busybox

${BUSYBOX} echo "[*] Starting services in emulated environment..."
${BUSYBOX} cat /firmadyne/service

if (${FIRMAE_ETC}); then
  ${BUSYBOX} sleep 100
  # some rules we need to apply for different services:
  if ${BUSYBOX} grep -q lighttpd /firmadyne/service; then
    # ensure we have the pid file for lighttpd:
    ${BUSYBOX} echo "[*] Creating pid directory for lighttpd service"
    ${BUSYBOX} mkdir -p /var/run/lighttpd 2>/dev/null
  fi
  if ${BUSYBOX} grep -q twonkystarter /firmadyne/service; then
    mkdir -p /var/twonky/twonkyserver 2>/dev/null
  fi

  while (true); do
    while IFS= read -r BINARY; do
      BINARY_NAME=$(${BUSYBOX} echo "${BINARY}" | ${BUSYBOX} cut -d\  -f1)
      BINARY_NAME=$(${BUSYBOX} basename "${BINARY_NAME}")
      if ( ! (${BUSYBOX} ps | ${BUSYBOX} grep -v grep | ${BUSYBOX} grep -sqi "${BINARY_NAME}") ); then
        ${BUSYBOX} echo "[*] Starting $BINARY_NAME service ..."
        ${BINARY} &
        ${BUSYBOX} sleep 5
        ${BUSYBOX} echo "[*] Netstat output ..."
        ${BUSYBOX} netstat -antu
        ${BUSYBOX} sleep 5
      fi
    done < "/firmadyne/service"
  done
fi

