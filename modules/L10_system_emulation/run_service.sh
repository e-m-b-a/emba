#!/firmadyne/sh

# Copyright (c) 2015 - 2016, Daming Dominic Chen
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright (c) 2022 - 2024 Siemens Energy AG

BUSYBOX=/firmadyne/busybox

# "${BUSYBOX}" touch /firmadyne/EMBA_service_init_done
ORANGE="\033[0;33m"
NC="\033[0m"

"${BUSYBOX}" echo -e "${ORANGE}[*] Starting services in emulated environment...${NC}"
"${BUSYBOX}" cat /firmadyne/service

if ("${FIRMAE_ETC}"); then
  # first, the system should do the job by itself
  # after 100sec we jump in with our service helpers
  "${BUSYBOX}" echo -e "${ORANGE}[*] Waiting 60sec before helpers starting services in emulated environment...${NC}"
  "${BUSYBOX}" sleep 60
  # some rules we need to apply for different services:
  if "${BUSYBOX}" grep -q lighttpd /firmadyne/service; then
    # ensure we have the pid file for lighttpd:
    "${BUSYBOX}" echo "[*] Creating pid directory for lighttpd service"
    "${BUSYBOX}" mkdir -p /var/run/lighttpd 2>/dev/null
  fi
  if "${BUSYBOX}" grep -q twonkystarter /firmadyne/service; then
    mkdir -p /var/twonky/twonkyserver 2>/dev/null
  fi

  while (true); do
    while IFS= read -r _BINARY; do
      BINARY_NAME=$("${BUSYBOX}" echo "${_BINARY}" | "${BUSYBOX}" cut -d\  -f1)
      BINARY_NAME=$("${BUSYBOX}" basename "${BINARY_NAME}")
      if ( ! ("${BUSYBOX}" ps | "${BUSYBOX}" grep -v grep | "${BUSYBOX}" grep -sqi "${BINARY_NAME}") ); then
        "${BUSYBOX}" echo -e "[*] Starting ${ORANGE}${BINARY_NAME}${NC} service ..."
        #BINARY variable could be something like: binary parameter parameter ...
        ${_BINARY} &
        "${BUSYBOX}" sleep 5
        "${BUSYBOX}" echo "[*] Netstat output:"
        "${BUSYBOX}" netstat -antu
        "${BUSYBOX}" echo "[*] Network configuration:"
        "${BUSYBOX}" brctl show
        "${BUSYBOX}" ifconfig
        "${BUSYBOX}" echo "[*] Currently running processes:"
        "${BUSYBOX}" ps
        "${BUSYBOX}" echo "[*] /proc filesytem:"
        "${BUSYBOX}" ls /proc
        "${BUSYBOX}" sleep 5
      fi
      # other scripts are just running if we have not created the following file
    done < "/firmadyne/service"
  done
fi

