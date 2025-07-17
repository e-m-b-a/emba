#!/firmadyne/sh

# Copyright 2015 - 2016 Daming Dominic Chen
# Copyright 2017 - 2020 Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright 2022 - 2025 Siemens Energy AG
#
# This script is based on the original scripts from the firmadyne and firmAE project
# Original firmadyne project can be found here: https://github.com/firmadyne/firmadyne
# Original firmAE project can be found here: https://github.com/pr0v3rbs/FirmAE

BUSYBOX=/firmadyne/busybox

# just in case we have already started our initial service configuration
if "${BUSYBOX}" grep -q "init service config started" /tmp/EMBA_config_state 2>/dev/null; then
  exit
fi

get_date() {
  "${BUSYBOX}" date
}

# we should build a real and useful PATH ... currently it is just guessing
export PATH="${PATH}":/bin/:/sbin/:/usr/bin/:/usr/sbin:/usr/local/bin:/usr/local/sbin

# "${BUSYBOX}" touch /firmadyne/EMBA_service_init_done
ORANGE="\033[0;33m"
NC="\033[0m"

"${BUSYBOX}" echo -e "${ORANGE}[*] $(get_date) - Starting initial services in emulated environment...${NC}"
"${BUSYBOX}" echo "init service config started" >> /tmp/EMBA_config_state

"${BUSYBOX}" cat /firmadyne/startup_service

if ("${EMBA_ETC}"); then
  "${BUSYBOX}" echo -e "${ORANGE}[*] Waiting 5sec before helpers starting initial services in emulated environment...${NC}"
  "${BUSYBOX}" sleep 5

  "${BUSYBOX}" echo -e "${ORANGE}[*] Starting initial EMBA services ...${NC}"
  while IFS= read -r SERVICE; do
    "${BUSYBOX}" sleep 1

    SERVICE_NAME=$("${BUSYBOX}" echo "${SERVICE}" | "${BUSYBOX}" cut -d\  -f1)
    SERVICE_NAME=$("${BUSYBOX}" basename "${SERVICE_NAME}")

    # normal service startups
    if ( ! ("${BUSYBOX}" ps | "${BUSYBOX}" grep -v grep | "${BUSYBOX}" grep -sqiw "${SERVICE_NAME}") ); then
      "${BUSYBOX}" echo -e "\tSERVICE_NAME: ${SERVICE_NAME}"
      "${BUSYBOX}" echo -e "\tSERVICE: ${SERVICE}"

      "${BUSYBOX}" echo -e "${NC}[*] Starting initial service ${ORANGE}${SERVICE_NAME} - ${SERVICE}${NC} ..."
      # shellcheck disable=SC3060
      "${BUSYBOX}" ls -l "${SERVICE/\ *}"
      # BINARY variable could be something like: binary parameter parameter ...
      # shellcheck disable=SC2086
      "${BUSYBOX}" sh -c ${SERVICE} &  # nosemgrep
    else
      "${BUSYBOX}" echo -e "${NC}[*] ${ORANGE}${SERVICE_NAME}${NC} already started ..."
    fi
  done < "/firmadyne/startup_service"
fi

