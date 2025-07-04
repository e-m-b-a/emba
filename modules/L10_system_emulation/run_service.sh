#!/firmadyne/sh

# Copyright 2015 - 2016 Daming Dominic Chen
# Copyright 2017 - 2020 Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright 2022 - 2025 Siemens Energy AG
#
# This script is based on the original scripts from the firmadyne and firmAE project
# Original firmadyne project can be found here: https://github.com/firmadyne/firmadyne
# Original firmAE project can be found here: https://github.com/pr0v3rbs/FirmAE

BUSYBOX=/firmadyne/busybox

# just in case we have already started our initial system configuration
if "${BUSYBOX}" grep -q "run_service started" /tmp/EMBA_config_state 2>/dev/null; then
  exit
fi

get_date() {
  "${BUSYBOX}" date
}

if ! [ -f /dev/null ]; then
  "${BUSYBOX}" mknod -m 666 /dev/null c 1 3
fi

# we should build a real and useful PATH ... currently it is just guessing
export PATH="${PATH}":/bin/:/sbin/:/usr/bin/:/usr/sbin:/usr/local/bin:/usr/local/sbin

# "${BUSYBOX}" touch /firmadyne/EMBA_service_init_done
ORANGE="\033[0;33m"
NC="\033[0m"

"${BUSYBOX}" echo -e "${ORANGE}[*] $(get_date) - Starting services in emulated environment...${NC}"
"${BUSYBOX}" echo "run_service started" >> /tmp/EMBA_config_state
"${BUSYBOX}" cat /firmadyne/service

if ("${EMBA_ETC}"); then
  INITIAL_DELAY=30
  # first, the system should do the job by itself
  # after 100sec we jump in with our service helpers
  "${BUSYBOX}" echo -e "${ORANGE}[*] Waiting ${INITIAL_DELAY} sec before helpers starting services in emulated environment...${NC}"
  "${BUSYBOX}" sleep "${INITIAL_DELAY}"
  # some rules we need to apply for different services:
  if "${BUSYBOX}" grep -q lighttpd /firmadyne/service; then
    # ensure we have the pid file for lighttpd:
    "${BUSYBOX}" echo "[*] Creating pid directory for lighttpd service"
    "${BUSYBOX}" mkdir -p /var/run/lighttpd 2>/dev/null
  fi
  if "${BUSYBOX}" grep -q twonkystarter /firmadyne/service; then
    mkdir -p /var/twonky/twonkyserver 2>/dev/null
  fi

  "${BUSYBOX}" echo -e "${ORANGE}[*] Starting EMBA services ...${NC}"
  while (true); do
    while IFS= read -r _BINARY; do
      "${BUSYBOX}" sleep 5
      "${BUSYBOX}" echo -e "${NC}[*] $(get_date) - Environment details ..."

      BINARY_NAME=$("${BUSYBOX}" echo "${_BINARY}" | "${BUSYBOX}" cut -d\  -f1)
      BINARY_NAME=$("${BUSYBOX}" basename "${BINARY_NAME}")

      "${BUSYBOX}" echo -e "\tEMBA_ETC: ${EMBA_ETC}"
      "${BUSYBOX}" echo -e "\tEMBA_BOOT: ${EMBA_BOOT}"
      "${BUSYBOX}" echo -e "\tEMBA_NET: ${EMBA_NET}"
      "${BUSYBOX}" echo -e "\tEMBA_NVRAM: ${EMBA_NVRAM}"
      "${BUSYBOX}" echo -e "\tEMBA_KERNEL: ${EMBA_KERNEL}"
      "${BUSYBOX}" echo -e "\tEMBA_NC: ${EMBA_NC}"
      "${BUSYBOX}" echo -e "\tKernel details: $("${BUSYBOX}" uname -a)"
      "${BUSYBOX}" echo -e "\tKernel cmdline: $("${BUSYBOX}" cat /proc/cmdline)"
      "${BUSYBOX}" echo -e "\tSystem uptime: $("${BUSYBOX}" uptime)"
      "${BUSYBOX}" echo -e "\tSystem environment: $("${BUSYBOX}" env | "${BUSYBOX}" tr '\n' '|')"

      "${BUSYBOX}" echo "[*] Netstat output:"
      "${BUSYBOX}" netstat -antu
      "${BUSYBOX}" echo "[*] Network configuration:"
      "${BUSYBOX}" brctl show
      "${BUSYBOX}" ifconfig -a
      "${BUSYBOX}" echo "[*] Running processes:"
      "${BUSYBOX}" ps
      "${BUSYBOX}" echo "[*] /proc filesystem:"
      "${BUSYBOX}" ls /proc

      # debugger bins - only started with EMBA_NC=true
      if [ "${EMBA_NC}" = "true" ]; then
        if [ "${BINARY_NAME}" = "netcat" ]; then
          "${BUSYBOX}" echo -e "\tBINARY_NAME: ${BINARY_NAME}"
          "${BUSYBOX}" echo -e "\tBINARY: ${_BINARY}"

          "${BUSYBOX}" echo -e "${NC}[*] Starting ${ORANGE}${BINARY_NAME} - ${_BINARY}${NC} debugging service ..."
          # we only start our netcat listener if we set EMBA_NC_STARTER on startup (see run.sh script)
          # otherwise we move on to the next binary starter
          ${_BINARY} &
          continue
        fi
        if [ "${_BINARY}" = "/firmadyne/busybox telnetd -p 9877 -l /firmadyne/sh" ]; then
          "${BUSYBOX}" echo -e "\tBINARY_NAME: ${BINARY_NAME}"
          "${BUSYBOX}" echo -e "\tBINARY: ${_BINARY}"

          "${BUSYBOX}" echo -e "${NC}[*] Starting ${ORANGE}Telnetd - ${_BINARY}${NC} debugging service ..."
          # shellcheck disable=SC2086
          "${BUSYBOX}" sh ${_BINARY} & # nosemgrep
          # ${_BINARY} &
          continue
        fi
      fi
      if [ "${BINARY_NAME}" = "netcat" ] || [ "${_BINARY}" = "/firmadyne/busybox telnetd -p 9877 -l /firmadyne/sh" ]; then
        continue
      fi

      # normal service startups
      if ( ! ("${BUSYBOX}" ps | "${BUSYBOX}" grep -v grep | "${BUSYBOX}" grep -sqiw "${BINARY_NAME}") ); then
        "${BUSYBOX}" echo -e "\tBINARY_NAME: ${BINARY_NAME}"
        "${BUSYBOX}" echo -e "\tBINARY: ${_BINARY}"

        "${BUSYBOX}" echo -e "${NC}[*] Starting ${ORANGE}${BINARY_NAME} - ${_BINARY}${NC} service ..."
        # BINARY variable could be something like: binary parameter parameter ...
        ${_BINARY} &
        # strip only the real binary including path:
        _BINARY_TMP=$("${BUSYBOX}" echo "${_BINARY}" | "${BUSYBOX}" cut -d ' ' -f1)
        "${BUSYBOX}" ls -l "${_BINARY_TMP}"
      else
        "${BUSYBOX}" echo -e "${NC}[*] ${ORANGE}${BINARY_NAME}${NC} already started ..."
      fi

      # ensure we flush all iptables rules regularly
      # netgear TL-WR841HP_V2_151124
      if "${BUSYBOX}" which iptables; then
        if [ "$(iptables -L | "${BUSYBOX}" grep -c "^ACCEPT\|^DROP")" -gt 0 ]; then
          "${BUSYBOX}" echo "[*] Flushing iptables ..."
          iptables -L
          iptables flush 2>/dev/null || true
          iptables -F 2>/dev/null || true
          iptables -P 2>/dev/null INPUT ACCEPT || true
        fi
      fi

      # finally check if we have a configured IP address or something weird happened and we lost our ip configuration
      # Do this only if we have some network_type configuration which means we are not in the network discovery mode
      # None means we are in network discovery mode
      ACTION=$("${BUSYBOX}" cat /firmadyne/network_type)
      # /tmp/EMBA_config_state is filled from modules/L10_system_emulation/network.sh
      if [ "${ACTION}" != "None" ] && ("${BUSYBOX}" grep -q "network config finished" /tmp/EMBA_config_state); then
        # shellcheck disable=SC2016
        IP=$("${BUSYBOX}" ip addr show | "${BUSYBOX}" grep "inet " | "${BUSYBOX}" grep -v "127\.0\.0\." | "${BUSYBOX}" awk '{print $2}' | "${BUSYBOX}" cut -d/ -f1)
        if ! ("${BUSYBOX}" echo "${IP}" | "${BUSYBOX}" grep -E -q "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"); then
          "${BUSYBOX}" echo -e "${ORANGE}[*] WARNING: Looks as we lost our network configuration -> reconfiguration starting now ...${NC}"
          /firmadyne/network.sh 1
        fi
      fi
    done < "/firmadyne/service"
  done
fi

