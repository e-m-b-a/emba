#!/firmadyne/sh
# shellcheck shell=sh

# Copyright (c) 2015 - 2016, Daming Dominic Chen
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright (c) 2022 - 2024 Siemens Energy AG
#
# This script is based on the original scripts from the firmadyne and firmAE project
# Original firmadyne project can be found here: https://github.com/firmadyne/firmadyne
# Original firmAE project can be found here: https://github.com/pr0v3rbs/FirmAE

BUSYBOX=/firmadyne/busybox

ACTION=$("${BUSYBOX}" cat /firmadyne/network_type)
IP_LOOP="127.0.0.1"

ORANGE="\033[0;33m"
NC="\033[0m"

"${BUSYBOX}" echo -e "\n[*] Network configuration - ACTION: ${ORANGE}${ACTION}${NC}"

if ("${EMBA_NET}"); then
  "${BUSYBOX}" echo "[*] Starting network configuration"
  "${BUSYBOX}" sleep 10

  "${BUSYBOX}" echo -e "[*] Starting network configuration lo - ${ORANGE}${IP_LOOP}${NC}"
  "${BUSYBOX}" ifconfig lo "${IP_LOOP}"
  # "${BUSYBOX}" route add "${IP_LOOP}"
  "${BUSYBOX}" route add -net 127.0.0.0 netmask 255.0.0.0 dev lo

  if [ "${ACTION}" = "default" ]; then
    IP_DEFAULT=$("${BUSYBOX}" cat /firmadyne/ip_default)
    "${BUSYBOX}" echo -e "[*] Starting network configuration br0 - ${ORANGE}${IP_DEFAULT}${NC}"
    "${BUSYBOX}" brctl addbr br0
    "${BUSYBOX}" ifconfig br0 "${IP_DEFAULT}"
    "${BUSYBOX}" echo -e "[*] Starting network configuration eth0 - ${ORANGE}0.0.0.0${NC}"
    "${BUSYBOX}" brctl addif br0 eth0
    "${BUSYBOX}" ifconfig eth0 0.0.0.0 up
  elif [ "${ACTION}" != "None" ]; then
    NET_BRIDGE=$("${BUSYBOX}" cat /firmadyne/net_bridge)
    NET_INTERFACE=$("${BUSYBOX}" cat /firmadyne/net_interface)

    # netgear WNR2000 bridge command
    CNT=0
    while (true); do
      CNT=$((CNT+1))
      echo "[*] Waiting until brctl shows up our ${NET_BRIDGE} - CNT: ${CNT} / 20"
      "${BUSYBOX}" sleep 5
      if ("${BUSYBOX}" brctl show | "${BUSYBOX}" grep -sq "${NET_BRIDGE}"); then
        echo "[+] brctl showed up our ${NET_BRIDGE} - CNT: ${CNT} / 20 -> proceeding"
        break
      fi
      if [ "${CNT}" -gt 20 ]; then
        echo "[-] brctl does not showed up our ${NET_BRIDGE} - CNT: ${CNT} / 20 -> proceeding"
        break
      fi
    done

    "${BUSYBOX}" sleep 5

    if [ "${ACTION}" = "normal" ]; then
      # shellcheck disable=SC2016
      IP=$("${BUSYBOX}" ip addr show "${NET_BRIDGE}" | "${BUSYBOX}" grep -m1 "inet\b" | "${BUSYBOX}" awk '{print $2}' | "${BUSYBOX}" cut -d/ -f1)
      if ("${BUSYBOX}" echo "${IP}" | "${BUSYBOX}" grep -E -q "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"); then
        "${BUSYBOX}" echo -e "[*] Identified IP address: ${ORANGE}${IP} / mode: normal${NC}"
      else
        IP=$("${BUSYBOX}" cat /firmadyne/ip_default)
        "${BUSYBOX}" echo -e "[*] Setting default IP address: ${ORANGE}${IP} / mode: normal${NC}"
      fi
      # tplink TL-WA860RE_EU_UK_US__V5_171116
      #"${BUSYBOX}" brctl addbr "${NET_BRIDGE}"
      #"${BUSYBOX}" ifconfig "${NET_BRIDGE}" "${IP}"
      "${BUSYBOX}" ifconfig "${NET_INTERFACE}" "${IP}" up
      #"${BUSYBOX}" ifconfig "${NET_INTERFACE}" 0.0.0.0 up
    elif [ "${ACTION}" = "interface" ]; then
      # with this mechanism we setup the eth interface with an IP address and not the bridge
      # this is usually used as an additional fallback solution
      # shellcheck disable=SC2016
      IP=$("${BUSYBOX}" ip addr show "${NET_INTERFACE}" | "${BUSYBOX}" grep -m1 "inet\b" | "${BUSYBOX}" awk '{print $2}' | "${BUSYBOX}" cut -d/ -f1)
      if ("${BUSYBOX}" echo "${IP}" | "${BUSYBOX}" grep -E -q "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"); then
        "${BUSYBOX}" echo -e "[*] Identified IP address: ${ORANGE}${IP} / mode: interface${NC}"
      else
        IP=$("${BUSYBOX}" cat /firmadyne/ip_default)
        "${BUSYBOX}" echo -e "[*] Setting default IP address: ${ORANGE}${IP} / mode: interface${NC}"
      fi
      "${BUSYBOX}" ifconfig "${NET_INTERFACE}" "${IP}" up
    elif [ "${ACTION}" = "reload" ]; then
      # this mode is not used by EMBA
      "${BUSYBOX}" ifconfig "${NET_BRIDGE}" 192.168.0.1
      "${BUSYBOX}" ifconfig "${NET_INTERFACE}" 0.0.0.0 up
    elif [ "${ACTION}" = "bridge" ]; then
      # unexpected intercept by another bridge
      # netgear WNR2000v5-V1.0.0.34
      # dlink DIR-505L_FIRMWARE_1.01.ZIP
      # tplink TL-WA850RE_V5_180228.zip
      if ("${BUSYBOX}" brctl show | "${BUSYBOX}" grep "eth0"); then
        # shellcheck disable=SC2016
        WAN_BRIDGE=$("${BUSYBOX}" brctl show | "${BUSYBOX}" grep "eth0" | "${BUSYBOX}" awk '{print $1}')
        "${BUSYBOX}" brctl delif "${WAN_BRIDGE}" eth0
      fi

      # shellcheck disable=SC2016
      IP=$("${BUSYBOX}" ip addr show "${NET_BRIDGE}" | "${BUSYBOX}" grep -m1 "inet\b" | "${BUSYBOX}" awk '{print $2}' | "${BUSYBOX}" cut -d/ -f1)
      "${BUSYBOX}" ip addr show "${NET_BRIDGE}"
      if ("${BUSYBOX}" echo "${IP}" | "${BUSYBOX}" grep -E -q "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"); then
        "${BUSYBOX}" echo -e "[*] Identified IP address: ${ORANGE}${IP} / mode: bridge / net_bridge: ${NET_BRIDGE} / net_interface: ${NET_INTERFACE}${NC}"
        "${BUSYBOX}" ip addr show "${NET_BRIDGE}"
      else
        IP=$("${BUSYBOX}" cat /firmadyne/ip_default)
        "${BUSYBOX}" echo -e "[*] Setting default IP address: ${ORANGE}${IP} / mode: bridge${NC}"
      fi

      # fallback mode - should not happen
      if (! "${BUSYBOX}" echo "${IP}" | "${BUSYBOX}" grep -E -q "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"); then
        "${BUSYBOX}" echo -e "[*] Setting fallback IP address: ${ORANGE}${IP} / mode: bridge${NC}"
        IP="192.168.0.1"
      fi

      "${BUSYBOX}" ifconfig "${NET_BRIDGE}" "${IP}"
      "${BUSYBOX}" brctl addif "${NET_BRIDGE}" eth0
      "${BUSYBOX}" ifconfig "${NET_INTERFACE}" 0.0.0.0 up
    fi
  fi

  "${BUSYBOX}" sleep 30
  "${BUSYBOX}" echo "[*] Current network configuration:"
  "${BUSYBOX}" ifconfig -a

  # netgear TL-WR841HP_V2_151124
  while (true); do
    if "${BUSYBOX}" which iptables; then
      if [ "$(iptables -L | "${BUSYBOX}" grep -c "^ACCEPT\|^DROP")" -gt 0 ]; then
        "${BUSYBOX}" echo "[*] Flushing iptables ..."
        iptables -L
        iptables flush 2>/dev/null || true
        iptables -F 2>/dev/null || true
        iptables -P 2>/dev/null INPUT ACCEPT || true
      fi
    fi
    "${BUSYBOX}" sleep 5
  done
fi
