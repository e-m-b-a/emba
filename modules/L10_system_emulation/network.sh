#!/firmadyne/sh
# shellcheck shell=sh

# Copyright (c) 2015 - 2016, Daming Dominic Chen
# Copyright (c) 2017 - 2020, Mingeun Kim, Dongkwan Kim, Eunsoo Kim
# Copyright (c) 2022, Siemens Energy AG

BUSYBOX=/firmadyne/busybox
ACTION=$("${BUSYBOX}" cat /firmadyne/network_type)

"${BUSYBOX}" echo "[*] Network configuration - ACTION: ${ACTION}" 

if ("${FIRMAE_NET}"); then
  "${BUSYBOX}" echo "[*] Starting network configuration"
  "${BUSYBOX}" sleep 10

  if [ "${ACTION}" = "default" ]; then
    IP_DEFAULT=$("${BUSYBOX}" cat /firmadyne/ip_default)
    "${BUSYBOX}" echo "[*] starting network configuration br0 - ${IP_DEFAULT}"
    "${BUSYBOX}" brctl addbr br0
    "${BUSYBOX}" ifconfig br0 "${IP_DEFAULT}"
    "${BUSYBOX}" echo "[*] starting network configuration eth0 - 0.0.0.0"
    "${BUSYBOX}" brctl addif br0 eth0
    "${BUSYBOX}" ifconfig eth0 0.0.0.0 up
  elif [ "${ACTION}" != "None" ]; then
    NET_BRIDGE=$("${BUSYBOX}" cat /firmadyne/net_bridge)
    NET_INTERFACE=$("${BUSYBOX}" cat /firmadyne/net_interface)

    # netgear WNR2000 bridge command
    CNT=0
    while (true); do
      CNT=$((CNT+1))
      echo "[*] Waiting CNT: ${CNT} / 40"
      "${BUSYBOX}" sleep 5
      if ("${BUSYBOX}" brctl show | "${BUSYBOX}" grep -sq "${NET_BRIDGE}"); then
        break
      fi
      if [ "${CNT}" -gt 40 ]; then
        break
      fi
    done

    "${BUSYBOX}" sleep 5

    if [ "${ACTION}" = "normal" ]; then

      # shellcheck disable=SC2016
      if ("${BUSYBOX}" ip addr show "${NET_BRIDGE}" | "${BUSYBOX}" grep -m1 "inet\b" | "${BUSYBOX}" awk '{print $2}' | "${BUSYBOX}" cut -d/ -f1); then
        IP=$("${BUSYBOX}" ip addr show "${NET_BRIDGE}" | "${BUSYBOX}" grep -m1 "inet\b" | "${BUSYBOX}" awk '{print $2}' | "${BUSYBOX}" cut -d/ -f1)
        "${BUSYBOX}" echo "[*] Identified IP address: ${IP}"
      else
        IP=$("${BUSYBOX}" cat /firmadyne/ip_default)
        "${BUSYBOX}" echo "[*] Setting default IP address: ${IP}"
      fi
      # tplink TL-WA860RE_EU_UK_US__V5_171116
      "${BUSYBOX}" ifconfig "${NET_BRIDGE}" "${IP}"
      "${BUSYBOX}" ifconfig "${NET_INTERFACE}" 0.0.0.0 up
    elif [ "${ACTION}" = "reload" ]; then
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
      if ("${BUSYBOX}" ip addr show "${NET_BRIDGE}" | "${BUSYBOX}" grep -m1 "inet\b" | "${BUSYBOX}" awk '{print $2}' | "${BUSYBOX}" cut -d/ -f1); then
        IP=$("${BUSYBOX}" ip addr show "${NET_BRIDGE}" | "${BUSYBOX}" grep -m1 "inet\b" | "${BUSYBOX}" awk '{print $2}' | "${BUSYBOX}" cut -d/ -f1)
        "${BUSYBOX}" echo "[*] Identified IP address: ${IP}"
      else
        IP=$("${BUSYBOX}" cat /firmadyne/ip_default)
        "${BUSYBOX}" echo "[*] Setting default IP address: ${IP}"
      fi

      "${BUSYBOX}" ifconfig "${NET_BRIDGE}" "${IP}"
      "${BUSYBOX}" brctl addif "${NET_BRIDGE}" eth0
      "${BUSYBOX}" ifconfig "${NET_INTERFACE}" 0.0.0.0 up
    elif [ "${ACTION}" = "bridgereload" ]; then
      if ("${BUSYBOX}" brctl show | "${BUSYBOX}" grep "eth0"); then
        # shellcheck disable=SC2016
        WAN_BRIDGE=$("${BUSYBOX}" brctl show | "${BUSYBOX}" grep "eth0" | "${BUSYBOX}" awk '{print $1}')
        "${BUSYBOX}" brctl delif "${WAN_BRIDGE}" eth0
      fi
      "${BUSYBOX}" ifconfig "${NET_BRIDGE}" 192.168.0.1
      "${BUSYBOX}" brctl addif "${NET_BRIDGE}" eth0
      "${BUSYBOX}" ifconfig "${NET_INTERFACE}" 0.0.0.0 up
    fi
  fi

  "${BUSYBOX}" sleep 60
  "${BUSYBOX}" echo "[*] Current network configuration:"
  "${BUSYBOX}" ifconfig -a

  # netgear TL-WR841HP_V2_151124
  while (true); do
    if "${BUSYBOX}" which iptables; then
      iptables flush 2>/dev/null || true
      iptables -F 2>/dev/null || true
      iptables -P 2>/dev/null INPUT ACCEPT || true
    fi
    "${BUSYBOX}" sleep 5
  done
fi
