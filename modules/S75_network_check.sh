#!/bin/bash

# emba - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2021 Siemens AG
# Copyright 2020-2021 Siemens Energy AG
#
# emba comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# emba is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  A more exceptional search for files like resolv.conf, iptables.conf and snmpf.conf and analyzes their content. 
#               Checks systemd network configuration files.

S75_network_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search network configs"

  NET_CFG_FOUND=0

  check_resolv
  check_iptables
  check_snmp
  check_network_configs

  module_end_log "${FUNCNAME[0]}" "$NET_CFG_FOUND"
}

check_resolv()
{
  sub_module_title "Search resolv.conf"

  local CHECK=0
  local RES_CONF_PATHS
  mapfile -t RES_CONF_PATHS < <(mod_path "/ETC_PATHS/resolv.conf")
  for RES_INFO_P in "${RES_CONF_PATHS[@]}"; do
    if [[ -e "$RES_INFO_P" ]] ; then
      CHECK=1
      print_output "[+] DNS config ""$(print_path "$RES_INFO_P")"

      DNS_INFO=$(grep "nameserver" "$RES_INFO_P" 2>/dev/null)
      if [[ "$DNS_INFO" ]] ; then
          print_output "$(indent "$DNS_INFO")"
          ((NET_CFG_FOUND++))
      fi
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No or empty network configuration found"
  fi
}

check_iptables()
{
  sub_module_title "Search iptables.conf"

  local CHECK=0
  local IPT_CONF_PATHS
  mapfile -t IPT_CONF_PATHS < <(mod_path "/ETC_PATHS/iptables")
  for IPT_INFO_P in "${IPT_CONF_PATHS[@]}"; do
    if [[ -e "$IPT_INFO_P" ]] ; then
      CHECK=1
      print_output "[+] iptables config ""$(print_path "$IPT_INFO_P")"
      ((NET_CFG_FOUND++))
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No iptables configuration found"
  fi
}

# This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_snmp
check_snmp()
{
  sub_module_title "Check SNMP configuration"

  local CHECK=0
  local SNMP_CONF_PATHS
  mapfile -t SNMP_CONF_PATHS < <(mod_path "/ETC_PATHS/snmp/snmpd.conf")
  for SNMP_CONF_P in "${SNMP_CONF_PATHS[@]}"; do
    if [[ -e "$SNMP_CONF_P" ]] ; then
      CHECK=1
      print_output "[+] SNMP config ""$(print_path "$SNMP_CONF_P")"
      mapfile -t FIND < <(awk '/^com2sec/ { print $4 }' "$SNMP_CONF_P")
      if [[ "${#FIND[@]}" -ne 0 ]] ; then
        print_output "[*] com2sec line/s:"
        for I in "${FIND[@]}"; do
          print_output "$(indent "$(orange "$I")")"
          ((NET_CFG_FOUND++))
        done
      fi
    fi
  done
  if [[ $CHECK -eq 0 ]] ; then
    print_output "[-] No SNMP configuration found"
  fi
}

check_network_configs()
{
  sub_module_title "Check for other network configurations"

  local NETWORK_CONFS
  readarray -t NETWORK_CONFS < <(printf '%s' "$(config_find "$CONFIG_DIR""/network_conf_files.cfg")")

  if [[ "${NETWORK_CONFS[0]}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ ${#NETWORK_CONFS[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#NETWORK_CONFS[@]}"" possible network configs:"
    for LINE in "${NETWORK_CONFS[@]}" ; do
      print_output "$(indent "$(orange "$(print_path "$LINE")")")"
      ((NET_CFG_FOUND++))
    done
  else
    print_output "[-] No network configs found"
  fi
}

