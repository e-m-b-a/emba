#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  A more exceptional search for files like resolv.conf, iptables.conf and snmpf.conf and analyzes their content.
#               Checks systemd network configuration files.

S75_network_check()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search network configs"
  pre_module_reporter "${FUNCNAME[0]}"

  export NET_CFG_FOUND=0

  check_resolv
  check_iptables
  check_snmp
  check_network_configs

  module_end_log "${FUNCNAME[0]}" "${NET_CFG_FOUND}"
}

check_resolv()
{
  sub_module_title "Search resolv.conf"

  local lCHECK=0
  local lRES_CONF_PATHS_ARR=()
  local lRES_INFO_P=""
  local lDNS_INFO=""

  mapfile -t lRES_CONF_PATHS_ARR < <(mod_path "/ETC_PATHS/resolv.conf")
  for lRES_INFO_P in "${lRES_CONF_PATHS_ARR[@]}"; do
    if [[ -e "${lRES_INFO_P}" ]] ; then
      lCHECK=1
      print_output "[+] DNS config ""$(print_path "${lRES_INFO_P}")"

      lDNS_INFO=$(grep "nameserver" "${lRES_INFO_P}" 2>/dev/null || true)
      if [[ "${lDNS_INFO}" ]] ; then
        print_output "$(indent "${lDNS_INFO}")"
        ((NET_CFG_FOUND+=1))
      fi
    fi
  done
  if [[ ${lCHECK} -eq 0 ]]; then
    print_output "[-] No or empty network configuration found"
  fi
}

check_iptables()
{
  sub_module_title "Search iptables.conf"

  local lCHECK=0
  local lIPT_CONF_PATHS_ARR=()
  local lIPT_INFO_P=""

  mapfile -t lIPT_CONF_PATHS_ARR < <(mod_path "/ETC_PATHS/iptables")
  for lIPT_INFO_P in "${lIPT_CONF_PATHS_ARR[@]}"; do
    if [[ -e "${lIPT_INFO_P}" ]] ; then
      lCHECK=1
      print_output "[+] iptables config ""$(print_path "${lIPT_INFO_P}")"
      ((NET_CFG_FOUND+=1))
    fi
  done
  if [[ ${lCHECK} -eq 0 ]]; then
    print_output "[-] No iptables configuration found"
  fi
}

# This check is based on source code from lynis: https://github.com/CISOfy/lynis/blob/master/include/tests_snmp
check_snmp()
{
  sub_module_title "Check SNMP configuration"

  local lCHECK=0
  local lSNMP_CONF_PATHS_ARR=()
  local lSNMP_CONF_P=""
  local lFIND_ARR=()
  local lI=""

  mapfile -t lSNMP_CONF_PATHS_ARR < <(mod_path "/ETC_PATHS/snmp/snmpd.conf")
  for lSNMP_CONF_P in "${lSNMP_CONF_PATHS_ARR[@]}"; do
    if [[ -e "${lSNMP_CONF_P}" ]] ; then
      lCHECK=1
      print_output "[+] SNMP config ""$(print_path "${lSNMP_CONF_P}")"
      mapfile -t lFIND_ARR < <(awk '/^com2sec/ { print $4 }' "${lSNMP_CONF_P}")
      if [[ "${#lFIND_ARR[@]}" -ne 0 ]] ; then
        print_output "[*] com2sec line/s:"
        for lI in "${lFIND_ARR[@]}"; do
          print_output "$(indent "$(orange "${lI}")")"
          ((NET_CFG_FOUND+=1))
        done
      fi
    fi
  done
  if [[ ${lCHECK} -eq 0 ]]; then
    print_output "[-] No SNMP configuration found"
  fi
}

check_network_configs()
{
  sub_module_title "Check for other network configurations"

  local lNETWORK_CONFS_ARR=()
  local lNW_CONF=""

  readarray -t lNETWORK_CONFS_ARR < <(printf '%s' "$(config_find "${CONFIG_DIR}""/network_conf_files.cfg")")

  if [[ "${lNETWORK_CONFS_ARR[0]-}" == "C_N_F" ]] ; then print_output "[!] Config not found"
  elif [[ ${#lNETWORK_CONFS_ARR[@]} -gt 0 ]] ; then
    print_output "[+] Found ""${#lNETWORK_CONFS_ARR[@]}"" possible network configs:"
    for lNW_CONF in "${lNETWORK_CONFS_ARR[@]}" ; do
      print_output "$(indent "$(orange "$(print_path "${lNW_CONF}")")")"
      ((NET_CFG_FOUND+=1))
    done
  else
    print_output "[-] No network configs found"
  fi
}

