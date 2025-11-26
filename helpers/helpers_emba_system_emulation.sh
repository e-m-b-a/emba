#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Helper functions for system emulation

restart_emulation() {
  local lIP_ADDRESS="${1:-}"
  local lIMAGE_NAME="${2:-}"
  # restart_scan is used to indicate a restarted scan. For this we do not need to restart the network
  local lRESTART_SCAN="${3:-0}"
  local lSTATE_CHECK_MECHANISM="${4:-"PING"}"
  local lRESTART_FORCE="${5:-0}"

  if [[ "${lRESTART_FORCE}" -eq 0 ]]; then
    if ping -c 1 "${lIP_ADDRESS}" &> /dev/null; then
      print_output "[+] System with ${ORANGE}${lIP_ADDRESS}${GREEN} responding again - probably it recovered automatically.${NC}" "no_log"
      return
    fi
  fi

  # shellcheck disable=SC2153
  if ! [[ -f "${ARCHIVE_PATH}"/run.sh ]]; then
    print_output "[!] Warning: Auto-maintaining not possible - emulation archive not available"
    return
  fi

  print_output "[!] Warning: System with ${ORANGE}${lIP_ADDRESS}${MAGENTA} not responding." "no_log"
  print_output "[*] Trying to auto-maintain emulated system now ..." "no_log"

  if [[ $(wc -l 2>/dev/null < "${TMP_DIR}/emulation_restarting.log") -gt "${MAX_SYSTEM_RESTART_CNT}" ]]; then
    print_output "[!] WARNING: Maximal restart counter reached ... no further service checks and system restarts performed"
    return 1
  fi

  write_log "[*] $(date) - system emulation restarting ..." "${TMP_DIR}/emulation_restarting.log"
  if [[ "$(wc -l 2>/dev/null < "${TMP_DIR}/emulation_restarting.log")" -gt 10 ]]; then
    print_output "[!] WARNING: Restarting system multiple times ..."
  fi

  stopping_emulation_process "${lIMAGE_NAME}"
  [[ "${lRESTART_SCAN}" -eq 0 ]] && reset_network_emulation 2

  check_qemu_instance_l10

  pushd "${ARCHIVE_PATH}" >/dev/null || { print_output "[-] Emulation archive path not found"; return 1; }
  ./run.sh &
  popd >/dev/null || { print_output "[-] EMBA path not available?"; return 1; }

  if [[ "${lSTATE_CHECK_MECHANISM}" == "PING" ]]; then
    if ping_check "${lIP_ADDRESS}" 1; then
      if service_online_check "${ARCHIVE_PATH}" "${lIP_ADDRESS}" 1 "NA"; then
        return 0
      fi
    fi
  elif [[ "${lSTATE_CHECK_MECHANISM}" == "HPING" ]]; then
    if hping_check "${lIP_ADDRESS}" 1; then
      if service_online_check "${ARCHIVE_PATH}" "${lIP_ADDRESS}" 1 "NA"; then
        return 0
      fi
    fi
  fi
  return 1
}

# EXECUTE: 0 -> just write script
# EXECUTE: 1 -> execute and write script
# EXECUTE: 2 -> just execute
reset_network_emulation() {
  local lIMAGE_NAME="${1:-}"
  local lEXECUTE="${2:-}"

  local lEXECUTE_tmp=0

  if ! [[ -v lIMAGE_NAME ]] || ! [[ -v ARCHIVE_PATH ]]; then
    return
  fi

  # Todo: handle network shutdown also on restarted tests
  if [[ "${RESTART}" -ne 0 ]]; then
    return
  fi

  if [[ "${lEXECUTE}" -ne 0 ]]; then
    print_output "[*] Stopping Qemu emulation ..." "no_log"
    pkill -9 -f "qemu-system-.*${lIMAGE_NAME}.*" || true &>/dev/null
  fi

  if [[ "${lEXECUTE}" -eq 1 ]] && ! grep -q "Deleting route" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    write_script_exec "echo -e \"Deleting route ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi
  if [[ -v HOSTNETDEV_0 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "ip route flush dev" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "[*] Deleting route..." "no_log"
    write_script_exec "ip route flush dev ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh "${lEXECUTE}"
  fi

  if [[ "${lEXECUTE}" -eq 1 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "Bringing down TAP device" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "[*] Bringing down TAP device..." "no_log"
    write_script_exec "echo -e \"Bringing down TAP device ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi
  if [[ "${lEXECUTE}" -lt 2 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "ip link set ${TAPDEV_0} down" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    lEXECUTE_tmp=1
  else
    lEXECUTE_tmp="${lEXECUTE}"
  fi
  if [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "ip link set ${TAPDEV_0} down" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    write_script_exec "ip link set ${TAPDEV_0} down" "${ARCHIVE_PATH}"/run.sh "${lEXECUTE_tmp}"
  fi

  if [[ "${lEXECUTE}" -eq 1 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "Removing VLAN" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "Removing VLAN..." "no_log"
    write_script_exec "echo -e \"Removing VLAN ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi

  if [[ "${lEXECUTE}" -lt 2 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "ip link delete ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    lEXECUTE_tmp=1
  else
    lEXECUTE_tmp="${lEXECUTE}"
  fi
  if [[ -v HOSTNETDEV_0 ]]; then
    if [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "ip link delete ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
      write_script_exec "ip link delete ${HOSTNETDEV_0}" "${ARCHIVE_PATH}"/run.sh "${lEXECUTE_tmp}"
    fi
  fi

  if [[ "${lEXECUTE}" -eq 1 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "Deleting TAP device" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    print_output "Deleting TAP device ${TAPDEV_0}..." "no_log"
    write_script_exec "echo -e \"Deleting TAP device ...\n\"" "${ARCHIVE_PATH}"/run.sh 0
  fi
  if [[ "${lEXECUTE}" -lt 2 ]] && [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "tunctl -d ${TAPDEV_0}" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    lEXECUTE_tmp=1
  else
    lEXECUTE_tmp="${lEXECUTE}"
  fi
  if [[ -f "${ARCHIVE_PATH}"/run.sh ]] && ! grep -q "tunctl -d ${TAPDEV_0}" "${ARCHIVE_PATH}"/run.sh >/dev/null; then
    write_script_exec "tunctl -d ${TAPDEV_0}" "${ARCHIVE_PATH}"/run.sh "${lEXECUTE_tmp}"
  fi
}

write_script_exec() {
  local lCOMMAND="${1:-}"
  # SCRIPT_WRITE: File to write
  local lSCRIPT_WRITE="${2:-}"

  # EXECUTE: 0 -> just write script
  # EXECUTE: 1 -> execute and write script
  # EXECUTE: 2 -> just execute
  local lEXECUTE="${3:-0}"
  local lPID=""

  if [[ "${lEXECUTE}" -ne 0 ]];then
    eval "${lCOMMAND}" || true &
    lPID="$!"
    disown "${lPID}" 2> /dev/null || true
  fi

  if [[ "${lEXECUTE}" -ne 2 ]];then
    if ! [[ -f "${lSCRIPT_WRITE}" ]]; then
      # just in case we have our script not already there we set it up now
      echo "#!/bin/bash -p" > "${lSCRIPT_WRITE}"
    fi

    # for the final script we need to adjust the paths:
    if [[ "${lCOMMAND}" == *"qemu-system-"* ]]; then
      # fix path for kernel: /external/EMBA_Live_bins/vmlinux.mipsel.4 -> ./vmlinux.mipsel.4
      # shellcheck disable=SC2001
      lCOMMAND=$(echo "${lCOMMAND}" | sed 's#-kernel\ .*\/EMBA_Live_bins\/#-kernel\ .\/#g')
      # shellcheck disable=SC2001
      lCOMMAND=$(echo "${lCOMMAND}" | sed "s#${IMAGE:-}#\.\/${IMAGE_NAME:-}#g")
      # shellcheck disable=SC2001
      lCOMMAND=$(echo "${lCOMMAND}" | sed "s|\"${LOG_PATH_MODULE:-}\"|\.|g")
      # remove the timeout from the qemu startup command
      lCOMMAND="${lCOMMAND#timeout --preserve-status --signal SIGINT [0-9]* }"
      # remove the tail kill command
      lCOMMAND="${lCOMMAND% ; pkill -9 -f tail.*-F.*}"
    fi

    echo "${lCOMMAND}" >> "${lSCRIPT_WRITE}"
  fi
}

service_online_check() {
  local lARCHIVE_PATH="${1:-}"
  local lIP_ADDRESS="${2:-}"
  # print details or do it silent
  local lPRINT_OUTPUT="${3:-1}"
  # lNW_SERVICE -> if set we check the availability of this service
  local lNW_SERVICE="${4:-NA}"

  local lMAX_CNT=100
  local lCNT=0

  local lNMAP_SERV_TCP_ARR=()
  local lSERVICE=""

  # we log how often we restart the system
  # if we are running into restarting the service more then MAX_SYSTEM_RESTART_CNT we return 1
  if [[ $(wc -l 2>/dev/null < "${TMP_DIR}/emulation_restarting.log") -gt "${MAX_SYSTEM_RESTART_CNT}" ]]; then
    print_output "[!] WARNING: Maximal restart counter reached ... no further service checks and system restarts performed"
    return 1
  fi

  mapfile -t lNMAP_SERV_TCP_ARR < <(grep -o -h -E "[0-9]+/open/tcp" "${lARCHIVE_PATH}/"*"_nmap_"*".gnmap" | cut -d '/' -f1 | sort -u || true)
  if [[ "${#lNMAP_SERV_TCP_ARR[@]}" -gt 0 ]]; then
    # we try this for lMAX_CNT times:
    while [[ "${lCNT}" -lt "${lMAX_CNT}" ]]; do
      # running through our extracted services and check if one of them is available via netcat
      for lSERVICE in "${lNMAP_SERV_TCP_ARR[@]}"; do
        if netcat -z -v -w1 "${lIP_ADDRESS}" "${lSERVICE}" >/dev/null; then
          [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[*] Network service ${ORANGE}${lSERVICE}${NC} available via the network" "no_log"
          # we exit for our relevant service is reachable
          # or we have no service that is relevant. This means we can
          # return as soon as some service is up and running
          if [[ "${lNW_SERVICE}" == "NA" ]] || [[ "${lSERVICE}" == "${lNW_SERVICE}" ]]; then
            return 0
          fi
        fi
      done
      [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[*] Waiting for responsive network services on ${ORANGE}${lIP_ADDRESS} - #${lCNT}/${lMAX_CNT}${NC}" "no_log"
      sleep 10
      lCNT=$((lCNT+1))
    done
  else
    [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[*] No network services detected for recovery ..." "no_log"
    return 1
  fi
  return 1
}

system_online_check() {
  local lIP_ADDRESS="${1:-}"
  # lNW_SERVICE -> if set we check the availability of this service
  local lNW_SERVICE="${2:-NA}"

  # STATE_CHECK_MECHANISM is exported by l10

  if [[ $(wc -l 2>/dev/null < "${TMP_DIR}/emulation_restarting.log") -gt "${MAX_SYSTEM_RESTART_CNT}" ]]; then
    print_output "[!] WARNING: Maximal restart counter reached ... no further service checks and system restarts performed"
    return 1
  fi

  # shellcheck disable=SC2153
  if [[ "${STATE_CHECK_MECHANISM:-PING}" == "PING" ]]; then
    if ping_check "${lIP_ADDRESS}" 0; then
      if service_online_check "${ARCHIVE_PATH}" "${lIP_ADDRESS}" 0 "${lNW_SERVICE}"; then
        return 0
      fi
    fi
  elif [[ "${STATE_CHECK_MECHANISM:-PING}" == "HPING" ]]; then
    if hping_check "${lIP_ADDRESS}" 0; then
      if service_online_check "${ARCHIVE_PATH}" "${lIP_ADDRESS}" 0 "${lNW_SERVICE}"; then
        return 0
      fi
    fi
  fi
  return 1
}

hping_check() {
  local lIP_ADDRESS="${1:-}"
  # print details or do it silent
  local lPRINT_OUTPUT="${2:-1}"
  local lCOUNTER=0
  # RESTARTER is used to indicate a non reachable system for another wait period after the system is recovered
  local lRESTARTER=0
  local lMAX_PING_CNT=50

  while ! [[ "$(hping3 -n -c 1 "${lIP_ADDRESS}" 2> /dev/null | grep -c "^len=")" -gt 0 ]]; do
    lRESTARTER=1
    [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[*] Waiting for restarted system ... hping mode" "no_log"
    ((lCOUNTER+=1))
    if [[ "${lCOUNTER}" -gt "${lMAX_PING_CNT}" ]]; then
      [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[-] System not recovered" "no_log"
      break
    fi
    sleep 6
  done

  if [[ "$(hping3 -n -c 1 "${lIP_ADDRESS}" 2>/dev/null | grep -c "^len=")" -gt 0 ]]; then
    [[ "${lPRINT_OUTPUT}" -eq 1 || "${lRESTARTER}" -eq 1 ]] && print_output "[*] System automatically maintained and should be available again in a few moments ... check ip address ${ORANGE}${lIP_ADDRESS}${NC}" "no_log"
    [[ "${lRESTARTER}" -eq 1 ]] && sleep 60
    export SYS_ONLINE=1
    export TCP="ok"
    return 0
  else
    export SYS_ONLINE=0
    export TCP="not ok"
    return 1
  fi
}

ping_check() {
  local lIP_ADDRESS="${1:-}"
  # print details or do it silent
  local lPRINT_OUTPUT="${2:-1}"
  local lCOUNTER=1
  local lRESTARTER=0

  while ! ping -c 1 "${lIP_ADDRESS}"; do
    lRESTARTER=1
    [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[*] Waiting for restarted system ... ping check #${lCOUNTER}/${MAX_PING_RETRY_CNT}" "no_log"
    ((lCOUNTER+=1))
    if [[ "${lCOUNTER}" -gt "${MAX_PING_RETRY_CNT}" ]]; then
      [[ "${lPRINT_OUTPUT}" -eq 1 ]] && print_output "[-] System not recovered" "no_log"
      break
    fi
    sleep 6
  done

  if ping -c 1 "${lIP_ADDRESS}" &> /dev/null; then
    [[ "${lPRINT_OUTPUT}" -eq 1 || "${lRESTARTER}" -eq 1 ]] && print_output "[*] System automatically maintained and should be available again in a few moments ... check ip address ${ORANGE}${lIP_ADDRESS}${NC}" "no_log"
    [[ "${lRESTARTER}" -eq 1 ]] && sleep 60
    export SYS_ONLINE=1
    export TCP="ok"
    return 0
  else
    export SYS_ONLINE=0
    export TCP="not ok"
    return 1
  fi
}

check_qemu_instance_l10() {
  export DEP_ERROR=0
  # using the dependency checker helper module:
  check_emulation_port "Running Qemu service" "2001"
  if [[ "${DEP_ERROR}" -eq 1 ]]; then
    while true; do
      DEP_ERROR=0
      check_emulation_port "Running Qemu service" "2001"
      if [[ "${DEP_ERROR}" -ne 1 ]]; then
        break
      fi
      if ! [[ -d "${LOG_DIR}" ]]; then
        # this usually happens if we automate analysis and remove the logging directory while this module was not finished at all
        break
      fi
      print_output "[-] Is there some Qemu instance already running?"
      print_output "[-] Check TCP ports 2000 - 2003!"
      sleep 10
    done
  fi
}

check_emulation_port() {
  local lTOOL_NAME="${1:-}"
  local lPORT_NR="${2:-}"

  print_output "    ""${lTOOL_NAME}"" - \\c" "no_log"
  if netstat -anpt | grep -q ":${lPORT_NR}[[:space:]] "; then
    echo -e "${RED}""not ok""${NC}"
    echo -e "${RED}""    System emulation services detected - check for running Qemu processes""${NC}"
    export DEP_ERROR=1
  else
    echo -e "${GREEN}""ok""${NC}"
  fi
}
