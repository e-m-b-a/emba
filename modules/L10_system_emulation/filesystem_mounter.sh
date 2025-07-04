#!/bin/bash -p
# see: https://developer.apple.com/library/archive/documentation/OpenSource/Conceptual/ShellScripting/ShellScriptSecurity/ShellScriptSecurity.html#//apple_ref/doc/uid/TP40004268-CH8-SW29

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

# Description:  Mounter/unmounter for L10 generated filesystems


## Color definition
export RED="\033[0;31m"
export GREEN="\033[0;32m"
export ORANGE="\033[0;33m"
export BLUE="\033[0;34m"
export MAGENTA="\033[0;35m"
export CYAN="\033[0;36m"
export NC="\033[0m"  # no color

delete_device_entry() {
  local lIMAGE="${1:-}"
  local lDEVICE="${2:-}"
  local lMNT_POINT="${3:-}"

  lIMAGE_PATH="$(realpath "${lIMAGE}")"
  lIMAGE_PATH="${lIMAGE_PATH%\/*}"
  lIMAGE_NAME="${lIMAGE/*\/}"

  echo "[*] Deleting device mapper for ${lIMAGE_PATH}/${lIMAGE_NAME}"

  kpartx -v -d "${lIMAGE_PATH}/${lIMAGE_NAME}"
  losetup -d "${lDEVICE}" &>/dev/null || true
  # just in case we check the output and remove our device:
  if losetup | grep -q "$(basename "${lIMAGE_NAME}")"; then
    losetup -d "$(losetup | grep "$(basename "${lIMAGE_NAME}")" | awk '{print $1}' || true)"
  fi
  dmsetup remove "$(basename "${lDEVICE}")" &>/dev/null || true
  rm -rf "${lMNT_POINT:?}/"* || true
  sleep 1
}

umount_qemu_image() {
  local lDEVICE=${1:-}
  sync
  if ! umount "${lDEVICE}"; then
    echo -e "[*] Warning: Normal umount was not successful. Trying to enforce unmounting of ${ORANGE}${lDEVICE}${NC}."
    umount -l "${lDEVICE}" || true
    umount -f "${lDEVICE}" || true
    sleep 5
  fi
}

add_partition_emulation() {
  local lIMAGE_PATH=""
  local lDEV_PATH="NA"
  local lFOUND=false
  local lCNT=0
  local lDEV_NR=0

  while (losetup | grep -q "${1}"); do
    local lLOOP=""
    ((lCNT+=1))
    lLOOP=$(losetup -a | grep "${1}" | sort -u)
    # we try to get rid of the entry nicely
    losetup -d "${lLOOP/:*}"
    if losetup -a | grep -q "${1}"; then
      # and now we go the brutal way
      losetup -D
      dmsetup remove_all -f &>/dev/null || true
    fi
    if [[ "${lCNT}" -gt 10 ]]; then
      break
    fi
    sleep 5
  done

  local lCNT=0
  while (! losetup -Pf "${1}"); do
    ((lCNT+=1))
    if [[ "${lCNT}" -gt 10 ]]; then
      break
    fi
    sleep 5
  done

  while (! "${lFOUND}"); do
    sleep 1
    ((lCNT+=1))
    local lLOSETUP_OUT_ARR=()
    mapfile -t lLOSETUP_OUT_ARR < <(losetup | grep -v "BACK-FILE")
    for LINE in "${lLOSETUP_OUT_ARR[@]}"; do
      lIMAGE_PATH=$(echo "${LINE}" | awk '{print $6}')
      if [[ "${lIMAGE_PATH}" == "${1}" ]]; then
        lDEV_PATH=$(echo "${LINE}" | awk '{print $1}')
        if [[ "$(dirname "${lDEV_PATH}")" == "/dev/loop" ]]; then
          # if we have the new naming like /dev/loop/0 -> dirname results in /dev/loop
          lDEV_NR=$(echo "${lDEV_PATH}" | rev | cut -d '/' -f1 | rev)
          lDEV_PATH="/dev/loop${lDEV_NR}p1"
        else
          # old naming like /dev/loop0 -> dirname results in /dev/
          lDEV_PATH=$(echo "${LINE}" | awk '{print $1}')p1
        fi
        if [[ -b "${lDEV_PATH}" ]]; then
          lFOUND=true
        fi
      fi
    done
    if [[ "${lCNT}" -gt 100 ]]; then
      # get an exit if nothing happens
      break
    fi
  done

  local lCNT=0
  while (! find "${lDEV_PATH}" -ls | grep -q "disk"); do
    sleep 1
    ((lCNT+=1))
    if [[ "${lCNT}" -gt 100 ]]; then
      # get an exit if nothing happens
      break
    fi
  done
  echo "${lDEV_PATH}"
}

image_mounter() {
  lIMAGE="${1:-}"

  lIMAGE_PATH="$(realpath "${lIMAGE}")"
  lIMAGE_PATH="${lIMAGE_PATH%\/*}"
  lIMAGE_NAME="${lIMAGE/*\/}"
  lMNT_POINT="${lIMAGE_PATH}"/mounter
  [[ ! -d "${lMNT_POINT}" ]] && mkdir "${lMNT_POINT}"

  echo -e "[*] Identify Qemu Image device for ${ORANGE}${lIMAGE_PATH}/${lIMAGE_NAME}${NC}"
  lDEVICE="$(add_partition_emulation "${lIMAGE_PATH}/${lIMAGE_NAME}")"
  if [[ "${lDEVICE}" == "NA" ]]; then
    lDEVICE="$(add_partition_emulation "${lIMAGE_PATH}/${lIMAGE_NAME}")"
  fi
  if [[ "${lDEVICE}" == "NA" ]]; then
    echo "[-] No Qemu Image device identified"
    exit 1
  fi
  sleep 1

  echo -e "[*] Device mapper created at ${ORANGE}${lDEVICE}${NC}"
  echo -e "[*] Mounting QEMU Image Partition 1 to ${ORANGE}${lMNT_POINT}${NC}"
  mount "${lDEVICE}" "${lMNT_POINT}" || true
  if mount | grep -q "${lMNT_POINT}"; then
    echo -e "[+] Mounting the filesystem was successful."
    echo -e "[+] The mounted firmware can be found in ${lMNT_POINT}"
  fi
}

image_unmounter() {
  # umount filesystem:
  lIMAGE="${1:-}"
  lIMAGE_PATH="$(realpath "${lIMAGE}")"
  lIMAGE_PATH="${lIMAGE_PATH%\/*}"
  lIMAGE_NAME="${lIMAGE/*\/}"
  lMNT_POINT="${lIMAGE_PATH}"/mounter

  if [[ ! -d "${lMNT_POINT}" ]]; then
    echo "[-] No mounted image identified"
    exit 1
  fi

  umount_qemu_image "${lMNT_POINT}"
  rm -r "${lMNT_POINT}"

  mapfile -t lDEVICE_ARR < <(losetup | grep "${lIMAGE_NAME}" | awk '{print $1}')
  for lDEVICE in "${lDEVICE_ARR[@]}"; do
    delete_device_entry "${lIMAGE}" "${lDEVICE}" "${lMNT_POINT}"
  done
}

## main functionality:
IMAGE="${1:-}"
MOUNTER="${2:-}"

if [[ ! -f "${IMAGE}" ]]; then
  echo -e "[-] No firmware image to mount found"
  exit 1
fi

IMAGE_DETAILS=$(file "${IMAGE}")

if [[ "${IMAGE_DETAILS}" != *"DOS/MBR boot sector; partition"* ]]; then
  echo -e "[-] No firmware image to mount found"
  exit 1
fi

if ! [[ ${EUID} -eq 0 ]] ; then
  echo -e "[-] Setting up the firmware mounter requires root privileges"
  exit 1
fi

if [[ "${MOUNTER}" != "mount" && "${MOUNTER}" != "umount" ]]; then
  echo -e "[-] Specify \"mount\" for mounting a filesystem or \"umount\" for unmounting a filesystem"
  exit 1
fi

if [[ "${MOUNTER}" == "mount" ]]; then
  image_mounter "${IMAGE}"
elif [[ "${MOUNTER}" == "umount" ]]; then
  image_unmounter "${IMAGE}"
fi

