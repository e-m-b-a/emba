#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2025-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Zenity based EMBA launcher with basic wizard functionality
#               start with ./launcher.sh from the EMBA installation directory

EMBA_PROFILE="default-scan.emba"

if ! command -v zenity >/dev/null ; then
  echo "[-] WARNING: zenity package not installed"
  echo "[*] Install it with sudo apt-get install zenity"
  exit 1
fi
if ! [[ -d ./helpers ]]; then
  echo "[-] WARNING: Start this launcher from the EMBA installation directory."
  exit 1
fi
if ! [[ -d ./external ]]; then
  echo "[-] WARNING: No EMBA external directory available - have you run the installer.sh script?"
  exit 1
fi

# shellcheck source=./helpers/helpers_emba_print.sh
source ./helpers/helpers_emba_print.sh

FIRMWARE_FILE=$(zenity --file-selection --icon=./helpers/emba.svg --title="EMBA firmware analysis - Firmware file" 2>/dev/null)

if [[ -z "${FIRMWARE_FILE}" ]]; then
  zenity --info --icon=./helpers/emba.svg --text="WARNING: NO firmware file available ..." 2>/dev/null &
  print_output "[-] WARNING: NO firmware file available ..." "no_log"
  exit 1
fi

EMBA_BASE_LOG_DIR=$(zenity --file-selection --directory --icon=./helpers/emba.svg --title="EMBA firmware analysis - base log directory" 2>/dev/null)
if [[ -z "${EMBA_BASE_LOG_DIR}" ]]; then
  zenity --info --icon=./helpers/emba.svg --text="WARNING: NO base log directory chosen ..." 2>/dev/null &
  print_output "[-] WARNING: NO base log directory chosen ..." "no_log"
  exit 1
fi

FW_VENDOR=$(zenity --entry --icon=./helpers/emba.svg --title="Add Firmware vendor" --text="Enter vendor of firmware:" 2>/dev/null)
if [[ -z "${FW_VENDOR}" ]]; then
  zenity --info --icon=./helpers/emba.svg --text="WARNING: NO vendor name available ..." 2>/dev/null &
  print_output "[-] WARNING: NO vendor name available ..." "no_log"
  exit 1
fi
if ! [[ "${FW_VENDOR}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  zenity --info --icon=./helpers/emba.svg --text="Invalid input detected - alphanumerical only" 2>/dev/null &
  print_output "[-] Invalid input detected - alphanumerical only" "no_log"
  exit 1
fi

FW_VERSION=$(zenity --entry --icon=./helpers/emba.svg --title="Add Firmware version" --text="Enter version of firmware:" 2>/dev/null)
if [[ -z "${FW_VERSION}" ]]; then
  zenity --info --icon=./helpers/emba.svg --text="WARNING: NO firmware version available ..." 2>/dev/null &
  print_output "[-] WARNING: NO firmware version available ..." "no_log"
  exit 1
fi
if ! [[ "${FW_VERSION}" =~ ^[a-zA-Z0-9./_:+'-']+$ ]]; then
  zenity --info --icon=./helpers/emba.svg --text="Invalid input detected - versions aka 1.2.3-a:b only" 2>/dev/null &
  print_output "[-] Invalid input detected - versions aka 1.2.3-a:b only" "no_log"
  exit 1
fi

if zenity --question --icon=./helpers/emba.svg --title="EMBA firmware analysis" --text="Would you like to start the EMBA firmware analysis process?" 2>/dev/null; then
  if ! sudo -nv; then
    zenity --info --icon=./helpers/emba.svg --text="Root privileges are requested via sudo on cli" 2>/dev/null &
  fi

  EMBA_LOG_DIR="emba_logs_$(basename "${FIRMWARE_FILE}")"
  EMBA_LOG_DIR="${EMBA_BASE_LOG_DIR}/${EMBA_LOG_DIR//\./_}"
  print_output "[*] Using Firmware file for analysis: ${FIRMWARE_FILE}" "no_log"
  print_output "[*] Using log directory for analysis: ${EMBA_LOG_DIR}" "no_log"
  print_output "[*] Using vendor name for analysis: ${FW_VENDOR}" "no_log"
  print_output "[*] Using firmware version for analysis: ${FW_VERSION}" "no_log"

  sudo ./emba -l "${EMBA_LOG_DIR}" -f "${FIRMWARE_FILE}" -p ./scan-profiles/"${EMBA_PROFILE}" -X "${FW_VERSION}" -Y "${FW_VENDOR}" -y
  EMBA_RET=$?
  if [[ "${EMBA_RET}" -eq 0 ]]; then
    if zenity --progress --text="EMBA run was successful - opening web report?" --percentage=100 2>/dev/null; then
      if command -v firefox >/dev/null ; then
        firefox "${EMBA_LOG_DIR}/html-report/index.html" &
      else
        print_output "[-] firefox not available ... install it and launch the web report" "no_log"
      fi
    fi
  else
    zenity --error --icon=./helpers/emba.svg --text="EMBA error - check cli output" 2>/dev/null
    exit 1
  fi
else
  zenity --info --icon=./helpers/emba.svg --text="EMBA not started - help dialog printed on CLI" 2>/dev/null &
  ./emba -h
  exit 1
fi
