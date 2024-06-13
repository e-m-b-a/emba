#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2024 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description:  Searches known locations for package management information

S08_package_mgmt_extractor()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search package management details"
  pre_module_reporter "${FUNCNAME[0]}"

  local NEG_LOG=0
  export DEBIAN_MGMT_STATUS=()
  export OPENWRT_MGMT_CONTROL=()

  debian_status_files_search
  openwrt_control_files_search
  rpm_package_files_search

  [[ "${#DEBIAN_MGMT_STATUS[@]}" -gt 0 || "${#OPENWRT_MGMT_CONTROL[@]}" -gt 0 || "${#RPM_PACKAGES[@]}" -gt 0 ]] && NEG_LOG=1
  module_end_log "${FUNCNAME[0]}" "${NEG_LOG}"
}

debian_status_files_search() {
  sub_module_title "Debian package management identification"

  local PACKAGING_SYSTEM="debian"
  local PACKAGE_FILE=""
  local DEBIAN_PACKAGES=()
  local PACKAGE_VERSION=""
  local PACKAGE=""
  local VERSION=""

  mapfile -t DEBIAN_MGMT_STATUS < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -path "*dpkg/status" -type f)

  if [[ -v DEBIAN_MGMT_STATUS[@] ]] ; then
    write_csv_log "Packaging system" "package file" "package" "original version" "stripped version"
    print_output "[*] Found ${ORANGE}${#DEBIAN_MGMT_STATUS[@]}${NC} debian package management files:"
    for PACKAGE_FILE in "${DEBIAN_MGMT_STATUS[@]}" ; do
      print_output "$(indent "$(orange "$(print_path "${PACKAGE_FILE}")")")"
    done
    for PACKAGE_FILE in "${DEBIAN_MGMT_STATUS[@]}" ; do
      if grep -q "Package: " "${PACKAGE_FILE}"; then
        mapfile -t DEBIAN_PACKAGES < <(grep "^Package: \|^Status: \|^Version: " "${PACKAGE_FILE}" | sed -z 's/\nVersion: / - Version: /g' | sed -z 's/\nStatus: / - Status: /g')
        print_output "[*] Found debian package details:"
        for PACKAGE_VERSION in "${DEBIAN_PACKAGES[@]}" ; do
          # Package: xxd - Status: install ok installed - 2:8.2.3995-1+b3
          PACKAGE=$(safe_echo "${PACKAGE_VERSION}" | awk '{print $2}' | tr -dc '[:print:]')
          VERSION=${PACKAGE_VERSION/*Version:\ /}
          # What is the state in an offline firmware image? Is it installed or not?
          # Futher investigation needed!
          # if ! echo "${PACKAGE_VERSION}" | grep -q "installed"; then
          #  # a not installed package - skip it
          #  continue
          # fi
          clean_package_versions "${VERSION}"
          print_output "[*] Debian package details: ${ORANGE}${PACKAGE_FILE}${NC} - ${ORANGE}${PACKAGE}${NC} - ${ORANGE}${VERSION}${NC}"
          write_csv_log "${PACKAGING_SYSTEM}" "${PACKAGE_FILE}" "${PACKAGE}" "${VERSION}" "${STRIPPED_VERSION}"
        done
      fi
    done
  else
    print_output "[-] No debian package files found!"
  fi
}

openwrt_control_files_search() {
  sub_module_title "OpenWRT package management identification"

  local PACKAGING_SYSTEM="OpenWRT"
  local PACKAGE_FILE=""
  local OPENWRT_PACKAGES=()
  local PACKAGE_VERSION=""
  local PACKAGE=""
  local VERSION=""

  mapfile -t OPENWRT_MGMT_CONTROL < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -path "*opkg/info/*.control" -type f)

  if [[ -v OPENWRT_MGMT_CONTROL[@] ]] ; then
    write_csv_log "Packaging system" "package file" "package" "version"
    print_output "[*] Found ${ORANGE}${#OPENWRT_MGMT_CONTROL[@]}${NC} OpenWRT package management files."
    for PACKAGE_FILE in "${OPENWRT_MGMT_CONTROL[@]}" ; do
      if grep -q "Package: " "${PACKAGE_FILE}"; then
        mapfile -t OPENWRT_PACKAGES < <(grep "^Package: \|^Version: " "${PACKAGE_FILE}" | sed -z 's/\nVersion: / - Version: /g')
        for PACKAGE_VERSION in "${OPENWRT_PACKAGES[@]}" ; do
          PACKAGE=$(safe_echo "${PACKAGE_VERSION}" | awk '{print $2}' | tr -dc '[:print:]')
          VERSION=${PACKAGE_VERSION/*Version:\ /}
          # What is the state in an offline firmware image? Is it installed or not?
          # Futher investigation needed!
          clean_package_versions "${VERSION}"
          print_output "[*] OpenWRT package details: ${ORANGE}${PACKAGE_FILE}${NC} - ${ORANGE}${PACKAGE}${NC} - ${ORANGE}${VERSION}${NC}"
          write_csv_log "${PACKAGING_SYSTEM}" "${PACKAGE_FILE}" "${PACKAGE}" "${VERSION}" "${STRIPPED_VERSION}"
        done
      fi
    done
  else
    print_output "[-] No OpenWRT package files found!"
  fi
}

rpm_package_files_search() {
  sub_module_title "RPM package management identification"
  export RPM_PACKAGES=()

  if ! command -v rpm > /dev/null; then
    print_output "[-] RPM command not found ... not executing RPM test module"
    return
  fi

  local PACKAGING_SYSTEM="RPM"
  local RPM_PACKAGE_DBS=()
  local PACKAGE_FILE=""
  local RPM_DIR=""
  local PACKAGE_VERSION=""
  local PACKAGE_NAME=""
  local PACKAGE_AND_VERSION=""

  mapfile -t RPM_PACKAGE_DBS < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -xdev -path "*rpm/Packages" -type f)

  if [[ -v RPM_PACKAGE_DBS[@] ]] ; then
    write_csv_log "Packaging system" "package dir" "package" "version"
    print_output "[*] Found ${ORANGE}${#RPM_PACKAGE_DBS[@]}${NC} RPM package management directories."
    for PACKAGE_FILE in "${RPM_PACKAGE_DBS[@]}" ; do
      RPM_DIR="$(dirname "${PACKAGE_FILE}")"
      # not sure this works on an offline system - we need further tests on this:
      mapfile -t RPM_PACKAGES < <(rpm -qa --dbpath "${RPM_DIR}" || true)
      for PACKAGE_AND_VERSION in "${RPM_PACKAGES[@]}" ; do
        PACKAGE_VERSION=$(rpm -qi --dbpath "${RPM_DIR}" "${PACKAGE_AND_VERSION}" | grep Version | awk '{print $3}' || true)
        PACKAGE_NAME=$(rpm -qi --dbpath "${RPM_DIR}" "${PACKAGE_AND_VERSION}" | grep Version | awk '{print $1}' || true)
        print_output "[*] RPM package details: ${ORANGE}${PACKAGE_NAME}${NC} - ${ORANGE}${PACKAGE_VERSION}${NC}"
        write_csv_log "${PACKAGING_SYSTEM}" "${RPM_DIR}" "${PACKAGE_NAME}" "${PACKAGE_VERSION}"
      done
    done
  else
    print_output "[-] No RPM package management database found!"
  fi
}

clean_package_versions() {
  local VERSION_="${1:-}"
  export STRIPPED_VERSION=""

  # usually we get a version like 1.2.3-4 or 1.2.3-0kali1bla or 1.2.3-unknown
  # this is a quick approach to clean this version identifier
  # there is a lot of room for future improvement
  STRIPPED_VERSION=$(safe_echo "${VERSION_}" | sed -r 's/-[0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-unknown$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+kali[0-9]+.*$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+ubuntu[0-9]+.*$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+build[0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+\.[0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/-[0-9]+\.[a-d][0-9]+$//g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/:[0-9]:/:/g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | sed -r 's/^[0-9]://g')
  STRIPPED_VERSION=$(safe_echo "${STRIPPED_VERSION}" | tr -dc '[:print:]')
}
