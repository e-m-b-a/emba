#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Searches known locations for package management information

S08_package_mgmt_extractor()
{
  module_log_init "${FUNCNAME[0]}"
  module_title "Search package management details"
  pre_module_reporter "${FUNCNAME[0]}"

  debian_status_files_search
  openwrt_control_files_search
  # Future work: rpm, ...
  #rpm_package_files_search

  module_end_log "${FUNCNAME[0]}" "${#DEBIAN_MGMT_STATUS[@]}"
}

debian_status_files_search() {
  sub_module_title "Debian package management identification"
  mapfile -t DEBIAN_MGMT_STATUS < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -path "*dpkg/status" -type f)

  PACKAGING_SYSTEM="debian"
  local PACKAGE_FILE=""
  local STRIPPED_VERSION=""
  if [[ -v DEBIAN_MGMT_STATUS[@] ]] ; then
    write_csv_log "Packaging system" "package file" "package" "original version" "stripped version"
    print_output "[*] Found $ORANGE${#DEBIAN_MGMT_STATUS[@]}$NC debian package management files:"
    for PACKAGE_FILE in "${DEBIAN_MGMT_STATUS[@]}" ; do
      print_output "$(indent "$(orange "$(print_path "$PACKAGE_FILE")")")"
    done
    for PACKAGE_FILE in "${DEBIAN_MGMT_STATUS[@]}" ; do
      if grep -q "Package: " "$PACKAGE_FILE"; then
        mapfile -t DEBIAN_PACKAGES < <(grep "^Package: \|^Version: " "$PACKAGE_FILE" | sed -z 's/\nVersion: / - /g')
        print_output ""
        print_output "[*] Found debian package details:"
        for PACKAGE_VERSION in "${DEBIAN_PACKAGES[@]}" ; do
          PACKAGE=$(echo "$PACKAGE_VERSION" | awk '{print $2}')
          VERSION=$(echo "$PACKAGE_VERSION" | awk '{print $4}')
          clean_package_versions "$VERSION"
          print_output "[*] Debian package details: $ORANGE$PACKAGE_FILE$NC - $ORANGE$PACKAGE$NC - $ORANGE$VERSION$NC"
          write_csv_log "$PACKAGING_SYSTEM" "$PACKAGE_FILE" "$PACKAGE" "$VERSION" "$STRIPPED_VERSION"
        done
      fi
    done
  else
    print_output "[-] No debian package files found!"
  fi
}

openwrt_control_files_search() {
  sub_module_title "OpenWRT package management identification"
  mapfile -t OPENWRT_MGMT_CONTROL < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -path "*opkg/info/*.control" -type f)

  PACKAGING_SYSTEM="OpenWRT"
  local PACKAGE_FILE=""
  local STRIPPED_VERSION=""
  if [[ -v OPENWRT_MGMT_CONTROL[@] ]] ; then
    write_csv_log "Packaging system" "package file" "package" "version"
    print_output "[*] Found $ORANGE{#OPENWRT_MGMT_CONTROL[@]}$NC OpenWRT package management files."
    for PACKAGE_FILE in "${OPENWRT_MGMT_CONTROL[@]}" ; do
      if grep -q "Package: " "$PACKAGE_FILE"; then
        mapfile -t OPENWRT_PACKAGES < <(grep "^Package: \|^Version: " "$PACKAGE_FILE" | sed -z 's/\nVersion: / - /g')
        print_output ""
        for PACKAGE_VERSION in "${OPENWRT_PACKAGES[@]}" ; do
          PACKAGE=$(echo "$PACKAGE_VERSION" | awk '{print $2}')
          VERSION=$(echo "$PACKAGE_VERSION" | awk '{print $4}')
          clean_package_versions "$VERSION"
          print_output "[*] OpenWRT package details: $ORANGE$PACKAGE_FILE$NC - $ORANGE$PACKAGE$NC - $ORANGE$VERSION$NC"
          write_csv_log "$PACKAGING_SYSTEM" "$PACKAGE_FILE" "$PACKAGE" "$VERSION" "$STRIPPED_VERSION"
        done
      fi
    done
  else
    print_output "[-] No OpenWRT package files found!"
  fi
}

clean_package_versions() {
  local VERSION_="${1:-}"
  # usually we get a version like 1.2.3-4 or 1.2.3-0kali1bla or 1.2.3-unknown
  # this is a quick approach to clean this version identifier
  # there is a lot of room for future improvement
  STRIPPED_VERSION=$(echo "$VERSION_" | sed -r 's/-[0-9]+$//g')
  STRIPPED_VERSION=$(echo "$STRIPPED_VERSION" | sed -r 's/-unknown$//g')
  STRIPPED_VERSION=$(echo "$STRIPPED_VERSION" | sed -r 's/-[0-9]+kali[0-9]+.*$//g')
  STRIPPED_VERSION=$(echo "$STRIPPED_VERSION" | sed -r 's/-[0-9]+ubuntu[0-9]+.*$//g')
  STRIPPED_VERSION=$(echo "$STRIPPED_VERSION" | sed -r 's/-[0-9]+build[0-9]+$//g')
  STRIPPED_VERSION=$(echo "$STRIPPED_VERSION" | sed -r 's/-[0-9]+\.[0-9]+$//g')
  STRIPPED_VERSION=$(echo "$STRIPPED_VERSION" | sed -r 's/-[0-9]+\.[a-d][0-9]+$//g')
  STRIPPED_VERSION=$(echo "$STRIPPED_VERSION" | sed -r 's/:[0-9]:/:/g')
  STRIPPED_VERSION=$(echo "$STRIPPED_VERSION" | sed -r 's/^[0-9]://g')
}
