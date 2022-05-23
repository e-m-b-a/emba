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
  # Future work: rpm, ...
  #rpm_package_files_search

  module_end_log "${FUNCNAME[0]}" "${#DEBIAN_MGMT_STATUS[@]}"
}

debian_status_files_search() {
  mapfile -t DEBIAN_MGMT_STATUS < <(find "$FIRMWARE_PATH" "${EXCL_FIND[@]}" -xdev -path "*dpkg/status" -type f)

  PACKAGING_SYSTEM="debian"
  if [[ -v DEBIAN_MGMT_STATUS[@] ]] ; then
    write_csv_log "Packaging system" "package file" "package" "version"
    print_output "[+] Found ""${#DEBIAN_MGMT_STATUS[@]}"" debian package management files:"
    for PACKAGE_FILE in "${DEBIAN_MGMT_STATUS[@]}" ; do
      if grep -q "Package: " "$PACKAGE_FILE"; then
        print_output "$(indent "$(orange "$(print_path "$PACKAGE_FILE")")")"
        mapfile -t DEBIAN_PACKAGES < <(grep "^Package: \|^Version: " "$PACKAGE_FILE" | sed -z 's/\nVersion: / - /g')
        print_output ""
        print_output "[+] Found debian package details:"
        for PACKAGE_VERSION in "${DEBIAN_PACKAGES[@]}" ; do
          PACKAGE=$(echo "$PACKAGE_VERSION" | awk '{print $2}')
          VERSION=$(echo "$PACKAGE_VERSION" | awk '{print $4}')
          print_output "[*] Debian package details: $ORANGE$PACKAGE_FILE$NC - $ORANGE$PACKAGE$NC - $ORANGE$VERSION$NC"
          write_csv_log "$PACKAGING_SYSTEM" "$PACKAGE_FILE" "$PACKAGE" "$VERSION"
        done
      fi
    done
  else
    print_output "[-] No debian package files found!"
  fi

}

