#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens AG
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Benedikt Kuehne

# Description: Helper/preinstaller module for (unix)-OS other than kali
# 

I02_ubuntu_os() {
  module_title "${FUNCNAME[0]}"
  # mongodb / cve-search
  echo -e "\\n""$MAGENTA""$BOLD""Installations for Ubuntu:jammy!""$NC"
  if ! dpkg -l libssl1.1 &>/dev/null; then
    # libssl1.1 missing
    echo -e "\\n""$BOLD""Installing libssl1.1 for mongodb!""$NC"
    echo "deb http://security.ubuntu.com/ubuntu impish-security main" | tee /etc/apt/sources.list.d/impish-security.list
    apt-get update
    print_tool_info "libssl1.1" 1
    apt-get install "${INSTALL_APP_LIST[@]}" -y
  fi
}


