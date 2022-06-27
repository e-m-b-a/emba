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

I02_custom_os() {
  module_title "${FUNCNAME[0]}"
  # mongodb / cve-search
  echo -e "\\n""$MAGENTA""$BOLD""Installations for Ubuntu:jammy!""$NC"
  apt-get update -y 
  apt-get install -y -q mongodb-org 2>/dev/null
  if dpkg -l libssl1.1 &>/dev/null; then
    # libssl1.1 missing
    echo -e "\\n""$YELLOW""$BOLD""Installing libssl1.1 for mongodb!""$NC"
    echo "deb http://security.ubuntu.com/ubuntu impish-security main" | tee /etc/apt/sources.list.d/impish-security.list
    apt-get update
    apt-get install libssl1.1
  fi
}


