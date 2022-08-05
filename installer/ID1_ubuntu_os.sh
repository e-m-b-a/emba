#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Benedikt Kuehne
# Contributor(s): Michael Messner

# Description: Helper/preinstaller module for (unix)-OS other than kali
# 

ID1_ubuntu_os() {
  module_title "${FUNCNAME[0]}"
  if [[ "$OTHER_OS" -eq 1 ]] && [[ "$UBUNTU_OS" -eq 1 ]]; then
    # mongodb / cve-search
    echo -e "\\n""$MAGENTA""$BOLD""Installations for Ubuntu:jammy!""$NC"

    print_tool_info "notification-daemon" 1
    apt-get install "${INSTALL_APP_LIST[@]}" -y

    if ! [[ -f "/usr/share/dbus-1/services/org.freedesktop.Notifications.service" ]] && [[ -f "/usr/lib/notification-daemon/notification-daemon" ]]; then
      echo "[D-BUS Service]" > /usr/lib/notification-daemon/notification-daemon
      echo "Name=org.freedesktop.Notifications" >> /usr/lib/notification-daemon/notification-daemon
      echo "Exec=/usr/lib/notification-daemon/notification-daemon" >> /usr/lib/notification-daemon/notification-daemon
    fi

    if ! dpkg -l libssl1.1 &>/dev/null; then
        # libssl1.1 missing
        echo -e "\\n""$BOLD""Installing libssl1.1 for mongodb!""$NC"
        #echo "deb http://security.ubuntu.com/ubuntu impish-security main" | tee /etc/apt/sources.list.d/impish-security.list
        wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl-dev_1.1.1-1ubuntu2.1~18.04.20_amd64.deb -O external/libssl-dev_1.1.1-1ubuntu2.1~18.04.20_amd64.deb
        wget http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1-1ubuntu2.1~18.04.20_amd64.deb -O external/libssl1.1_1.1.1-1ubuntu2.1~18.04.20_amd64.deb
        dpkg -i external/libssl1.1_1.1.1-1ubuntu2.1~18.04.20_amd64.deb
        dpkg -i external/libssl-dev_1.1.1-1ubuntu2.1~18.04.20_amd64.deb
        rm external/libssl1.1_1.1.1-1ubuntu2.1~18.04.20_amd64.deb
        rm external/libssl-dev_1.1.1-1ubuntu2.1~18.04.20_amd64.deb
    fi

    if [[ "$WSL" -eq 1 ]]; then
      # docker installation on Ubuntu jammy in WSL environment is somehow broken
      echo -e "\\n""$MAGENTA""$BOLD""Docker installation for Ubuntu:jammy in WSL environment!""$NC"

      apt-get install lsb-release ca-certificates apt-transport-https software-properties-common -y

      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

      echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

      apt-get update
      apt-get install docker-ce -y
    fi
  fi
}


