#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
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
  if [[ "${OTHER_OS}" -eq 1 ]] && [[ "${UBUNTU_OS}" -eq 1 ]]; then
    # mongodb / cve-search
    echo -e "\\n""${MAGENTA}""${BOLD}""Installations for Ubuntu:jammy!""${NC}"

    print_tool_info "notification-daemon" 1
    print_tool_info "dbus" 1
    print_tool_info "dbus-x11" 1
    # To using ubi and nandsim with modprobe, the linux-modules-extra package must be installed. (Ubuntu 22.04)
    print_tool_info "linux-modules-extra-$(uname -r)" 1

    # is not available in Ubuntu 24.04 -> need to check on this:
    # print_tool_info "libnotify-cil-dev" 1

    if [[ -f /etc/apt/apt.conf.d/20auto-upgrades ]]; then
      echo "[*] Testing for unattended update settings"
      if awk '{print $2}' /etc/apt/apt.conf.d/20auto-upgrades | grep -q "1"; then
        echo -e "\\n""${MAGENTA}""${BOLD}""Automatic updates are enabled - this could result in unexpected behavior during installation!""${NC}"
      fi
    fi

    apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

    if ! [[ -f "/usr/share/dbus-1/services/org.freedesktop.Notifications.service" ]] && [[ -f "/usr/lib/notification-daemon/notification-daemon" ]]; then
      echo "[D-BUS Service]" > /usr/share/dbus-1/services/org.freedesktop.Notifications.service
      echo "Name=org.freedesktop.Notifications" >> /usr/share/dbus-1/services/org.freedesktop.Notifications.service
      echo "Exec=/usr/lib/notification-daemon/notification-daemon" >> /usr/share/dbus-1/services/org.freedesktop.Notifications.service
    fi

    if [[ "${WSL}" -eq 1 ]]; then
      # docker installation on Ubuntu jammy in WSL environment is somehow broken
      echo -e "\\n""${MAGENTA}""${BOLD}""Docker installation for Ubuntu:jammy in WSL environment!""${NC}"

      apt-get install lsb-release ca-certificates apt-transport-https software-properties-common -y

      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

      echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

      apt-get update
      apt-get install docker-ce -y
    fi
  fi
}


