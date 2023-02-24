#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
# Copyright 2020-2023 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Installs live testing tools - used for full system emulation

IL15_emulated_checks_init() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    INSTALL_APP_LIST=()
    cd "$HOME_PATH" || ( echo "Could not install EMBA component system emulator" && exit 1 )
    print_git_info "routersploit" "m-1-k-3/routersploit" "The RouterSploit Framework is an open-source exploitation framework dedicated to embedded devices. (EMBA fork)"
    print_file_info "routersploit_patch" "FirmAE routersploit patch" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/analyses/routersploit_patch" "external/routersploit/docs/routersploit_patch"
    print_git_info "testssl" "EMBA-support-repos/testssl.sh.git" "TestSSL.sh"
    print_file_info "arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz" "Arachni web application scanner" "https://github.com/Arachni/arachni/releases/download/v1.6.1.3/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz" "external/arachni"

    print_tool_info "dnsutils" 1
    print_tool_info "nmap" 1
    print_tool_info "snmp" 1
    print_tool_info "nikto" 1
    # tools only available on Kali Linux:
    if [[ "$OTHER_OS" -eq 0 ]] && [[ "$UBUNTU_OS" -eq 0 ]]; then
      print_tool_info "snmpcheck" 1
    else
      echo -e "$RED""$BOLD""Not installing snmpcheck. Your EMBA installation will be incomplete""$NC"
    fi
    print_tool_info "python3-pip" 1
    print_tool_info "cutycapt" 1

    # needed for cutycapt
    print_tool_info "xvfb" 1
    # print_tool_info "libqt5webkit5" 1
    # print_tool_info "xfonts-100dpi" 1
    # print_tool_info "xfonts-75dpi" 1
    # print_tool_info "xfonts-cyrillic" 1
    # print_tool_info "xorg" 1
    # print_tool_info "dbus-x11" 1
    # print_tool_info "g++" 1
    # needed for cutycapt

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The live testing dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
  
      apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends
 
      download_file "arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz" "https://github.com/Arachni/arachni/releases/download/v1.6.1.3/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz" "external/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz"
      if ! [[ -d external/arachni/ ]]; then
        mkdir external/arachni/
      fi
      tar -xzf external/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz -C external/arachni/
      rm external/arachni-1.6.1.3-0.6.1.1-linux-x86_64.tar.gz
      if ! grep -q arachni /etc/passwd; then
        useradd arachni
      fi
      chown arachni external/arachni -R
      chown arachni external/arachni -R

      if ! [[ -d external/testssl.sh ]]; then
        git clone --depth 1 https://github.com/EMBA-support-repos/testssl.sh.git external/testssl.sh
      fi

      if ! [[ -d external/routersploit ]]; then
        # currently this gentle guy has started to update routersploit on this fork:
        git clone --branch dev_rework https://github.com/GH0st3rs/routersploit.git external/routersploit
      fi

      cd external/routersploit || ( echo "Could not install EMBA component routersploit" && exit 1 )

      if ! [[ -f "external/routersploit/docs/routersploit_patch" ]]; then
        # is already applied in the used fork (leave this here for future usecases):
        download_file "routersploit_patch" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/analyses/routersploit_patch" "docs/routersploit_patch"
        patch -f -p1 < docs/routersploit_patch || true
      else
        echo -e "$GREEN""routersploit_patch already downloaded""$NC"
      fi

      python3 -m pip install -r requirements.txt --break-system-packages
      # if the default log path is set we reset it to /tmp
      if ! grep -q "/tmp/routersploit.log" rsf.py; then
        sed -i 's/routersploit\.log/\/tmp\/routersploit\.log/' ./rsf.py
      fi

      cd "$HOME_PATH" || ( echo "Could not install EMBA component routersploit" && exit 1 )

      # we need to safe /var/lib/nikto now
      if [[ -d /var/lib/nikto ]]; then
        echo "[*] Backup nikto directory to /external"
        mkdir external/var_lib_nikto
        cp -pr /var/lib/nikto external/var_lib_nikto
      fi

      ;;
    esac
  fi
}
