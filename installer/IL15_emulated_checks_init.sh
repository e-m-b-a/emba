#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
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

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then
    INSTALL_APP_LIST=()
    cd "${HOME_PATH}" || ( echo "Could not install EMBA component system emulator" && exit 1 )
    print_git_info "testssl" "EMBA-support-repos/testssl.sh.git" "TestSSL.sh"
    print_git_info "Nikto" "sullo/nikto" "external/nikto"

    print_tool_info "bind9-dnsutils" 1
    print_tool_info "nmap" 1
    print_tool_info "snmp" 1
    # nikto is somehow complicated with our read only container -> we install it manually
    # print_tool_info "nikto" 1
    # tools only available on Kali Linux:
    if [[ "${OTHER_OS}" -eq 0 ]] && [[ "${UBUNTU_OS}" -eq 0 ]]; then
      print_tool_info "snmpcheck" 1
    else
      echo -e "${RED}""${BOLD}""Not installing snmpcheck. Your EMBA installation will be incomplete""${NC}"
    fi
    print_tool_info "python3-pip" 1
    # mini UPnP client
    print_tool_info "miniupnpc" 1
    # print_tool_info "cutycapt" 1

    # needed for cutycapt
    # print_tool_info "xvfb" 1
    # print_tool_info "libqt5webkit5" 1
    # print_tool_info "xfonts-100dpi" 1
    # print_tool_info "xfonts-75dpi" 1
    # print_tool_info "xfonts-cyrillic" 1
    # print_tool_info "xorg" 1
    # print_tool_info "dbus-x11" 1
    # print_tool_info "g++" 1
    # needed for cutycapt
    #
    # future extension
    print_tool_info "libxslt1-dev"
    print_tool_info "libxml2-dev"
    # currently upnpclient failes during installing lxml:
    #   ERROR: Failed building wheel for lxml -> see also https://github.com/flyte/upnpclient/pull/44/files
    #   pip3 install lxml==5.3.1
    #   pip3 install upnpclient --no-dependencies lxml
    print_pip_info "lxml" "5.3.1"
    print_pip_info "upnpclient"
    print_pip_info "beautifulsoup4"

    # chromium headless shell
    print_tool_info "libnss3"
    print_tool_info "libatk1.0-0t64"
    print_tool_info "libatk-bridge2.0-dev"
    print_tool_info "libxkbcommon0"
    print_tool_info "libxdamage1"
    print_tool_info "libasound2t64"
    print_tool_info "npm"

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""The live testing dependencies (if not already on the system) will be downloaded and installed!""${NC}"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )

      apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

      if ! [[ -d external/testssl.sh ]]; then
        git clone --depth 1 https://github.com/EMBA-support-repos/testssl.sh.git external/testssl.sh
      fi

      if ! [[ -d external/nikto ]]; then
        git clone https://github.com/sullo/nikto.git external/nikto
      fi

      # chrome-headless-shell
      cd ./external || ( echo "Could not install EMBA component chrome-headless-shell" && exit 1 )
      npx -y @puppeteer/browsers install chrome-headless-shell@stable
      cd "${HOME_PATH}" || ( echo "Could not install EMBA component chrome-headless-shell@stable" && exit 1 )

      # EMBAbite fuzzer used this:
      # pip_install "upnpclient"
      pip_install "lxml==5.3.1"
      # pip_install helper function does not support further parameters
      # Todo: fix this
      pip3 install "upnpclient" --no-dependencies lxml
      ;;
    esac
  fi
}
