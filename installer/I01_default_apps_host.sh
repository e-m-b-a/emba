#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Basic applications needed for EMBA to run

I01_default_apps_host() {
  module_title "${FUNCNAME[0]}"

  echo -e "\\nTo use EMBA, some applications must be installed and some data (database for CVS for example) downloaded and parsed."
  echo -e "\\n""${ORANGE}""${BOLD}""These applications will be installed/updated:""${NC}"
  print_tool_info "jq" 1
  print_tool_info "shellcheck" 1
  print_tool_info "unzip" 1
  print_tool_info "bc" 1
  print_tool_info "coreutils" 1
  print_tool_info "ncurses-bin" 1
  print_tool_info "libnotify-bin" 1
  print_tool_info "inotify-tools" 1
  print_tool_info "dbus-x11" 1
  # as we need it for multiple tools we can install it by default
  print_tool_info "git" 1
  print_tool_info "net-tools" 1
  print_tool_info "curl" 1
  print_tool_info "file" 1

  # python3.10-request
  print_tool_info "python3-pip" 1
  print_pip_info "requests"

  if [[ "${LIST_DEP}" -eq 1 ]] ; then
    ANSWER=("n")
  else
    echo -e "\\n""${MAGENTA}""${BOLD}""These applications will be installed/updated!""${NC}"
    ANSWER=("y")
  fi
  case ${ANSWER:0:1} in
    y|Y )
      echo
      apt-get install "${INSTALL_APP_LIST[@]}" -y
      pip_install "requests" "-U"

      if ! command -v "${DOCKER_COMPOSE[@]}" > /dev/null; then
        echo "Installing ${DOCKER_COMPOSE[*]} manually:"
        # install docker-compose manually:
        curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
      fi

    ;;
  esac
}
