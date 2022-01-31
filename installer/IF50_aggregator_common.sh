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
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs common aggregator tools for EMBA 

if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then

    INSTALL_APP_LIST=()
    print_tool_info "python3-pip" 1
    print_tool_info "net-tools" 1
    print_pip_info "cve-searchsploit"

    if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
      echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install the net-tools, pip3, cve-search and cve_searchsploit (if not already on the system)?""$NC"
      read -p "(y/N)" -r ANSWER
    elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""net-tools, pip3, cve-search and cve_searchsploit (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y
        pip3 install cve_searchsploit 2>/dev/null

        if [[ "$IN_DOCKER" -eq 1 ]] ; then
          if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
            echo -e "\\n""$MAGENTA""$BOLD""Do you want to update the cve_searchsploit database in EMBA docker environment?""$NC"
            read -p "(y/N)" -r ANSWER
          else
            echo -e "\\n""$MAGENTA""$BOLD""Updating cve_searchsploit database on docker.""$NC"
            ANSWER=("y")
          fi
          case ${ANSWER:0:1} in
            y|Y )
              cve_searchsploit -u
            ;;
          esac
        fi
      ;;
    esac
fi

