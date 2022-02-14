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

IF50_aggregator_common() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
  
    INSTALL_APP_LIST=()
    print_tool_info "python3-pip" 1
    print_tool_info "net-tools" 1
    print_pip_info "cve-searchsploit"
    print_git_info "trickest cve database" "trickest/cve" "Trickest CVE to github exploit database"

  
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""net-tools, pip3, cve-search, trickest and cve_searchsploit (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi
  
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y
        pip3 install cve_searchsploit 2>/dev/null

        # get trickest repository
        if ! [[ -d external/trickest_cve_db ]]; then
          git clone https://github.com/trickest/cve.git external/trickest_cve_db
        else
          cd external/trickest_cve_db || exit 1
          git pull
          cd "$HOME_PATH" || exit 1
        fi
  
        if [[ "$IN_DOCKER" -eq 1 ]] ; then
          echo -e "\\n""$MAGENTA""$BOLD""Updating cve_searchsploit database on docker.""$NC"
          cve_searchsploit -u
        fi
      ;;
    esac
  fi
  apt-get install p7zip-full -y
} 
