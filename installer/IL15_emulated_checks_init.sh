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

# Description:  Installs routersploit - used for full system emulation

IL15_emulated_checks_init() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    INSTALL_APP_LIST=()
    cd "$HOME_PATH" || exit 1
    print_git_info "routersploit" "m-1-k-3/routersploit" "The RouterSploit Framework is an open-source exploitation framework dedicated to embedded devices. (EMBA fork)"
    print_tool_info "python3-pip" 1
    print_file_info "routersploit_patch" "FirmAE routersploit patch" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/analyses/routersploit_patch" "external/routersploit/docs/routersploit_patch"

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The routersploit dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
  
      apt-get install "${INSTALL_APP_LIST[@]}" -y
 
      git clone https://github.com/m-1-k-3/routersploit.git external/routersploit

      if ! [[ -f "external/routersploit/docs/routersploit_patch" ]]; then
        # is already applied in the used fork (leave this here for future usecases):
        download_file "routersploit_patch" "https://raw.githubusercontent.com/pr0v3rbs/FirmAE/master/analyses/routersploit_patch" "external/routersploit/docs/routersploit_patch"
        patch -f -p1 < docs/routersploit_patch
      else
        echo -e "$GREEN""routersploit_patch already downloaded""$NC"
      fi

      cd external/routersploit || exit 1
      python3 -m pip install -r requirements.txt

      cd "$HOME_PATH" || exit 1

      ;;
    esac
  fi
}
