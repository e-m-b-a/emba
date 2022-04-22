#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2022 Siemens Energy AG
# Copyright 2020-2022 Siemens AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann

# Description:  Installs FirmAE full system emulation
#               This is a temporary module which will be removed in the future without any further note!

IL21_firmae_system_emulator() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    cd "$HOME_PATH" || exit 1

    print_tool_info "xdg-utils" 1
    print_tool_info "fonts-liberation" 1
    print_tool_info "openjdk-11-jdk" 1

    print_git_info "FirmAE system mode emulator" "pr0v3rbs/FirmAE" "FirmAE is a fully-automated framework that performs emulation and vulnerability analysis."

    echo -e "\\n""$MAGENTA""$BOLD""This is a temporary module which will be removed in the future without any further note!""$NC"

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""The FirmAE system emulation dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )

        apt-get install "${INSTALL_APP_LIST[@]}" -y

        if ! [[ -d external/FirmAE_orig ]]; then
          git clone --recursive https://github.com/pr0v3rbs/FirmAE.git external/FirmAE_orig
          cd external/FirmAE_orig || exit 1
        else
          cd external/FirmAE_orig || exit 1
          git pull
        fi

        ./download.sh
        ./install.sh
        ./init.sh

        cd "$HOME_PATH" || exit 1

      ;;
    esac
  fi
}

