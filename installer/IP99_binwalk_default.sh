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

# Description:  Installs binwalk and dependencies for EMBA

IP99_binwalk_default() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${IN_DOCKER}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 0 ]] || [[ "${FULL}" -eq 1 ]]; then
    cd "${HOME_PATH}" || ( echo "Could not install EMBA component binwalk" && exit 1 )
    INSTALL_APP_LIST=()

    print_tool_info "git" 1
    print_tool_info "7zip-standalone" 1

    if [[ "${LIST_DEP}" -eq 1 ]] || [[ "${DOCKER_SETUP}" -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""${MAGENTA}""${BOLD}""binwalk and dependencies (if not already on the system) will be downloaded and installed!""${NC}"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends

        git clone https://github.com/ReFirmLabs/binwalk.git external/binwalk
        cd external/binwalk || ( echo "Could not install EMBA component binwalk" && exit 1 )
        # sed -i -r 's/(pip3.*)$/\1 --break-system-packages/' dependencies/pip.sh
        # We currently stick to the commit right before the plotty changes
        # otherwise we break the entropy generation in EMBA
        git fetch origin 2916ddfed802c61b84f4567c9c1734d69c2e320d
        git checkout FETCH_HEAD

        export PIP_BREAK_SYSTEM_PACKAGES=1
        ./dependencies/ubuntu.sh
        cargo build --release

        cd "${HOME_PATH}" || ( echo "Could not install EMBA component binwalk" && exit 1 )

        if [[ -e "external/binwalk/target/release/binwalk" ]] ; then
          echo -e "${GREEN}""binwalk installed successfully""${NC}"
        else
          echo -e "${ORANGE}""binwalk installation failed - check it manually""${NC}"
        fi

        if ! [[ -d external/cpu_rec ]]; then
          git clone https://github.com/EMBA-support-repos/cpu_rec.git external/cpu_rec
        fi
      ;;
    esac
  fi
}
