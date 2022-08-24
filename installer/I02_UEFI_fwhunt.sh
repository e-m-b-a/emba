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
# Author(s): Michael Messner

# Description:  Installs fwhunt-scan including rules
#               fwhunt-scan https://github.com/binarly-io/fwhunt-scan
#               fwhunt rules https://github.com/binarly-io/FwHunt

I02_UEFI_fwhunt() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then

    print_pip_info "rzpipe"
    print_pip_info "uefi_firmware"
    print_pip_info "pyyaml"
    print_pip_info "click"
    print_tool_info "meson" 1
    print_git_info "rizin" "rizinorg/rizin" ""
    print_git_info "fwhunt-scan" "binarly-io/fwhunt-scan" "Tools for analyzing UEFI firmware and checking UEFI modules with FwHunt rules."
    print_git_info "fwhunt-rules" "binarly-io/FwHunt" "The Binarly Firmware Hunt (FwHunt) rule format was designed to scan for known vulnerabilities in UEFI firmware."
    print_git_info "BIOSUtilities" "platomav/BIOSUtilities" "Various BIOS Utilities for Modding/Research"
  
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""These applications (if not already on the system) will be downloaded!""$NC"
      ANSWER=("y")
    fi
  
    case ${ANSWER:0:1} in
      y|Y )
  
        pip3 install rzpipe 2>/dev/null
        pip3 install click 2>/dev/null
        pip3 install pyyaml 2>/dev/null
        pip3 install uefi_firmware 2>/dev/null

        # rizin:
        apt-get install "${INSTALL_APP_LIST[@]}" -y
        echo -e "$ORANGE""$BOLD""Installing rizin""$NC"
        git clone https://github.com/rizinorg/rizin.git external/rizin
        cd external/rizin || ( echo "Could not install EMBA component rizin" && exit 1 )
        meson build
        ninja -C build
        ninja -C build install
        cd "$HOME_PATH" || ( echo "Could not install EMBA component rizin" && exit 1 )

        # BIOSUtilities
        echo -e "$ORANGE""$BOLD""Installing BIOSUtilities""$NC"
        git clone --branch refactor https://github.com/platomav/BIOSUtilities.git external/BIOSUtilities

        echo -e "$ORANGE""$BOLD""Installing FwHunt""$NC"
        git clone https://github.com/binarly-io/fwhunt-scan.git external/fwhunt-scan
        cd external/fwhunt-scan || ( echo "Could not install EMBA component fwhunt-scan" && exit 1 )
        git clone https://github.com/binarly-io/FwHunt.git rules
        echo "Installed $(find rules/ -iname "BRLY-*" | wc -l) fwhunt rules"
        # currently the following installation step is failing:
        python3 setup.py install || true
        cd "$HOME_PATH" || ( echo "Could not install EMBA component fwhunt-scan" && exit 1 )
      ;;
    esac
  fi
} 
