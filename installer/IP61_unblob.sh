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

# Description:  Installs unblob and dependencies for EMBA

IP61_unblob() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    cd "$HOME_PATH" || ( echo "Could not install EMBA component unblob" && exit 1 )
    INSTALL_APP_LIST=()

    echo -e "$ORANGE""Unblob will be downloaded and installed via Nix.""$NC"

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""unblob with all dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y

        if ! command -v nix > /dev/null ; then
          echo "Installing Nix installation environment ..."
          apt-get install nix-bin nix-setup-systemd -y
          #wget https://nixos.org/nix/install -O ./external/unblob/install
          #cd external/unblob || ( echo "Could not install EMBA component unblob" && exit 1 )
          #chmod +x install
          #echo "y" | ./install --daemon
        else
          echo -e "$GREEN""Nix installation environment already installed""$NC"
        fi

        if command -v nix > /dev/null ; then
          if ! [[ -d ~/.config/nix/ ]]; then
            mkdir -p ~/.config/nix/
          fi
          echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf

          echo "Installing unblob ..."
          nix profile install github:onekey-sec/unblob
          echo
        fi

        if command -v unblob > /dev/null ; then
          unblob --show-external-dependencies
          echo -e "$GREEN""unblob installed successfully""$NC"
          echo
        elif nix profile list | grep -q unblob; then
          UNBLOB_PATH=$(nix profile list | grep unblob | awk '{print $4}' | sort -u)
          "$UNBLOB_PATH"/bin/unblob --show-external-dependencies
          echo -e "$GREEN""unblob installed successfully""$NC"
        else
          echo -e "$ORANGE""unblob installation failed - check it manually""$NC"
        fi
      ;;
    esac
  fi
} 
