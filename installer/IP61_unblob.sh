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

    print_tool_info "curl" 1
    print_tool_info "e2fsprogs" 1
    print_tool_info "gcc" 1
    print_tool_info "git" 1
    print_tool_info "img2simg" 1
    print_tool_info "liblzo2-dev" 1
    print_tool_info "lz4"
    print_tool_info "lziprecover" 1
    print_tool_info "lzop" 1
    print_tool_info "p7zip-full" 1
    print_tool_info "unar" 1
    print_tool_info "xz-utils" 1
    print_tool_info "zlib1g-dev" 1
    print_tool_info "libmagic1" 1
    print_tool_info "libhyperscan5" 1
    print_tool_info "zstd" 1

    print_file_info "sasquatch_1.0_amd64.deb" "sasquatch_1.0_amd64.deb" "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v1.0/sasquatch_1.0_amd64.deb" "external/sasquatch_1.0_amd64.deb"

    print_git_info "unblob" "onekey-sec/unblob" "Unblob is a powerful firmware extractor"

    echo -e "$ORANGE""Unblob will be downloaded and installed via poetry.""$NC"

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""unblob with all dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y

        #if ! command -v nix > /dev/null ; then
        #  echo "Installing Nix installation environment ..."
        #  apt-get install nix-bin nix-setup-systemd -y
        #  #wget https://nixos.org/nix/install -O ./external/unblob/install
        #  #cd external/unblob || ( echo "Could not install EMBA component unblob" && exit 1 )
        #  #chmod +x install
        #  #echo "y" | ./install --daemon
        #else
        #  echo -e "$GREEN""Nix installation environment already installed""$NC"
        #fi

        #if command -v nix > /dev/null ; then
        #  if ! [[ -d ~/.config/nix/ ]]; then
        #    mkdir -p ~/.config/nix/
        #  fi
        #  echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf

        #  echo "Installing unblob ..."
        #  nix profile install github:onekey-sec/unblob
        #  echo
        #fi

        download_file "sasquatch_1.0_amd64.deb" "https://github.com/onekey-sec/sasquatch/releases/download/sasquatch-v1.0/sasquatch_1.0_amd64.deb" "external/sasquatch_1.0_amd64.deb"
        dpkg -i external/sasquatch_1.0_amd64.deb
        rm -f external/sasquatch_1.0_amd64.deb

        git clone https://github.com/onekey-sec/unblob.git external/unblob

        # install poetry
        curl -sSL https://install.python-poetry.org | python3 -
        cd unblob
        poetry install --only main

        if command -v unblob > /dev/null ; then
          unblob --show-external-dependencies
          echo -e "$GREEN""unblob installed successfully""$NC"
          echo
        elif nix profile list | grep -q unblob; then
          UNBLOB_PATH=$(nix profile list | grep unblob | awk '{print $4}' | sort -u)
          "$UNBLOB_PATH"/bin/unblob --show-external-dependencies
          echo "$UNBLOB_PATH" > ./external/unblob_path.cfg
          echo -e "$GREEN""unblob installed successfully""$NC"
        else
          echo -e "$ORANGE""unblob installation failed - check it manually""$NC"
        fi
      ;;
    esac
  fi
} 
