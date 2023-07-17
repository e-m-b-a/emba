#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens Energy AG
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

    print_tool_info "python3-pip" 1
    print_tool_info "libpython3-dev" 1
    print_tool_info "zlib1g" 1
    print_tool_info "zlib1g-dev" 1
    print_tool_info "liblzo2-2" 1
    print_tool_info "liblzo2-dev" 1
    print_tool_info "python3-lzo" 1
    print_tool_info "e2fsprogs" 1
    print_tool_info "gcc" 1
    print_tool_info "git" 1
    # print_tool_info "img2simg" 1
    print_tool_info "android-sdk-libsparse-utils" 1
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
    print_tool_info "libhyperscan-dev" 1
    print_tool_info "zstd" 1
    print_tool_info "python3-magic" 1
    print_tool_info "pkg-config" 1
    print_tool_info "pkgconf" 1
    print_tool_info "unblob" 1

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""unblob with all dependencies (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y

        cd "$HOME_PATH" || ( echo "Could not install EMBA component unblob" && exit 1 )

        if command -v unblob > /dev/null ; then
          unblob --show-external-dependencies
          echo -e "$GREEN""unblob installed successfully""$NC"
          echo
        else
          echo -e "$ORANGE""unblob installation failed - check it manually""$NC"
          echo
        fi
      ;;
    esac
  fi
}
