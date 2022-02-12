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

# Description:  Installs binutils and other tools like radare2 for s12-14 

I13_objdump() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
  
    BINUTIL_VERSION_NAME="binutils-2.35.1"
  
    INSTALL_APP_LIST=()
  
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] ; then
      print_file_info "$BINUTIL_VERSION_NAME" "The GNU Binutils are a collection of binary tools." "https://ftp.gnu.org/gnu/binutils/$BINUTIL_VERSION_NAME.tar.gz" "external/$BINUTIL_VERSION_NAME.tar.gz" "external/objdump"
      print_tool_info "texinfo" 1
      print_tool_info "gcc" 1
      print_tool_info "build-essential" 1
      print_tool_info "gawk" 1
      print_tool_info "bison" 1
      print_tool_info "debuginfod" 1
      print_tool_info "radare2" 1
    fi
  
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""$BINUTIL_VERSION_NAME"" will be downloaded (if not already on the system) and objdump compiled!""$NC"
    fi
  
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y
  
        if ! [[ -f "external/objdump" ]] ; then
          download_file "$BINUTIL_VERSION_NAME" "https://ftp.gnu.org/gnu/binutils/$BINUTIL_VERSION_NAME.tar.gz" "external/$BINUTIL_VERSION_NAME.tar.gz"
          if [[ -f "external/$BINUTIL_VERSION_NAME.tar.gz" ]] ; then
            tar -zxf external/"$BINUTIL_VERSION_NAME".tar.gz -C external
            cd external/"$BINUTIL_VERSION_NAME"/ || exit 1
            echo -e "$ORANGE""$BOLD""Compile objdump""$NC"
            ./configure --enable-targets=all
            make
            cd "$HOME_PATH" || exit 1
          fi
          if [[ -f "external/$BINUTIL_VERSION_NAME/binutils/objdump" ]] ; then
            mv "external/$BINUTIL_VERSION_NAME/binutils/objdump" "external/objdump"
            rm -R "external/""$BINUTIL_VERSION_NAME"
            rm "external/""$BINUTIL_VERSION_NAME"".tar.gz"
            if [[ -f "external/objdump" ]] ; then
              echo -e "$GREEN""objdump installed successfully""$NC"
            fi
          else
            echo -e "$ORANGE""objdump installation failed - check it manually""$NC"
          fi
        else
          echo -e "$GREEN""objdump already installed - no further action performed.""$NC"
        fi
      ;;
    esac
  fi
}
