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

# Description:  Installs basic extractor tools

IP00_extractors(){
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]] ; then

    print_tool_info "python3-pip" 1
    print_pip_info "protobuf"
    print_pip_info "bsdiff4"
    print_git_info "payload_dumper" "vm03/payload_dumper" "Android OTA payload.bin extractor"
  
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""These applications will be installed/updated!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        echo

        apt-get install "${INSTALL_APP_LIST[@]}" -y
        pip3 install protobuf
        pip3 install bsdiff4

        if ! [[ -d external/payload_dumper ]]; then
          git clone https://github.com/vm03/payload_dumper.git external/payload_dumper
        else
          cd external/payload_dumper || exit 1 
          git pull
          cd "$HOME_PATH" || exit 1
        fi
      ;;
    esac
  fi
}
