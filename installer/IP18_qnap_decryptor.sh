#!/bin/bash

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2023 Siemens AG
# Copyright 2020-2023 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
#
# Author(s): Michael Messner, Pascal Eckmann
# Contributor(s): Stefan Haboeck, Nikolas Papaioannou

# Description:  Installs QNAP decryptor for EMBA

IP18_qnap_decryptor() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    cd "$HOME_PATH" || ( echo "Could not install EMBA component QNAP decryptor" && exit 1 )
    INSTALL_APP_LIST=()
    print_tool_info "gcc" 1
    print_file_info "PC1.c" "Decryptor for QNAP firmware images" "https://gist.githubusercontent.com/galaxy4public/0420c7c9a8e3ff860c8d5dce430b2669/raw/1f8a42c0525efb188c0165c6a4cb205e82f851e2/pc1.c" "external/pc1.c"

    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""QNAP decryptor (if not already on the system) will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi

    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y --no-install-recommends
        download_file "PC1.c" "https://gist.githubusercontent.com/galaxy4public/0420c7c9a8e3ff860c8d5dce430b2669/raw/1f8a42c0525efb188c0165c6a4cb205e82f851e2/pc1.c" "external/pc1.c"

        if [[ -f "external/pc1.c" ]]; then
          cd ./external || ( echo "Could not install EMBA component QNAP decryptor" && exit 1 )
          echo -e "[*] Compiling QNAP decryptor"
          gcc -pipe -Wall -O0 -ggdb -o PC1 pc1.c
          chmod +x ./PC1

          cd "$HOME_PATH" || ( echo "Could not install EMBA component QNAP decryptor" && exit 1 )

          if [[ -f "external/PC1" ]] ; then
            echo -e "$GREEN""QNAP decryptor installed successfully""$NC"
          fi
          if [[ -f "external/pc1.c" ]] ; then
            rm "external/pc1.c"
          fi
        fi
      ;;
    esac
  fi
}
