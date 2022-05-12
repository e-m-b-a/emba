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

# Description:  Installs FACT-extractor for EMBA
#               FACT will be completely removed in the future

IP60_fact_extractor() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
    print_tool_info "curl" 1
    print_git_info "fact-extractor" "m-1-k-3/fact_extractor" "Wraps FACT unpack plugins into standalone utility. Should be able to extract most of the common container formats. (EMBA fork)"
    echo -e "$ORANGE""fact_extractor will be downloaded.""$NC"
  
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]]; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""FACT-extractor will be downloaded and installed!""$NC"
      ANSWER=("y")
    fi
  
    case ${ANSWER:0:1} in
      y|Y )
        if ! [[ -d ./external/fact_extractor ]]; then

          # Note: This is a temporary solution until the official FACT repo supports a current kali linux
          # Note: This is a temporary solution as long as the installation via pip does not work
          apt-get install "${INSTALL_APP_LIST[@]}" -y

          cd "$HOME_PATH" || exit 1

          # get the FACT base repository:
          git clone https://github.com/m-1-k-3/fact_extractor.git external/fact_extractor
          cd external/fact_extractor/ || exit 1

          # for entropython we need rust:
          curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > rustup
          chmod +x rustup
          ./rustup -y

          # entropython is currently not available via pip:
          git clone https://github.com/fkie-cad/entropython.git
          cd entropython || exit 1

          /root/.cargo/bin/cargo build --release
          mv target/release/libentropython.so entropython.so
          cp entropython.so /usr/local/lib/python3.10/dist-packages/
          cd .. || exit 1

          # now it is possible to build conmmon_helper_unpacking_classifier (without entropython - which is already installed):
          git clone https://github.com/fkie-cad/common_helper_unpacking_classifier.git
          cd common_helper_unpacking_classifier/ || exit 1
          sed -i "s/'entropython/#'entropython/" setup.py
          pip install .

          cd "$HOME_PATH" || exit 1
          cd external/fact_extractor/fact_extractor/ || exit 1
          ./install/pre_install.sh
          python3 ./install.py
          cd .. || exit 1
          rm rustup

          cd "$HOME_PATH" || exit 1
        fi
  
        if python3 ./external/fact_extractor/fact_extractor/fact_extract.py -h | grep -q "FACT extractor - Standalone extraction utility"; then
          echo -e "$GREEN""FACT-extractor installed""$NC"
        fi
      ;;
    esac
  fi
} 
