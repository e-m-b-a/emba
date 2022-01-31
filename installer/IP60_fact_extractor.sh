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

if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
  print_git_info "fact-extractor" "m-1-k-3/fact_extractor" "Wraps FACT unpack plugins into standalone utility. Should be able to extract most of the common container formats. (EMBA fork)"
  echo -e "$ORANGE""fact_extractor will be downloaded.""$NC"

  if [[ "$FORCE" -eq 0 ]] && [[ "$LIST_DEP" -eq 0 ]] ; then
    echo -e "\\n""$MAGENTA""$BOLD""Do you want to download and install FACT-extractor?""$NC"
    read -p "(y/N)" -r ANSWER
  elif [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]]; then
    ANSWER=("n")
  else
    echo -e "\\n""$MAGENTA""$BOLD""FACT-extractor will be downloaded and installed!""$NC"
    ANSWER=("y")
  fi
  case ${ANSWER:0:1} in
    y|Y )
      if ! [[ -d ./external/fact_extractor ]]; then
        # this is a temporary solution until the official fact repo supports a current kali linux
        git clone https://github.com/m-1-k-3/fact_extractor.git external/fact_extractor
        cd ./external/fact_extractor/fact_extractor/ || exit 1
        ./install/pre_install.sh
        python3 ./install.py
        cd "$HOME_PATH" || exit 1
      fi

      if python3 ./external/fact_extractor/fact_extractor/fact_extract.py -h | grep -q "FACT extractor - Standalone extraction utility"; then
        echo -e "$GREEN""FACT-extractor installed""$NC"
      fi
    ;;
  esac
fi

