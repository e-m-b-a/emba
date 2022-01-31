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

# Description:  Installs iniscan for PHP.ini checks

I20_php_check() {
  module_title "${FUNCNAME[0]}"

  if [[ "$LIST_DEP" -eq 1 ]] || [[ $IN_DOCKER -eq 1 ]] || [[ $DOCKER_SETUP -eq 0 ]] || [[ $FULL -eq 1 ]]; then
  
    cd "$HOME_PATH" || exit 1
    INSTALL_APP_LIST=()
  
    echo -e "\\nTo check the php.ini config for common security practices we have to install Composer and inicheck."
  
    print_tool_info "php" 1
    print_file_info "iniscan/composer.phar" "A Dependency Manager for PHP" "https://getcomposer.org/installer" "external/iniscan/composer.phar"
  
    if [[ "$LIST_DEP" -eq 1 ]] || [[ $DOCKER_SETUP -eq 1 ]] ; then
      ANSWER=("n")
    else
      echo -e "\\n""$MAGENTA""$BOLD""Composer and iniscan (if not already on the system) will be downloaded!""$NC"
      ANSWER=("y")
    fi
  
    case ${ANSWER:0:1} in
      y|Y )
        apt-get install "${INSTALL_APP_LIST[@]}" -y
        if ! [[ -d "external/iniscan" ]] ; then
          mkdir external/iniscan
        fi
        download_file "iniscan/composer.phar" "https://getcomposer.org/installer" "external/iniscan/composer.phar"
        cd ./external/iniscan || exit 1
        php composer.phar build --no-interaction
        php composer.phar global require psecio/iniscan --no-interaction
        cd "$HOME_PATH" || exit 1
        cp -r "/root/.config/composer/vendor/." "./external/iniscan/"
      ;;
    esac
  fi
} 
